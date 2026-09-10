"""Tests for the delegated ecdsa-sd-2023 (selective disclosure) verify path —
ob3.ldp.

openbadgeslib only VERIFIES ecdsa-sd-2023, delegating the crypto to
openvc-core. These tests use openvc-core to issue a base proof and derive a
holder presentation, then verify it through OB3LdpVerifier / the low-level
entry, so they exercise openbadgeslib's wiring (P-256 key -> JWK, the pinned
OB3 @context set handed to the delegate, exception mapping, the cryptosuite
registry) rather than re-testing openvc's crypto internals. They need the
[ldp-sd] extra (openvc-core + pyld): missing it SKIPs locally but FAILs under
CI, where the extra is installed on purpose (#221). The "extra absent" test at
the bottom runs always.
"""
import copy
import importlib
import os
import sys

import pytest

from openbadgeslib.ob3 import OB3VerificationError
from openbadgeslib.ob3.ldp import (
    OB3LdpVerifier,
    _verify_ecdsa_sd_2023,
    verify_data_integrity_proof,
)

# Core fields always revealed; credentialSchema is left non-mandatory so it can
# be disclosed selectively (exercising the per-statement signatures) or withheld
# (exercising a genuine selective-disclosure omission). validUntil and
# credentialStatus are issuer-signed but NOT mandatory: that is what lets a
# holder hide them, which OB3LdpVerifier.verify must refuse (#328).
MANDATORY = ['/id', '/type', '/name', '/issuer', '/validFrom',
             '/credentialSubject']

_STATUS_ENTRY = {
    'id': 'https://example.com/status/1#0',
    'type': 'BitstringStatusListEntry',
    'statusPurpose': 'revocation',
    'statusListIndex': '0',
    'statusListCredential': 'https://example.com/status/1',
}


def _lifecycle_credential(ob3_credential):
    """Copy of *ob3_credential* with validUntil and credentialStatus set.

    ecdsa-sd-2023 presentations that omit either claim are rejected at
    OB3LdpVerifier.verify, so the happy-path fixture has to carry both.
    """
    from dataclasses import replace
    from datetime import datetime, timezone
    return replace(
        ob3_credential,
        expiration_date=datetime(2030, 1, 1, tzinfo=timezone.utc),
        credential_status=[dict(_STATUS_ENTRY)],
    )


def _p256_pem_pair():
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    return (
        priv.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                           ser.NoEncryption()),
        priv.public_key().public_bytes(
            ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo),
    )


def _issue_and_derive(ob3_credential, *, selective):
    """openvc issues an ecdsa-sd-2023 base proof over a did:key-issuer OB3
    credential, then derives a presentation revealing MANDATORY + *selective*.
    Returns (derived_doc, p256_pub_pem, issuer_did)."""
    from openvc.keys import P256SigningKey
    from openvc.proof.ecdsa_sd import EcdsaSdProofSuite

    from openbadgeslib.ob3.contexts import bundled_contexts
    from openbadgeslib.ob3.did import did_key_from_pem

    priv_pem, pub_pem = _p256_pem_pair()
    did = did_key_from_pem(pub_pem)
    vm = '%s#%s' % (did, did[len('did:key:'):])

    doc = ob3_credential.to_vc()
    doc['issuer'] = {'id': did, 'type': ['Profile'], 'name': 'Test Issuer',
                     'url': 'https://example.com'}

    # openvc canonicalizes with its own engine, which does not bundle the OB3
    # (imsglobal) contexts — hand it openbadgeslib's pinned set, exactly as the
    # verify path does. Otherwise issuance fails to normalize the OB3 document.
    ctx = bundled_contexts()
    suite = EcdsaSdProofSuite()
    base = suite.add_base_proof(
        doc, signing_key=P256SigningKey.from_pem(priv_pem, kid=vm),
        verification_method=vm, mandatory_pointers=MANDATORY,
        extra_contexts=ctx)
    derived = suite.derive_proof(base, selective_pointers=selective,
                                 extra_contexts=ctx)
    return derived, pub_pem, did


def _require_ldp_sd() -> None:
    """Ensure the [ldp-sd] delegate stack (openvc-core + pyld) is importable.

    Missing it SKIPs, except where the extra is installed on purpose — the main
    CI test job sets ``OPENBADGES_REQUIRE_LDP_SD=1`` — where it FAILs instead, so
    an import that stops resolving there (e.g. an openvc-core packaging change)
    turns the whole ecdsa-sd-2023 suite red rather than passing by skipping in
    silence (#221). A core-only CI leg that deliberately omits [ldp-sd] (e.g. the
    windows-latest leg) does not set the flag and so skips cleanly (#230).
    """
    for mod in ('openvc', 'pyld'):
        try:
            importlib.import_module(mod)
        except ImportError as exc:
            reason = ('the [ldp-sd] extra is required for the ecdsa-sd-2023 '
                      'tests but %r is not importable: %s' % (mod, exc))
            if os.environ.get('OPENBADGES_REQUIRE_LDP_SD') == '1':
                pytest.fail(reason, pytrace=False)
            pytest.skip(reason)


@pytest.fixture(scope='session')
def sd_credential(ob3_credential):
    """A holder presentation revealing schema + the lifecycle claims."""
    _require_ldp_sd()
    return _issue_and_derive(
        _lifecycle_credential(ob3_credential),
        selective=['/credentialSchema', '/validUntil', '/credentialStatus'])


class TestEcdsaSdVerify:
    def test_pinned_key_roundtrip(self, sd_credential):
        derived, pub_pem, _ = sd_credential
        cred = OB3LdpVerifier(pubkey_pem=pub_pem).verify(derived)
        assert cred.achievement.name == 'Test Achievement'

    def test_low_level_entry_verifies(self, sd_credential):
        derived, pub_pem, _ = sd_credential
        verify_data_integrity_proof(derived, pub_pem)  # no raise == verified

    def test_did_key_resolution_roundtrip(self, sd_credential):
        # No pinned key: the P-256 did:key verificationMethod is resolved, and
        # (issuer == that did:key) authorizes it.
        derived, _, did = sd_credential
        cred = OB3LdpVerifier().verify(derived)
        assert cred.issuer.id == did

    def test_tampered_disclosed_field_rejected(self, sd_credential):
        derived, pub_pem, _ = sd_credential
        tampered = copy.deepcopy(derived)
        tampered['name'] = 'Bachelor of Villainy'
        with pytest.raises(OB3VerificationError):
            OB3LdpVerifier(pubkey_pem=pub_pem).verify(tampered)

    def test_wrong_key_rejected(self, sd_credential):
        derived, _, _ = sd_credential
        _, other_pub = _p256_pem_pair()
        with pytest.raises(OB3VerificationError):
            OB3LdpVerifier(pubkey_pem=other_pub).verify(derived)

    def test_ed25519_key_rejected(self, sd_credential, ed25519_keypair):
        # ecdsa-sd-2023 is P-256 only; an Ed25519 key fails before the delegate.
        derived, _, _ = sd_credential
        _, ed_pub = ed25519_keypair
        with pytest.raises(OB3VerificationError, match='P-256'):
            OB3LdpVerifier(pubkey_pem=ed_pub).verify(derived)

    def test_selective_omission(self, ob3_credential):
        # Withhold credentialSchema entirely: still verifies, and the field is
        # absent from the presentation the verifier sees. Lifecycle claims stay
        # disclosed — omitting those is a fail, not a selective-disclosure
        # feature (#328).
        # Unlike the other tests this uses ob3_credential (not the sd_credential
        # fixture), so it must run the [ldp-sd] guard itself — otherwise the
        # direct openvc import in _issue_and_derive would fail instead of skip.
        _require_ldp_sd()
        derived, pub_pem, _ = _issue_and_derive(
            _lifecycle_credential(ob3_credential),
            selective=['/validUntil', '/credentialStatus'])
        assert 'credentialSchema' not in derived
        OB3LdpVerifier(pubkey_pem=pub_pem).verify(derived)

    def test_omitted_valid_until_is_rejected(self, ob3_credential):
        _require_ldp_sd()
        derived, pub_pem, _ = _issue_and_derive(
            _lifecycle_credential(ob3_credential),
            selective=['/credentialStatus'])
        assert 'validUntil' not in derived
        with pytest.raises(OB3VerificationError, match='validUntil'):
            OB3LdpVerifier(pubkey_pem=pub_pem).verify(derived)

    def test_omitted_credential_status_is_rejected(self, ob3_credential):
        _require_ldp_sd()
        derived, pub_pem, _ = _issue_and_derive(
            _lifecycle_credential(ob3_credential),
            selective=['/validUntil'])
        assert 'credentialStatus' not in derived
        with pytest.raises(OB3VerificationError, match='credentialStatus'):
            OB3LdpVerifier(pubkey_pem=pub_pem).verify(derived)

    def test_low_level_entry_does_not_enforce_lifecycle(self, ob3_credential):
        # verify_data_integrity_proof checks the proof alone; hiding
        # validUntil is a high-level OB3LdpVerifier policy, not a crypto
        # failure.
        _require_ldp_sd()
        derived, pub_pem, _ = _issue_and_derive(
            _lifecycle_credential(ob3_credential), selective=[])
        assert 'validUntil' not in derived
        verify_data_integrity_proof(derived, pub_pem)

    def test_registered_in_cryptosuites(self):
        from openbadgeslib.ob3.ldp import _CRYPTOSUITES
        assert 'ecdsa-sd-2023' in _CRYPTOSUITES


# ── behaviour without the [ldp-sd] extra (runs with or without openvc) ───────

def test_missing_openvc_yields_actionable_error(monkeypatch):
    # Null the submodules too — nulling only the top package is ignored when the
    # submodules are already cached in sys.modules.
    for name in ('openvc', 'openvc.proof.ecdsa_sd', 'openvc.proof.errors'):
        monkeypatch.setitem(sys.modules, name, None)
    with pytest.raises(OB3VerificationError, match=r'ldp-sd'):
        _verify_ecdsa_sd_2023({}, {'proofPurpose': 'assertionMethod'},
                              b'irrelevant', None)
