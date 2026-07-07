"""Tests for Data Integrity (eddsa-rdfc-2022) issuance — ob3.ldp signing.

The crypto tests need pyld (the [ldp] extra) and skip without it; the
"extra absent" tests run always. tests/ldp_helpers.py stays as an
independent oracle: it shares no code with the production signer beyond
_canonize, so an encoding/hashing regression shows up as a divergence.
"""
import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openbadgeslib.errors import ErrorSigningFile
from openbadgeslib.ob3 import add_data_integrity_proof, verify_data_integrity_proof
from openbadgeslib.ob3.credential import _parse_iso

from ldp_helpers import did_key as _did_key
from ldp_helpers import sign_ldp as _sign_ldp

FIXTURES = Path(__file__).parent / 'fixtures' / 'vc_di_eddsa'

_MULTICODEC_ED25519_PRIV = 0x1300


def _unsecured_ob3_doc(ob3_credential, pub_pem) -> dict:
    doc = ob3_credential.to_vc()
    # Name the did:key as issuer so key-from-proof resolution is trustable.
    doc['issuer'] = {'id': _did_key(pub_pem), 'type': ['Profile'],
                     'name': 'Test Issuer'}
    return doc


def _did_key_vm(pub_pem) -> str:
    did = _did_key(pub_pem)
    return '%s#%s' % (did, did[len('did:key:'):])


@pytest.fixture(scope='session')
def vector():
    pytest.importorskip('pyld')
    return json.loads((FIXTURES / 'signed-credential.json').read_text())


@pytest.fixture(scope='session')
def vector_privkey_pem():
    from openbadgeslib.ob3.did import _b58btc_decode, _read_varint
    mk = json.loads((FIXTURES / 'key-pair.json').read_text())
    code, raw = _read_varint(_b58btc_decode(mk['privateKeyMultibase'][1:]))
    assert code == _MULTICODEC_ED25519_PRIV
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    return priv.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                              ser.NoEncryption())


@pytest.fixture(scope='session')
def examples_ctx():
    return {
        'https://www.w3.org/ns/credentials/examples/v2':
            json.loads((FIXTURES / 'credentials-examples-v2.json').read_text()),
    }


# ── low-level signing: add_data_integrity_proof ─────────────────────────────

class TestAddDataIntegrityProof:
    @pytest.fixture(autouse=True)
    def _needs_pyld(self):
        pytest.importorskip('pyld')

    def test_sign_then_verify_roundtrip(self, ob3_credential, ed25519_keypair):
        priv_pem, pub_pem = ed25519_keypair
        doc = _unsecured_ob3_doc(ob3_credential, pub_pem)
        signed = add_data_integrity_proof(doc, priv_pem, _did_key_vm(pub_pem))
        verify_data_integrity_proof(signed, pub_pem)

    def test_reproduces_official_w3c_vector(self, vector, vector_privkey_pem,
                                            examples_ctx):
        # Ed25519 is deterministic: signing the vector's document with its
        # own key, created timestamp and verificationMethod must reproduce
        # the published proof byte for byte, proofValue included.
        unsecured = copy.deepcopy(vector)
        expected_proof = unsecured.pop('proof')
        signed = add_data_integrity_proof(
            unsecured, vector_privkey_pem,
            expected_proof['verificationMethod'],
            created=_parse_iso(expected_proof['created']),
            extra_contexts=examples_ctx)
        assert signed['proof'] == expected_proof
        assert signed == vector

    def test_matches_test_helper_oracle(self, ob3_credential, ed25519_keypair):
        # ldp_helpers.sign_ldp is an independent ~30-line implementation of
        # the same algorithm; identical inputs must yield identical output.
        priv_pem, pub_pem = ed25519_keypair
        doc = _unsecured_ob3_doc(ob3_credential, pub_pem)
        from_helper = _sign_ldp(doc, priv_pem, pub_pem)
        from_lib = add_data_integrity_proof(
            doc, priv_pem, _did_key_vm(pub_pem),
            created=datetime(2026, 7, 3, tzinfo=timezone.utc))
        assert from_lib == from_helper

    def test_tampering_after_signing_detected(self, ob3_credential,
                                              ed25519_keypair):
        from openbadgeslib.ob3 import OB3VerificationError
        priv_pem, pub_pem = ed25519_keypair
        doc = _unsecured_ob3_doc(ob3_credential, pub_pem)
        signed = add_data_integrity_proof(doc, priv_pem, _did_key_vm(pub_pem))
        signed['name'] = 'Forged Achievement'
        with pytest.raises(OB3VerificationError):
            verify_data_integrity_proof(signed, pub_pem)

    def test_embedded_proof_has_no_context(self, ob3_credential,
                                           ed25519_keypair):
        priv_pem, pub_pem = ed25519_keypair
        doc = _unsecured_ob3_doc(ob3_credential, pub_pem)
        signed = add_data_integrity_proof(doc, priv_pem, _did_key_vm(pub_pem))
        assert '@context' not in signed['proof']
        assert signed['proof']['proofValue'].startswith('z')

    def test_input_document_not_mutated(self, ob3_credential, ed25519_keypair):
        priv_pem, pub_pem = ed25519_keypair
        doc = _unsecured_ob3_doc(ob3_credential, pub_pem)
        snapshot = copy.deepcopy(doc)
        add_data_integrity_proof(doc, priv_pem, _did_key_vm(pub_pem))
        assert doc == snapshot

    def test_default_created_is_valid_iso_utc(self, ob3_credential,
                                              ed25519_keypair):
        priv_pem, pub_pem = ed25519_keypair
        doc = _unsecured_ob3_doc(ob3_credential, pub_pem)
        signed = add_data_integrity_proof(doc, priv_pem, _did_key_vm(pub_pem))
        created = _parse_iso(signed['proof']['created'])
        assert abs((created - datetime.now(timezone.utc)).total_seconds()) < 60

    def test_document_with_existing_proof_rejected(self, ob3_credential,
                                                   ed25519_keypair):
        priv_pem, pub_pem = ed25519_keypair
        doc = _unsecured_ob3_doc(ob3_credential, pub_pem)
        signed = add_data_integrity_proof(doc, priv_pem, _did_key_vm(pub_pem))
        with pytest.raises(ErrorSigningFile, match='already carries'):
            add_data_integrity_proof(signed, priv_pem, _did_key_vm(pub_pem))

    def test_non_ed25519_key_rejected(self, ob3_credential, ed25519_keypair,
                                      rsa_priv_pem, ecc_priv_pem):
        _, pub_pem = ed25519_keypair
        doc = _unsecured_ob3_doc(ob3_credential, pub_pem)
        for pem in (rsa_priv_pem, ecc_priv_pem):
            with pytest.raises(ErrorSigningFile, match='Ed25519'):
                add_data_integrity_proof(doc, pem, _did_key_vm(pub_pem))

    def test_non_dict_document_rejected(self, ed25519_keypair):
        priv_pem, pub_pem = ed25519_keypair
        with pytest.raises(ErrorSigningFile, match='JSON object'):
            add_data_integrity_proof('[]', priv_pem, _did_key_vm(pub_pem))  # type: ignore[arg-type]

    def test_empty_verification_method_rejected(self, ob3_credential,
                                                ed25519_keypair):
        priv_pem, pub_pem = ed25519_keypair
        doc = _unsecured_ob3_doc(ob3_credential, pub_pem)
        with pytest.raises(ErrorSigningFile, match='verificationMethod'):
            add_data_integrity_proof(doc, priv_pem, '')

    def test_unlisted_context_fails_closed(self, ob3_credential,
                                           ed25519_keypair):
        priv_pem, pub_pem = ed25519_keypair
        doc = _unsecured_ob3_doc(ob3_credential, pub_pem)
        doc['@context'] = list(doc['@context']) + ['https://evil.example/ctx']
        with pytest.raises(ErrorSigningFile):
            add_data_integrity_proof(doc, priv_pem, _did_key_vm(pub_pem))


# ── high-level signer: OB3LdpSigner ──────────────────────────────────────────

class TestOB3LdpSigner:
    @pytest.fixture(autouse=True)
    def _needs_pyld(self):
        pytest.importorskip('pyld')

    def _did_key_credential(self, ob3_credential, pub_pem):
        from openbadgeslib.ob3 import Issuer
        import dataclasses
        return dataclasses.replace(
            ob3_credential, issuer=Issuer(id=_did_key(pub_pem), name='Test Issuer'))

    def test_sign_verifies_with_pinned_key(self, ob3_credential,
                                           ed25519_keypair):
        from openbadgeslib.ob3 import OB3LdpSigner, OB3LdpVerifier
        priv_pem, pub_pem = ed25519_keypair
        signed = OB3LdpSigner(priv_pem).sign(ob3_credential)
        cred = OB3LdpVerifier(pubkey_pem=pub_pem).verify(signed)
        assert cred.id == ob3_credential.id
        # The LDP path exposes the raw document too (set in _from_vc), including
        # the proof it was verified with.
        assert cred.raw is not None and 'proof' in cred.raw

    def test_sign_verifies_unpinned_via_did_key(self, ob3_credential,
                                                ed25519_keypair):
        # did:key issuer + default VM: the proof itself carries the key.
        from openbadgeslib.ob3 import OB3LdpSigner, OB3LdpVerifier
        priv_pem, pub_pem = ed25519_keypair
        credential = self._did_key_credential(ob3_credential, pub_pem)
        signed = OB3LdpSigner(priv_pem).sign(credential)
        cred = OB3LdpVerifier().verify(signed)
        assert cred.issuer.id == _did_key(pub_pem)

    def test_default_vm_is_did_key_of_signing_key(self, ed25519_keypair):
        from openbadgeslib.ob3 import OB3LdpSigner
        priv_pem, pub_pem = ed25519_keypair
        assert OB3LdpSigner(priv_pem).verification_method == \
            _did_key_vm(pub_pem)

    def test_did_web_roundtrip_with_published_document(self, ob3_credential,
                                                       ed25519_keypair):
        # The §publisher contract: sign with did:web:host#badge_1 and verify
        # against the DID document openbadges-publish would serve.
        import dataclasses
        from openbadgeslib.keys import public_jwk_from_pem
        from openbadgeslib.ob3 import (Issuer, OB3LdpSigner, OB3LdpVerifier,
                                       build_did_document)
        priv_pem, pub_pem = ed25519_keypair
        did = 'did:web:issuer.example'
        doc = build_did_document(did, [('badge_1',
                                        public_jwk_from_pem(pub_pem))])
        credential = dataclasses.replace(
            ob3_credential, issuer=Issuer(id=did, name='Test Issuer'))
        signer = OB3LdpSigner(priv_pem, verification_method=did + '#badge_1')
        signed = signer.sign(credential)

        fetch = lambda url: json.dumps(doc).encode('utf-8')  # noqa: E731
        cred = OB3LdpVerifier().verify(signed, download=fetch)
        assert cred.issuer.id == did
        cred = OB3LdpVerifier.for_issuer_did(did).verify(signed,
                                                         download=fetch)
        assert cred.issuer.id == did

    def test_sign_into_svg_roundtrip(self, ob3_credential, ed25519_keypair,
                                     svg_image):
        from openbadgeslib.ob3 import OB3LdpSigner, OB3LdpVerifier, OB3Verifier
        priv_pem, pub_pem = ed25519_keypair
        credential = self._did_key_credential(ob3_credential, pub_pem)
        baked = OB3LdpSigner(priv_pem).sign_into_svg(credential, svg_image)
        token = OB3Verifier.extract_token_from_svg(baked)
        assert token.lstrip().startswith('{')
        cred = OB3LdpVerifier(pubkey_pem=pub_pem).verify(token)
        assert cred.id == credential.id

    def test_sign_into_png_roundtrip(self, ob3_credential, ed25519_keypair,
                                     png_image):
        from openbadgeslib.ob3 import OB3LdpSigner, OB3LdpVerifier, OB3Verifier
        priv_pem, pub_pem = ed25519_keypair
        credential = self._did_key_credential(ob3_credential, pub_pem)
        baked = OB3LdpSigner(priv_pem).sign_into_png(credential, png_image)
        token = OB3Verifier.extract_token_from_png(baked)
        assert token.lstrip().startswith('{')
        cred = OB3LdpVerifier(pubkey_pem=pub_pem).verify(token)
        assert cred.id == credential.id

    def test_constructor_rejects_non_ed25519(self, rsa_priv_pem,
                                             ecc_priv_pem):
        from openbadgeslib.ob3 import OB3LdpSigner
        for pem in (rsa_priv_pem, ecc_priv_pem):
            with pytest.raises(ErrorSigningFile, match='Ed25519'):
                OB3LdpSigner(pem)


# ── behaviour without the [ldp] extra (runs with or without pyld) ───────────

class TestSignExtraAbsent:
    def test_missing_pyld_yields_actionable_error(self, monkeypatch,
                                                  ed25519_keypair):
        monkeypatch.setitem(sys.modules, 'pyld', None)
        priv_pem, pub_pem = ed25519_keypair
        doc = {'@context': ['https://www.w3.org/ns/credentials/v2'],
               'id': 'urn:uuid:x',
               'type': ['VerifiableCredential']}
        with pytest.raises(ErrorSigningFile,
                           match=r'pip install openbadgeslib\[ldp\]'):
            add_data_integrity_proof(doc, priv_pem, _did_key_vm(pub_pem))

    def test_signer_constructs_without_pyld_but_sign_fails(self, monkeypatch,
                                                           ob3_credential,
                                                           ed25519_keypair):
        from openbadgeslib.ob3 import OB3LdpSigner
        monkeypatch.setitem(sys.modules, 'pyld', None)
        priv_pem, _ = ed25519_keypair
        signer = OB3LdpSigner(priv_pem)   # construction needs no pyld
        with pytest.raises(ErrorSigningFile,
                           match=r'pip install openbadgeslib\[ldp\]'):
            signer.sign(ob3_credential)
