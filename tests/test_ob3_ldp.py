"""Tests for Data Integrity (eddsa-rdfc-2022) verification — ob3.ldp.

The crypto tests need pyld (the [ldp] extra) and skip without it; the
"extra absent" tests at the bottom run always.
"""
import copy
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from openbadgeslib.ob3 import OB3VerificationError, OB3Verifier
from openbadgeslib.ob3.ldp import (
    MAX_LDP_DOCUMENT_BYTES,
    OB3LdpVerifier,
    verify_data_integrity_proof,
)

from ldp_helpers import b58encode as _b58encode
from ldp_helpers import did_key as _did_key
from ldp_helpers import sign_ldp as _sign_ldp

FIXTURES = Path(__file__).parent / 'fixtures' / 'vc_di_eddsa'


@pytest.fixture(scope='session')
def ldp_signed_vc(ob3_credential, ed25519_keypair):
    pytest.importorskip('pyld')
    priv_pem, pub_pem = ed25519_keypair
    doc = ob3_credential.to_vc()
    # Name the did:key as issuer so key-from-proof resolution is trustable.
    doc['issuer'] = {'id': _did_key(pub_pem), 'type': ['Profile'],
                     'name': 'Test Issuer'}
    return _sign_ldp(doc, priv_pem, pub_pem)


# ── official W3C test vectors (interop) ──────────────────────────────────────

@pytest.fixture(scope='session')
def vector():
    pytest.importorskip('pyld')
    return json.loads((FIXTURES / 'signed-credential.json').read_text())


@pytest.fixture(scope='session')
def vector_pem():
    from openbadgeslib.ob3 import resolve_verification_method
    mk = json.loads((FIXTURES / 'key-pair.json').read_text())
    return resolve_verification_method('did:key:%(k)s#%(k)s' % {
        'k': mk['publicKeyMultibase']})


@pytest.fixture(scope='session')
def examples_ctx():
    return {
        'https://www.w3.org/ns/credentials/examples/v2':
            json.loads((FIXTURES / 'credentials-examples-v2.json').read_text()),
    }


class TestOfficialVectors:
    def test_official_vector_verifies(self, vector, vector_pem, examples_ctx):
        verify_data_integrity_proof(vector, vector_pem,
                                    extra_contexts=examples_ctx)

    def test_intermediate_hashes_match_spec(self, vector, examples_ctx):
        from openbadgeslib.ob3.contexts import document_loader
        from openbadgeslib.ob3.ldp import _canonize
        loader = document_loader(examples_ctx)
        unsecured = copy.deepcopy(vector)
        proof = unsecured.pop('proof')
        config = {k: v for k, v in proof.items() if k != 'proofValue'}
        config['@context'] = vector['@context']
        doc_hash = hashlib.sha256(_canonize(unsecured, loader).encode()).hexdigest()
        cfg_hash = hashlib.sha256(_canonize(config, loader).encode()).hexdigest()
        assert doc_hash == (FIXTURES / 'doc-hash.txt').read_text().strip()
        assert cfg_hash == (FIXTURES / 'proof-config-hash.txt').read_text().strip()

    def test_tampered_document_rejected(self, vector, vector_pem, examples_ctx):
        tampered = copy.deepcopy(vector)
        tampered['name'] = 'Bachelor of Villainy'
        with pytest.raises(OB3VerificationError):
            verify_data_integrity_proof(tampered, vector_pem,
                                        extra_contexts=examples_ctx)

    def test_tampered_proof_value_rejected(self, vector, vector_pem, examples_ctx):
        tampered = copy.deepcopy(vector)
        pv = tampered['proof']['proofValue']
        tampered['proof']['proofValue'] = pv[:-2] + ('11' if pv[-2:] != '11' else '22')
        with pytest.raises(OB3VerificationError):
            verify_data_integrity_proof(tampered, vector_pem,
                                        extra_contexts=examples_ctx)


# ── full OB3 flow ────────────────────────────────────────────────────────────

class TestOB3LdpVerifier:
    def test_pinned_key_verifies(self, ldp_signed_vc, ed25519_pub_pem):
        cred = OB3LdpVerifier(pubkey_pem=ed25519_pub_pem).verify(
            ldp_signed_vc, expected_recipient='recipient@example.com')
        assert cred.achievement.name == 'Test Achievement'

    def test_key_resolved_from_proof_did_key(self, ldp_signed_vc):
        cred = OB3LdpVerifier().verify(ldp_signed_vc)
        assert cred.issuer.id.startswith('did:key:')

    def test_accepts_json_string_and_bytes(self, ldp_signed_vc, ed25519_pub_pem):
        v = OB3LdpVerifier(pubkey_pem=ed25519_pub_pem)
        text = json.dumps(ldp_signed_vc)
        assert v.verify(text).id == ldp_signed_vc['id']
        assert v.verify(text.encode('utf-8')).id == ldp_signed_vc['id']

    def test_anchored_did_binding(self, ldp_signed_vc):
        did = ldp_signed_vc['issuer']['id']
        assert OB3LdpVerifier.for_issuer_did(did).verify(ldp_signed_vc)
        with pytest.raises(OB3VerificationError, match='anchored'):
            OB3LdpVerifier.for_issuer_did('did:web:other.example').verify(
                ldp_signed_vc)

    def test_vm_of_foreign_did_issuer_rejected(self, ldp_signed_vc):
        # Unpinned verification must refuse a proof whose verificationMethod
        # does not belong to the credential's DID issuer.
        doc = copy.deepcopy(ldp_signed_vc)
        doc['issuer'] = {'id': 'did:web:issuer.example', 'type': ['Profile'],
                         'name': 'Someone Else'}
        with pytest.raises(OB3VerificationError, match='does not belong'):
            OB3LdpVerifier().verify(doc)

    def test_tampering_after_signing_rejected(self, ldp_signed_vc,
                                              ed25519_pub_pem):
        doc = copy.deepcopy(ldp_signed_vc)
        doc['credentialSubject']['id'] = 'mailto:attacker@example.com'
        with pytest.raises(OB3VerificationError):
            OB3LdpVerifier(pubkey_pem=ed25519_pub_pem).verify(doc)

    def test_recipient_mismatch_rejected(self, ldp_signed_vc, ed25519_pub_pem):
        with pytest.raises(OB3VerificationError, match='Recipient mismatch'):
            OB3LdpVerifier(pubkey_pem=ed25519_pub_pem).verify(
                ldp_signed_vc, expected_recipient='other@example.com')

    def test_non_ed25519_pinned_key_rejected(self, ldp_signed_vc, rsa_pub_pem):
        with pytest.raises(OB3VerificationError, match='Ed25519'):
            OB3LdpVerifier(pubkey_pem=rsa_pub_pem).verify(ldp_signed_vc)

    def test_check_status_runs_on_ldp_credentials(self, ob3_credential,
                                                  ed25519_keypair):
        pytest.importorskip('pyld')
        priv_pem, pub_pem = ed25519_keypair
        doc = ob3_credential.to_vc()
        doc['issuer'] = {'id': _did_key(pub_pem), 'type': ['Profile'], 'name': 'I'}
        doc['credentialStatus'] = {
            'type': 'BitstringStatusListEntry', 'statusPurpose': 'revocation',
            'statusListIndex': '3',
            'statusListCredential': 'https://issuer.example/status.jwt'}
        signed = _sign_ldp(doc, priv_pem, pub_pem)
        from openbadgeslib.ob3.status_list import build_status_list_credential
        status_vc = build_status_list_credential(
            'https://issuer.example/', 'https://issuer.example/status.jwt',
            'revocation', [3])
        import openbadgeslib.ob3.status as status_mod
        v = OB3LdpVerifier(pubkey_pem=pub_pem)
        assert v.verify(signed)                     # without status: passes
        orig = status_mod.download_file
        status_mod.download_file = lambda url: json.dumps(status_vc).encode()
        try:
            with pytest.raises(OB3VerificationError, match='revocation'):
                v.verify(signed, check_status=True)
        finally:
            status_mod.download_file = orig


# ── proof validation edge cases ──────────────────────────────────────────────

class TestProofValidation:
    def _base(self, ldp_signed_vc):
        return copy.deepcopy(ldp_signed_vc)

    def test_unknown_cryptosuite_fails_closed(self, ldp_signed_vc):
        # A real Data Integrity suite openbadgeslib does not implement (only the
        # whole-document eddsa-rdfc-2022 and selective-disclosure ecdsa-sd-2023
        # are supported); the failure names the supported set.
        doc = self._base(ldp_signed_vc)
        doc['proof']['cryptosuite'] = 'ecdsa-rdfc-2019'
        with pytest.raises(OB3VerificationError,
                           match='supported cryptosuites: ecdsa-sd-2023, '
                                 'eddsa-rdfc-2022'):
            OB3LdpVerifier().verify(doc)

    def test_wrong_proof_type_fails_closed(self, ldp_signed_vc):
        doc = self._base(ldp_signed_vc)
        doc['proof']['type'] = 'Ed25519Signature2020'
        with pytest.raises(OB3VerificationError, match='no supported'):
            OB3LdpVerifier().verify(doc)

    def test_wrong_proof_purpose_rejected(self, ldp_signed_vc):
        doc = self._base(ldp_signed_vc)
        doc['proof']['proofPurpose'] = 'authentication'
        with pytest.raises(OB3VerificationError, match='proofPurpose'):
            OB3LdpVerifier().verify(doc)

    def test_missing_proof_rejected(self, ldp_signed_vc):
        doc = self._base(ldp_signed_vc)
        del doc['proof']
        with pytest.raises(OB3VerificationError, match='no supported'):
            OB3LdpVerifier().verify(doc)

    def test_two_supported_proofs_rejected(self, ldp_signed_vc):
        doc = self._base(ldp_signed_vc)
        doc['proof'] = [doc['proof'], copy.deepcopy(doc['proof'])]
        with pytest.raises(OB3VerificationError, match='multiple'):
            OB3LdpVerifier().verify(doc)

    @pytest.mark.parametrize('bad', ['not-multibase', 'zzz', '', None, 42])
    def test_malformed_proof_value_rejected(self, ldp_signed_vc,
                                            ed25519_pub_pem, bad):
        doc = self._base(ldp_signed_vc)
        doc['proof']['proofValue'] = bad
        with pytest.raises(OB3VerificationError):
            OB3LdpVerifier(pubkey_pem=ed25519_pub_pem).verify(doc)

    def test_expired_proof_rejected(self, ldp_signed_vc, ed25519_pub_pem):
        doc = self._base(ldp_signed_vc)
        doc['proof']['expires'] = '2001-01-01T00:00:00Z'
        with pytest.raises(OB3VerificationError, match='expired'):
            OB3LdpVerifier(pubkey_pem=ed25519_pub_pem).verify(doc)

    def test_expired_credential_rejected(self, ob3_credential, ed25519_keypair):
        pytest.importorskip('pyld')
        priv_pem, pub_pem = ed25519_keypair
        doc = ob3_credential.to_vc()
        doc['issuer'] = {'id': _did_key(pub_pem), 'type': ['Profile'], 'name': 'I'}
        doc['validUntil'] = '2001-01-01T00:00:00Z'
        signed = _sign_ldp(doc, priv_pem, pub_pem)
        with pytest.raises(OB3VerificationError, match='expired'):
            OB3LdpVerifier(pubkey_pem=pub_pem).verify(signed)

    def test_unlisted_context_fails_closed(self, ldp_signed_vc,
                                           ed25519_pub_pem):
        doc = self._base(ldp_signed_vc)
        doc['@context'] = list(doc['@context']) + ['https://evil.example/ctx']
        with pytest.raises(OB3VerificationError, match='allowlist'):
            OB3LdpVerifier(pubkey_pem=ed25519_pub_pem).verify(doc)

    def test_oversized_document_rejected(self, ldp_signed_vc, ed25519_pub_pem):
        doc = self._base(ldp_signed_vc)
        doc['description'] = 'x' * (MAX_LDP_DOCUMENT_BYTES + 1)
        with pytest.raises(OB3VerificationError, match='byte limit'):
            OB3LdpVerifier(pubkey_pem=ed25519_pub_pem).verify(doc)

    def test_non_object_document_rejected(self, ed25519_pub_pem):
        with pytest.raises(OB3VerificationError, match='JSON'):
            OB3LdpVerifier(pubkey_pem=ed25519_pub_pem).verify('[1, 2]')


# ── behaviour without the [ldp] extra (runs with or without pyld) ───────────

class TestExtraAbsent:
    def test_missing_pyld_yields_actionable_error(self, monkeypatch,
                                                  ed25519_pub_pem):
        monkeypatch.setitem(sys.modules, 'pyld', None)
        doc = {'@context': [
                   'https://www.w3.org/ns/credentials/v2',
                   'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'],
               'id': 'urn:uuid:x',
               'type': ['VerifiableCredential', 'OpenBadgeCredential'],
               'issuer': {'id': 'did:web:i.example', 'name': 'I'},
               'validFrom': '2026-01-01T00:00:00Z',
               'credentialSubject': {
                   'id': 'mailto:r@example.com',
                   'type': ['AchievementSubject'],
                   'achievement': {'id': 'https://a.example/1', 'name': 'A',
                                   'type': ['Achievement'], 'description': 'd',
                                   'criteria': {'narrative': 'c'}}},
               'proof': {'type': 'DataIntegrityProof',
                         'cryptosuite': 'eddsa-rdfc-2022',
                         'proofPurpose': 'assertionMethod',
                         'verificationMethod': 'did:web:i.example#k',
                         # A well-formed 64-byte signature, so the flow gets
                         # past the structural checks and actually needs pyld.
                         'proofValue': 'z' + _b58encode(b'\x01' * 64)}}
        with pytest.raises(OB3VerificationError,
                           match=r'pip install openbadgeslib\[ldp\]'):
            OB3LdpVerifier(pubkey_pem=ed25519_pub_pem).verify(doc)

    def test_jwt_verifier_redirects_ldp_documents(self, ed25519_pub_pem):
        # OB3Verifier must not choke cryptically on an LDP document.
        with pytest.raises(OB3VerificationError, match='OB3LdpVerifier'):
            OB3Verifier(pubkey_pem=ed25519_pub_pem).verify('{"proof": {}}')


def test_now_is_utc_everywhere():
    # Guard against naive-datetime regressions in proof expiry handling.
    assert datetime.now(timezone.utc).tzinfo is not None


def test_validate_proof_rejects_non_string_created():
    # #193 -- a non-string proof.created (JSON number/bool/array) is attacker-
    # controlled input; it must raise OB3VerificationError, not a raw
    # AttributeError out of _parse_iso(str).replace(...).
    from openbadgeslib.ob3.ldp import _validate_proof
    proof = {'proofPurpose': 'assertionMethod',
             'verificationMethod': 'did:key:z6MkTest#z6MkTest',
             'created': 12345}
    with pytest.raises(OB3VerificationError, match='created'):
        _validate_proof(proof, 'assertionMethod')


def test_validate_proof_rejects_non_string_expires():
    from openbadgeslib.ob3.ldp import _validate_proof
    proof = {'proofPurpose': 'assertionMethod',
             'verificationMethod': 'did:key:z6MkTest#z6MkTest',
             'expires': [2025]}
    with pytest.raises(OB3VerificationError, match='expires'):
        _validate_proof(proof, 'assertionMethod')
