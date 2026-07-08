"""#169 — error-branch coverage for the OB 3.0 Data Integrity (LDP) path:
proof validation, key/document errors, and parse failures. Needs the [ldp]
extra (pyld); skipped otherwise.
"""
import copy

import pytest

pytest.importorskip('pyld')

from openbadgeslib.ob3 import (  # noqa: E402
    Achievement, Issuer, OB3LdpSigner, OB3LdpVerifier, OB3VerificationError,
    OpenBadgeCredential, add_data_integrity_proof, verify_data_integrity_proof)
from openbadgeslib.ob3.did import did_key_from_pem  # noqa: E402
from openbadgeslib.errors import ErrorSigningFile  # noqa: E402


def _vc():
    return OpenBadgeCredential(
        issuer=Issuer(id='https://issuer.example', name='I'),
        recipient_id='mailto:r@example.com',
        achievement=Achievement(id='https://a.example/1', name='A',
                                description='d', criteria_narrative='c')).to_vc()


@pytest.fixture()
def signed(ed25519_keypair):
    priv, pub = ed25519_keypair
    did = did_key_from_pem(pub)
    vm = '%s#%s' % (did, did[len('did:key:'):])
    return add_data_integrity_proof(_vc(), priv, vm), pub


# ── signer / add_proof errors ────────────────────────────────────────────────

class TestSignErrors:
    def test_signer_unusable_key(self):
        with pytest.raises(ErrorSigningFile, match='unusable signing key'):
            OB3LdpSigner(b'-----BEGIN PRIVATE KEY-----\nnope\n')

    def test_add_proof_non_dict_document(self, ed25519_keypair):
        priv, _ = ed25519_keypair
        with pytest.raises(ErrorSigningFile, match='must be a JSON object'):
            add_data_integrity_proof('not a dict', priv, 'did:key:z#z')

    def test_add_proof_already_has_proof(self, signed):
        doc, _ = signed
        with pytest.raises(ErrorSigningFile, match='already carries a proof'):
            add_data_integrity_proof(doc, b'x', 'did:key:z#z')

    def test_add_proof_unusable_key(self):
        with pytest.raises(ErrorSigningFile):
            add_data_integrity_proof(_vc(), b'bad-key', 'did:key:z#z')


# ── verify entry-point / parse errors ────────────────────────────────────────

class TestVerifyEntry:
    def test_verify_non_dict_document(self, ed25519_keypair):
        _, pub = ed25519_keypair
        with pytest.raises(OB3VerificationError, match='must be a JSON object'):
            verify_data_integrity_proof('not a dict', pub)

    def test_parse_malformed_json(self, ed25519_keypair):
        _, pub = ed25519_keypair
        with pytest.raises(OB3VerificationError):
            OB3LdpVerifier(pubkey_pem=pub).verify(b'{ not json')

    def test_parse_non_object_json(self, ed25519_keypair):
        _, pub = ed25519_keypair
        with pytest.raises(OB3VerificationError):
            OB3LdpVerifier(pubkey_pem=pub).verify('[1, 2, 3]')


# ── proof validation errors (mutate a genuinely-signed document) ─────────────

class TestProofValidation:
    def test_happy_path_still_verifies(self, signed):
        doc, pub = signed
        # sanity: the unmutated document verifies (guards the mutations below).
        OB3LdpVerifier(pubkey_pem=pub).verify(doc)

    def test_missing_verification_method(self, signed):
        doc, pub = signed
        bad = copy.deepcopy(doc)
        bad['proof'].pop('verificationMethod')
        with pytest.raises(OB3VerificationError, match='verificationMethod'):
            OB3LdpVerifier(pubkey_pem=pub).verify(bad)

    def test_wrong_proof_purpose(self, signed):
        doc, pub = signed
        bad = copy.deepcopy(doc)
        bad['proof']['proofPurpose'] = 'keyAgreement'
        with pytest.raises(OB3VerificationError):
            OB3LdpVerifier(pubkey_pem=pub).verify(bad)

    def test_expired_proof(self, signed):
        doc, pub = signed
        bad = copy.deepcopy(doc)
        bad['proof']['expires'] = '2000-01-01T00:00:00Z'
        with pytest.raises(OB3VerificationError, match='expired'):
            OB3LdpVerifier(pubkey_pem=pub).verify(bad)

    def test_tampered_signature_fails(self, signed):
        doc, pub = signed
        bad = copy.deepcopy(doc)
        bad['name'] = 'tampered'                    # body changed → hash mismatch
        with pytest.raises(OB3VerificationError):
            OB3LdpVerifier(pubkey_pem=pub).verify(bad)

    def test_proof_value_not_multibase(self, signed):
        doc, pub = signed
        bad = copy.deepcopy(doc)
        bad['proof']['proofValue'] = 'not-multibase-z'
        with pytest.raises(OB3VerificationError):
            OB3LdpVerifier(pubkey_pem=pub).verify(bad)

    def test_proof_value_malformed_base58(self, signed):
        doc, pub = signed
        bad = copy.deepcopy(doc)
        bad['proof']['proofValue'] = 'z0OIl'        # 'z' prefix, invalid base58
        with pytest.raises(OB3VerificationError):
            OB3LdpVerifier(pubkey_pem=pub).verify(bad)
