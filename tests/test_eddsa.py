"""Tests for EdDSA / Ed25519 key support (keys, _jws, OB3)."""
import pytest

from openbadgeslib.keys import (
    KeyType, KeyFactory, KeyEd25519, alg_for_key_type, key_to_pem, detect_key_type,
)
from openbadgeslib._jws import sign, verify_block
from openbadgeslib._jws import utils
from openbadgeslib._jws.exceptions import SignatureError
from openbadgeslib.errors import UnknownKeyType


def _build_jws(header, payload, raw_signature):
    return (
        utils.encode(header) + b'.'
        + utils.encode(payload) + b'.'
        + utils.to_base64(raw_signature)
    )


PAYLOAD = {'uid': 'test-123', 'recipient': {'identity': 'sha256$abc'}}


# ── keys ─────────────────────────────────────────────────────────────────────

class TestKeyEd25519:
    def test_factory_returns_ed25519(self):
        assert isinstance(KeyFactory(KeyType.ED25519), KeyEd25519)

    def test_generate_returns_pem_pair(self, ed25519_priv_pem, ed25519_pub_pem):
        assert ed25519_priv_pem.startswith(b'-----BEGIN PRIVATE KEY-----')
        assert ed25519_pub_pem.startswith(b'-----BEGIN PUBLIC KEY-----')

    def test_read_roundtrip(self, ed25519_priv_pem, ed25519_pub_pem):
        k = KeyEd25519()
        k.read_private_key(ed25519_priv_pem)
        k.read_public_key(ed25519_pub_pem)
        assert k.get_priv_key_pem() == ed25519_priv_pem
        assert k.get_pub_key_pem() == ed25519_pub_pem

    def test_alg_for_key_type(self):
        assert alg_for_key_type(KeyType.ED25519) == 'EdDSA'

    def test_key_to_pem_from_object(self, ed25519_priv_pem, ed25519_pub_pem):
        k = KeyEd25519()
        k.read_private_key(ed25519_priv_pem)
        k.read_public_key(ed25519_pub_pem)
        assert key_to_pem(k.get_priv_key()) == ed25519_priv_pem
        assert key_to_pem(k.get_pub_key()) == ed25519_pub_pem

    def test_read_rsa_pem_as_ed25519_rejected(self, rsa_pub_pem):
        with pytest.raises(UnknownKeyType):
            KeyEd25519().read_public_key(rsa_pub_pem)


class TestDetectKeyType:
    def test_ed25519_detected_as_ed25519_not_ecc(self, ed25519_pub_pem, ed25519_priv_pem):
        # Regression: the ecdsa library ACCEPTS an Ed25519 PEM and would
        # misclassify it as ECC; detection must return ED25519 for both halves.
        assert detect_key_type(ed25519_pub_pem) is KeyType.ED25519
        assert detect_key_type(ed25519_priv_pem) is KeyType.ED25519

    def test_ed25519_pem_as_str(self, ed25519_pub_pem):
        assert detect_key_type(ed25519_pub_pem.decode('ascii')) is KeyType.ED25519

    def test_rsa_still_rsa(self, rsa_pub_pem):
        assert detect_key_type(rsa_pub_pem) is KeyType.RSA

    def test_ecc_still_ecc(self, ecc_pub_pem):
        assert detect_key_type(ecc_pub_pem) is KeyType.ECC


# ── _jws round-trip + pinning ─────────────────────────────────────────────────

class TestEdDSAJws:
    def _keys(self, priv_pem, pub_pem):
        k = KeyEd25519()
        k.read_private_key(priv_pem)
        k.read_public_key(pub_pem)
        return k.get_priv_key(), k.get_pub_key()

    def test_sign_verify_roundtrip(self, ed25519_priv_pem, ed25519_pub_pem):
        priv, pub = self._keys(ed25519_priv_pem, ed25519_pub_pem)
        raw_sig = sign({'alg': 'EdDSA'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'EdDSA'}, PAYLOAD, raw_sig)
        assert verify_block(jws, key=pub) is True

    def test_tampered_payload_rejected(self, ed25519_priv_pem, ed25519_pub_pem):
        priv, pub = self._keys(ed25519_priv_pem, ed25519_pub_pem)
        raw_sig = sign({'alg': 'EdDSA'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'EdDSA'}, {'uid': 'EVIL'}, raw_sig)
        with pytest.raises(SignatureError):
            verify_block(jws, key=pub)

    def test_ed25519_key_rejects_rs256_header(self, ed25519_priv_pem, ed25519_pub_pem):
        # alg pinning: an Ed25519 verify key must reject a token claiming RS256.
        _, pub = self._keys(ed25519_priv_pem, ed25519_pub_pem)
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, b'sig')
        with pytest.raises(SignatureError):
            verify_block(jws, key=pub)

    def test_rsa_key_rejects_eddsa_header(self, rsa_pub_pem):
        from openbadgeslib.keys import KeyRSA
        k = KeyRSA()
        k.read_public_key(rsa_pub_pem)
        jws = _build_jws({'alg': 'EdDSA'}, PAYLOAD, b'sig')
        with pytest.raises(SignatureError):
            verify_block(jws, key=k.get_pub_key())


# ── OB3 JWT-VC round-trip ─────────────────────────────────────────────────────

class TestEdDSAOB3:
    def test_sign_verify_roundtrip(self, ob3_ed25519_signer, ob3_ed25519_verifier, ob3_credential):
        token = ob3_ed25519_signer.sign(ob3_credential)
        cred = ob3_ed25519_verifier.verify(token)
        assert cred.achievement.name == ob3_credential.achievement.name

    def test_token_header_is_eddsa(self, ob3_ed25519_signer, ob3_credential):
        import jwt
        token = ob3_ed25519_signer.sign(ob3_credential)
        assert jwt.get_unverified_header(token)['alg'] == 'EdDSA'

    def test_rsa_verifier_rejects_eddsa_token(self, ob3_ed25519_signer, ob3_rsa_verifier, ob3_credential):
        from openbadgeslib.ob3 import OB3VerificationError
        token = ob3_ed25519_signer.sign(ob3_credential)
        with pytest.raises(OB3VerificationError):
            ob3_rsa_verifier.verify(token)

    def test_ed25519_verifier_rejects_rsa_token(self, ob3_rsa_signer, ob3_ed25519_verifier, ob3_credential):
        from openbadgeslib.ob3 import OB3VerificationError
        token = ob3_rsa_signer.sign(ob3_credential)
        with pytest.raises(OB3VerificationError):
            ob3_ed25519_verifier.verify(token)
