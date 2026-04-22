"""Tests for the openbadgeslib._jws module (sign, verify, utils, algos)."""
import json
import pytest

from openbadgeslib._jws import sign, verify_block
from openbadgeslib._jws import utils
from openbadgeslib._jws.exceptions import (
    SignatureError, RouteMissingError, MissingKey, MissingSigner,
)


# ── helpers ────────────────────────────────────────────────────────────────────

def _build_jws(header, payload, raw_signature):
    """Assemble a complete JWS block from raw signature bytes."""
    return (
        utils.encode(header) + b'.'
        + utils.encode(payload) + b'.'
        + utils.to_base64(raw_signature)
    )


def _load_rsa_keys(rsa_priv_pem, rsa_pub_pem):
    from openbadgeslib.keys import KeyRSA
    k = KeyRSA()
    k.read_private_key(rsa_priv_pem)
    k.read_public_key(rsa_pub_pem)
    return k.get_priv_key(), k.get_pub_key()


def _load_ecc_keys(ecc_priv_pem, ecc_pub_pem):
    from openbadgeslib.keys import KeyECC
    k = KeyECC()
    k.read_private_key(ecc_priv_pem)
    k.read_public_key(ecc_pub_pem)
    return k.get_priv_key(), k.get_pub_key()


PAYLOAD = {'uid': 'test-123', 'recipient': {'identity': 'sha256$abc'}}


# ── sign + verify_block round-trips ───────────────────────────────────────────

class TestRSARoundTrip:
    def test_sign_returns_bytes(self, rsa_priv_pem, rsa_pub_pem):
        priv, _ = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        assert isinstance(sig, bytes)

    def test_verify_block_valid(self, rsa_priv_pem, rsa_pub_pem):
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, raw_sig)
        assert verify_block(jws, key=pub) is True

    def test_wrong_public_key_raises(self, rsa_priv_pem, rsa_pub_pem, ecc_pub_pem):
        from openbadgeslib.keys import KeyECC
        priv, _ = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        k2 = KeyECC()
        k2.read_public_key(ecc_pub_pem)
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, raw_sig)
        with pytest.raises(Exception):
            verify_block(jws, key=k2.get_pub_key())

    def test_tampered_payload_raises(self, rsa_priv_pem, rsa_pub_pem):
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        evil_payload = {'uid': 'EVIL', 'recipient': {'identity': 'sha256$abc'}}
        jws = _build_jws({'alg': 'RS256'}, evil_payload, raw_sig)
        with pytest.raises(SignatureError):
            verify_block(jws, key=pub)

    def test_truncated_signature_raises(self, rsa_priv_pem, rsa_pub_pem):
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, raw_sig)[:-10] + b'AAAAAAAAAA'
        with pytest.raises((SignatureError, Exception)):
            verify_block(jws, key=pub)


class TestECCRoundTrip:
    def test_sign_returns_bytes(self, ecc_priv_pem, ecc_pub_pem):
        priv, _ = _load_ecc_keys(ecc_priv_pem, ecc_pub_pem)
        sig = sign({'alg': 'ES256'}, PAYLOAD, key=priv)
        assert isinstance(sig, bytes)

    def test_verify_block_valid(self, ecc_priv_pem, ecc_pub_pem):
        priv, pub = _load_ecc_keys(ecc_priv_pem, ecc_pub_pem)
        raw_sig = sign({'alg': 'ES256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'ES256'}, PAYLOAD, raw_sig)
        assert verify_block(jws, key=pub) is True

    def test_tampered_payload_raises(self, ecc_priv_pem, ecc_pub_pem):
        priv, pub = _load_ecc_keys(ecc_priv_pem, ecc_pub_pem)
        raw_sig = sign({'alg': 'ES256'}, PAYLOAD, key=priv)
        evil = {'uid': 'EVIL', 'recipient': {'identity': 'sha256$abc'}}
        jws = _build_jws({'alg': 'ES256'}, evil, raw_sig)
        with pytest.raises(SignatureError):
            verify_block(jws, key=pub)

    def test_wrong_key_raises(self, ecc_priv_pem, ecc_pub_pem, rsa_pub_pem):
        from openbadgeslib.keys import KeyRSA
        priv, _ = _load_ecc_keys(ecc_priv_pem, ecc_pub_pem)
        k2 = KeyRSA()
        k2.read_public_key(rsa_pub_pem)
        raw_sig = sign({'alg': 'ES256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'ES256'}, PAYLOAD, raw_sig)
        with pytest.raises(Exception):
            verify_block(jws, key=k2.get_pub_key())


class TestVerifyBlockEdgeCases:
    def test_malformed_block_no_dots(self):
        with pytest.raises(SignatureError):
            verify_block(b'notajwstoken', key=None)

    def test_malformed_block_one_dot(self):
        with pytest.raises(SignatureError):
            verify_block(b'header.payload', key=None)

    def test_missing_key_raises(self, rsa_priv_pem, rsa_pub_pem):
        priv, pub = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        raw_sig = sign({'alg': 'RS256'}, PAYLOAD, key=priv)
        jws = _build_jws({'alg': 'RS256'}, PAYLOAD, raw_sig)
        with pytest.raises(MissingKey):
            verify_block(jws, key=None)


# ── utils ──────────────────────────────────────────────────────────────────────

class TestUtils:
    def test_encode_decode_roundtrip(self):
        data = {'hello': 'world', 'n': 42}
        assert utils.decode(utils.encode(data)) == data

    def test_to_base64_from_base64_roundtrip(self):
        raw = b'\x00\x01\x02\xff\xfe'
        assert utils.from_base64(utils.to_base64(raw)) == raw

    def test_base64_no_padding(self):
        encoded = utils.to_base64(b'test')
        assert b'=' not in encoded

    def test_from_json_bytes(self):
        assert utils.from_json(b'"hello"') == 'hello'
        assert utils.from_json(b'{"k": 1}') == {'k': 1}

    def test_from_json_str(self):
        assert utils.from_json('{"k": 1}') == {'k': 1}

    def test_to_json_produces_bytes(self):
        result = utils.to_json({'a': 1})
        assert isinstance(result, bytes)
        assert json.loads(result) == {'a': 1}


# ── sign edge cases ────────────────────────────────────────────────────────────

class TestSignEdgeCases:
    def test_missing_key_raises(self, rsa_pub_pem):
        with pytest.raises(MissingKey):
            sign({'alg': 'RS256'}, PAYLOAD, key=None)

    def test_missing_alg_raises(self, rsa_priv_pem, rsa_pub_pem):
        priv, _ = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        with pytest.raises(MissingSigner):
            sign({}, PAYLOAD, key=priv)

    def test_unknown_algorithm_raises(self, rsa_priv_pem, rsa_pub_pem):
        priv, _ = _load_rsa_keys(rsa_priv_pem, rsa_pub_pem)
        with pytest.raises(RouteMissingError):
            sign({'alg': 'XX999'}, PAYLOAD, key=priv)

    def test_wrong_key_type_for_algorithm_raises(self, rsa_priv_pem, ecc_pub_pem):
        from openbadgeslib.keys import KeyECC
        k = KeyECC()
        k.read_public_key(ecc_pub_pem)
        with pytest.raises((SignatureError, Exception)):
            sign({'alg': 'RS256'}, PAYLOAD, key=k.get_pub_key())
