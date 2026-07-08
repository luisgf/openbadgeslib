"""#169 — coverage for openbadgeslib.keys conversion/algorithm helpers: the
per-key-type branches of key_to_pem, the algorithm lookup, and the legacy
pycryptodome/python-ecdsa soft-import compat (dropped as deps in #167).
"""
import pytest
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from openbadgeslib import keys
from openbadgeslib.keys import (KeyType, UnknownKeyType, alg_for_key_type,
                                key_to_pem)


class TestAlgForKeyType:
    def test_known_key_types(self):
        assert alg_for_key_type(KeyType.RSA) == 'RS256'
        assert alg_for_key_type(KeyType.ECC) == 'ES256'
        assert alg_for_key_type(KeyType.ED25519) == 'EdDSA'

    def test_unknown_key_type_raises(self):
        with pytest.raises(UnknownKeyType):
            alg_for_key_type('not a key type')


class TestKeyToPem:
    def test_bytes_and_str_pass_through(self):
        assert key_to_pem(b'PEM bytes') == b'PEM bytes'
        assert key_to_pem('PEM string') == 'PEM string'

    def test_rsa_private_and_public_objects(self, rsa_priv_pem):
        priv = load_pem_private_key(rsa_priv_pem, password=None)
        assert b'PRIVATE KEY' in key_to_pem(priv)
        assert b'PUBLIC KEY' in key_to_pem(priv.public_key())

    def test_ed25519_private_and_public_objects(self, ed25519_keypair):
        priv = load_pem_private_key(ed25519_keypair[0], password=None)
        assert b'PRIVATE KEY' in key_to_pem(priv)
        assert b'PUBLIC KEY' in key_to_pem(priv.public_key())

    def test_unknown_object_raises(self):
        with pytest.raises(UnknownKeyType, match='Unsupported key object'):
            key_to_pem(object())


class TestPublicJwk:
    def test_rsa_pem_to_jwk(self, rsa_pub_pem):
        jwk = keys.public_jwk_from_pem(rsa_pub_pem)
        assert jwk['kty'] == 'RSA' and 'n' in jwk and 'e' in jwk

    def test_ecc_pem_to_jwk(self, ecc_pub_pem):
        jwk = keys.public_jwk_from_pem(ecc_pub_pem)
        assert jwk['kty'] == 'EC' and 'x' in jwk and 'y' in jwk


class TestEcCurveFromPem:
    def test_ec_key_returns_curve_name(self, ecc_pub_pem):
        assert keys.ec_curve_from_pem(ecc_pub_pem) == 'secp256r1'

    def test_non_ec_key_returns_none(self, rsa_pub_pem):
        assert keys.ec_curve_from_pem(rsa_pub_pem) is None

    def test_unreadable_pem_returns_none(self):
        assert keys.ec_curve_from_pem(b'not a pem at all') is None


class TestLegacyKeyToPem:
    def test_absent_legacy_libs_return_none(self):
        # pycryptodome / python-ecdsa were dropped (#167); the soft-import path
        # finds neither, so it returns None for any object (and key_to_pem then
        # raises UnknownKeyType).
        assert keys._legacy_key_to_pem(object()) is None
