"""#169 — coverage for openbadgeslib.keys conversion/algorithm helpers: the
per-key-type branches of key_to_pem and the algorithm lookup. The live
pycryptodome/python-ecdsa key-object compat was dropped in 4.0.0 (#170); those
libraries stopped being dependencies in #167.
"""
import pytest
from cryptography.exceptions import UnsupportedAlgorithm
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


# ── #244: the cryptography exception contract across the supported floor ─────

class TestKeyLoadErrorContract:
    """A failed PEM load must land in the library's taxonomy whatever
    `cryptography` is resolved.

    v47 changed the contract: loading a key of an unsupported algorithm raises
    `UnsupportedAlgorithm` — which is NOT a ValueError — where earlier versions
    raised ValueError. Our floor (>=45) spans that change, so both are asserted
    here; a catch-clause that handled only one would let a raw crypto exception
    escape as a traceback on half the supported range.
    """

    GARBAGE = b'-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n'

    def test_garbage_public_pem_raises_public_key_read_error(self):
        from openbadgeslib.errors import PublicKeyReadError
        from openbadgeslib.keys import KeyRSA
        with pytest.raises(PublicKeyReadError):
            KeyRSA().read_public_key(self.GARBAGE)

    def test_garbage_private_pem_raises_private_key_read_error(self):
        from openbadgeslib.errors import PrivateKeyReadError
        from openbadgeslib.keys import KeyECC
        with pytest.raises(PrivateKeyReadError):
            KeyECC().read_private_key(b'-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n')

    @pytest.mark.parametrize('raised', [
        ValueError('unsupported key type'),            # cryptography <47
        UnsupportedAlgorithm('unsupported key type'),  # cryptography >=47
    ])
    def test_both_exception_contracts_map_to_the_taxonomy(self, monkeypatch,
                                                          raised, rsa_pub_pem,
                                                          rsa_priv_pem):
        from openbadgeslib import keys as keys_mod
        from openbadgeslib.errors import (KeyGenExceptions, PrivateKeyReadError,
                                          PublicKeyReadError)

        def boom(*a, **kw):
            raise raised

        monkeypatch.setattr(keys_mod._crypto_serialization,
                            'load_pem_public_key', boom)
        monkeypatch.setattr(keys_mod._crypto_serialization,
                            'load_pem_private_key', boom)
        with pytest.raises(PublicKeyReadError) as pub:
            keys_mod.KeyRSA().read_public_key(rsa_pub_pem)
        with pytest.raises(PrivateKeyReadError):
            keys_mod.KeyRSA().read_private_key(rsa_priv_pem)
        assert isinstance(pub.value, KeyGenExceptions)   # one family to catch
        assert pub.value.__cause__ is raised             # the real cause kept

    @pytest.mark.parametrize('raised', [
        ValueError('unsupported key type'),
        UnsupportedAlgorithm('unsupported key type'),
    ])
    def test_ed25519_loaders_map_both_contracts(self, monkeypatch, raised,
                                                ed25519_pub_pem):
        from openbadgeslib import keys as keys_mod
        from openbadgeslib.errors import PublicKeyReadError

        def boom(*a, **kw):
            raise raised

        monkeypatch.setattr(keys_mod._crypto_serialization,
                            'load_pem_public_key', boom)
        with pytest.raises(PublicKeyReadError):
            keys_mod.KeyEd25519().read_public_key(ed25519_pub_pem)

    @pytest.mark.parametrize('raised', [
        ValueError('unsupported key type'),
        UnsupportedAlgorithm('unsupported key type'),
    ])
    def test_detection_helpers_stay_total_under_both(self, monkeypatch, raised,
                                                     rsa_pub_pem):
        # detect_key_type/ec_curve_from_pem probe with both loaders and must not
        # leak either exception: one reports UnknownKeyType, the other None.
        from openbadgeslib import keys as keys_mod
        from openbadgeslib.errors import UnknownKeyType

        def boom(*a, **kw):
            raise raised

        monkeypatch.setattr(keys_mod._crypto_serialization,
                            'load_pem_public_key', boom)
        monkeypatch.setattr(keys_mod._crypto_serialization,
                            'load_pem_private_key', boom)
        with pytest.raises(UnknownKeyType):
            keys_mod.detect_key_type(rsa_pub_pem)
        assert keys_mod.ec_curve_from_pem(rsa_pub_pem) is None

    @pytest.mark.parametrize('raised', [
        ValueError('unsupported key type'),
        UnsupportedAlgorithm('unsupported key type'),
    ])
    def test_public_jwk_from_pem_maps_both(self, monkeypatch, raised,
                                           rsa_pub_pem):
        from openbadgeslib import keys as keys_mod
        from openbadgeslib.errors import PublicKeyReadError

        def boom(*a, **kw):
            raise raised

        monkeypatch.setattr(keys_mod._crypto_serialization,
                            'load_pem_public_key', boom)
        with pytest.raises(PublicKeyReadError):
            keys_mod.public_jwk_from_pem(rsa_pub_pem)


class TestRsaKeySizeFloor:
    """cryptography v48 enforces a 1024-bit floor on rsa.generate_private_key;
    an absurd configured size must be a library error, not a raw traceback."""

    def test_undersized_rsa_key_raises_gen_private_key_error(self):
        from openbadgeslib.errors import GenPrivateKeyError
        from openbadgeslib.keys import KeyRSA
        with pytest.raises(GenPrivateKeyError):
            KeyRSA(key_size=512).generate_keypair()

    def test_normal_size_still_generates(self):
        from openbadgeslib.keys import KeyRSA
        priv, pub = KeyRSA().generate_keypair()
        assert b'PRIVATE KEY' in priv and b'PUBLIC KEY' in pub
