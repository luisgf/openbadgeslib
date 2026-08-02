import os
import stat
import unittest

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from openbadgeslib import keys
from openbadgeslib.errors import UnknownKeyType
from openbadgeslib.confparser import ConfParser
from openbadgeslib.keys import detect_key_type, KeyRSA, KeyECC, KeyType
from openbadgeslib.openbadges_keygenerator import _write_pem_file


class check_key_factory(unittest.TestCase):
    def test_rsa(self):
        key = keys.KeyFactory(keys.KeyType.RSA)
        self.assertIsInstance(key, keys.KeyRSA)

    def test_ec(self):
        key = keys.KeyFactory(keys.KeyType.ECC)
        self.assertIsInstance(key, keys.KeyECC)

    def test_unknown(self):
        self.assertRaises(UnknownKeyType, keys.KeyFactory, 'XXX')


class checkKeysBase:
    """Cross-check that keys.py-generated (and committed) key material is valid
    and usable — sign/verify round-trips — using cryptography directly, the
    library keys.py now sits on. (pycryptodome/python-ecdsa were dropped, #167.)
    """

    @classmethod
    def setUpClass(cls):
        cls.config = ConfParser('./config1.ini').read_conf()
        cls.key = cls._KEY()
        cls.key._TEST_private_key_pem, cls.key._TEST_public_key_pem = \
            cls.key.generate_keypair()

    def test_creation(self):
        public_key_pem = self.key._TEST_public_key_pem.strip().split(b'\n')
        private_key_pem = self.key._TEST_private_key_pem.strip().split(b'\n')

        self.assertEqual(public_key_pem[0], b'-----BEGIN PUBLIC KEY-----')
        self.assertEqual(public_key_pem[-1], b'-----END PUBLIC KEY-----')

        return self._checkPrivateFraming(private_key_pem)

    def _importSigningKey(self, private_key):
        return serialization.load_pem_private_key(private_key, password=None)

    def _importVerifyingKey(self, public_key):
        return serialization.load_pem_public_key(public_key)

    def _verifier(self, public_key):
        def verify(msg, signature):
            try:
                public_key.verify(signature, msg, *self._verify_args())
                return True
            except Exception:
                return False
        return verify

    def test_sign(self):
        msg = b'3.14159265'
        private_key = self._importSigningKey(self.key.get_priv_key_pem())
        signer = self._signer(private_key)
        signature = signer(msg)
        public_key = self._importVerifyingKey(self.key.get_pub_key_pem())
        verifier = self._verifier(public_key)
        self.assertTrue(verifier(msg, signature))

        with open(self._PRIVATEKEYNAME, 'rb') as f:
            test_private_key = self._importSigningKey(f.read())
        with open(self._PUBLICKEYNAME, 'rb') as f:
            test_public_key = self._importVerifyingKey(f.read())
        signer = self._signer(test_private_key)
        test_signature = signer(msg)
        verifier = self._verifier(test_public_key)
        self.assertTrue(verifier(msg, test_signature))

        # A signature from one key must not verify under the other.
        verifier = self._verifier(test_public_key)
        self.assertFalse(verifier(msg, signature))

        verifier = self._verifier(public_key)
        self.assertFalse(verifier(msg, test_signature))


class checkKeysRSA(checkKeysBase, unittest.TestCase):
    _KEY = keys.KeyRSA
    _PUBLICKEYNAME = 'test_verify_rsa.pem'
    _PRIVATEKEYNAME = 'test_sign_rsa.pem'

    def _checkPrivateFraming(self, private_key_pem):
        self.assertEqual(private_key_pem[0],
                         b'-----BEGIN RSA PRIVATE KEY-----')
        self.assertEqual(private_key_pem[-1],
                         b'-----END RSA PRIVATE KEY-----')

    def _signer(self, private_key):
        def sign(msg):
            return private_key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        return sign

    def _verify_args(self):
        return (padding.PKCS1v15(), hashes.SHA256())


class checkKeysECC(checkKeysBase, unittest.TestCase):
    _KEY = keys.KeyECC
    _PUBLICKEYNAME = 'test_verify_ecc.pem'
    _PRIVATEKEYNAME = 'test_sign_ecc.pem'

    def _checkPrivateFraming(self, private_key_pem):
        self.assertEqual(private_key_pem[0],
                         b'-----BEGIN EC PRIVATE KEY-----')
        self.assertEqual(private_key_pem[-1],
                         b'-----END EC PRIVATE KEY-----')

    def _signer(self, private_key):
        def sign(msg):
            return private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        return sign

    def _verify_args(self):
        return (ec.ECDSA(hashes.SHA256()),)


# ── pytest-style tests using session fixtures from conftest.py ─────────────────


class TestDetectKeyType:
    def test_rsa_public_key_detected(self, rsa_pub_pem):
        assert detect_key_type(rsa_pub_pem) is KeyType.RSA

    def test_rsa_private_key_detected(self, rsa_priv_pem):
        assert detect_key_type(rsa_priv_pem) is KeyType.RSA

    def test_ecc_public_key_detected(self, ecc_pub_pem):
        assert detect_key_type(ecc_pub_pem) is KeyType.ECC

    def test_ecc_private_key_detected(self, ecc_priv_pem):
        assert detect_key_type(ecc_priv_pem) is KeyType.ECC

    def test_ed25519_detected(self, ed25519_pub_pem, ed25519_priv_pem):
        # cryptography's loaders never confuse Ed25519 with the ECDSA curves
        # (python-ecdsa used to accept an Ed25519 PEM as EC — the #167 port
        # removes that whole class of ambiguity).
        assert detect_key_type(ed25519_pub_pem) is KeyType.ED25519
        assert detect_key_type(ed25519_priv_pem) is KeyType.ED25519

    def test_garbage_raises_unknown(self):
        with pytest.raises(UnknownKeyType):
            detect_key_type(b'not a pem key at all')

    def test_empty_raises_unknown(self):
        with pytest.raises(UnknownKeyType):
            detect_key_type(b'')


class TestKeyRSAReadWrite:
    def test_read_private_key_and_export(self, rsa_priv_pem):
        k = KeyRSA()
        k.read_private_key(rsa_priv_pem)
        exported = k.get_priv_key_pem()
        assert exported.strip().startswith(b'-----BEGIN RSA PRIVATE KEY-----')

    def test_read_public_key_and_export(self, rsa_pub_pem):
        k = KeyRSA()
        k.read_public_key(rsa_pub_pem)
        exported = k.get_pub_key_pem()
        assert exported.strip().startswith(b'-----BEGIN PUBLIC KEY-----')

    def test_get_priv_key_returns_cryptography_key(self, rsa_priv_pem):
        k = KeyRSA()
        k.read_private_key(rsa_priv_pem)
        assert isinstance(k.get_priv_key(), rsa.RSAPrivateKey)

    def test_get_pub_key_returns_cryptography_key(self, rsa_pub_pem):
        k = KeyRSA()
        k.read_public_key(rsa_pub_pem)
        assert isinstance(k.get_pub_key(), rsa.RSAPublicKey)

    def test_generate_then_read_roundtrip(self):
        k1 = KeyRSA()
        priv_pem, pub_pem = k1.generate_keypair()
        k2 = KeyRSA()
        k2.read_private_key(priv_pem)
        k2.read_public_key(pub_pem)
        assert k2.get_priv_key_pem() == priv_pem
        assert k2.get_pub_key_pem() == pub_pem


class TestKeyECCReadWrite:
    def test_read_private_key_and_export(self, ecc_priv_pem):
        k = KeyECC()
        k.read_private_key(ecc_priv_pem)
        exported = k.get_priv_key_pem()
        assert exported.strip().startswith(b'-----BEGIN EC PRIVATE KEY-----')

    def test_read_public_key_and_export(self, ecc_pub_pem):
        k = KeyECC()
        k.read_public_key(ecc_pub_pem)
        exported = k.get_pub_key_pem()
        assert exported.strip().startswith(b'-----BEGIN PUBLIC KEY-----')

    def test_get_priv_key_returns_cryptography_key(self, ecc_priv_pem):
        k = KeyECC()
        k.read_private_key(ecc_priv_pem)
        assert isinstance(k.get_priv_key(), ec.EllipticCurvePrivateKey)

    def test_get_pub_key_returns_cryptography_key(self, ecc_pub_pem):
        k = KeyECC()
        k.read_public_key(ecc_pub_pem)
        assert isinstance(k.get_pub_key(), ec.EllipticCurvePublicKey)

    def test_generate_then_read_roundtrip(self):
        k1 = KeyECC()
        priv_pem, pub_pem = k1.generate_keypair()
        k2 = KeyECC()
        k2.read_private_key(priv_pem)
        k2.read_public_key(pub_pem)
        assert k2.get_priv_key_pem() == priv_pem
        assert k2.get_pub_key_pem() == pub_pem


class TestKeyGeneratorFileWrites:
    @pytest.mark.skipif(os.name == 'nt', reason='POSIX permissions required')
    def test_private_key_file_is_owner_only_under_permissive_umask(self, tmp_path):
        path = tmp_path / 'sign.pem'
        old_umask = os.umask(0)
        try:
            _write_pem_file(str(path), b'private-key', 0o600)
        finally:
            os.umask(old_umask)

        assert path.read_bytes() == b'private-key'
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_write_pem_file_refuses_to_overwrite_existing_file(self, tmp_path):
        path = tmp_path / 'sign.pem'
        path.write_bytes(b'existing')

        with pytest.raises(FileExistsError):
            _write_pem_file(str(path), b'new', 0o600)

        assert path.read_bytes() == b'existing'

    def test_write_pem_file_missing_parent_dir_raises_oserror(self, tmp_path):
        # #289: a path whose parent directory does not exist must surface as
        # OSError (caught by the CLI and turned into a clean exit), not a
        # different exception type.
        path = tmp_path / 'no' / 'such' / 'dir' / 'key.pem'
        with pytest.raises(OSError):
            _write_pem_file(str(path), b'private-key', 0o600)
