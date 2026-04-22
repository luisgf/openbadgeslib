import unittest
from unittest.mock import Mock, patch, mock_open, call

import functools, hashlib

import test_common

from openbadgeslib import keys
from openbadgeslib.errors import UnknownKeyType
from openbadgeslib.confparser import ConfParser

import ecdsa
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15 as PKCS1_v1_5
from Crypto.Hash import SHA256

class check_key_factory(unittest.TestCase) :
    def test_rsa(self) :
        key = keys.KeyFactory(keys.KeyType.RSA)
        self.assertIsInstance(key, keys.KeyRSA)

    def test_ec(self) :
        key = keys.KeyFactory(keys.KeyType.ECC)
        self.assertIsInstance(key, keys.KeyECC)

    def test_unknown(self) :
        self.assertRaises(UnknownKeyType, keys.KeyFactory, 'XXX')

class checkKeysBase :
    @classmethod
    def setUpClass(cls) :
        cls.config = ConfParser().read_conf()
        cls.key = cls._KEY()
        cls.key._TEST_private_key_pem, cls.key._TEST_public_key_pem = cls.key.generate_keypair()

    def test_creation(self) :
        public_key_pem = self.key._TEST_public_key_pem.strip().split(b'\n')
        private_key_pem = self.key._TEST_private_key_pem.strip().split(b'\n')

        self.assertEqual(public_key_pem[0], b'-----BEGIN PUBLIC KEY-----')
        self.assertEqual(public_key_pem[-1], b'-----END PUBLIC KEY-----')

        return self._checkPrivateFraming(private_key_pem)

    def test_sign(self) :
        msg = b'3.14159265'
        private_key = self._importSigningKey(self.key.get_priv_key_pem())
        signer = self._signer(private_key)
        signature = signer(msg)
        public_key = self._importVerifyingKey(self.key.get_pub_key_pem())
        verifier = self._verifier(public_key)
        self.assertTrue(verifier(msg, signature))

        with open(self._PRIVATEKEYNAME, 'rb') as f :
            test_private_key = self._importSigningKey(f.read())
        with open(self._PUBLICKEYNAME, 'rb') as f :
            test_public_key = self._importVerifyingKey(f.read())
        signer = self._signer(test_private_key)
        test_signature = signer(msg)
        verifier = self._verifier(test_public_key)
        self.assertTrue(verifier(msg, test_signature))

        verifier = self._verifier(test_public_key)
        self.assertFalse(verifier(msg, signature))

        verifier = self._verifier(public_key)
        self.assertFalse(verifier(msg, test_signature))

class checkKeysRSA(checkKeysBase, unittest.TestCase) :
    _KEY = keys.KeyRSA
    _PUBLICKEYNAME = 'test_verify_rsa.pem'
    _PRIVATEKEYNAME = 'test_sign_rsa.pem'

    def _checkPrivateFraming(self, private_key_pem) :
        self.assertEqual(private_key_pem[0],
                b'-----BEGIN RSA PRIVATE KEY-----')
        self.assertEqual(private_key_pem[-1],
                b'-----END RSA PRIVATE KEY-----')

    def _importSigningKey(self, private_key) :
        return RSA.importKey(private_key)

    def _importVerifyingKey(self, public_key) :
        return RSA.importKey(public_key)

    def _signer(self, private_key) :
        def sign(msg) :
            h = SHA256.new(msg)
            return PKCS1_v1_5.new(private_key).sign(h)
        return sign

    def _verifier(self, public_key) :
        def verify(msg, signature) :
            h = SHA256.new(msg)
            try:
                PKCS1_v1_5.new(public_key).verify(h, signature)
                return True
            except (ValueError, TypeError):
                return False
        return verify

class checkKeysECC(checkKeysBase, unittest.TestCase) :

    _KEY = keys.KeyECC
    _PUBLICKEYNAME = 'test_verify_ecc.pem'
    _PRIVATEKEYNAME = 'test_sign_ecc.pem'

    def _checkPrivateFraming(self, private_key_pem) :
        self.assertEqual(private_key_pem[0],
                b'-----BEGIN EC PRIVATE KEY-----')
        self.assertEqual(private_key_pem[-1],
                b'-----END EC PRIVATE KEY-----')

    def _importSigningKey(self, private_key) :
        return ecdsa.SigningKey.from_pem(private_key)

    def _importVerifyingKey(self, public_key) :
        return ecdsa.VerifyingKey.from_pem(public_key)

    def _signer(self, private_key) :
        sign = functools.partial(private_key.sign_deterministic,
                hashfunc = hashlib.sha256)
        return sign

    def _verifier(self, public_key) :
        def verify(msg, signature) :
            try :
                public_key.verify(signature, msg, hashfunc = hashlib.sha256)
            except ecdsa.BadSignatureError :
                return False
            return True

        return verify


# ── pytest-style tests using session fixtures from conftest.py ─────────────────

import pytest
from openbadgeslib.keys import detect_key_type, KeyRSA, KeyECC, KeyType
from openbadgeslib.errors import UnknownKeyType


class TestDetectKeyType:
    def test_rsa_public_key_detected(self, rsa_pub_pem):
        assert detect_key_type(rsa_pub_pem) is KeyType.RSA

    def test_rsa_private_key_detected(self, rsa_priv_pem):
        assert detect_key_type(rsa_priv_pem) is KeyType.RSA

    def test_ecc_public_key_detected(self, ecc_pub_pem):
        assert detect_key_type(ecc_pub_pem) is KeyType.ECC

    def test_ecc_private_key_detected(self, ecc_priv_pem):
        assert detect_key_type(ecc_priv_pem) is KeyType.ECC

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

    def test_get_priv_key_returns_rsa_key(self, rsa_priv_pem):
        from Crypto.PublicKey import RSA
        k = KeyRSA()
        k.read_private_key(rsa_priv_pem)
        assert isinstance(k.get_priv_key(), RSA.RsaKey)

    def test_get_pub_key_returns_rsa_key(self, rsa_pub_pem):
        from Crypto.PublicKey import RSA
        k = KeyRSA()
        k.read_public_key(rsa_pub_pem)
        assert isinstance(k.get_pub_key(), RSA.RsaKey)

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

    def test_get_priv_key_returns_signing_key(self, ecc_priv_pem):
        k = KeyECC()
        k.read_private_key(ecc_priv_pem)
        assert hasattr(k.get_priv_key(), 'sign_deterministic')

    def test_get_pub_key_returns_verifying_key(self, ecc_pub_pem):
        k = KeyECC()
        k.read_public_key(ecc_pub_pem)
        assert hasattr(k.get_pub_key(), 'verify')

    def test_generate_then_read_roundtrip(self):
        k1 = KeyECC()
        priv_pem, pub_pem = k1.generate_keypair()
        k2 = KeyECC()
        k2.read_private_key(priv_pem)
        k2.read_public_key(pub_pem)
        assert k2.get_priv_key_pem() == priv_pem
        assert k2.get_pub_key_pem() == pub_pem

