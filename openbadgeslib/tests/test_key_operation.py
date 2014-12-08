import unittest
from unittest.mock import Mock, patch, mock_open, call

import functools, hashlib

import test_common

from openbadgeslib import keys
from openbadgeslib.errors import UnknownKeyType, PrivateKeyExists

import ecdsa
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

class KeyBase :
    def __init__(self, *args, **kwargs) :
        self._has_key = False
        super().__init__(*args, **kwargs)

    def save_keypair(self, private_key_pem, public_key_pem) :
        if self._has_key :
            raise RuntimeError('No debemos grabar si ya tenemos la clave')
        self._TEST_private_key_pem = private_key_pem
        self._TEST_public_key_pem = public_key_pem

    def has_key(self) :
        if self._has_key :
            raise PrivateKeyExists(self.get_privkey_path())

    def set_has_key(self) :
        self._has_key = True


class KeyRSA(KeyBase, keys.KeyRSA) :
    pass

class KeyECC(KeyBase, keys.KeyECC) :
    pass

class check_key_factory(unittest.TestCase) :
    def test_rsa(self) :
        config = {'keys': {
                        'private': 'path_private',
                        'public': 'path_public',
                        'size': 2048,
                        'crypto': 'RSA',
                    },
                }
        key = keys.KeyFactory(config)
        self.assertIsInstance(key, keys.KeyRSA)

    def test_ec(self) :
        config = {'keys': {
                        'private': 'path_private',
                        'public': 'path_public',
                        'size': 256,
                        'crypto': 'ECC',
                    },
                }
        key = keys.KeyFactory(config)
        self.assertIsInstance(key, keys.KeyECC)

    def test_unknown(self) :
        config = {'keys': {
                        'private': 'path_private',
                        'public': 'path_public',
                        'size': 256,
                        'crypto': 'XXX',
                    },
                }
        self.assertRaises(UnknownKeyType, keys.KeyFactory, config)

class checkKeysBase :
    @classmethod
    def setUpClass(cls) :
        cls.config['keys'].update({'private':'path_private',
                    'public': 'path_public'})
        cls.key = cls._KEY(cls.config)
        cls.key.generate_keypair()

    def test_creation(self) :
        public_key_pem = self.key._TEST_public_key_pem.strip().split(b'\n')
        private_key_pem = self.key._TEST_private_key_pem.strip().split(b'\n')

        self.assertEqual(public_key_pem[0], b'-----BEGIN PUBLIC KEY-----')
        self.assertEqual(public_key_pem[-1], b'-----END PUBLIC KEY-----')

        return self._checkPrivateFraming(private_key_pem)

    def test_creationOverwrite(self) :
        key = self._KEY(self.config)
        key.set_has_key()
        self.assertRaises(PrivateKeyExists, key.generate_keypair)

    def test_load(self) :
        key = self._KEY(self.config)

        # Bug in Python 3.4: "mock_open() should allow reading binary data"
        # http://bugs.python.org/issue23004
        m = mock_open()
        m.return_value.read.side_effect = lambda : self.key.get_pub_key_pem()

        with patch('openbadgeslib.keys.open', m, create = True) :
            key.read_public_key()
        self.assertEqual(m.call_args_list[0],
                call(self.config['keys']['public'], 'rb'))
        m.assert_has_calls([call().read()])

        # Bug in Python 3.4: "mock_open() should allow reading binary data"
        # http://bugs.python.org/issue23004
        m = mock_open()
        m.return_value.read.side_effect = lambda : self.key.get_priv_key_pem()

        with patch('openbadgeslib.keys.open', m, create = True) :
            key.read_private_key()
        self.assertEqual(m.call_args_list[0],
                call(self.config['keys']['private'], 'rb'))
        m.assert_has_calls([call().read()])

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
    config = {'keys': {
                    'size': 2048,
                },
            }

    _KEY = KeyRSA
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
            return PKCS1_v1_5.new(public_key).verify(h, signature)
        return verify

class checkKeysECC(checkKeysBase, unittest.TestCase) :
    config = {'keys': {
                    'curve': 'NIST256p' ,
                },
            }

    _KEY = KeyECC
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

