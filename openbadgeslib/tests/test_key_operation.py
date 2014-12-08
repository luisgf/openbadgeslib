import unittest
from unittest.mock import Mock, patch, mock_open, call

import test_common

from openbadgeslib import keys
from openbadgeslib.errors import UnknownKeyType

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

class KeyRSA(keys.KeyRSA) :
    def save_keypair(self, private_key_pem, public_key_pem) :
        self._TEST_private_key_pem = private_key_pem
        self._TEST_public_key_pem = public_key_pem

    def has_key(self) :
        return False

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

class check_keys_RSA(unittest.TestCase) :
    config = {'keys': {
                    'private': 'path_private',
                    'public': 'path_public',
                    'size': 2048,
                },
            }

    @classmethod
    def setUpClass(cls) :
        cls.key = KeyRSA(cls.config)
        cls.key.generate_keypair()

    def test_creation(self) :
        public_key_pem = self.key._TEST_public_key_pem.split(b'\n')
        private_key_pem = self.key._TEST_private_key_pem.split(b'\n')

        self.assertEqual(public_key_pem[0], b'-----BEGIN PUBLIC KEY-----')
        self.assertEqual(public_key_pem[-1], b'-----END PUBLIC KEY-----')
        self.assertEqual(private_key_pem[0],
                b'-----BEGIN RSA PRIVATE KEY-----')
        self.assertEqual(private_key_pem[-1],
                b'-----END RSA PRIVATE KEY-----')

    def test_load(self) :
        key = keys.KeyRSA(self.config)

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
        mensaje = b'3.14159265'
        h = SHA256.new(mensaje)

        private_key = RSA.importKey(self.key.get_priv_key_pem())
        signer = PKCS1_v1_5.new(private_key)
        signature = signer.sign(h)
        public_key = RSA.importKey(self.key.get_pub_key_pem())
        verifier = PKCS1_v1_5.new(public_key)
        self.assertTrue(verifier.verify(h, signature))

        with open('test_sign_rsa.pem', 'rb') as f :
            test_private_key = RSA.importKey(f.read())
        with open('test_verify_rsa.pem', 'rb') as f :
            test_public_key = RSA.importKey(f.read())
        signer = PKCS1_v1_5.new(test_private_key)
        test_signature = signer.sign(h)
        verifier = PKCS1_v1_5.new(test_public_key)
        self.assertTrue(verifier.verify(h, test_signature))

        verifier = PKCS1_v1_5.new(test_public_key)
        self.assertFalse(verifier.verify(h, signature))

        verifier = PKCS1_v1_5.new(public_key)
        self.assertFalse(verifier.verify(h, test_signature))

