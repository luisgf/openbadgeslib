import unittest
from unittest.mock import Mock, patch, mock_open, call

import functools, hashlib

import test_common

from openbadgeslib import signer
from openbadgeslib.errors import UnknownKeyType
from openbadgeslib.confparser import ConfParser

class check_signer_factory(unittest.TestCase) :               
    def test_rsa(self) :
        sign = signer.SignerFactory('RSA')
        self.assertIsInstance(sign, signer.SignerRSA)

    def test_ec(self) :
        sign = signer.SignerFactory('ECC')
        self.assertIsInstance(sign, signer.SignerECC)

    def test_unknown(self) :
        self.assertRaises(UnknownKeyType, signer.SignerFactory, 'XXX')
        
class check_signer_methods(unittest.TestCase):
    @classmethod
    def setUpClass(cls) :
        cls.signer = signer.SignerBase()
        
    def test_signer_uid_generation(self):
        uid = self.signer.generate_uid()
        self.assertEqual(len(uid), 40)