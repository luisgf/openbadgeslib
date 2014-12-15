import unittest
from unittest.mock import Mock, patch, mock_open, call

import functools, hashlib

import test_common

from openbadgeslib import verifier
from openbadgeslib.errors import UnknownKeyType
from openbadgeslib.confparser import ConfParser

class check_verifier_factory(unittest.TestCase) :
    def test_rsa(self) :
        verify = verifier.VerifyFactory('RSA')
        self.assertIsInstance(verify, verifier.VerifyRSA)

    def test_ec(self) :
        verify = verifier.VerifyFactory('ECC')
        self.assertIsInstance(verify, verifier.VerifyECC)

    def test_unknown(self) :
        self.assertRaises(UnknownKeyType, verifier.VerifyFactory, 'XXX')