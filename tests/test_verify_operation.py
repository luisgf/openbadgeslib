import unittest
from unittest.mock import Mock, patch, mock_open, call

import functools, hashlib

import test_common

from openbadgeslib import verifier
from openbadgeslib.errors import UnknownKeyType
from openbadgeslib.confparser import ConfParser
from openbadgeslib.keys import KeyType

class check_verifier_factory(unittest.TestCase) :
    @classmethod
    def setUpClass(cls) :
        cls.verifier = verifier.Verifier()

