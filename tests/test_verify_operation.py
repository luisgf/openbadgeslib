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
        cls.assertion = b'eyJhbGciOiAiUlMyNTYifQ.eyJpbWFnZSI6ICJodHRwczovL29wZW5iYWRnZXMubHVpc2dmLmVzL2lzc3Vlci9iYWRnZV8xL2JhZGdlLnN2ZyIsICJ2ZXJpZnkiOiB7InVybCI6ICJodHRwczovL29wZW5iYWRnZXMubHVpc2dmLmVzL2lzc3Vlci9iYWRnZV8xL3ZlcmlmeV9yc2Ffa2V5LnBlbSIsICJ0eXBlIjogInNpZ25lZCJ9LCAidWlkIjogIjQ2MjhjMWY2YjFkOGQyNzczNTBhYTE0NDkzYjIyOTlhNjI3NGU0NjYiLCAiaXNzdWVkT24iOiAxNDE5NDIwNDMzLCAiYmFkZ2UiOiAiaHR0cHM6Ly9vcGVuYmFkZ2VzLmx1aXNnZi5lcy9pc3N1ZXIvYmFkZ2VfMS9iYWRnZS5qc29uIiwgInJlY2lwaWVudCI6IHsic2FsdCI6ICI3MTcyMTVlODc1MjgyY2EzNmUyNWVmY2Y0MDgwNTE0OSIsICJpZGVudGl0eSI6ICJzaGEyNTYkMzc3NzU4MDVmOWExZGVkYTdkN2ZhNTBkMzk4YzU4NDcyYTIxZThjODI0ZWJiNDllZWYwNTZiMTM3ODMyOTFkNSIsICJ0eXBlIjogImVtYWlsIiwgImhhc2hlZCI6ICJ0cnVlIn0sICJleHBpcmVzIjogMTQxOTUwNjgzM30.l9WMBHZYjoP0fMMoKc1jgc6OOr99g-qumWy6UPRcnkiqm6XIPg7aXbGPkwCC1rk8O_JlkubjHD0bwBWTdzjVzHjZRzt50P-UP55nQF1-PYvCk56lLvY8uoop_uX1Y7zkvB5zL36xlGRODu8KuEIPBfTOaO5ggc0B27EvJ6np8GwPHXQECZAY0FIvJxDbarg7e8eJuukHqD50x7A7TyxfeSHwEshuuAsiIe38PGPV4iK2U4TPmPgoXBFr1uFVijObTdFmshk7-DiDRgWls8LezL2V9lPERln7soHvaJL27sk0WKYGti2OsScCeDvgA9-jB7oLMIDVjjgY9uHdLQa0BQ'
        cls.identity = b'test@test.es'
        cls.verifier = verifier.VerifyBase(assertion=cls.assertion,
                                           identity=cls.identity)

    def test_rsa(self) :
        verify = verifier.VerifyFactory(key_type=KeyType.RSA,
                                        assertion=self.assertion,
                                        identity=self.identity)
        self.assertIsInstance(verify, verifier.VerifyRSA)

    def test_ec(self) :
        verify = verifier.VerifyFactory(key_type=KeyType.ECC,
                                        assertion=self.assertion,
                                        identity=self.identity)
        self.assertIsInstance(verify, verifier.VerifyECC)

    def test_unknown(self) :
        self.assertRaises(UnknownKeyType, verifier.VerifyFactory, 'XXX')