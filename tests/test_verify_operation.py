import unittest
from unittest.mock import Mock, patch, mock_open, call

import functools, hashlib

import test_common

from openbadgeslib import verifier
from openbadgeslib.errors import UnknownKeyType
from openbadgeslib.confparser import ConfParser
from openbadgeslib.keys import KeyType


# ── pytest-style tests using session fixtures from conftest.py ─────────────────

import pytest
import time
from openbadgeslib.verifier import Verifier, VerifyInfo
from openbadgeslib.badge import BadgeStatus, BadgeSigned, Assertion
from openbadgeslib._jws.exceptions import SignatureError as JWSSignatureError
from conftest import VERIFY_IDENTITY, VERIFY_SALT


class TestCheckJWSSignature:
    def test_valid_rsa_signature(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        result = v.check_jws_signature(badge)
        assert result.status is BadgeStatus.VALID

    def test_valid_ecc_signature(self, badge_for_verify_ecc):
        badge, identity = badge_for_verify_ecc
        v = Verifier(identity=identity)
        result = v.check_jws_signature(badge)
        assert result.status is BadgeStatus.VALID

    def test_tampered_assertion_returns_signature_error(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)

        # Corrupt the signature part of the assertion
        original = badge.assertion.get_assertion()
        head, body, sig = original.split(b'.')
        tampered_sig = sig[:-4] + b'AAAA'
        badge.assertion.signature = tampered_sig

        result = v.check_jws_signature(badge)
        assert result.status is BadgeStatus.SIGNATURE_ERROR


class TestCheckIdentity:
    def test_matching_identity_returns_true(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        assert v.check_identity(badge) is True

    def test_wrong_identity_returns_false(self, badge_for_verify_rsa):
        badge, _ = badge_for_verify_rsa
        v = Verifier(identity='other@example.com')
        assert v.check_identity(badge) is False

    def test_empty_salt_with_matching_identity(self, svg_rsa_badge):
        from openbadgeslib.util import hash_email
        identity = 'nosalt@example.com'
        salt = b''
        hashed = b'sha256$' + hash_email(identity, salt)
        badge = BadgeSigned(
            source=svg_rsa_badge,
            identity=hashed,
            salt=salt,
        )
        v = Verifier(identity=identity)
        assert v.check_identity(badge) is True


class TestCheckExpiration:
    def test_not_expired_returns_none(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        # Make badge appear not expired: expiration > issuedOn
        badge.expiration = int(time.time()) + 10000
        badge.issue_date = int(time.time())
        result = v.check_expiration(badge)
        assert result is None

    def test_expired_returns_date_string(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        # expiration < issuedOn → counts as expired in current logic
        badge.expiration = 1000
        badge.issue_date = 2000
        result = v.check_expiration(badge)
        assert result is not None
        assert isinstance(result, str)


class TestGetBadgeStatus:
    def test_valid_badge_returns_valid(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        with patch.object(v, 'check_revocation', return_value=None):
            result = v.get_badge_status(badge)
        assert result.status is BadgeStatus.VALID

    def test_invalid_signature_returns_signature_error(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        # Replace the assertion signature with garbage
        orig = badge.assertion.get_assertion()
        head, body, _ = orig.split(b'.')
        badge.assertion.signature = b'AAAAAAAAAAAAAAAA'
        result = v.get_badge_status(badge)
        assert result.status is BadgeStatus.SIGNATURE_ERROR

    def test_revoked_badge_returns_revoked(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        with patch.object(v, 'check_revocation', return_value='Test reason'):
            result = v.get_badge_status(badge)
        assert result.status is BadgeStatus.REVOKED

    def test_identity_mismatch_returns_identity_error(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity='wrong@example.com')
        with patch.object(v, 'check_revocation', return_value=None):
            result = v.get_badge_status(badge)
        assert result.status is BadgeStatus.IDENTITY_ERROR

    def test_expired_badge_returns_expired(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        badge.expiration = 1000
        badge.issue_date = 2000
        with patch.object(v, 'check_revocation', return_value=None):
            result = v.get_badge_status(badge)
        assert result.status is BadgeStatus.EXPIRED


class check_verifier_factory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Verifier requires an identity string; omitting it causes AttributeError.
        # This class exists as a placeholder; real tests are in pytest classes above.
        pass

