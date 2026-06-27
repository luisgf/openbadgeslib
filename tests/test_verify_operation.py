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
        # Expiration in the future relative to now → not expired.
        now = int(time.time())
        badge.issue_date = now - 10000
        badge.expiration = now + 10000
        result = v.check_expiration(badge)
        assert result is None

    def test_expired_returns_date_string(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        # Realistic expired badge: issued in the past, expired in the past, but
        # expiration AFTER issuance. This must be detected as expired (it would
        # NOT be under the old expiration<issue_date logic).
        now = int(time.time())
        badge.issue_date = now - 20000
        badge.expiration = now - 10000
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

    def test_verifier_without_identity_does_not_crash(self, badge_for_verify_rsa):
        # Verifier(identity=None) must construct cleanly (identity only needed
        # for check_identity), rather than raising on None.encode().
        v = Verifier(identity=None)
        assert v.get_identity() is None
        assert v.check_jws_signature(badge_for_verify_rsa[0]).status is BadgeStatus.VALID

    def test_trusted_key_is_used_for_verification(self, badge_for_verify_rsa, ecc_pub_pem):
        # Supplying a non-matching trusted verify_key must fail verification,
        # proving the operator key (not the badge-embedded key) is used.
        badge, identity = badge_for_verify_rsa
        v = Verifier(verify_key=ecc_pub_pem, identity=identity)
        assert v.check_jws_signature(badge).status is BadgeStatus.SIGNATURE_ERROR

    def test_expired_badge_returns_expired(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        now = int(time.time())
        badge.issue_date = now - 20000
        badge.expiration = now - 10000
        with patch.object(v, 'check_revocation', return_value=None):
            result = v.get_badge_status(badge)
        assert result.status is BadgeStatus.EXPIRED


class TestCheckRevocation:
    """Exercise the real check_revocation network/JSON chaining (mocked I/O)."""

    @staticmethod
    def _fake_download(badge, badge_json, issuer_json, revocation_json):
        import json as _json

        def fake_download(url, *a, **k):
            if url == badge.source.json_url:
                return _json.dumps(badge_json).encode()
            if url == badge_json['issuer']:
                return _json.dumps(issuer_json).encode()
            if url == issuer_json.get('revocationList'):
                return _json.dumps(revocation_json).encode()
            raise AssertionError('unexpected url %s' % url)
        return fake_download

    def test_revoked_serial_returns_reason(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        badge_json = {'issuer': 'https://example.com/issuer.json'}
        issuer_json = {'revocationList': 'https://example.com/revoked.json'}
        revocation_json = {str(badge.serial_num): 'Mistake'}
        with patch('openbadgeslib.ob2.verifier.download_file',
                   side_effect=self._fake_download(badge, badge_json, issuer_json, revocation_json)):
            assert v.check_revocation(badge) == 'Mistake'

    def test_not_revoked_returns_none(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        badge_json = {'issuer': 'https://example.com/issuer.json'}
        issuer_json = {'revocationList': 'https://example.com/revoked.json'}
        revocation_json = {'some-other-serial': 'Mistake'}
        with patch('openbadgeslib.ob2.verifier.download_file',
                   side_effect=self._fake_download(badge, badge_json, issuer_json, revocation_json)):
            assert v.check_revocation(badge) is None

    def test_missing_revocation_list_is_not_revoked(self, badge_for_verify_rsa):
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        badge_json = {'issuer': 'https://example.com/issuer.json'}
        issuer_json = {}  # no revocationList key — must be treated as not revoked
        with patch('openbadgeslib.ob2.verifier.download_file',
                   side_effect=self._fake_download(badge, badge_json, issuer_json, {})):
            assert v.check_revocation(badge) is None

