import time

import pytest
from unittest.mock import patch

from openbadgeslib.verifier import Verifier
from openbadgeslib.badge import BadgeStatus, BadgeSigned
from openbadgeslib.errors import VerifierExceptions


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

    def test_malformed_jws_header_returns_signature_error(self, badge_for_verify_rsa):
        from openbadgeslib._jws import utils as jws_utils
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)

        # Header is base64url-valid but not JSON at all.
        badge.assertion.header = jws_utils.to_base64(b'not-json-at-all')

        result = v.check_jws_signature(badge)
        assert result.status is BadgeStatus.SIGNATURE_ERROR

    def test_header_missing_alg_returns_signature_error(self, badge_for_verify_rsa):
        # verify_block() raises MissingVerifier (a JWSException sibling of
        # SignatureError) for a header missing 'alg'; check_jws_signature()
        # must catch that too, not just SignatureError itself.
        from openbadgeslib._jws import utils as jws_utils
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)

        badge.assertion.header = jws_utils.encode({'typ': 'JWS'})  # no 'alg'

        result = v.check_jws_signature(badge)
        assert result.status is BadgeStatus.SIGNATURE_ERROR

    def test_missing_verification_key_returns_signature_error(self, badge_for_verify_rsa):
        # verify_block() raises MissingKey when no key is available at all
        # (no trusted key and no badge-embedded key); that must also resolve
        # to a clean SIGNATURE_ERROR, not an uncaught exception.
        # badge.source is a shared fixture object (see conftest.py), so patch
        # its pub_key temporarily rather than mutating it in place.
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)

        with patch.object(badge.source, 'pub_key', None):
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

    def test_non_numeric_expiration_raises_clean_error(self, badge_for_verify_rsa):
        from openbadgeslib.errors import AssertionFormatIncorrect
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        # An untrusted 'expires' claim of the wrong type must not raise a raw
        # TypeError from the `<` comparison.
        badge.expiration = 'not-a-timestamp'
        with pytest.raises(AssertionFormatIncorrect):
            v.check_expiration(badge)


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

    def test_non_https_revocation_url_returns_signature_error(self, badge_for_verify_rsa):
        # download_file() raises a plain ValueError for a non-HTTPS URL; that
        # must surface as a clean SIGNATURE_ERROR, not an unhandled exception.
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        with patch.object(v, 'check_revocation', side_effect=ValueError('insecure scheme')):
            result = v.get_badge_status(badge)
        assert result.status is BadgeStatus.SIGNATURE_ERROR


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

    def test_issuer_without_issuer_url_raises_clean_error(self, badge_for_verify_rsa):
        # A badge JSON missing 'issuer' must raise a VerifierException, not a
        # raw KeyError/TypeError (SEC-5 guard).
        import json as _json
        from openbadgeslib.errors import AssertionFormatIncorrect
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        with patch('openbadgeslib.ob2.verifier.download_file',
                   return_value=_json.dumps({}).encode()):  # badge JSON has no 'issuer'
            with pytest.raises(AssertionFormatIncorrect):
                v.check_revocation(badge)

    def test_non_json_issuer_body_raises_clean_error(self, badge_for_verify_rsa):
        import json as _json
        from openbadgeslib.errors import AssertionFormatIncorrect
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)

        def fake_download(url, *a, **k):
            if url == badge.source.json_url:
                return _json.dumps({'issuer': 'https://example.com/issuer.json'}).encode()
            return b'<<not json>>'   # issuer body is garbage

        with patch('openbadgeslib.ob2.verifier.download_file', side_effect=fake_download):
            with pytest.raises(AssertionFormatIncorrect):
                v.check_revocation(badge)

    def test_non_object_badge_json_raises_clean_error(self, badge_for_verify_rsa):
        # Valid JSON that isn't an object (e.g. an array) must not raise a
        # raw AttributeError from badge_obj.get('issuer').
        from openbadgeslib.errors import AssertionFormatIncorrect
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        with patch('openbadgeslib.ob2.verifier.download_file', return_value=b'[1, 2, 3]'):
            with pytest.raises(AssertionFormatIncorrect):
                v.check_revocation(badge)

    def test_non_object_issuer_json_raises_clean_error(self, badge_for_verify_rsa):
        import json as _json
        from openbadgeslib.errors import AssertionFormatIncorrect
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        badge_json = {'issuer': 'https://example.com/issuer.json'}

        def fake_download(url, *a, **k):
            if url == badge.source.json_url:
                return _json.dumps(badge_json).encode()
            return b'"just-a-string"'   # issuer body is valid JSON, not an object

        with patch('openbadgeslib.ob2.verifier.download_file', side_effect=fake_download):
            with pytest.raises(AssertionFormatIncorrect):
                v.check_revocation(badge)

    def test_non_object_revocation_json_raises_clean_error(self, badge_for_verify_rsa):
        import json as _json
        from openbadgeslib.errors import AssertionFormatIncorrect
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        badge_json = {'issuer': 'https://example.com/issuer.json'}
        issuer_json = {'revocationList': 'https://example.com/revoked.json'}

        def fake_download(url, *a, **k):
            if url == badge.source.json_url:
                return _json.dumps(badge_json).encode()
            if url == badge_json['issuer']:
                return _json.dumps(issuer_json).encode()
            return b'[1, 2, 3]'   # revocation list is valid JSON, not an object

        with patch('openbadgeslib.ob2.verifier.download_file', side_effect=fake_download):
            with pytest.raises(AssertionFormatIncorrect):
                v.check_revocation(badge)

    def test_non_string_issuer_url_raises_clean_error(self, badge_for_verify_rsa):
        # A non-string 'issuer' URL must not reach download_file()/urlparse()
        # and leak a raw AttributeError.
        import json as _json
        from openbadgeslib.errors import AssertionFormatIncorrect
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        with patch('openbadgeslib.ob2.verifier.download_file',
                   return_value=_json.dumps({'issuer': 12345}).encode()):
            with pytest.raises(AssertionFormatIncorrect):
                v.check_revocation(badge)

    def test_non_string_revocation_url_raises_clean_error(self, badge_for_verify_rsa):
        import json as _json
        from openbadgeslib.errors import AssertionFormatIncorrect
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        badge_json = {'issuer': 'https://example.com/issuer.json'}

        def fake_download(url, *a, **k):
            if url == badge.source.json_url:
                return _json.dumps(badge_json).encode()
            return _json.dumps({'revocationList': 12345}).encode()

        with patch('openbadgeslib.ob2.verifier.download_file', side_effect=fake_download):
            with pytest.raises(AssertionFormatIncorrect):
                v.check_revocation(badge)

    def test_non_string_json_url_raises_clean_error(self, badge_for_verify_rsa):
        # badge.source.json_url comes from the untrusted assertion 'badge'
        # field; a non-string must not leak a raw AttributeError.
        from openbadgeslib.errors import AssertionFormatIncorrect
        badge, identity = badge_for_verify_rsa
        v = Verifier(identity=identity)
        with patch.object(badge.source, 'json_url', 12345):
            with pytest.raises(AssertionFormatIncorrect):
                v.check_revocation(badge)


class TestVerifierConstructorKeyTypeValidation:
    def test_garbage_verify_key_raises_verifier_exception(self):
        # detect_key_type() raises the sibling KeyGenExceptions.UnknownKeyType,
        # not a VerifierExceptions — the constructor must translate it so the
        # CLI's `except VerifierExceptions` clause can catch it cleanly.
        with pytest.raises(VerifierExceptions):
            Verifier(verify_key=b'this is not a pem key at all, just garbage text',
                     identity='foo@example.com')


class TestEmbeddedKeyFallback:
    """The verify_key=None path trusts the key embedded in the badge itself —
    the trust-on-first-use branch a forger can exploit. These pin its behaviour
    so the security trade-off can never silently change (SEC-2 / TEST-1)."""

    def test_fallback_uses_badge_embedded_key(self, badge_for_verify_rsa):
        # No operator key: verification falls back to badge.source.pub_key,
        # which here is the genuine signing key, so it verifies.
        badge, identity = badge_for_verify_rsa
        v = Verifier(verify_key=None, identity=identity)
        assert v.check_jws_signature(badge).status is BadgeStatus.VALID

    def test_self_signed_badge_passes_untrusted_but_fails_when_key_pinned(
            self, badge_for_verify_rsa, ecc_pub_pem):
        # With no trusted key the badge self-describes its own verifying key, so
        # even a self-signed forgery looks VALID. Pinning a different trusted
        # issuer key rejects it — demonstrating why a trusted key is required.
        badge, identity = badge_for_verify_rsa
        assert Verifier(verify_key=None, identity=identity)\
            .check_jws_signature(badge).status is BadgeStatus.VALID
        assert Verifier(verify_key=ecc_pub_pem, identity=identity)\
            .check_jws_signature(badge).status is BadgeStatus.SIGNATURE_ERROR
