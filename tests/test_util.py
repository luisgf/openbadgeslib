"""Tests for openbadgeslib.util."""
import hashlib
from unittest.mock import patch, MagicMock

import pytest

from openbadgeslib.util import (
    sha1_string, sha256_string, md5_string,
    hash_email, download_file, show_ecc_disclaimer,
    normalize_recipient_id,
    __version__,
)


class TestHashFunctions:
    def test_sha1_returns_bytes(self):
        result = sha1_string(b'hello')
        assert isinstance(result, bytes)

    def test_sha1_correct_value(self):
        expected = hashlib.sha1(b'hello').hexdigest().encode('latin-1')
        assert sha1_string(b'hello') == expected

    def test_sha256_returns_bytes(self):
        assert isinstance(sha256_string(b'hello'), bytes)

    def test_sha256_correct_value(self):
        expected = hashlib.sha256(b'hello').hexdigest().encode('latin-1')
        assert sha256_string(b'hello') == expected

    def test_md5_returns_bytes(self):
        assert isinstance(md5_string(b'hello'), bytes)

    def test_md5_correct_value(self):
        expected = hashlib.md5(b'hello').hexdigest().encode('latin-1')
        assert md5_string(b'hello') == expected

    def test_sha1_string_input(self):
        # _hash_string encodes str to utf-8 before hashing
        expected = hashlib.sha1(b'hello').hexdigest().encode('latin-1')
        assert sha1_string('hello') == expected

    def test_sha256_string_input(self):
        expected = hashlib.sha256(b'world').hexdigest().encode('latin-1')
        assert sha256_string('world') == expected


class TestHashEmail:
    def test_bytes_email_bytes_salt(self):
        result = hash_email(b'user@example.com', b'salt')
        assert isinstance(result, bytes)
        expected = sha256_string(b'user@example.com' + b'salt')
        assert result == expected

    def test_str_email_bytes_salt(self):
        # Mixed types must produce the same result as bytes+bytes
        r1 = hash_email('user@example.com', b'salt')
        r2 = hash_email(b'user@example.com', b'salt')
        assert r1 == r2

    def test_str_email_str_salt(self):
        r1 = hash_email('user@example.com', 'salt')
        r2 = hash_email(b'user@example.com', b'salt')
        assert r1 == r2

    def test_deterministic(self):
        a = hash_email(b'a@b.com', b'salt')
        b = hash_email(b'a@b.com', b'salt')
        assert a == b

    def test_different_emails_differ(self):
        assert hash_email(b'a@b.com', b'salt') != hash_email(b'c@d.com', b'salt')

    def test_different_salts_differ(self):
        assert hash_email(b'a@b.com', b'salt1') != hash_email(b'a@b.com', b'salt2')

    def test_empty_salt(self):
        result = hash_email(b'user@example.com', b'')
        assert isinstance(result, bytes)


def _mock_urlopen(content=b'file content'):
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    # download_file() now reads in chunks until an empty read signals EOF.
    mock_resp.read.side_effect = [content, b'']
    return mock_resp


def _mock_opener(content=b'file content', open_side_effect=None):
    mock_opener = MagicMock()
    if open_side_effect is not None:
        mock_opener.open.side_effect = open_side_effect
    else:
        mock_opener.open.return_value = _mock_urlopen(content)
    return mock_opener


class TestDownloadFile:
    def test_returns_bytes_on_success(self):
        with patch('openbadgeslib.util.request.build_opener', return_value=_mock_opener()):
            result = download_file('https://example.com/file.pem')
        assert result == b'file content'

    def test_https_url_no_warning(self, capsys):
        with patch('openbadgeslib.util.request.build_opener', return_value=_mock_opener()):
            download_file('https://example.com/file.pem')
        out = capsys.readouterr().out
        assert 'Warning' not in out

    def test_http_url_rejected_by_default(self):
        # HTTP is refused: the verify key is the root of trust.
        with pytest.raises(ValueError):
            download_file('http://example.com/file.pem')

    def test_http_url_allowed_with_flag_prints_warning(self, capsys):
        with patch('openbadgeslib.util.request.build_opener', return_value=_mock_opener()):
            download_file('http://example.com/file.pem', allow_insecure=True)
        out = capsys.readouterr().out
        assert 'Warning' in out

    def test_timeout_is_passed(self):
        mock_opener = _mock_opener()
        with patch('openbadgeslib.util.request.build_opener', return_value=mock_opener):
            download_file('https://example.com/file')
        _, kwargs = mock_opener.open.call_args
        assert kwargs.get('timeout') == 30

    def test_propagates_network_errors(self):
        from urllib.error import URLError
        mock_opener = _mock_opener(open_side_effect=URLError('unreachable'))
        with patch('openbadgeslib.util.request.build_opener', return_value=mock_opener):
            with pytest.raises(URLError):
                download_file('https://example.com/file')

    def test_oversized_response_raises(self):
        from openbadgeslib.util import MAX_DOWNLOAD_SIZE
        chunk = b'x' * 65536
        n_chunks = MAX_DOWNLOAD_SIZE // len(chunk) + 2  # guaranteed to exceed the cap
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.side_effect = [chunk] * n_chunks + [b'']
        mock_opener = MagicMock()
        mock_opener.open.return_value = mock_resp
        with patch('openbadgeslib.util.request.build_opener', return_value=mock_opener):
            with pytest.raises(ValueError):
                download_file('https://example.com/huge-file')

    def test_response_just_under_cap_succeeds(self):
        from openbadgeslib.util import MAX_DOWNLOAD_SIZE
        content = b'x' * (MAX_DOWNLOAD_SIZE - 1)
        with patch('openbadgeslib.util.request.build_opener', return_value=_mock_opener(content)):
            result = download_file('https://example.com/almost-too-big')
        assert len(result) == MAX_DOWNLOAD_SIZE - 1


class TestHTTPSOnlyRedirectHandler:
    """Regression coverage for the redirect scheme-downgrade fix."""

    def _handler(self, allow_insecure=False):
        from openbadgeslib.util import _HTTPSOnlyRedirectHandler
        return _HTTPSOnlyRedirectHandler(allow_insecure)

    def _get_request(self):
        # The base HTTPRedirectHandler.redirect_request (called for an
        # allowed scheme) requires a real GET/HEAD/POST method, not a
        # MagicMock-generated one.
        req = MagicMock()
        req.get_method.return_value = 'GET'
        req.get_full_url.return_value = 'https://example.com/original.pem'
        req.unredirected_hdrs = {}
        req.headers = {}
        return req

    def test_rejects_redirect_to_http(self):
        with pytest.raises(ValueError):
            self._handler().redirect_request(
                self._get_request(), None, 302, 'Found', {}, 'http://evil.example.com/key.pem')

    def test_rejects_redirect_to_non_https_scheme(self):
        with pytest.raises(ValueError):
            self._handler().redirect_request(
                self._get_request(), None, 302, 'Found', {}, 'ftp://example.com/key.pem')

    def test_allows_redirect_to_http_when_insecure_allowed(self):
        req = self._handler(allow_insecure=True).redirect_request(
            self._get_request(), None, 302, 'Found', {}, 'http://example.com/key.pem')
        assert req is not None

    def test_allows_redirect_to_https(self):
        req = self._handler().redirect_request(
            self._get_request(), None, 302, 'Found', {}, 'https://example.com/key.pem')
        assert req is not None

    def test_download_file_uses_https_only_redirect_handler(self):
        from openbadgeslib.util import _HTTPSOnlyRedirectHandler
        mock_opener = _mock_opener()
        with patch('openbadgeslib.util.request.build_opener', return_value=mock_opener) as m:
            download_file('https://example.com/file.pem')
        (handler,), _ = m.call_args
        assert isinstance(handler, _HTTPSOnlyRedirectHandler)


class TestMisc:
    def test_show_ecc_disclaimer_does_not_raise(self, capsys):
        show_ecc_disclaimer()
        out = capsys.readouterr().out
        assert 'DISCLAIMER' in out

    def test_version_is_string(self):
        assert isinstance(__version__, str)
        assert len(__version__) > 0


class TestNormalizeRecipientId:
    def test_bare_email_gets_mailto(self):
        assert normalize_recipient_id('a@b.com') == 'mailto:a@b.com'

    def test_existing_mailto_unchanged(self):
        assert normalize_recipient_id('mailto:a@b.com') == 'mailto:a@b.com'

    def test_did_passthrough(self):
        assert normalize_recipient_id('did:example:123') == 'did:example:123'

    def test_none_passthrough(self):
        assert normalize_recipient_id(None) is None
