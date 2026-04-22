"""Tests for openbadgeslib.util."""
import hashlib
from unittest.mock import patch, MagicMock

import pytest

from openbadgeslib.util import (
    sha1_string, sha256_string, md5_string,
    hash_email, download_file, show_ecc_disclaimer,
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


class TestDownloadFile:
    def _mock_urlopen(self, content=b'file content'):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = content
        return mock_resp

    def test_returns_bytes_on_success(self):
        with patch('openbadgeslib.util.request.urlopen', return_value=self._mock_urlopen()):
            result = download_file('https://example.com/file.pem')
        assert result == b'file content'

    def test_https_url_no_warning(self, capsys):
        with patch('openbadgeslib.util.request.urlopen', return_value=self._mock_urlopen()):
            download_file('https://example.com/file.pem')
        out = capsys.readouterr().out
        assert 'Warning' not in out

    def test_http_url_prints_warning(self, capsys):
        with patch('openbadgeslib.util.request.urlopen', return_value=self._mock_urlopen()):
            download_file('http://example.com/file.pem')
        out = capsys.readouterr().out
        assert 'Warning' in out

    def test_timeout_is_passed(self):
        mock = self._mock_urlopen()
        with patch('openbadgeslib.util.request.urlopen', return_value=mock) as m:
            download_file('https://example.com/file')
        _, kwargs = m.call_args
        assert kwargs.get('timeout') == 30

    def test_propagates_network_errors(self):
        from urllib.error import URLError
        with patch('openbadgeslib.util.request.urlopen', side_effect=URLError('unreachable')):
            with pytest.raises(URLError):
                download_file('https://example.com/file')


class TestMisc:
    def test_show_ecc_disclaimer_does_not_raise(self, capsys):
        show_ecc_disclaimer()
        out = capsys.readouterr().out
        assert 'DISCLAIMER' in out

    def test_version_is_string(self):
        assert isinstance(__version__, str)
        assert len(__version__) > 0
