"""Tests for openbadgeslib.util."""
import hashlib
import json
from unittest.mock import patch, MagicMock

import pytest

from openbadgeslib.util import (
    sha1_string, sha256_string, md5_string,
    hash_email, download_file, show_ecc_disclaimer,
    normalize_recipient_id, recipient_ids_match,
    emit_cli_json, __version__,
)


class TestEmitCliJson:
    """The shared --json contract used by the signer/publish/keygenerator
    CLIs (#166): 0 success, 2 partial, 1 any error; human stdout swallowed."""

    def _run(self, fn, capsys):
        with pytest.raises(SystemExit) as exc:
            emit_cli_json(fn)
        return exc.value.code, json.loads(capsys.readouterr().out)

    def test_success_exits_0(self, capsys):
        code, result = self._run(lambda: {'ok': 1}, capsys)
        assert code == 0 and result == {'ok': 1}

    def test_human_stdout_is_swallowed(self, capsys):
        def run():
            print('human noise that must not reach stdout')
            return {'value': 42}
        code, result = self._run(run, capsys)
        assert code == 0 and result == {'value': 42}

    def test_exit_key_sets_partial_status(self, capsys):
        code, result = self._run(lambda: {'skipped': ['b'], '_exit': 2}, capsys)
        assert code == 2
        assert result == {'skipped': ['b']}   # _exit is stripped from payload

    def test_exception_becomes_json_error(self, capsys):
        def run():
            raise ValueError('boom')
        code, result = self._run(run, capsys)
        assert code == 1 and result['error'] == 'ValueError: boom'

    def test_sys_exit_message_becomes_json_error(self, capsys):
        def run():
            raise SystemExit('[!] something went wrong')
        code, result = self._run(run, capsys)
        assert code == 1 and result['error'] == '[!] something went wrong'

    def test_sys_exit_code_recovers_last_printed_line(self, capsys):
        def run():
            print('[!] the real reason')
            raise SystemExit(-1)     # numeric code: message is in the buffer
        code, result = self._run(run, capsys)
        assert code == 1 and result['error'] == '[!] the real reason'


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
    @pytest.fixture(autouse=True)
    def _public_resolver(self):
        # download_file now resolves the host and rejects non-public IPs. Pin
        # resolution to a fixed public address so these behavioural tests stay
        # hermetic (no DNS) — SSRF blocking is covered by TestSSRFProtection.
        with patch('openbadgeslib.util._resolve_host', return_value=['93.184.216.34']):
            yield

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

    @pytest.fixture(autouse=True)
    def _public_resolver(self):
        # The redirect handler now also rejects a redirect to a non-public host;
        # pin resolution so the "allowed" redirect cases stay hermetic.
        with patch('openbadgeslib.util._resolve_host', return_value=['93.184.216.34']):
            yield

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


class TestSSRFProtection:
    """download_file must refuse attacker-controlled URLs that resolve to
    non-public hosts (cloud metadata, loopback, RFC1918)."""

    @pytest.mark.parametrize('ip', [
        '127.0.0.1', '169.254.169.254', '10.0.0.5', '192.168.1.1',
        '172.16.0.1', '0.0.0.0', '::1', 'fe80::1', 'fc00::1',
        '::ffff:127.0.0.1',
        # RFC 6598 carrier-grade NAT: not is_private, but not globally routable.
        '100.64.0.1', '100.127.255.255',
    ])
    def test_private_host_rejected(self, ip):
        with patch('openbadgeslib.util._resolve_host', return_value=[ip]):
            with pytest.raises(ValueError):
                download_file('https://internal.example/x')

    def test_literal_metadata_ip_rejected(self):
        # A literal IP needs no DNS: getaddrinfo returns it directly, so this
        # exercises the real resolver + classifier without touching the network.
        with pytest.raises(ValueError):
            download_file('https://169.254.169.254/latest/meta-data/')

    def test_literal_loopback_ipv6_rejected(self):
        with pytest.raises(ValueError):
            download_file('https://[::1]:8080/admin')

    def test_percent_encoded_localhost_port_rejected(self):
        # Mirrors a did:web:localhost%3A8080 URL after unquoting.
        with pytest.raises(ValueError):
            download_file('https://localhost:8080/issuer/did.json')

    def test_public_host_allowed(self):
        with patch('openbadgeslib.util._resolve_host', return_value=['93.184.216.34']), \
                patch('openbadgeslib.util.request.build_opener', return_value=_mock_opener()):
            assert download_file('https://example.com/f') == b'file content'

    def test_any_private_address_in_set_rejects(self):
        # A mixed public+private resolution (round-robin / rebinding) is refused.
        with patch('openbadgeslib.util._resolve_host',
                   return_value=['93.184.216.34', '127.0.0.1']):
            with pytest.raises(ValueError):
                download_file('https://example.com/f')

    def test_allow_private_opt_out(self):
        with patch('openbadgeslib.util._resolve_host', return_value=['127.0.0.1']), \
                patch('openbadgeslib.util.request.build_opener', return_value=_mock_opener()):
            assert download_file('https://localhost/f', allow_private=True) == b'file content'

    def test_redirect_to_private_host_rejected(self):
        from openbadgeslib.util import _HTTPSOnlyRedirectHandler
        req = MagicMock()
        req.get_method.return_value = 'GET'
        req.get_full_url.return_value = 'https://example.com/original'
        req.unredirected_hdrs = {}
        req.headers = {}
        with patch('openbadgeslib.util._resolve_host', return_value=['169.254.169.254']):
            with pytest.raises(ValueError):
                _HTTPSOnlyRedirectHandler(allow_insecure=False).redirect_request(
                    req, None, 302, 'Found', {}, 'https://evil.example/x')


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

    def test_uppercase_mailto_scheme_not_double_prefixed(self):
        # The scheme check must be case-insensitive (RFC 6068): an
        # already-prefixed URI in a different case must not get a second
        # 'mailto:' prepended.
        assert normalize_recipient_id('MAILTO:a@b.com') == 'MAILTO:a@b.com'

    def test_other_scheme_with_at_not_prefixed(self):
        # Any value already carrying a scheme (a ':' before the first '@') is
        # left untouched — only a bare email is prefixed. A spurious mailto:
        # would corrupt e.g. acct: identifiers or userinfo-bearing URLs.
        assert normalize_recipient_id('acct:user@host') == 'acct:user@host'
        assert normalize_recipient_id('https://user@host/x') == 'https://user@host/x'


class TestRecipientIdsMatch:
    def test_mailto_case_insensitive_match(self):
        assert recipient_ids_match('mailto:John@Example.com', 'mailto:john@example.com')

    def test_mailto_mixed_scheme_case_match(self):
        assert recipient_ids_match('mailto:a@b.com', 'MAILTO:A@B.COM')

    def test_did_is_case_sensitive(self):
        assert not recipient_ids_match('did:example:ABC', 'did:example:abc')

    def test_did_exact_match(self):
        assert recipient_ids_match('did:example:abc', 'did:example:abc')

    def test_none_only_matches_none(self):
        assert recipient_ids_match(None, None)
        assert not recipient_ids_match(None, 'mailto:a@b.com')
        assert not recipient_ids_match('mailto:a@b.com', None)

    def test_different_recipients_do_not_match(self):
        assert not recipient_ids_match('mailto:a@b.com', 'mailto:c@d.com')
