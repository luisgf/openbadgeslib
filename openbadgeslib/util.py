#!/usr/bin/env python3
"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es
        Copyright (c) 2014-2026, Jesús Cea Avión, jcea@jcea.es

        All rights reserved.

        This library is free software; you can redistribute it and/or
        modify it under the terms of the GNU Lesser General Public
        License as published by the Free Software Foundation; either
        version 3.0 of the License, or (at your option) any later version.

        This library is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
        Lesser General Public License for more details.

        You should have received a copy of the GNU Lesser General Public
        License along with this library.
"""

__version__ = '4.6.3'

import contextlib
import functools
import hashlib
import http.client
import io
import ipaddress
import json
import socket
import sys
import time
from collections import OrderedDict
from datetime import timedelta
from typing import Any, Callable, List, Optional, Union, overload
from urllib import request
from urllib.error import HTTPError
from urllib.parse import urlparse

# A value that is accepted as either text or raw bytes (encoded to UTF-8).
StrOrBytes = Union[str, bytes]

#: Wall-clock leeway applied to every validity window (vc validFrom/validUntil,
#: the status list's own window, and endorsements) so a small clock offset
#: between the issuing and verifying hosts does not reject a credential the
#: instant it is issued. 60 s matches the common JWT ``leeway`` default; the
#: JWT registered claims (nbf/exp) already get their own leeway from PyJWT.
CLOCK_SKEW_LEEWAY = timedelta(seconds=60)


def _hash_string(hash_name: str, string: StrOrBytes) -> bytes:
    h = hashlib.new(hash_name)
    if isinstance(string, str):
        string = string.encode('utf-8')
    h.update(string)
    # hexdigest() is ASCII-only ([0-9a-f]); encode as ascii to signal that.
    return h.hexdigest().encode('ascii')


def sha1_string(string: StrOrBytes) -> bytes:
    return _hash_string('sha1', string)


def sha256_string(string: StrOrBytes) -> bytes:
    return _hash_string('sha256', string)


def md5_string(string: StrOrBytes) -> bytes:
    return _hash_string('md5', string)


@overload
def normalize_recipient_id(value: str) -> str: ...
@overload
def normalize_recipient_id(value: None) -> None: ...


def normalize_recipient_id(value: Optional[str]) -> Optional[str]:
    """Normalize a recipient identifier to its credentialSubject.id form.

    A bare email address gets a ``mailto:`` scheme; DIDs and identifiers that
    already carry a scheme are returned unchanged. Shared by the OB3 signer and
    verifier so both agree (an unconditional ``mailto:`` prefix would corrupt a
    DID into ``mailto:did:...``).

    "Already carries a scheme" is detected as a ``:`` before the first ``@``,
    so scheme-qualified values such as ``mailto:``/``acct:user@host`` or an
    ``https://user@host`` URL are left untouched — only a bare ``user@host``
    email is prefixed.
    """
    if value is None:
        return None
    if '@' not in value:
        return value
    if ':' in value[:value.index('@')]:
        return value
    return 'mailto:' + value


def recipient_ids_match(a: Optional[str], b: Optional[str]) -> bool:
    """Compare two credentialSubject.id values for recipient binding.

    A ``mailto:`` URI is compared case-insensitively (RFC 6068 treats the
    scheme as case-insensitive, and email addresses are conventionally
    treated the same way), so a recipient who signed with one casing and
    verifies with another is not wrongly rejected. Anything else (in
    particular a DID) is compared exactly, since DID method-specific
    identifiers can be case-sensitive.
    """
    if a is None or b is None:
        return a == b
    if a.lower().startswith('mailto:') and b.lower().startswith('mailto:'):
        return a.lower() == b.lower()
    return a == b


def hash_email(email: StrOrBytes, salt: StrOrBytes) -> bytes:
    if isinstance(email, str):
        email = email.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    return sha256_string(email + salt)


def _resolve_host(host: str, port: int) -> List[str]:
    """Resolve *host* to a list of IP-address strings.

    A thin wrapper over socket.getaddrinfo, kept as the single dependency seam
    the SSRF host check uses so tests can patch resolution without the network.
    """
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    # sockaddr[0] is the address; getaddrinfo's sockaddr is typed as a tuple
    # union (str | int), so coerce to str for the annotated return type.
    return [str(info[4][0]) for info in infos]


# RFC 6598 carrier-grade NAT shared address space. Python's ipaddress does not
# flag it as private/reserved, but it is not globally routable and commonly
# fronts internal ISP/cloud infrastructure, so it is a valid SSRF target.
_CGNAT_V4 = ipaddress.ip_network('100.64.0.0/10')


def _ip_is_blocked(ip_str: str) -> bool:
    """True if *ip_str* is a loopback/private/link-local/reserved/CGNAT address
    a verifier must never be steered into fetching (an SSRF sink)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable address: fail closed
    # An IPv4-mapped IPv6 address (::ffff:127.0.0.1) must be judged by its
    # embedded IPv4 address, not the v6 wrapper, or the loopback slips through.
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 4 and ip in _CGNAT_V4:
        return True
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _assert_public_host(url: str) -> None:
    """Raise ValueError if *url*'s host resolves to any non-public address.

    download_file is called with fully attacker-controlled URLs: a did:web
    host, a credentialStatus list, and the OB2 badge/issuer/revocationList URLs
    all come from untrusted badge data. Without this check a verifier can be
    steered into GETting cloud-metadata endpoints (169.254.169.254), loopback
    admin interfaces, or RFC1918 internal hosts (SSRF). Every resolved address
    is checked, and the check is re-applied to redirect targets in
    _HTTPSOnlyRedirectHandler (a public host can 30x to an internal address).

    This is the early pre-connection check. DNS rebinding (a name that resolves
    public here but private at connect time) is defeated separately by
    :class:`_PinnedHTTPSConnection`, which re-resolves, re-validates and dials
    the validated IP in one step for the actual HTTPS connection.
    """
    parts = urlparse(url)
    host = parts.hostname
    if not host:
        raise ValueError('Refusing to download %s: URL has no host' % url)
    try:
        addrs = _resolve_host(host, parts.port or 443)
    except OSError as exc:
        raise ValueError(
            'Could not resolve host %r for %s: %s' % (host, url, exc)) from exc
    if not addrs:
        raise ValueError('Could not resolve host %r for %s' % (host, url))
    for ip_str in addrs:
        if _ip_is_blocked(ip_str):
            raise ValueError(
                'Refusing to download %s: host %r resolves to non-public address '
                '%s (possible SSRF). Pass allow_private=True to override.'
                % (url, host, ip_str))


class _HTTPSOnlyRedirectHandler(request.HTTPRedirectHandler):
    """Reject any redirect whose target is not HTTPS or resolves to a
    non-public host.

    Plain ``urlopen()`` follows redirects with the default HTTPRedirectHandler,
    which never re-checks scheme or host: an https:// URL that 302s to http://
    (or to an attacker-chosen insecure/internal origin) would be followed
    transparently, defeating the HTTPS-only and public-host checks below.
    """

    def __init__(self, allow_insecure: bool, allow_private: bool = False) -> None:
        self._allow_insecure = allow_insecure
        self._allow_private = allow_private

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any,
                         newurl: str) -> Any:
        new_scheme = urlparse(newurl).scheme
        if new_scheme != 'https' and not self._allow_insecure:
            raise ValueError(
                'Refusing to follow redirect to %s over insecure %r scheme; HTTPS is '
                'required (pass allow_insecure=True to override).'
                % (newurl, new_scheme))
        if not self._allow_private:
            _assert_public_host(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@contextlib.contextmanager
def _pinned_dial(conn: http.client.HTTPConnection, default_port: int,
                 allow_private: bool) -> Any:
    """Resolve *conn.host*, SSRF-validate, and dial the validated IP.

    Shared by the HTTPS and (allow_insecure) HTTP connection classes so a
    name that answers public at the pre-check and private at connect (DNS
    rebinding) is caught on both schemes (#328).
    """
    port = conn.port or default_port
    try:
        addrs = _resolve_host(conn.host, port)
    except OSError as exc:
        raise ValueError('Could not resolve host %r: %s'
                         % (conn.host, exc)) from exc
    if not addrs:
        raise ValueError('Could not resolve host %r' % conn.host)
    if not allow_private:
        for ip_str in addrs:
            if _ip_is_blocked(ip_str):
                raise ValueError(
                    'Refusing to connect to %r: resolves to non-public '
                    'address %s (possible SSRF / DNS rebinding).'
                    % (conn.host, ip_str))
    pinned = addrs[0]
    original = getattr(conn, '_create_connection')

    def _dial_pinned(address: Any, *a: Any, **k: Any) -> Any:
        return original((pinned, address[1]), *a, **k)

    setattr(conn, '_create_connection', _dial_pinned)
    try:
        yield
    finally:
        setattr(conn, '_create_connection', original)


#: The timeout of one network operation (a connect, one recv). It does not
#: bound a download: the budget below does.
_SOCKET_TIMEOUT = 30


class _DownloadBudgetExceeded(Exception):
    """The wall-clock budget of a download ran out mid-response; download_file
    turns it into the ValueError that names the URL.

    Deliberately not a ValueError: ``http.client`` reads the size line of a
    chunked body inside ``try: ... except ValueError: raise IncompleteRead``,
    so a ValueError raised from the reader there reached the caller as an
    unrelated ``IncompleteRead`` instead of the budget's own error."""


class _BudgetReader(io.RawIOBase):
    """A raw reader over a connected socket that spends one wall-clock budget.

    ``socket.settimeout`` bounds a single recv, and ``http.client`` reads a
    response through a buffered file that loops recv until it has what it asked
    for: a status line, a header line, 64 KiB of body. A server that sends a
    byte every few seconds never trips the per-recv timeout and holds that loop
    open indefinitely, in the response headers as much as in the body. Here
    every recv is capped by what is left of the budget, and checked before it
    starts, so the loop cannot outlive it.
    """

    def __init__(self, raw: Any, sock: Any, deadline: float) -> None:
        super().__init__()
        self._raw = raw
        self._sock = sock
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def fileno(self) -> int:
        return int(self._raw.fileno())

    def readinto(self, buffer: Any) -> Optional[int]:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise _DownloadBudgetExceeded()
        self._sock.settimeout(min(_SOCKET_TIMEOUT, remaining))
        try:
            return self._raw.readinto(buffer)       # type: ignore[no-any-return]
        except OSError:
            # The recv ran into the budget (a timeout, or an SSL error that
            # reports one): that is the budget, not a network fault.
            if time.monotonic() >= self._deadline:
                raise _DownloadBudgetExceeded() from None
            raise

    def close(self) -> None:
        if not self.closed:
            self._raw.close()
        super().close()


class _BudgetSocket:
    """What http.client.HTTPResponse asks of its socket: ``makefile('rb')``,
    here a buffered reader that spends the budget (:class:`_BudgetReader`).
    ``makefile(buffering=0)`` of the real socket keeps its close accounting:
    urllib closes the socket object after getresponse(), and the file object
    is what keeps the connection open until the body is read."""

    def __init__(self, sock: Any, deadline: float) -> None:
        self._sock = sock
        self._deadline = deadline

    def makefile(self, mode: str = 'rb', *args: Any, **kwargs: Any) -> Any:
        raw = self._sock.makefile('rb', buffering=0)
        return io.BufferedReader(_BudgetReader(raw, self._sock, self._deadline))


class _BudgetResponse(http.client.HTTPResponse):
    """An HTTPResponse whose status line, headers and body all spend one
    download budget (see :class:`_BudgetReader`)."""

    def __init__(self, sock: Any, *args: Any, deadline: float,
                 **kwargs: Any) -> None:
        # Duck-typed: HTTPResponse only ever calls sock.makefile('rb').
        stand_in: Any = _BudgetSocket(sock, deadline)
        super().__init__(stand_in, *args, **kwargs)


def _bound_response(conn: http.client.HTTPConnection,
                    deadline: Optional[float]) -> None:
    """Make *conn* read its responses under *deadline* (a time.monotonic()
    value); None leaves the stock behaviour."""
    if deadline is not None:
        setattr(conn, 'response_class',
                functools.partial(_BudgetResponse, deadline=deadline))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """An HTTPSConnection that resolves and SSRF-validates the host *at connect
    time* and dials the validated IP, while still presenting the original
    hostname for TLS SNI, certificate validation and the ``Host`` header.

    ``_assert_public_host`` runs before the connection, but ``opener.open`` would
    otherwise re-resolve on its own — a hostile DNS with TTL 0 can answer public
    during the pre-check and internal (169.254.169.254, 127.0.0.1, RFC1918) on
    the real connect (DNS rebinding). Resolving and connecting in the same breath
    here closes that window: the IP that is validated is the exact IP dialed.
    ``allow_private`` skips the classification for a private deployment.
    """

    def __init__(self, host: str, *args: Any,
                 allow_private: bool = False,
                 deadline: Optional[float] = None, **kwargs: Any) -> None:
        super().__init__(host, *args, **kwargs)
        self._allow_private = allow_private
        _bound_response(self, deadline)

    def connect(self) -> None:
        with _pinned_dial(self, 443, self._allow_private):
            super().connect()


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP twin of :class:`_PinnedHTTPSConnection` for ``allow_insecure=True``.

    Without this, an http:// download skipped the connect-time pin and
    re-resolved at dial, reopening the DNS-rebinding window the HTTPS path
    closed (#328).
    """

    def __init__(self, host: str, *args: Any,
                 allow_private: bool = False,
                 deadline: Optional[float] = None, **kwargs: Any) -> None:
        super().__init__(host, *args, **kwargs)
        self._allow_private = allow_private
        _bound_response(self, deadline)

    def connect(self) -> None:
        with _pinned_dial(self, 80, self._allow_private):
            super().connect()


class _PinnedHTTPSHandler(request.HTTPSHandler):
    """Route every HTTPS connection — the initial request and any redirect —
    through :class:`_PinnedHTTPSConnection`, so the SSRF host check and the
    socket connect share one DNS resolution (no rebinding window). TLS still
    uses urllib's default verifying context (verify + hostname check)."""

    def __init__(self, allow_private: bool = False,
                 deadline: Optional[float] = None) -> None:
        super().__init__()
        self._allow_private = allow_private
        self._deadline = deadline

    def https_open(self, req: Any) -> Any:
        return self.do_open(
            _PinnedHTTPSConnection, req, allow_private=self._allow_private,
            deadline=self._deadline)


class _PinnedHTTPHandler(request.HTTPHandler):
    """Route plain-HTTP connections through :class:`_PinnedHTTPConnection`."""

    def __init__(self, allow_private: bool = False,
                 deadline: Optional[float] = None) -> None:
        super().__init__()
        self._allow_private = allow_private
        self._deadline = deadline

    def http_open(self, req: Any) -> Any:
        return self.do_open(
            _PinnedHTTPConnection, req, allow_private=self._allow_private,
            deadline=self._deadline)


#: Verify keys, issuer documents, and revocation lists are all small JSON/PEM
#: payloads; cap reads well above any legitimate size to bound memory use
#: against an attacker-influenced URL serving an oversized/streamed response.
MAX_DOWNLOAD_SIZE = 5 * 1024 * 1024  # 5 MiB

#: Global wall-clock budget for a single download. ``timeout=30`` on the socket
#: is per-operation, so a server that drips one byte per 29 s would hold the
#: connection open far longer than any legitimate small fetch needs; the size
#: cap bounds bytes but not time. This bounds the total read wall-clock.
MAX_DOWNLOAD_SECONDS = 60


def download_file(url: str, allow_insecure: bool = False,
                  allow_private: bool = False) -> bytes:
    """Download a file over HTTPS using urllib's default TLS validation.

    Non-HTTPS URLs are rejected by default: the verification key is the
    OpenBadges 2.0 root of trust, so fetching it over an unauthenticated
    channel would let an active network attacker substitute their own key and
    forge badges. Pass ``allow_insecure=True`` to explicitly permit plain HTTP.
    A redirect to a non-HTTPS target is rejected the same way.

    The destination host is also required to resolve to a public address:
    because the URL is attacker-influenced (a did:web host, a credentialStatus
    list, an OB2 badge/issuer/revocationList URL), fetching a private/loopback/
    link-local target would be a server-side request forgery (SSRF) sink. Pass
    ``allow_private=True`` to permit internal hosts (e.g. a private deployment).
    The check is re-applied to redirect targets. HTTPS always, and HTTP when
    ``allow_insecure=True``, pin the socket to the validated IP (DNS
    rebinding). The response body is bounded to MAX_DOWNLOAD_SIZE to limit
    memory use, and the whole call (every redirect, the status line, headers
    and body, a chunked body's size lines included) to MAX_DOWNLOAD_SECONDS.

    Raises:
        ValueError: the URL or a redirect target is refused (a non-HTTPS
            scheme, a non-public host, a host that does not resolve), the body
            exceeds MAX_DOWNLOAD_SIZE, or the MAX_DOWNLOAD_SECONDS budget runs
            out (a server that sends a byte every few seconds).
        OSError: a network fault: ``urllib.error.URLError``, ``HTTPError`` (an
            HTTP error status) and the socket and TLS errors.
        http.client.HTTPException: the server sent a malformed response, such
            as a chunked body that ends inside a chunk (``IncompleteRead``).
            It is neither a ValueError nor an OSError: a caller that must
            survive a hostile server catches it too (``ob1.Verifier`` does).
    """
    u = urlparse(url)

    if u.scheme != 'https':
        if not allow_insecure:
            raise ValueError(
                'Refusing to download %s over insecure %r scheme; HTTPS is '
                'required (pass allow_insecure=True to override).'
                % (url, u.scheme))
        print('Warning! %s does not use TLS.' % url)

    if not allow_private:
        _assert_public_host(url)

    # _PinnedHTTPSHandler pins the connection to the validated IP (defeats DNS
    # rebinding); the HTTP twin does the same when allow_insecure permits
    # plain HTTP. The redirect handler re-applies the scheme/host checks to any
    # 30x target (which then also connects through the pinned handler).
    # The budget starts now and is shared by every connection of this call (a
    # redirect opens another), which spend it as they read: the response
    # headers and body (see _BudgetReader). Connecting, the TLS handshake and
    # DNS resolution are bounded per operation (_SOCKET_TIMEOUT), not by it.
    deadline = time.monotonic() + MAX_DOWNLOAD_SECONDS
    handlers: List[Any] = [
        _PinnedHTTPSHandler(allow_private, deadline),
        _HTTPSOnlyRedirectHandler(allow_insecure, allow_private),
    ]
    if allow_insecure:
        handlers.insert(0, _PinnedHTTPHandler(allow_private, deadline))
    opener = request.build_opener(*handlers)
    over_budget = ('Refusing to download %s: exceeded the %d-second time budget '
                   '(slow-drip response)' % (url, MAX_DOWNLOAD_SECONDS))
    try:
        resp_cm = opener.open(url, timeout=_SOCKET_TIMEOUT)
    except HTTPError as exc:
        # The error owns the response's socket; callers that swallow it would
        # otherwise leave it to GC (a ResourceWarning on recent Pythons).
        exc.close()
        raise
    except _DownloadBudgetExceeded:
        raise ValueError(over_budget) from None
    with resp_cm as response:
        chunks = []
        total = 0
        while True:
            # A per-socket timeout does not bound total time: a slow-drip server
            # can keep resetting it. The budget does (and bounds each recv of
            # the read below, so a drip inside a single read cannot outlast it).
            if time.monotonic() > deadline:
                raise ValueError(over_budget)
            try:
                chunk = response.read(65536)
            except _DownloadBudgetExceeded:
                raise ValueError(over_budget) from None
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_DOWNLOAD_SIZE:
                raise ValueError(
                    'Refusing to download %s: response exceeds the %d byte limit'
                    % (url, MAX_DOWNLOAD_SIZE))
            chunks.append(chunk)
        return b''.join(chunks)


class CachingDownloader:
    """A memoizing wrapper around a downloader, for verifying many credentials
    from the same issuer without re-fetching identical URLs.

    Verification is one-shot by default: verifying N badges re-fetches the same
    did:web ``did.json`` and status list(s) N times. Construct one instance and
    pass it as the ``download=`` argument to the resolution/verification entry
    points that accept one — ``OB3Verifier.for_issuer_did`` / ``.verify``,
    ``OB3LdpVerifier.verify``, ``check_credential_status``,
    ``verify_endorsement_jwt`` — to serve repeated URLs from an in-process cache
    with a short time-to-live::

        dl = CachingDownloader(ttl_seconds=300)
        verifier = OB3Verifier.for_issuer_did(issuer_did, download=dl)
        for token in batch:
            verifier.verify(token, check_status=True, download=dl)

    Each entry is the raw bytes the wrapped downloader returned, so every
    ``download_file`` protection (HTTPS-only, the SSRF guard, the size cap) runs
    on the first fetch, before anything is cached. Entries expire after
    ``ttl_seconds`` on a monotonic clock (immune to wall-clock jumps).
    ``max_entries`` bounds the **entry count** (not bytes) with LRU eviction —
    each entry may be up to :data:`MAX_DOWNLOAD_SIZE` (5 MiB), so the default of
    256 admits roughly 1.25 GiB resident in the worst case. Lower ``max_entries``
    for untrusted batches. **Not thread-safe** — use one per verifying thread,
    or guard it. For real-time revocation keep the TTL short, or omit the cache
    and pay the fetch.
    """

    def __init__(self, download: Optional[Callable[[str], bytes]] = None, *,
                 ttl_seconds: float = 300.0, max_entries: int = 256) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive, got %r" % (ttl_seconds,))
        if max_entries <= 0:
            raise ValueError("max_entries must be positive, got %r" % (max_entries,))
        self._download = download if download is not None else download_file
        self._ttl = float(ttl_seconds)
        self._max_entries = max_entries
        self._cache: OrderedDict[str, tuple[float, bytes]] = OrderedDict()

    def __call__(self, url: str) -> bytes:
        now = time.monotonic()
        entry = self._cache.get(url)
        if entry is not None:
            expiry, data = entry
            if expiry > now:
                self._cache.move_to_end(url)
                return data
            del self._cache[url]                 # expired: fall through to refetch
        data = self._download(url)               # protections run here, pre-cache
        self._cache[url] = (now + self._ttl, data)
        self._cache.move_to_end(url)
        while len(self._cache) > self._max_entries:
            self._cache.popitem(last=False)      # evict least-recently-used
        return data

    def clear(self) -> None:
        """Drop all cached entries (e.g. to force a fresh revocation check)."""
        self._cache.clear()


def _last_nonempty_line(text: str) -> Optional[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else None


def emit_cli_json(run: Callable[[], dict[str, Any]]) -> None:
    """Run a CLI operation in ``--json`` mode: emit exactly one JSON object and
    set the process exit status per the shared machine-output contract.

    *run* performs the operation and RETURNS the machine-readable result dict;
    its human-readable stdout is captured and discarded so that only the JSON
    object reaches stdout. A result may carry an ``_exit`` key to request a
    specific status (stripped from the emitted payload) — e.g. ``2`` for a
    partial success; otherwise a returned result exits ``0``.

    Any failure — a raised exception, or a ``sys.exit(...)`` from the operation
    (including the shared read_config_or_exit) — is reported as
    ``{"error": "..."}`` on stdout with exit status ``1``, so automation never
    has to parse a traceback or a half-written human message.

    Exit contract shared by the signer/publish/keygenerator ``--json`` paths:
    ``0`` success, ``2`` partial success (some work skipped), ``1`` any error.
    """
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            result = run()
    except SystemExit as exc:
        # A sys.exit('message') carries the message in .code; a sys.exit(1)
        # after a human print left it in the captured buffer — recover either.
        detail = exc.code if isinstance(exc.code, str) \
            else _last_nonempty_line(buffer.getvalue())
        print(json.dumps({'error': detail or 'operation failed'}))
        sys.exit(1)
    except Exception as exc:
        print(json.dumps({'error': '%s: %s' % (type(exc).__name__, exc)}))
        sys.exit(1)
    exit_code = result.pop('_exit', 0)
    print(json.dumps(result))
    sys.exit(exit_code)


def show_ecc_disclaimer() -> None:
    print("""    DISCLAIMER!

    You are running the program with support for Elliptic
    Curve cryptography.

    The implementation of ECC in JWS Draft is not clear about the
    signature/verification process and may lead to problems for
    you and others when verifying your badges.

    Use at your own risk!\n""")
