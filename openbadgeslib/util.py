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

__version__ = '3.6.0'

import hashlib
import ipaddress
import socket
from typing import Any, List, Optional, Union, overload
from urllib import request
from urllib.parse import urlparse

# A value that is accepted as either text or raw bytes (encoded to UTF-8).
StrOrBytes = Union[str, bytes]


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

    This is a pre-connection check; it does not on its own defeat DNS rebinding
    (a name that resolves public here but private at connect time), which would
    require pinning the socket to the validated address.
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


#: Verify keys, issuer documents, and revocation lists are all small JSON/PEM
#: payloads; cap reads well above any legitimate size to bound memory use
#: against an attacker-influenced URL serving an oversized/streamed response.
MAX_DOWNLOAD_SIZE = 5 * 1024 * 1024  # 5 MiB


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
    The check is re-applied to redirect targets. The response body is bounded to
    MAX_DOWNLOAD_SIZE to limit memory use.
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

    opener = request.build_opener(
        _HTTPSOnlyRedirectHandler(allow_insecure, allow_private))
    with opener.open(url, timeout=30) as response:
        chunks = []
        total = 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_DOWNLOAD_SIZE:
                raise ValueError(
                    'Refusing to download %s: response exceeds the %d byte limit'
                    % (url, MAX_DOWNLOAD_SIZE))
            chunks.append(chunk)
        return b''.join(chunks)


def show_ecc_disclaimer() -> None:
    print("""    DISCLAIMER!

    You are running the program with support for Elliptic
    Curve cryptography.

    The implementation of ECC in JWS Draft is not clear about the
    signature/verification process and may lead to problems for
    you and others when verifying your badges.

    Use at your own risk!\n""")
