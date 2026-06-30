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

__version__ = '1.1.5'

import hashlib
from typing import Any, Optional, Union, overload
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
    """
    if value is None:
        return None
    if not value.startswith('mailto:') and '@' in value:
        return 'mailto:' + value
    return value


def hash_email(email: StrOrBytes, salt: StrOrBytes) -> bytes:
    if isinstance(email, str):
        email = email.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    return sha256_string(email + salt)


class _HTTPSOnlyRedirectHandler(request.HTTPRedirectHandler):
    """Reject any redirect whose target is not HTTPS.

    Plain ``urlopen()`` follows redirects with the default HTTPRedirectHandler,
    which never re-checks scheme: an https:// URL that 302s to http:// (or to
    an attacker-chosen insecure origin) would be followed transparently,
    defeating the HTTPS-only check below.
    """

    def __init__(self, allow_insecure: bool) -> None:
        self._allow_insecure = allow_insecure

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any,
                         newurl: str) -> Any:
        new_scheme = urlparse(newurl).scheme
        if new_scheme != 'https' and not self._allow_insecure:
            raise ValueError(
                'Refusing to follow redirect to %s over insecure %r scheme; HTTPS is '
                'required (pass allow_insecure=True to override).'
                % (newurl, new_scheme))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


#: Verify keys, issuer documents, and revocation lists are all small JSON/PEM
#: payloads; cap reads well above any legitimate size to bound memory use
#: against an attacker-influenced URL serving an oversized/streamed response.
MAX_DOWNLOAD_SIZE = 5 * 1024 * 1024  # 5 MiB


def download_file(url: str, allow_insecure: bool = False) -> bytes:
    """Download a file over HTTPS using urllib's default TLS validation.

    Non-HTTPS URLs are rejected by default: the verification key is the
    OpenBadges 2.0 root of trust, so fetching it over an unauthenticated
    channel would let an active network attacker substitute their own key and
    forge badges. Pass ``allow_insecure=True`` to explicitly permit plain HTTP.
    A redirect to a non-HTTPS target is rejected the same way. The response
    body is bounded to MAX_DOWNLOAD_SIZE to limit memory use.
    """
    u = urlparse(url)

    if u.scheme != 'https':
        if not allow_insecure:
            raise ValueError(
                'Refusing to download %s over insecure %r scheme; HTTPS is '
                'required (pass allow_insecure=True to override).'
                % (url, u.scheme))
        print('Warning! %s does not use TLS.' % url)

    opener = request.build_opener(_HTTPSOnlyRedirectHandler(allow_insecure))
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
