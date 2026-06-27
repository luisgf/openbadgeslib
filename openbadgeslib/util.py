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

__version__ = '1.1.0'

import hashlib
from urllib import request
from urllib.parse import urlparse


def _hash_string(hash_name, string):
    h = hashlib.new(hash_name)
    if isinstance(string, str):
        string = string.encode('utf-8')
    h.update(string)
    # hexdigest() is ASCII-only ([0-9a-f]); encode as ascii to signal that.
    return h.hexdigest().encode('ascii')


def sha1_string(string):
    return _hash_string('sha1', string)


def sha256_string(string):
    return _hash_string('sha256', string)


def md5_string(string):
    return _hash_string('md5', string)


def hash_email(email, salt):
    if isinstance(email, str):
        email = email.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    return sha256_string(email + salt)


def download_file(url, allow_insecure=False):
    """Download a file over HTTPS using urllib's default TLS validation.

    Non-HTTPS URLs are rejected by default: the verification key is the
    OpenBadges 2.0 root of trust, so fetching it over an unauthenticated
    channel would let an active network attacker substitute their own key and
    forge badges. Pass ``allow_insecure=True`` to explicitly permit plain HTTP.
    """
    u = urlparse(url)

    if u.scheme != 'https':
        if not allow_insecure:
            raise ValueError(
                'Refusing to download %s over insecure %r scheme; HTTPS is '
                'required (pass allow_insecure=True to override).'
                % (url, u.scheme))
        print('Warning! %s does not use TLS.' % url)

    with request.urlopen(url, timeout=30) as response:
        return response.read()


def show_ecc_disclaimer():
    print("""    DISCLAIMER!

    You are running the program with support for Elliptic
    Curve cryptography.

    The implementation of ECC in JWS Draft is not clear about the
    signature/verification process and may lead to problems for
    you and others when verifying your badges.

    Use at your own risk!\n""")
