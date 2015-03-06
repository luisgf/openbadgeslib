#!/usr/bin/env python3
"""
        OpenBadges Library

        Copyright (c) 2015, Luis González Fernández, luisgf@luisgf.es
        Copyright (c) 2015, Jesús Cea Avión, jcea@jcea.es

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


__version__ = 'v0.4'     # Package Version

import hashlib
from urllib import request
from urllib.request import HTTPSHandler
from urllib.parse import urlparse
from ssl import SSLContext, CERT_NONE, VERIFY_CRL_CHECK_CHAIN, PROTOCOL_TLSv1
from ssl import SSLError

def _hash_string(hash_name, string) :
    h = hashlib.new(hash_name)
    h.update(string)
    return h.hexdigest().encode('latin-1')

def sha1_string(string) :
    return _hash_string('sha1', string)

def sha256_string(string):
    return _hash_string('sha256', string)

def md5_string(string):
    return _hash_string('md5', string)

def hash_email(email, salt):
    return sha256_string(email + salt)

def download_file(url):
    """ This function download a file from server """

    u = urlparse(url)

    if u.scheme != 'https':
        print('Warning! %s don\'t use TLS.', url)

    if u.hostname == b'':
        raise AssertionFormatIncorrect('The URL %s was malformed' % url)

    # SSL Context
    sslctx = SSLContext(PROTOCOL_TLSv1)
    sslctx.verify_mode = CERT_NONE
    sslctx_handler = HTTPSHandler(context=sslctx, check_hostname=False)

    request.install_opener(request.build_opener(sslctx_handler))

    with request.urlopen(url, timeout=30) as kd:
        file = kd.read()

    return file

def show_ecc_disclaimer():
    print("""    DISCLAIMER!

    You are running the program with support for Elliptic
    Curve cryptography.

    The implementation of ECC in JWS Draft is not clear about the
    signature/verification process and may lead to problems for
    you and others when verifying your badges.

    Use at your own risk!\n""")