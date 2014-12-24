#!/usr/bin/env python3
"""
        OpenBadges Library

        Copyright (c) 2014, Luis González Fernández, luisgf@luisgf.es
        Copyright (c) 2014, Jesús Cea Avión, jcea@jcea.es

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

import logging
logger = logging.getLogger(__name__)

import os
import sys

from enum import Enum
from Crypto.PublicKey import RSA
from ecdsa import SigningKey, VerifyingKey, NIST256p

from urllib import request
from urllib.request import HTTPSHandler
from urllib.parse import urlparse
from ssl import SSLContext, CERT_NONE, VERIFY_CRL_CHECK_CHAIN, PROTOCOL_TLSv1
from xml.dom.minidom import parseString

from urllib.error import HTTPError, URLError
from ssl import SSLError
import json

# Local imports
from .errors import UnknownKeyType, AssertionFormatIncorrect, \
            NotIdentityInAssertion, ErrorParsingFile, PublicKeyReadError

from .jws import utils as jws_utils
from .jws import verify_block as jws_verify_block
from .jws.exceptions import SignatureError as JWS_SignatureError
from .keys import KeyType, detect_key_type
from .util import hash_email, sha256_string

class BadgeStatus(Enum):
    VALID = 1
    SIGNATURE_ERROR = 2
    EXPIRED = 3
    REVOKED = 4
    IDENTITY_ERROR = 5
    NONE = 6

class VerifyInfo():
    def __init__(self, status=BadgeStatus.NONE, msg=None):
        self.status = status
        self.msg = msg

def VerifyFactory(key_type=KeyType.RSA, *args, **kwargs):
    """ Verify Factory Object, Return a Given object type passing a name
        to the constructor. """

    if key_type == KeyType.ECC:
       return VerifyECC(*args, **kwargs)
    if key_type == KeyType.RSA:
       return VerifyRSA(*args, **kwargs)
    else:
       raise UnknownKeyType()

""" Signature Verification Factory """
class VerifyBase():
    def __init__(self, assertion=None, identity=None, verify_key=None):
        self._assertion = assertion
        self._identity = identity
        self._metadata = self.extract_metadata()

        if (verify_key is None):
            self._verify_key = self.download_pubkey()
        else:
            self._verify_key = verify_key

        self._key_type = detect_key_type(self._verify_key)

    def print_payload(self):
        print('[+] This is the assertion content:')
        print(json.dumps(self._metadata['payload'], sort_keys=True, indent=4))

    def check_jws_signature(self, assertion, key):
        try:
            if jws_verify_block(assertion, key):
                return VerifyInfo(BadgeStatus.VALID, 'OK')

        except JWS_SignatureError as err:
            return VerifyInfo(BadgeStatus.SIGNATURE_ERROR, err)

    def get_signature_status(self):
        self.show_disclaimer()

        assertion = self._metadata['assertion']
        payload = self._metadata['payload']

        try:
            if self.check_jws_signature(assertion, self._verify_key) is not BadgeStatus.VALID:
                """ Signature is cryptographically correct """

                 # Are this badge revoked?
                reason = self.check_revocation(payload)
                if reason:
                    error = 'The badge %s has been revoked. Reason: %s' % (payload['uid'],reason)
                    return VerifyInfo(BadgeStatus.REVOKED, error)

                # Are this badge expired?
                try:
                    expiration = self.check_expiration(payload['issuedOn'], payload['expires'])
                    if expiration:
                        error = 'The badge with UID %s has expired at: %s' % (payload['uid'], expiration)
                        return VerifyInfo(BadgeStatus.EXPIRED, error)
                except KeyError:
                    pass

                if not self.check_identity():
                    error = 'Identity mismatch for: %s' % self._identity
                    return VerifyInfo(BadgeStatus.IDENTITY_ERROR, error)
            else:
                return VerifyInfo(BadgeStatus.SIGNATURE_ERROR, 'Signature invalid, corrupted or tampered')

        except HTTPError as e:
            return VerifyInfo(BadgeStatus.SIGNATURE_ERROR, e.reason)
        except URLError as e:
            return VerifyInfo(BadgeStatus.SIGNATURE_ERROR, e.reason)

        # OK, all is correct.
        return VerifyInfo(BadgeStatus.VALID, 'OK')

    def check_expiration(self, ts_expedition, ts_expiration):
        from time import gmtime, strftime

        if ts_expiration < ts_expedition:
            return "%s" % strftime("%a, %d %b %Y %H:%M:%S +0000",
                                                 gmtime(ts_expiration))
        else:
            return None

    def check_revocation(self, payload):
        """ Return true if the badge has been revoked """
        uid = payload['uid']

        badge_json = self.download_file(payload['badge'])
        badge = jws_utils.from_json(badge_json)

        issuer_json = self.download_file(badge['issuer'])
        issuer = jws_utils.from_json(issuer_json)

        revocation_json = self.download_file(issuer['revocationList'])
        revocation = jws_utils.from_json(revocation_json)

        if revocation:
            for badge_id in revocation:
                if badge_id == uid:
                    return revocation[badge_id]

        return None

    def check_identity(self):
        payload = self._metadata['payload']

        try:
            try:
                email_salt = payload['recipient']['salt'].encode('utf-8')
            except:
                email_salt = b''

            email_hashed = (b'sha256$' + hash_email(self._identity.encode(), email_salt)).decode('utf-8')
            if email_hashed == payload['recipient']['identity']:
                return True
            else:
                return False
        except:
            raise NotIdentityInAssertion('The assertion doesn\'t have an identify ')

    def download_pubkey(self):
        return self.download_file(self._metadata['payload']['verify']['url'])

    def download_file(self, url):
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

    @staticmethod
    def extract_svg_assertion(svg_data):
        """ Extract the assertion embeded in a SVG file. """

        try:
            # Parse de SVG XML
            svg_doc = parseString(svg_data)

            # Extract the assertion
            xml_node = svg_doc.getElementsByTagName("openbadges:assertion")
            assertion = xml_node[0].attributes['verify'].nodeValue.encode('utf-8')

        except:
            raise ErrorParsingFile('Error Parsing SVG file: ')
        finally:
            svg_doc.unlink()
            return assertion

    def extract_metadata(self):
        # The assertion MUST be a string like head.payload.signature
        try:
            data = self._assertion.split(b'.')

            return dict(header = jws_utils.decode(data[0]),
                        payload = jws_utils.decode(data[1]),
                        signature = data[2],
                        assertion = self._assertion)
        except:
            raise AssertionFormatIncorrect()


""" RSA Verify Factory """
class VerifyRSA(VerifyBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def load_pubkey_inline(self, pub_key_pem):
        """ Create a crypto object from a pem string """
        return RSA.importKey(pub_key_pem)

    def show_key_info(self, key):
         print('[+] Using an RSA Key of %d bits size' % key.size())

    def show_disclaimer(self):
        pass

class VerifyECC(VerifyBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def load_pubkey_inline(self, pub_key_pem):
        """ Create a crypto object from a pem string """
        return VerifyingKey.from_pem(pub_key_pem)

    def show_key_info(self, key):
        print('[+] Using an ECC Key with a curve type %s' % key.curve.name)

    def show_disclaimer(self):
        print("""DISCLAIMER!

        You are running the program with support for Elliptic
        Curve cryptography.

        The implementation of ECC in JWS Draft is not clear about the
        signature/verification process and may lead to problems for
        you and others when verifying your badges.

        Use at your own risk!""")
