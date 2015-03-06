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

import logging
logger = logging.getLogger(__name__)

import os
import sys

from enum import Enum
from Crypto.PublicKey import RSA
from ecdsa import SigningKey, VerifyingKey, NIST256p

from xml.dom.minidom import parseString
from urllib.error import HTTPError, URLError

import json

# Local imports
from .errors import UnknownKeyType, AssertionFormatIncorrect, \
            NotIdentityInAssertion, ErrorParsingFile, PublicKeyReadError

from .jws import utils as jws_utils
from .jws import verify_block as jws_verify_block
from .jws.exceptions import SignatureError as JWS_SignatureError
from .keys import KeyType, detect_key_type
from .util import hash_email, sha256_string, download_file, show_ecc_disclaimer
from .badge import BadgeStatus

class VerifyInfo():
    def __init__(self, status=BadgeStatus.NONE, msg=None):
        self.status = status
        self.msg = msg

class Verifier():
    def __init__(self, verify_key=None, identity=None):
        self.verify_key = verify_key
        self.identity = identity.encode('utf-8')

        if self.verify_key:
            self.key_type = detect_key_type(self.verify_key)

    def get_identity(self):
        return self.identity.decode('utf-8')

    def get_badge_status(self, badge):

        if badge.source.key_type is KeyType.ECC:
            show_ecc_disclaimer()

        try:
            if self.check_jws_signature(badge) is not BadgeStatus.VALID:
                """ Signature is cryptographically correct """

                 # Are this badge revoked?
                reason = self.check_revocation(badge)
                if reason:
                    error = 'The badge %s has been revoked. Reason: %s' % (badge.serial_num, reason)
                    return VerifyInfo(BadgeStatus.REVOKED, error)

                # Are this badge expired?
                if badge.expiration:
                    expiration = self.check_expiration(badge)
                    if expiration:
                        error = 'The badge with UID %s has expired at: %s' % (badge.serial_num, expiration)
                        return VerifyInfo(BadgeStatus.EXPIRED, error)

                if not self.check_identity(badge):
                    error = 'Identity mismatch for: %s' % self.get_identity()
                    return VerifyInfo(BadgeStatus.IDENTITY_ERROR, error)
            else:
                return VerifyInfo(BadgeStatus.SIGNATURE_ERROR, 'Signature invalid, corrupted or tampered')

        except HTTPError as e:
            return VerifyInfo(BadgeStatus.SIGNATURE_ERROR, e.reason)
        except URLError as e:
            return VerifyInfo(BadgeStatus.SIGNATURE_ERROR, e.reason)

        # OK, all is correct.
        return VerifyInfo(BadgeStatus.VALID, 'OK')

    def check_jws_signature(self, badge):
        try:
            if jws_verify_block(badge.assertion.get_assertion(), badge.source.pub_key):
                return VerifyInfo(BadgeStatus.VALID, 'OK')

        except JWS_SignatureError as err:
            return VerifyInfo(BadgeStatus.SIGNATURE_ERROR, err)

    def check_revocation(self, badge):
        """ Return true if the badge has been revoked """

        serial_num = badge.serial_num

        badge_json = download_file(badge.source.json_url)
        badge = jws_utils.from_json(badge_json)

        issuer_json = download_file(badge['issuer'])
        issuer = jws_utils.from_json(issuer_json)

        revocation_json = download_file(issuer['revocationList'])
        revocation = jws_utils.from_json(revocation_json)

        if revocation:
            for badge_id in revocation:
                if badge_id == serial_num:
                    return revocation[badge_id]

        return None

    def check_expiration(self, badge):
        from time import gmtime, strftime

        if badge.expiration < badge.issue_date:
            return "%s" % strftime("%a, %d %b %Y %H:%M:%S +0000",
                                                 gmtime(badge.expiration))
        else:
            return None

    def check_identity(self, badge):
        try:
            email_salt = badge.salt if badge.salt else b''
            email_hashed = b'sha256$' + hash_email(self.identity, email_salt)

            if email_hashed == badge.identity:
                return True
            else:
                return False
        except:
            raise NotIdentityInAssertion('The assertion doesn\'t have an identify ')

    def print_payload(self, badge):
        print('[+] This is the assertion content:')
        print(json.dumps(badge.assertion.decode_body(), sort_keys=True, indent=4))


