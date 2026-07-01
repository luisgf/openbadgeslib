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

from typing import Any, Optional

from .badge import BadgeStatus
from ..util import hash_email, download_file, show_ecc_disclaimer
from ..keys import KeyType, detect_key_type
from .._jws.exceptions import JWSException
from .._jws import verify_block as jws_verify_block
from .._jws import utils as jws_utils
from ..errors import AssertionFormatIncorrect, NotIdentityInAssertion
import json
from urllib.error import HTTPError, URLError
import logging
logger = logging.getLogger(__name__)


class VerifyInfo():
    def __init__(self, status: BadgeStatus = BadgeStatus.NONE,
                 msg: Optional[Any] = None) -> None:
        self.status = status
        self.msg = msg


class Verifier():
    def __init__(self, verify_key: Optional[Any] = None,
                 identity: Optional[str] = None) -> None:
        self.verify_key = verify_key
        self.identity = identity.encode('utf-8') if identity is not None else None
        self.key_type = None

        if self.verify_key:
            self.key_type = detect_key_type(self.verify_key)

    def get_identity(self) -> Optional[str]:
        return self.identity.decode('utf-8') if self.identity is not None else None

    def get_badge_status(self, badge: Any) -> VerifyInfo:

        if badge.source.key_type is KeyType.ECC:
            show_ecc_disclaimer()

        try:
            sig_check = self.check_jws_signature(badge)
            if sig_check.status is not BadgeStatus.VALID:
                return sig_check

            # Signature is cryptographically valid; check further conditions.

            # Is this badge revoked?
            reason = self.check_revocation(badge)
            if reason:
                error = 'The badge %s has been revoked. Reason: %s' % (badge.serial_num, reason)
                return VerifyInfo(BadgeStatus.REVOKED, error)

            # Is this badge expired?
            if badge.expiration:
                expiration = self.check_expiration(badge)
                if expiration:
                    error = 'The badge with UID %s has expired at: %s' % (badge.serial_num, expiration)
                    return VerifyInfo(BadgeStatus.EXPIRED, error)

            if not self.check_identity(badge):
                error = 'Identity mismatch for: %s' % self.get_identity()
                return VerifyInfo(BadgeStatus.IDENTITY_ERROR, error)

        except HTTPError as e:
            return VerifyInfo(BadgeStatus.SIGNATURE_ERROR, e.reason)
        except URLError as e:
            return VerifyInfo(BadgeStatus.SIGNATURE_ERROR, e.reason)
        except ValueError as e:
            # download_file() (used by check_revocation for the badge JSON,
            # issuer JSON, and revocation list URLs, all attacker-influenced)
            # raises ValueError for a non-HTTPS URL; treat it the same as the
            # network-error cases above instead of letting it escape uncaught.
            return VerifyInfo(BadgeStatus.SIGNATURE_ERROR, str(e))

        # OK, all is correct.
        return VerifyInfo(BadgeStatus.VALID, 'OK')

    def check_jws_signature(self, badge: Any) -> VerifyInfo:
        # Verify against the operator-supplied trusted key when present, falling
        # back to the key the badge itself points to only when no trusted key
        # was given. Trusting solely badge.source.pub_key (downloaded from a URL
        # inside the untrusted badge) would let an attacker self-sign forgeries.
        verify_key = self.verify_key if self.verify_key is not None else badge.source.pub_key
        try:
            jws_verify_block(badge.assertion.get_assertion(), verify_key)
            return VerifyInfo(BadgeStatus.VALID, 'OK')
        except JWSException as err:
            # Any JWS-layer failure — bad signature, malformed/missing 'alg',
            # missing key, unsupported algorithm — is a clean, untrusted-input
            # driven signature-verification failure, not a library bug.
            return VerifyInfo(BadgeStatus.SIGNATURE_ERROR, str(err))

    def check_revocation(self, badge: Any) -> Optional[str]:
        """ Return the revocation reason if the badge has been revoked, else None """

        serial_num = str(badge.serial_num)
        json_url = badge.source.json_url

        badge_json = download_file(json_url)
        if not badge_json:
            raise AssertionFormatIncorrect('Badge JSON doesn\'t exists %s' % json_url)
        try:
            badge_obj = jws_utils.from_json(badge_json)
        except Exception:
            raise AssertionFormatIncorrect("Badge JSON format incorrect at %s" % json_url)
        if not isinstance(badge_obj, dict):
            raise AssertionFormatIncorrect("Badge JSON at %s is not a JSON object" % json_url)

        issuer_url = badge_obj.get('issuer')
        if not issuer_url:
            raise AssertionFormatIncorrect(
                "Badge JSON at %s has no 'issuer' URL" % json_url)
        issuer_json = download_file(issuer_url)
        if not issuer_json:
            raise AssertionFormatIncorrect("Issuer JSON doesn't exist %s" % issuer_url)
        try:
            issuer = jws_utils.from_json(issuer_json)
        except Exception:
            raise AssertionFormatIncorrect("Issuer JSON format incorrect at %s" % issuer_url)
        if not isinstance(issuer, dict):
            raise AssertionFormatIncorrect("Issuer JSON at %s is not a JSON object" % issuer_url)

        # revocationList is optional in OpenBadges 2.0; its absence means the
        # issuer publishes no revocations, so the badge is simply not revoked.
        revocation_url = issuer.get('revocationList')
        if not revocation_url:
            return None

        revocation_json = download_file(revocation_url)
        if not revocation_json:
            return None
        try:
            revocation = jws_utils.from_json(revocation_json)
        except Exception:
            raise AssertionFormatIncorrect(
                "Revocation list format incorrect at %s" % revocation_url)
        if not isinstance(revocation, dict):
            raise AssertionFormatIncorrect(
                "Revocation list at %s is not a JSON object" % revocation_url)

        if revocation:
            for badge_id in revocation:
                if str(badge_id) == serial_num:
                    return revocation[badge_id]

        return None

    def check_expiration(self, badge: Any) -> Optional[str]:
        from time import time, gmtime, strftime

        # A badge is expired when its expiration timestamp is in the past
        # relative to *now* — not relative to its own issue date.
        try:
            expired = badge.expiration < time()
        except TypeError as exc:
            raise AssertionFormatIncorrect(
                "Badge 'expires' field is not a valid timestamp: %r" % (badge.expiration,)) from exc

        if expired:
            return "%s" % strftime("%a, %d %b %Y %H:%M:%S +0000",
                                   gmtime(badge.expiration))
        else:
            return None

    def check_identity(self, badge: Any) -> bool:
        # No identity supplied means signature-only verification: skip the
        # recipient check instead of crashing on hash_email(None, ...).
        if self.identity is None:
            return True
        try:
            email_salt = badge.salt if badge.salt else b''
            email_hashed = b'sha256$' + hash_email(self.identity, email_salt)

            return email_hashed == badge.identity
        except Exception:
            raise NotIdentityInAssertion('The assertion doesn\'t have an identify ')

    def print_payload(self, badge: Any) -> None:
        print('[+] This is the assertion content:')
        print(json.dumps(badge.assertion.decode_body(), sort_keys=True, indent=4))
