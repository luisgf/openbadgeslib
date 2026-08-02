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

from enum import Enum
from typing import Any, Optional, Union, cast

from ..keys import detect_key_type
from ..errors import (BadgeImgFormatUnsupported, AssertionFormatIncorrect,
                      ErrorParsingFile)
from .._jws import utils as jws_utils
from ..util import hash_email, download_file
from .. import baking
# The version-neutral model lives in badge_model now; re-exported here (via
# __all__) so ob1.badge and the openbadgeslib.badge shim keep exposing them.
from ..badge_model import Badge, BadgeImgType

__all__ = [
    'BadgeStatus', 'BadgeImgType', 'BadgeType',
    'Assertion', 'Badge', 'BadgeSigned',
    'extract_svg_assertion', 'extract_png_assertion',
]


class BadgeStatus(Enum):
    VALID = 1
    SIGNATURE_ERROR = 2
    EXPIRED = 3
    REVOKED = 4
    IDENTITY_ERROR = 5
    NONE = 6  # unset sentinel (VerifyInfo default); never returned by a real check


class BadgeType(Enum):
    SIGNED = 0
    HOSTED = 1


class Assertion():
    def __init__(self, header: Optional[bytes] = None, body: Optional[bytes] = None,
                 signature: Optional[bytes] = None) -> None:
        self.header: Any = header          # In Base64
        self.body: Any = body              # In Base64
        self.signature: Any = signature

    @staticmethod
    def decode(data: bytes) -> 'Assertion':
        try:
            header, body, signature = data.split(b'.')
            return Assertion(header, body, signature)
        except Exception:
            raise AssertionFormatIncorrect()

    def decode_header(self) -> Any:
        return jws_utils.decode(self.header)

    def decode_body(self) -> Any:
        return jws_utils.decode(self.body)

    def get_assertion(self) -> bytes:
        return cast(bytes, self.header + b'.' + self.body + b'.' + self.signature)

    def encode_header(self, header: Any) -> None:
        self.header = jws_utils.encode(header)

    def encode_body(self, body: Any) -> None:
        self.body = jws_utils.encode(body)

    def encode_signature(self, signature: bytes) -> None:
        self.signature = jws_utils.to_base64(signature)

    def __str__(self) -> str:
        return 'Header: %s\nBody: %s\nSignature: %s' % (self.header, self.body, self.signature)


class BadgeSigned():
    """ A Signed Badge Object """

    def __init__(self, source: Optional[Badge] = None,
                 serial_num: Optional[Union[str, bytes]] = None,
                 identity: Optional[Union[str, bytes]] = None,
                 evidence: Optional[str] = None, expiration: Optional[int] = None,
                 salt: Optional[Union[str, bytes]] = None,
                 issue_date: Optional[int] = None,
                 assertion: Optional[Assertion] = None) -> None:
        self.source: Any = source                # Badge source object, if exists
        self.signed: Any = None                  # Binary signed data
        self.serial_num: Any = serial_num
        # Normalize identity/salt to bytes so the accessors are type-stable
        # regardless of whether the caller passed str or bytes.
        self.identity: Any = identity.encode('utf-8') if isinstance(identity, str) else identity
        self.evidence = evidence
        self.expiration = expiration             # Timestamp
        self.salt: Any = salt.encode('utf-8') if isinstance(salt, str) else salt
        self.signed_assertion: Any = None        # Signed Assertion
        self.issue_date = issue_date             # Timestamp
        self.assertion = assertion
        self.file_out: Optional[str] = None      # Path to signed file if saved

    @staticmethod
    def read_from_file(file_name: str) -> 'BadgeSigned':
        """ Read a Signed Badge from file """
        with open(file_name, 'rb') as file:
            file_data = file.read()              # Binary Data Signed

        if file_name.lower().endswith('.svg'):
            assertion = extract_svg_assertion(file_data)
        elif file_name.lower().endswith('.png'):
            assertion = extract_png_assertion(file_data)
        else:
            raise BadgeImgFormatUnsupported('The image format for %s is not supported' % file_name)

        try:
            body = assertion.decode_body()
        except (ValueError, TypeError) as exc:
            # decode_body → base64url + UTF-8 + JSON. A crafted token whose
            # payload is valid base64url of non-UTF-8 or non-JSON text raises
            # UnicodeDecodeError / JSONDecodeError / binascii.Error — all
            # ValueError subclasses, not LibOpenBadgesException. Map them so a
            # caller trapping library errors still gets a clean verdict (#281).
            raise AssertionFormatIncorrect(
                'OpenBadge assertion body is not valid base64url JSON: %s'
                % exc) from exc
        if not isinstance(body, dict):
            # The body can decode to any JSON value; a non-object would raise a
            # raw TypeError/AttributeError on the field accesses below, before
            # the guarded construction block further down.
            raise AssertionFormatIncorrect(
                'OpenBadge assertion body is not a JSON object')

        try:
            evidence = body['evidence']
        except KeyError:
            evidence = None

        try:
            expiration = body['expires']
        except KeyError:
            expiration = None

        # Read the verify URL once, before the try block, so a missing or
        # malformed 'verify' object cannot raise a fresh, unwrapped
        # KeyError/TypeError when the except clause below re-references it.
        verify_dict = body.get('verify')
        verify_url = verify_dict.get('url') if isinstance(verify_dict, dict) else None
        if not verify_url:
            raise ErrorParsingFile("OpenBadge assertion body is missing 'verify.url'")

        try:
            pubkey_pem = download_file(verify_url)
            key_type = detect_key_type(pubkey_pem)
        except Exception as exc:
            raise ErrorParsingFile(
                'Unable to verify OpenBadge: the verify key URL %s could not be '
                'fetched (%s)' % (verify_url, exc)) from exc

        try:
            badge = Badge(image_url=body['image'], verify_key_url=verify_url,
                          json_url=body['badge'], key_type=key_type,
                          pubkey_pem=pubkey_pem)

            badge_sig = BadgeSigned(source=badge, serial_num=body['uid'],
                                    identity=body['recipient']['identity'].encode('utf-8'),
                                    evidence=evidence, expiration=expiration,
                                    salt=body['recipient']['salt'].encode('utf-8'),
                                    issue_date=body['issuedOn'],
                                    assertion=assertion)
        except (KeyError, TypeError, AttributeError) as exc:
            raise AssertionFormatIncorrect(
                'OpenBadge assertion is missing or has a malformed field: %s' % exc) from exc
        return badge_sig

    def save_to_file(self, file_name: str) -> None:
        with open(file_name, 'wb') as f:
            f.write(self.signed)
        self.file_out = file_name

    def get_identity(self) -> str:
        return cast(str, self.identity.decode('utf-8'))

    def get_identity_hashed(self) -> str:
        return (b'sha256$' + hash_email(self.identity, self.salt)).decode('utf-8')

    def get_salt(self) -> str:
        return cast(str, self.salt.decode('utf-8'))

    def get_assertion(self) -> Optional[str]:
        if self.assertion:
            if self.assertion.signature:
                return self.assertion.get_assertion().decode('utf-8')
        return None

    def get_serial_num(self) -> str:
        # serial_num is ascii bytes for a freshly-signed badge (sha1_string)
        # but a str/int for one read back from a file (JSON 'uid'); handle both.
        if isinstance(self.serial_num, (bytes, bytearray)):
            return self.serial_num.decode('utf-8')
        return str(self.serial_num)

    def __str__(self) -> str:
        return (
            'Serial Num: %s\nIdentity: %s\nEvidence %s\nExpiration: %s\nSalt: %s\n'
            % (self.serial_num, self.identity, self.evidence, self.expiration, self.salt)
        )

    def get_signkey_pem(self) -> Union[str, bytes]:
        """ Return the public key pem used to sign the openbadge """

        return cast(Union[str, bytes], self.source.pubkey_pem)


def extract_svg_assertion(file_data: bytes) -> Assertion:
    """ Extract the assertion embeded in a SVG file. """

    try:
        token = baking.extract_svg(file_data)
    except Exception as err:
        raise ErrorParsingFile('Error parsing SVG file: %s' % err) from err
    if token is None:
        raise ErrorParsingFile('No OpenBadges assertion found in SVG file')
    return Assertion.decode(token.encode('utf-8'))


def extract_png_assertion(file_data: bytes) -> Assertion:
    try:
        token = baking.extract_png(file_data)
    except Exception as err:
        raise ErrorParsingFile('Error parsing PNG file: %s' % err) from err
    if token is None:
        raise AssertionFormatIncorrect('No OpenBadges assertion found in PNG file')
    return Assertion.decode(token.encode('utf-8'))
