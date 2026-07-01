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

import os
from enum import Enum
from typing import Any, Optional, Union

from Crypto.PublicKey import RSA
from ecdsa import SigningKey, VerifyingKey

from ..keys import KeyType, detect_key_type
from ..errors import (BadgeImgFormatUnsupported, AssertionFormatIncorrect,
                      ErrorParsingFile, UnknownKeyType, PrivateKeyReadError,
                      PublicKeyReadError)
from .._jws import utils as jws_utils
from ..util import hash_email, download_file
from .. import baking


class BadgeStatus(Enum):
    VALID = 1
    SIGNATURE_ERROR = 2
    EXPIRED = 3
    REVOKED = 4
    IDENTITY_ERROR = 5
    NONE = 6  # unset sentinel (VerifyInfo default); never returned by a real check


class BadgeImgType(Enum):
    SVG = 0
    PNG = 1


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
        return self.header + b'.' + self.body + b'.' + self.signature

    def encode_header(self, header: Any) -> None:
        self.header = jws_utils.encode(header)

    def encode_body(self, body: Any) -> None:
        self.body = jws_utils.encode(body)

    def encode_signature(self, signature: bytes) -> None:
        self.signature = jws_utils.to_base64(signature)

    def __str__(self) -> str:
        return 'Header: %s\nBody: %s\nSignature: %s' % (self.header, self.body, self.signature)


class Badge():
    def __init__(self, ini_name: Optional[str] = None, name: Optional[str] = None,
                 description: Optional[str] = None, image_type: Optional[BadgeImgType] = None,
                 image: Optional[bytes] = None, image_url: Optional[str] = None,
                 criteria_url: Optional[str] = None, json_url: Optional[str] = None,
                 verify_key_url: Optional[str] = None, key_type: Optional[KeyType] = None,
                 privkey_pem: Optional[Union[str, bytes]] = None,
                 pubkey_pem: Optional[Union[str, bytes]] = None) -> None:

        self.ini_name = ini_name
        self.name = name
        self.description = description
        self.image_type = image_type
        self.image = image                  # Binary contents of image file
        self.image_url = image_url
        self.criteria_url = criteria_url
        self.json_url = json_url
        self.verify_key_url = verify_key_url
        self.key_type = key_type
        self.privkey_pem = privkey_pem
        self.pubkey_pem = pubkey_pem

        # Initialize an Key Object
        if self.key_type is KeyType.RSA:
            if self.pubkey_pem:
                try:
                    self.pub_key = RSA.import_key(self.pubkey_pem)
                except Exception as exc:
                    raise PublicKeyReadError('Unable to read RSA public key: %s' % exc) from exc
            if self.privkey_pem:
                try:
                    self.priv_key = RSA.import_key(self.privkey_pem)
                except Exception as exc:
                    raise PrivateKeyReadError('Unable to read RSA private key: %s' % exc) from exc
        elif self.key_type is KeyType.ECC:
            if self.pubkey_pem:
                try:
                    self.pub_key = VerifyingKey.from_pem(self.pubkey_pem)
                except Exception as exc:
                    raise PublicKeyReadError('Unable to read ECC public key: %s' % exc) from exc
            if self.privkey_pem:
                try:
                    self.priv_key = SigningKey.from_pem(self.privkey_pem)
                except Exception as exc:
                    raise PrivateKeyReadError('Unable to read ECC private key: %s' % exc) from exc
        elif self.key_type is not None:
            # key_type=None is a valid "no key material yet" state; any other
            # value is an unsupported key type and must fail loudly.
            raise UnknownKeyType('Unsupported key type: %r' % (self.key_type,))

    @staticmethod
    def create_from_conf(conf: Any, badge: str) -> 'Badge':
        """ Create a Badge Object reading params from config.ini """

        """ Keys """
        with open(conf[badge]['private_key'], 'rb') as key:
            privkey_pem = key.read()

        with open(conf[badge]['public_key'], 'rb') as key:
            pubkey_pem = key.read()

        key_type = detect_key_type(pubkey_pem)

        """ Image """
        img_path = os.path.join(conf['paths']['base_image'], conf[badge]['local_image'])

        if not os.path.isfile(img_path):
            print('Badge file %s NOT exists.' % img_path)
            raise IOError

        with open(img_path, 'rb') as file:
            img_content = file.read()

        if img_path.lower().endswith('.svg'):
            img_type = BadgeImgType.SVG
        elif img_path.lower().endswith('.png'):
            img_type = BadgeImgType.PNG
        else:
            raise BadgeImgFormatUnsupported('The image format for %s is not supported' % badge)

        """ Object Creation """
        return Badge(ini_name=badge,
                     name=conf[badge]['name'],
                     description=conf[badge]['description'],
                     image_type=img_type,
                     image=img_content,
                     image_url=conf[badge]['image'],
                     criteria_url=conf[badge]['criteria'],
                     json_url=conf[badge]['badge'],
                     verify_key_url=conf[badge]['verify_key'],
                     key_type=key_type,
                     privkey_pem=privkey_pem,
                     pubkey_pem=pubkey_pem)

        return None

    def __str__(self) -> str:
        return (
            'INI Name: %s\nName: %s\nDescription: %s\nImage Type: %s\n'
            'Image Url: %s\nKey Type: %s\nVerify Key: %s\nJSON Url: %s\n'
            % (self.ini_name, self.name, self.description, self.image_type,
               self.image_url, self.key_type, self.verify_key_url, self.json_url)
        )

    def urls_has_problems(self) -> bool:
        """ Check if urls in Badge are corrects and online """

        error = False
        checks = [
            (self.image_url, 'OpenBadge Image'),
            (self.criteria_url, 'OpenBadge Criteria'),
            (self.json_url, 'OpenBadge JSon'),
            (self.verify_key_url, 'OpenBadge Verify key'),
        ]

        # 'data' is reset for every URL so a previous success can never mask a
        # later download failure.
        for url, label in checks:
            data = None
            try:
                data = download_file(url) if url else None
            except Exception:
                pass
            if not data:
                print('[!] %s at config file is pointing to a wrong url: %s' % (label, url))
                error = True

        return error


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

        body = assertion.decode_body()

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
        return self.identity.decode('utf-8')

    def get_identity_hashed(self) -> str:
        return (b'sha256$' + hash_email(self.identity, self.salt)).decode('utf-8')

    def get_salt(self) -> str:
        return self.salt.decode('utf-8')

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

        return self.source.pubkey_pem


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
