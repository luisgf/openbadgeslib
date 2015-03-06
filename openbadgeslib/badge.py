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

import os, sys
from enum import Enum

from Crypto.PublicKey import RSA
from ecdsa import SigningKey, VerifyingKey, NIST256p
from xml.dom.minidom import parseString
from png import Reader
from struct import unpack

from .confparser import ConfParser
from .keys import KeyType, detect_key_type
from .errors import BadgeImgFormatUnsupported, AssertionFormatIncorrect
from .jws import utils as jws_utils
from .util import hash_email, download_file

class BadgeStatus(Enum):
    VALID = 1
    SIGNATURE_ERROR = 2
    EXPIRED = 3
    REVOKED = 4
    IDENTITY_ERROR = 5
    NONE = 6

class BadgeImgType(Enum):
    SVG = 0
    PNG = 1

class BadgeType(Enum):
    SIGNED = 0
    HOSTED = 1

class Assertion():
    def __init__(self, header=None, body=None, signature=None):
        self.header = header               # In Base64
        self.body = body                   # In Base64
        self.signature = signature

    @staticmethod
    def decode(data):
        try:
            header, body, signature = data.split(b'.')
            return Assertion(header, body, signature)
        except:
            raise AssertionFormatIncorrect()

    def decode_header(self):
        return jws_utils.decode(self.header)

    def decode_body(self):
        return jws_utils.decode(self.body)

    def get_assertion(self):
        return self.header + b'.' + self.body + b'.' + self.signature

    def encode_header(self, header):
        self.header = jws_utils.encode(header)

    def encode_body(self, body):
        self.body = jws_utils.encode(body)

    def encode_signature(self, signature):
        self.signature = jws_utils.to_base64(signature)

    def __str__(self):
        return 'Header: %s\nBody: %s\nSignature: %s' % (self.header, self.body, self.signature)

class Badge():
    def __init__(self, ini_name=None, name=None, description=None, image_type=None,
                 image=None, image_url=None, criteria_url=None, json_url=None,
                 verify_key_url=None, key_type=None, privkey_pem=None,
                 pubkey_pem=None):

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
                self.pub_key = RSA.importKey(self.pubkey_pem)
            if self.privkey_pem:
                self.priv_key = RSA.importKey(self.privkey_pem)
        elif self.key_type is KeyType.ECC:
            if self.pubkey_pem:
                self.pub_key = VerifyingKey.from_pem(self.pubkey_pem)
            if self.privkey_pem:
                self.priv_key = SigningKey.from_pem(self.privkey_pem)

    @staticmethod
    def create_from_conf(conf, badge):
        """ Create a Badge Object reading params from config.ini """

        if conf[badge]:

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


    def __str__(self):
        return 'INI Name: %s\nName: %s\nDescription: %s\nImage Type: %s\nImage Url: %s\nKey Type: %s\nVerify Key: %s\nJSON Url: %s\n' % (self.ini_name, self.name, self.description, self.image_type, self.image_url, self.key_type, self.verify_key_url, self.json_url)


class BadgeSigned():
    """ A Signed Badge Object """

    def __init__(self, source=None, serial_num=None, identity=None,
                 evidence=None, expiration=None, salt=None, issue_date=None,
                 assertion=None):
        self.source = source                     # Badge source object, if exists
        self.signed = None                       # Binary signed data
        self.serial_num = serial_num
        self.identity = identity
        self.evidence = evidence
        self.expiration = expiration             # Timestamp
        self.salt = salt
        self.signed_assertion = None             # Signed Assertion
        self.issue_date = issue_date             # Timestamp
        self.assertion = assertion
        self.file_out = None                     # Path to signed file if saved

    @staticmethod
    def read_from_file(file_name):
        """ Read a Signed Badge from file """
        with open(file_name, 'rb') as file:
            file_data = file.read()              # Binary Data Signed

        if file_name.lower().endswith('.svg'):
            img_type = BadgeImgType.SVG
            assertion = extract_svg_assertion(file_data)
        elif file_name.lower().endswith('.png'):
            img_type = BadgeImgType.PNG
            assertion = extract_png_assertion(file_data)
        else:
            raise BadgeImgFormatUnsupported('The image format for %s is not supported' % badge)

        body = assertion.decode_body()

        try:
            evidence=body['evidence']
        except KeyError:
            evidence=None

        try:
            expiration=body['expires']
        except KeyError:
            expiration=None

        # TODO: Download from internet the files associated
        pubkey_pem = download_file(body['verify']['url'])
        key_type = detect_key_type(pubkey_pem)

        badge = Badge(image_url=body['image'], verify_key_url=body['verify']['url'],
                      json_url=body['badge'], key_type=key_type,
                      pubkey_pem=pubkey_pem)

        badge_sig = BadgeSigned(source=badge, serial_num=body['uid'],
                                identity=body['recipient']['identity'].encode('utf-8'),
                                evidence=evidence, expiration=expiration,
                                salt=body['recipient']['salt'].encode('utf-8'),
                                issue_date=body['issuedOn'],
                                assertion=assertion)
        return badge_sig

    def save_to_file(self, file_name):
         with open(file_name, 'wb') as f:
                f.write(self.signed)
         self.file_out = file_name

    def get_identity(self):
        return self.identity.decode('utf-8')

    def get_identity_hashed(self):
        return (b'sha256$' + hash_email(self.identity, self.salt)).decode('utf-8')

    def get_salt(self):
        return self.salt.decode('utf-8')

    def get_assertion(self):
        if self.assertion:
            if self.assertion.signature:
                return self.assertion.get_assertion().decode('utf-8')

    def get_serial_num(self):
        return self.serial_num.decode('utf-8')

    def __str__(self):
        return 'Serial Num: %s\nIdentity: %s\nEvidence %s\nExpiration: %s\nSalt: %s\n' % (self.serial_num, self.identity, self.evidence, self.expiration, self.salt)

def extract_svg_assertion(file_data):
    """ Extract the assertion embeded in a SVG file. """

    try:
        # Parse de SVG XML
        svg_doc = parseString(file_data)

        # Extract the assertion
        xml_node = svg_doc.getElementsByTagName("openbadges:assertion")
        return Assertion.decode(xml_node[0].attributes['verify'].nodeValue.encode('utf-8'))
    except:
        raise ErrorParsingFile('Error Parsing SVG file: ')
    finally:
        svg_doc.unlink()

def extract_png_assertion(file_data):
    png = Reader(bytes=file_data)

    for tag, data in png.chunks():
        if tag == 'iTXt':
            fmt_len = len(data)-15        # 15=len('openbadges'+pack('BBBBB'))
            fmt = '<10s5B%ds' % fmt_len
            return Assertion.decode(unpack(fmt, data)[6])

if __name__ == '__main__':
    pass






