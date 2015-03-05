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

from .confparser import ConfParser
from .keys import KeyType, detect_key_type
from .errors import BadgeImgFormatUnsupported
from .jws import utils as jws_utils
from .util import hash_email

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
            self.pub_key = RSA.importKey(self.pubkey_pem)
            self.priv_key = RSA.importKey(self.privkey_pem)
        elif self.key_type is KeyType.ECC:
            self.pub_key = VerifyingKey.from_pem(self.pubkey_pem)
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
                sys.exit(-1)

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
                 evidence=None, expiration=None, salt=None):
        self.source = source                     # Badge source object, if exists
        self.signed = None                       # Binary signed data
        self.serial_num = serial_num
        self.identity = identity
        self.evidence = evidence
        self.expiration = expiration
        self.salt = salt
        self.signed_assertion = None           # Signed Assertion
        """ This should be methods """
        self.jws_header = None
        self.jws_body = None
        self.jws_signature = None

    @staticmethod
    def read_from_file(file_name, file_type):
        """ Read a Signed Badge from file """
        pass

    def save_to_file(self, file_name):
         with open(file_name, 'wb') as f:
                f.write(self.signed)

    def get_identity(self):
        return self.identity.decode('utf-8')

    def get_identity_hashed(self):
        return (b'sha256$' + hash_email(self.identity, self.salt)).decode('utf-8')

    def get_salt(self):
        return self.salt.decode('utf-8')

    def get_assertion(self):
        return (jws_utils.encode(self.jws_header) + b'.' + jws_utils.encode(self.jws_body) + b'.' + jws_utils.to_base64(self.jws_signature)).decode('utf-8')

    def get_serial_num(self):
        return self.serial_num.decode('utf-8')

if __name__ == '__main__':
    pass






