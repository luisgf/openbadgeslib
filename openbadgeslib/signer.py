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

import os, os.path
import sys
import time
import json

from datetime import datetime
from xml.dom.minidom import parse, parseString

from .errors import UnknownKeyType, FileToSignNotExists, BadgeSignedFileExists, ErrorSigningFile, PrivateKeyReadError

from .util import hash_email, md5_string, sha1_string, sha256_string
from .keys import KeyFactory, KeyType

from .jws import utils as jws_utils
from .jws import sign as jws_sign

def SignerFactory(key_type=KeyType.RSA, *args, **kwargs):
    """ Signer Factory Object, Return a Given object type passing a name
        to the constructor. """

    if key_type == KeyType.ECC:
        return SignerECC(*args, **kwargs)
    if key_type == KeyType.RSA:
        return SignerRSA(*args, **kwargs)
    else:
        raise UnknownKeyType()

class SignerBase():
    """ JWS Signer Factory """

    def __init__(self, badge_name='',
                 image_url=None, json_url=None, identity='',
                 evidence=None, verify_key=None, deterministic=False,
                 expires=None, sign_key=None):
        self.badge_name = badge_name.encode('utf-8')
        self.badge_image_url = image_url
        self.badge_json_url = json_url
        self.receptor = identity.encode('utf-8')     # Receptor of the badge
        self.evidence = evidence                     # URL to evidence
        self.verify_key_url = verify_key
        self.deterministic = deterministic           # Randomness
        self.expires = expires
        self.sign_key = sign_key

    def generate_uid(self):
        self.uid = sha1_string(self.badge_name + self.receptor + datetime.now().isoformat().encode('utf-8'))
        return self.uid

    def get_uid(self):
        return self.uid.decode('utf-8')

    def generate_jws_payload(self):
        self.generate_uid()

        mail_salt = b's4lt3d' if self.deterministic else md5_string(os.urandom(128))
        # All this data MUST be a Str string in order to be converted to json properly.
        recipient_data = dict (
            identity = (b'sha256$' + hash_email(self.receptor, mail_salt)).decode('utf-8'),
            type = 'email',
            salt = mail_salt.decode('utf-8'),
            hashed = 'true'
        )

        verify_data = dict(
            type = 'signed',
            url = self.verify_key_url
        )

        payload = dict(
                        uid = 0 if self.deterministic else self.get_uid(),
                        recipient = recipient_data,
                        image = self.badge_image_url,
                        badge = self.badge_json_url,
                        verify = verify_data,
                        issuedOn = 0 if self.deterministic else int(time.time())
                     )

        if self.expires:
            payload['expires'] = self.expires

        if self.evidence:
            payload['evidence'] = self.evidence

        #self.log.console.debug('JWS Payload %s ' % json.dumps(payload))

        return payload

    def sign_svg(self, svg_in, assertion):
        svg_doc = parseString(svg_in)

        if (self.has_assertion(svg_doc)):
            raise ErrorSigningFile('The input SVG file is already signed.')

        # Assertion
        svg_tag = svg_doc.getElementsByTagName('svg').item(0)
        assertion_tag = svg_doc.createElement("openbadges:assertion")
        assertion_tag.attributes['xmlns:openbadges'] = 'http://openbadges.org'
        assertion_tag.attributes['verify']= assertion.decode('utf-8')
        svg_tag.appendChild(assertion_tag)

        svg_signed = svg_doc.toxml()
        svg_doc.unlink()

        return svg_signed

    def generate_output_filename(self, file_in, output_dir):
        """ Generate an output filename based on the source
            name and the receptor email """

        fbase = os.path.basename(file_in)
        fname, fext = os.path.splitext(fbase)
        #fsuffix = receptor.replace('@','_').replace('.','_')
        fsuffix = self.receptor.decode('utf-8')

        return os.path.join(output_dir, fname + '-'+ fsuffix + fext)

    def generate_openbadge_assertion(self):
        """ Generate and Sign and OpenBadge assertion """

        header = self.generate_jose_header()
        payload = self.generate_jws_payload()

        self.key.read_private_key(self.sign_key)

        signature = jws_sign(header, payload, self.key.get_priv_key())
        assertion = jws_utils.encode(header) + b'.' + jws_utils.encode(payload) + b'.' + jws_utils.to_base64(signature)

        return assertion

    def has_assertion(self, xml_obj):
        if xml_obj.getElementsByTagName('openbadges:assertion'):
            return True
        else:
            return False

class SignerRSA(SignerBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key_type = KeyType.RSA
        self.key = KeyFactory(KeyType.RSA)

    def generate_jose_header(self):
        jose_header = { 'alg': 'RS256' }

        #self.log.console.debug('JOSE HEADER %s ' % json.dumps(jose_header))
        return jose_header

class SignerECC(SignerBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key_type = KeyType.ECC
        self.key = KeyFactory(KeyType.ECC)

    def generate_jose_header(self):
        jose_header = { 'alg': 'ES256' }

        #self.log.console.debug('JOSE HEADER %s ' % json.dumps(jose_header))
        return jose_header


