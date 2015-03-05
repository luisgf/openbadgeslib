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

import os, os.path
import sys
import time
import json

from struct import pack
from datetime import datetime
from xml.dom.minidom import parse, parseString
from zlib import crc32

from png import Reader, write_chunks, _signature

from .errors import UnknownKeyType, FileToSignNotExists, BadgeSignedFileExists, ErrorSigningFile, PrivateKeyReadError
from .util import md5_string, sha1_string, sha256_string, __version__
from .keys import KeyFactory, KeyType
from .badge import BadgeSigned, BadgeType, BadgeImgType


from .jws import sign as jws_sign

class Signer():
    def __init__(self, identity=None, evidence=None, expiration=None,
                 deterministic=False, badge_type=None):
        self.identity = identity.encode('utf-8')
        self.evidence = evidence
        self.expiration = expiration
        self.badge_type = badge_type
        self.deterministic = deterministic

    def generate_uid(self):
        return sha1_string(self.identity + datetime.now().isoformat().encode('utf-8'))

    def sign_badge(self, badge_obj):
        if (self.has_assertion(badge_obj)):
            raise ErrorSigningFile('The input file is already signed.')

        serial_num = self.generate_uid()
        salt = b's4lt3d' if self.deterministic else md5_string(os.urandom(128))

        out = BadgeSigned(source=badge_obj, serial_num=serial_num,
                          identity=self.identity, evidence=self.evidence,
                          expiration=self.expiration, salt=salt)

        self.generate_assertion(out)

        if badge_obj.image_type is BadgeImgType.SVG:
            self.append_svg_assertion(out)
        elif badge_obj.image_type is BadgeImgType.PNG:
            self.append_png_assertion(out)

        return out

    def generate_jws(self, badge):
        """ Generate the JWS Payload using an BadgeSigned Object as input """

        if badge.source.key_type is KeyType.RSA:
            jose_header = { 'alg': 'RS256' }
        elif badge.source.key_type is KeyType.ECC:
            jose_header = { 'alg': 'ES256' }

        # All this data MUST be a Str string in order to be converted to json properly.
        recipient_data = dict (
            identity = badge.get_identity_hashed(),
            type = 'email',
            salt = badge.get_salt(),
            hashed = 'true'
        )

        if self.badge_type is BadgeType.SIGNED:
            verify_data = dict(
                type = 'signed',
                url = badge.source.verify_key_url
            )

        payload = dict(
                        uid = 0 if self.deterministic else badge.get_serial_num(),
                        recipient = recipient_data,
                        image = badge.source.image_url,
                        badge = badge.source.json_url,
                        verify = verify_data,
                        issuedOn = 0 if self.deterministic else int(time.time())
                     )

        if badge.expiration:
            payload['expires'] = badge.expiration

        if badge.evidence:
            payload['evidence'] = badge.evidence

        return jose_header, payload

    def generate_assertion(self, badge):
        """ Generate and Sign and OpenBadge assertion """

        badge.jws_header, badge.jws_body = self.generate_jws(badge)
        badge.jws_signature = jws_sign(badge.jws_header, badge.jws_body, badge.source.priv_key)

        return badge.get_assertion()

    def has_assertion(self, badge):
        """ Detect if a Badge is already signed """

        if badge.image_type is BadgeImgType.SVG:
            return self.has_svg_assertion(badge)
        elif badge.image_type is BadgeImgType.PNG:
            return self.has_png_assertion(badge)


    def append_svg_assertion(self, badge):
        """ Append the assertion to a SVG File """

        svg_doc = parseString(badge.source.image)

        # Assertion
        svg_tag = svg_doc.getElementsByTagName('svg').item(0)
        assertion_tag = svg_doc.createElement("openbadges:assertion")
        assertion_tag.attributes['xmlns:openbadges'] = 'http://openbadges.org'
        assertion_tag.attributes['verify']= badge.get_assertion()
        svg_tag.appendChild(assertion_tag)
        svg_tag.appendChild(svg_doc.createComment(' Signed with OpenBadgesLib %s ' % __version__))

        badge.signed = svg_doc.toxml().encode('utf-8')
        svg_doc.unlink()

    def append_png_assertion(self, badge):
        """ Append the assertion to a PNG file """

        badge.signed = _signature

        chunks = list()
        png = Reader(bytes=badge.source.image)

        for chunk in png.chunks():
            chunks.append(chunk)

        itxt_data = b'openbadges' + pack('BBBBB',0,0,0,0,0) + badge.get_assertion().encode('utf-8')
        itxt = ('iTXt', itxt_data)
        chunks.insert(len(chunks)-1,itxt)

        text_data = 'Comment Signed with OpenBadgesLib %s' % __version__
        text = ('tEXt', text_data.encode('utf-8'))
        chunks.insert(len(chunks)-1,text)

        for tag, data in chunks:
            badge.signed = badge.signed + pack("!I", len(data))
            tag = tag.encode('iso8859-1')
            badge.signed = badge.signed + tag
            badge.signed = badge.signed + data
            checksum = crc32(tag)
            checksum = crc32(data, checksum)
            checksum &= 2**32-1
            badge.signed = badge.signed + pack("!I", checksum)

    def has_svg_assertion(self, badge):
        xml_doc = parseString(badge.image)
        has_assertion = False

        if xml_doc.getElementsByTagName('openbadges:assertion'):
            has_assertion = True

        xml_doc.unlink()
        return has_assertion

    def has_png_assertion(self, badge):
        return False

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
        svg_tag.appendChild(svg_doc.createComment(' Signed with OpenBadgesLib %s ' % __version__))

        svg_signed = svg_doc.toxml()
        svg_doc.unlink()

        return svg_signed

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



