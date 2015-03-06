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
from .badge import BadgeSigned, BadgeType, BadgeImgType, Assertion


from .jws import sign as jws_sign

class Signer():
    def __init__(self, identity=None, evidence=None, expiration=None,
                 deterministic=False, badge_type=None):
        self.identity = identity
        self.evidence = evidence
        self.expiration = expiration
        self.badge_type = badge_type
        self.deterministic = deterministic

    def generate_uid(self):
        return sha1_string(os.urandom(128))

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

        header, body = self.generate_jws(badge)
        signature = jws_sign(header, body, badge.source.priv_key)

        badge.assertion = Assertion()
        badge.assertion.encode_header(header)
        badge.assertion.encode_body(body)
        badge.assertion.encode_signature(signature)

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
        png = Reader(bytes=badge.image)

        for tag, data in png.chunks():
            if tag == 'iTXt':
                if data.startswith(b'openbadges'):
                    return True

        return False


