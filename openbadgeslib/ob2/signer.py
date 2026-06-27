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
import os.path
import time

from ..errors import ErrorSigningFile, BadgeImgFormatUnsupported
from ..util import md5_string, sha1_string, __version__
from ..keys import alg_for_key_type
from .badge import BadgeSigned, BadgeType, BadgeImgType, Assertion
from .. import baking

from .._jws import sign as jws_sign


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
        else:
            raise BadgeImgFormatUnsupported(
                'Unsupported image type: %r' % (badge_obj.image_type,))

        return out

    def generate_jws(self, badge):
        """ Generate the JWS Payload using an BadgeSigned Object as input """

        jose_header = {'alg': alg_for_key_type(badge.source.key_type)}

        # All this data MUST be a Str string in order to be converted to json properly.
        recipient_data = dict(
            identity=badge.get_identity_hashed(),
            type='email',
            salt=badge.get_salt(),
            hashed='true'
        )

        if self.badge_type is BadgeType.HOSTED:
            verify_data = dict(
                type='hosted',
                url=badge.source.json_url
            )
        else:
            # Default to a signed assertion (BadgeType.SIGNED or unset).
            verify_data = dict(
                type='signed',
                url=badge.source.verify_key_url
            )

        payload = dict(
            uid=0 if self.deterministic else badge.get_serial_num(),
            recipient=recipient_data,
            image=badge.source.image_url,
            badge=badge.source.json_url,
            verify=verify_data,
            issuedOn=0 if self.deterministic else int(time.time())
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
        else:
            raise BadgeImgFormatUnsupported(
                'Unsupported image type: %r' % (badge.image_type,))

    def append_svg_assertion(self, badge):
        """ Append the assertion to a SVG File """
        badge.signed = baking.bake_svg(
            badge.source.image, badge.get_assertion(),
            comment=' Signed with OpenBadgesLib %s ' % __version__)

    def append_png_assertion(self, badge):
        """ Append the assertion to a PNG file """
        badge.signed = baking.bake_png(
            badge.source.image, badge.get_assertion(),
            text_comment='Comment Signed with OpenBadgesLib %s' % __version__)

    def has_svg_assertion(self, badge):
        return baking.has_svg(badge.image)

    def has_png_assertion(self, badge):
        return baking.has_png(badge.image)
