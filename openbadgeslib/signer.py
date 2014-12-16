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

import logging
logger = logging.getLogger(__name__)

import os
import sys
import time
import json
import os

from datetime import datetime
from xml.dom.minidom import parse, parseString

from .errors import UnknownKeyType, FileToSignNotExists, BadgeSignedFileExists, ErrorSigningFile, PrivateKeyReadError

from .util import hash_email, md5_string, sha1_string, sha256_string
from .keys import KeyFactory
from .verifier import VerifyFactory

from .jws import utils as jws_utils
from .jws import sign as jws_sign

def SignerFactory(key_type='RSA', *args, **kwargs):
    """ Signer Factory Object, Return a Given object type passing a name
        to the constructor. """

    if key_type == 'ECC':
        return SignerECC(*args, **kwargs)
    if key_type == 'RSA':
        return SignerRSA(*args, **kwargs)
    else:
        raise UnknownKeyType()

class SignerBase():
    """ JWS Signer Factory """

    def __init__(self, issuer='', badge_name='', badge_file_path=None, badge_image_url=None, badge_json_url=None, receptor='', evidence=None, verify_key_url=None, deterministic=False):
        self.issuer = issuer.encode('utf-8')
        self.badge_name = badge_name.encode('utf-8')
        self.badge_file_path = badge_file_path       # Path to local file
        self.badge_image_url = badge_image_url
        self.badge_json_url = badge_json_url
        self.receptor = receptor.encode('utf-8')     # Receptor of the badge
        self.evidence = evidence                     # Url to evidence
        self.verify_key_url = verify_key_url
        self.deterministic = deterministic           # Randomness

    def generate_uid(self):
        return sha1_string(self.issuer + self.badge_name + self.receptor + datetime.now().isoformat().encode('utf-8'))

    def generate_jws_payload(self):

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
                        uid = 0 if self.deterministic else self.generate_uid().decode('utf-8'),
                        recipient = recipient_data,
                        image = self.badge_image_url,
                        badge = self.badge_json_url,
                        verify = verify_data,
                        issuedOn = 0 if self.deterministic else int(time.time())
                     )

        if self.evidence:
            payload['evidence'] = self.evidence

        logger.debug('JWS Payload %s ' % json.dumps(payload))

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

        """ Log the signing process before returning it.
                That's prevents the existence of a signed badge without traces """

        logger.info('"%s" SIGNED successfully for receptor "%s"' % (self.badge_name, self.receptor.decode('utf-8')))

        svg_signed = svg_doc.toxml()
        svg_doc.unlink()

        return svg_signed

    def generate_output_filename(self, file_in, output_dir, receptor):
        """ Generate an output filename based on the source
            name and the receptor email """

        fbase = os.path.basename(file_in)
        fname, fext = os.path.splitext(fbase)
        fsuffix = receptor.replace('@','_').replace('.','_')

        return output_dir + fname + '_'+ fsuffix + fext

    def generate_openbadge_assertion(self, priv_key_pem, pub_key_pem):
        """ Generate and Sign and OpenBadge assertion """

        header = self.generate_jose_header()
        payload = self.generate_jws_payload()

        self.key.read_private_key(priv_key_pem)
        self.key.read_public_key(pub_key_pem)

        signature = jws_sign(header, payload, self.key.get_priv_key())
        assertion = jws_utils.encode(header) + b'.' + jws_utils.encode(payload) + b'.' + jws_utils.to_base64(signature)

        # Verify the assertion just after the generation.
        vf = VerifyFactory()
        vf.load_pubkey_inline(self.key.get_pub_key_pem())

        if not vf.verify_jws_signature(assertion, self.key.get_pub_key()):
            return None
        else:
            logger.debug('Assertion %s' % assertion)
            return assertion

    def has_assertion(self, xml_obj):
        if xml_obj.getElementsByTagName('openbadges:assertion'):
            return True
        else:
            return False

class SignerRSA(SignerBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = KeyFactory('RSA')

    def generate_jose_header(self):
        jose_header = { 'alg': 'RS256' }

        logger.debug('JOSE HEADER %s ' % json.dumps(jose_header))
        return jose_header

class SignerECC(SignerBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = KeyFactory('ECC')

    def generate_jose_header(self):
        jose_header = { 'alg': 'ES256' }

        logger.debug('JOSE HEADER %s ' % json.dumps(jose_header))
        return jose_header


