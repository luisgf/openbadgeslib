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

from Crypto.PublicKey import RSA
from ecdsa import SigningKey, VerifyingKey, NIST256p

from urllib import request
from urllib.request import HTTPSHandler
from urllib.parse import urlparse
from ssl import SSLContext, CERT_NONE, VERIFY_CRL_CHECK_CHAIN, PROTOCOL_TLSv1
from xml.dom.minidom import parseString

from urllib.error import HTTPError, URLError
from ssl import SSLError

# Local imports
from .errors import UnknownKeyType, AssertionFormatIncorrect, \
            NotIdentityInAssertion, ErrorParsingFile, PublicKeyReadError

from .jws import utils as jws_utils
from .jws import verify_block as jws_verify_block

from .util import sha256_string

def VerifyFactory(key_type='RSA'):
    """ Verify Factory Object, Return a Given object type passing a name
        to the constructor. """

    if key_type == 'ECC':
       return VerifyECC()
    if key_type == 'RSA':
       return VerifyRSA()
    else:
       raise UnknownKeyType()

""" Signature Verification Factory """
class VerifyBase():
    def __init__(self, receptor=''):
        self.key = None                                         # Crypto Object
        self._receptor = receptor.encode('utf-8')

    def verify_jws_signature(self, assertion, verif_key):
        """ Verify the JWS Signature, Return True if the signature
            block is Good """

        self.show_disclaimer()

        return jws_verify_block(assertion, verif_key)

    def verify_signature_inlocal(self, assertion, receptor):
        """ Verify that a signature is valid and has emitted for a
            given receptor """
        import json

        # Check if the JWS assertion is valid
        #try:
        self.show_key_info(self.key)
        self.verify_jws_signature(assertion, self.key)
        #except:
        #    return False

        # The assertion is signed with our local key. Receptor check...
        head_encoded, payload_encoded, signature_encoded = assertion.split(b'.')

        # Try to decode the payload
        try:
            payload = jws_utils.decode(payload_encoded)
        except:
            raise AssertionFormatIncorrect('Payload deserialization error')

        # Receptor verification
        email_hashed = (b'sha256$' + sha256_string(receptor)).decode('utf-8')
        if email_hashed == payload['recipient']['identity']:
            return True
        else:
            return False

    def verify_signature_inverse(self, assertion, receptor):
        """ Check the assertion against the Key specified in JWS Paload """
        import json
        # The assertion MUST have a string like head.payload.signature
        try:
            head_encoded, payload_encoded, signature_encoded = assertion.split(b'.')
        except:
            raise AssertionFormatIncorrect()

        # Try to decode the payload
        try:
            payload = jws_utils.decode(payload_encoded)
        except:
            raise AssertionFormatIncorrect('Payload deserialization error')

        """ Parse URL to detect that has a correct format and a secure source.
             Warning User otherwise """

        u = urlparse(payload['verify']['url'])

        if u.scheme != 'https':
            print('[!] Warning! The public key is in a server that\'s lacks TLS support.', payload['verify']['url'])
        else:
            print('[+] The public key appears to be in a server with TLS support. Good!', payload['verify']['url'])

        if u.hostname == b'':
            raise AssertionFormatIncorrect('The URL thats point to public key not exists in this assertion')

        # OK, is time to download the pubkey
        pub_key_pem = self.download_pubkey(payload['verify']['url'])

        print('[+] This is the assertion content:')
        print(json.dumps(payload, sort_keys=True, indent=4))

        # Ok, is time to verify the assertion againts the key downloaded.
        vk_external = self.get_crypto_object(pub_key_pem)

        # Show key info of the downloaded key
        self.show_key_info(vk_external)

        try:
            signature_valid = self.verify_jws_signature(assertion, vk_external)
        except:
             return False

        # Ok, the signature is valid, now i check if the badge is emitted for this receptor
        try:
            email_hashed = (b'sha256$' + sha256_string(receptor)).decode('utf-8')
            if email_hashed == payload['recipient']['identity']:
                # OK, the signature is valid and the badge is emitted for this user
                return True
            else:
                return False
        except:
            raise NotIdentityInAssertion('The assertion doesn\'t have an identify ')

    def download_pubkey(self, url):
        """ This function return the Key in pem format from server """

        # SSL Context
        sslctx = SSLContext(PROTOCOL_TLSv1)
        sslctx.verify_mode = CERT_NONE
        sslctx_handler = HTTPSHandler(context=sslctx, check_hostname=False)

        request.install_opener(request.build_opener(sslctx_handler))

        with request.urlopen(url, timeout=30) as kd:
            pub_key_pem = kd.read()

        return pub_key_pem

    def extract_svg_signature(self, svg_data):
        """ Extract the signature embeded in a SVG file. """

        try:
            # Parse de SVG XML
            svg_doc = parseString(svg_data)

            # Extract the assertion
            assertion = svg_doc.getElementsByTagName("openbadges:assertion")
            signature = assertion[0].attributes['verify'].nodeValue.encode('utf-8')

        except:
            raise ErrorParsingFile('Error Parsing SVG file: ')
        finally:
            svg_doc.unlink()
            return signature

    def is_svg_signature_valid(self, svg_data, email='', local_key=None):
        """ This function return True/False if the signature in the
             file is correct or no """

        assertion = self.extract_svg_signature(svg_data)
        receptor = email.encode('utf-8')

        try:
            if local_key:
                self.key = self.load_pubkey_inline(local_key)
                return self.verify_signature_inlocal(assertion, receptor)
            else:
                return self.verify_signature_inverse(assertion, receptor)
        except HTTPError as e:
            print('[!] And error has occurred during PubKey download. HTTP Error: ', e.code, e.reason)
        except URLError as e:
            print('[!] And error has occurred during PubKey download. Reason: ', e.reason)

    def get_crypto_object(self, pem_data):
        """ Crypto Object can be a create with a key that
            i don't know their type yet. I need to guess it """

        try:
            return RSA.importKey(pem_data)
        except:
            pass

        try:
            return VerifyingKey.from_pem(pem_data)
        except:
            pass

        return None

""" RSA Verify Factory """
class VerifyRSA(VerifyBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def load_pubkey_inline(self, pub_key_pem):
        """ Create a crypto object from a pem string """
        return RSA.importKey(pub_key_pem)

    def show_key_info(self, key):
         print('[+] Using an RSA Key of %d bits size' % key.size())

    def show_disclaimer(self):
        pass

class VerifyECC(VerifyBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def load_pubkey_inline(self, pub_key_pem):
        """ Create a crypto object from a pem string """
        return VerifyingKey.from_pem(pub_key_pem)

    def show_key_info(self, key):
        print('[+] Using an ECC Key with a curve type %s' % key.curve.name)

    def show_disclaimer(self):
        print("""DISCLAIMER!

                You are running the program with support for Elliptic
                Curve cryptography.

                The implementation of ECC in JWS Draft is not clear about the
                signature/verification process and may lead to problems for
                you and others when verifying your badges.

                Use at your own risk!

                Expiration and Revocations status of badges are not verified
                by this library version. """)
