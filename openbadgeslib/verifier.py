#!/usr/bin/env python3
"""
        OpenBadges Library

        Copyright (c) 2014, Luis Gonzalez Fernandez, All rights reserved.

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
"""   
    Verifier Module
    
    Author:   Luis G.F <luisgf@luisgf.es>
    Date:     20141201
    Version:  0.1

"""
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
from openbadgeslib.errors import UnknownKeyType, AssertionFormatIncorrect, NotIdentityInAssertion, ErrorParsingFile, PublicKeyReadError

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "./3dparty/")))
import jws.utils
from openbadgeslib.util import sha256_string

class VerifyFactory():
    """ Verify Factory Object, Return a Given object type passing a name
        to the constructor. """
        
    def __new__(cls, conf):
        if conf['keys']['crypto'] == 'ECC':
            return VerifyECC(conf)
        if conf['keys']['crypto'] == 'RSA':
            return VerifyRSA(conf)
        else:
            raise UnknownKeyType()        

""" Signature Verification Factory """
class VerifyBase():
    """ JWS Signature Verifier Factory """
    
    def __init__(self, conf):
        self.conf = conf                              # Access to config.py values  
        self.vk = None                                # Crypto Object
         
    def verify_jws_signature(self, assertion, verif_key):
        """ Verify the JWS Signature, Return True if the signature block is Good """
        
        self.show_disclaimer()
        
        return jws.verify_block(assertion, verif_key)                               
    
    def verify_signature_inlocal(self, assertion, receptor):
        """ Verify that a signature is valid and has emitted for a given receptor """
        import json
        
        # Check if the JWS assertion is valid
        try:
            self.show_key_info(self.vk)
            self.verify_jws_signature(assertion, self.vk) 
        except:  
            return False
        
        # Here the assertion is signed against our local key. Receptor check...
        
        # The assertion MUST have a string like head.payload.signature         
        try:
            head_encoded, payload_encoded, signature_encoded = assertion.split(b'.')
        except:
            raise AssertionFormatIncorrect()
         
        # Try to decode the payload
        try:
            payload = jws.utils.decode(payload_encoded)
        except:
            raise AssertionFormatIncorrect('Payload deserialization error')
        
        # Receptor verification
        email_hashed = (b'sha256$' + sha256_string(receptor)).decode('utf-8')
        if email_hashed == payload['recipient']['identity']:
            # OK, the badge has been emitted for this user
            return True
        else:
            return False
                        
    def verify_signature_inverse(self, assertion, receptor):
         """ Check the assertion signature With the Key specified in JWS Paload """
         import json
         # The assertion MUST have a string like head.payload.signature         
         try:
            head_encoded, payload_encoded, signature_encoded = assertion.split(b'.')
         except:
             raise AssertionFormatIncorrect()
         
         # Try to decode the payload
         try:
             payload = jws.utils.decode(payload_encoded)
         except:
             raise AssertionFormatIncorrect('Payload deserialization error')
         
         """ Parse URL to detect that has a correct format and a secure source.
             Warning User otherwise """
            
         u = urlparse(payload['verify']['url'])
         
         if u.scheme != 'https':
             print('[!] Warning! The public key is in a server that\'s lacks TLS support.', payload['verify']['url'])
         else:
             print('[+] The public key is in a server with TLS support. Good!', payload['verify']['url'])
             
         if u.hostname == b'':
             raise AssertionFormatIncorrect('The URL thats point to public key not exists in this assertion')
                                            
         # OK, is time to download the pubkey
         try:
            pub_key_pem = self.download_pubkey(payload['verify']['url'])
         except HTTPError as e:
            print('[!] And error has occurred during PubKey download. HTTP Error: ', e.code, e.reason)
         except URLError as e:
            print('[!] And error has occurred during PubKey download. Reason: ', e.reason)                  
         
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
            return assertion[0].attributes['verify'].nodeValue.encode('utf-8')            
            
        except:
            raise ErrorParsingFile('Error Parsing SVG file: ')
        finally:
            svg_doc.unlink()
     
    def is_svg_signature_valid(self, file_in, email, inline_data=False, local_verification=False):
        """ This function return True/False if the signature in the
             file is correct or no """
        
        if not inline_data:
            if not os.path.exists(file_in):
                raise errors.FileToSignNotExists()     
            else:
                with open(file_in, "rb") as f:
                    svg_data = f.read()
        else:    
            svg_data = file_in
             
        try:    
            assertion = self.extract_svg_signature(svg_data)  
            
            receptor = email.encode('utf-8')
            
            # If pub_key exist, the verification use the local key
            if local_verification:
                return self.verify_signature_inlocal(assertion, receptor)
            else:
                return self.verify_signature_inverse(assertion, receptor)
            
        except ErrorParsingFile:
           print('[!] SVG format incorrect or this badge has not assertion signature embeded')

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

    def show_key_info(self, key):
        """ Guess the key type and show the appropiate info """
        if key.__class__.__name__ == '_RSAobj':
            # RSA Key.
            print('[+] Using an RSA Key of %d bits size' % key.size())
        elif key.__class__.__name__ == 'SigningKey' or key.__class__.__name__ == 'VerifyingKey':
            # ECC key
            print('[+] Using an ECC Key with a curve type %s' % key.curve.name)
        else:
            print('[!] Unknown key type! %s' % key.__class__.__name__)
            
            
    def show_disclaimer(self):
        if self.conf['keys']['crypto'] == 'ECC':
            print("""DISCLAIMER!
                  
            You are running the program with support for Elliptic Curve cryptography.
                
            The implementation of ECC in JWS Draft is not clear about the signature/verification
            process and may lead to problems for you and others when verifying your badges.
                  
            Use at your own risk!
            
            Expiration and Revocations status of badges are not verified by this library version.
                  
            """)
                         
""" RSA Verify Factory """
class VerifyRSA(VerifyBase):  
    def __init__(self, config):
        VerifyBase.__init__(self, config)
        
        # The pubkey is in a file
        try:
            with open(self.conf['keys']['public'], "rb") as key_file:
                self.vk = RSA.importKey(key_file.read())
        except:
            raise PublicKeyReadError()
             
    def load_pubkey_inline(self, pem_data):
        """ Create a crypto object from a pem string """
        return RSA.importKey(pem_data)

class VerifyECC(VerifyBase):
    def __init__(self, config):
        VerifyBase.__init__(self, config)
         
        # The pubkey is in a file
        try:
            with open(self.conf['keys']['public'], "rb") as key_file:
                self.vk = VerifyingKey.from_pem(key_file.read())
        except:
            raise PublicKeyReadError()    
               
    def load_pubkey_inline(self, pem_data):
        """ Create a crypto object from a pem string """
        return VerifyingKey.from_pem(pem_data)
 