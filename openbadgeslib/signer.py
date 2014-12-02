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
    Signer Module
    
    Author:   Luis G.F <luisgf@luisgf.es>
    Date:     20141201
    Version:  0.1

"""
import os
import sys
import time
import json

from xml.dom.minidom import parse, parseString

# Local imports
from openbadgeslib.errors import UnknownKeyType, BadgeNotFound, FileToSignNotExists, BadgeSignedFileExists, ErrorSigningFile, PrivateKeyReadError 

from openbadgeslib.util import sha1_string, sha256_string
from openbadgeslib.keys import KeyFactory
from openbadgeslib.verifier import VerifyFactory

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "./3dparty/")))
import jws.utils
        
class SignerFactory():
    """ Signer Factory Object, Return a Given object type passing a name
        to the constructor. """
        
    def __new__(cls, config, badgename, receptor, evidence=None, debug_enabled=None):
        if config['keys']['crypto'] == 'ECC':
            return SignerECC(config, badgename, receptor, evidence, debug_enabled)
        if config['keys']['crypto'] == 'RSA':
            return SignerRSA(config, badgename, receptor, evidence, debug_enabled)
        else:
            raise UnknownKeyType()
        
class SignerBase():
    """ JWS Signer Factory """
    
    def __init__(self, config, badgename, receptor, evidence=None, debug_enabled=False):
        self.conf = config                            # Access to config.py values                
        self.receptor = receptor.encode('utf-8')      # Receptor of the badge
        self.in_debug = debug_enabled                 # Debug mode enabled
        self.badge = None
        self.evidence = evidence                      # Url to the user evidence
        
        for badge in config['badges']:
            if badge['name'] == badgename:
                self.badge = badge
        
        if not self.badge:
            raise BadgeNotFound()
        
    def generate_uid(self):
        """ Generate a UID for a signed badge """
        
        return sha1_string((self.conf['issuer']['name'] + self.badge['name']).encode() + self.receptor)
    
    def generate_jws_payload(self): 
        """ Generate JWS Payload """        
        
        # All this data MUST be a Str string in order to be converted to json properly.        
        recipient_data = dict (
            identity = (b'sha256$' + sha256_string(self.receptor)).decode('utf-8'),
            type = 'email',
            hashed = 'true'
        )                
        
        verify_data = dict(
            type = 'signed',
            url = self.badge['url_key_verif']
        )                
        
        payload = dict(
                        uid = self.generate_uid().decode('utf-8'),
                        recipient = recipient_data,
                        image = self.badge['image'],
                        badge = self.badge['json_url'],
                        verify = verify_data,
                        issuedOn = int(time.time())
                     )  
        
        if self.evidence:
            payload['evidence'] = self.evidence
            
        self.debug('JWS Payload %s ' % json.dumps(payload))
        
        return payload
        
    def sign_svg_file(self, file_out):
        """ Add the Assertion information into the SVG file. """
    
        file_in = self.get_badge_local_path()
    
        if not os.path.exists(file_in):
            raise FileToSignNotExists()
        
        if os.path.exists(file_out):
            raise BadgeSignedFileExists('Output file exists at:', file_out)
    
        try:
            
            assertion = self.generate_openbadge_assertion()
            
            # Parse de SVG XML
            svg_doc = parse(file_in)  
                    
            # Assertion
            xml_tag = svg_doc.createElement("openbadges:assertion")
            xml_tag.attributes['xmlns:openbadges'] = 'http://openbadges.org'
            svg_doc.childNodes[1].appendChild(xml_tag) 
            xml_tag.attributes['verify']= assertion.decode('utf-8')
            svg_doc.childNodes[1].appendChild(xml_tag) 
            
            """ Log the signing process before write the badge to disk.
                That's prevents the existence of a signed badge without traces """
            
            self.log(self.conf, '"%s" SIGNED successfully for receptor "%s" in file "%s"' % (self.badge['name'], self.receptor.decode('utf-8'), file_out))
            
            with open(file_out, "w") as f:
                svg_doc.writexml(f)
                    
        except:
            raise ErrorSigningFile('Error Signing file: ', file_in)
        finally:
            svg_doc.unlink()
            
        return True
        
    def debug(self, msg):
        """ Show debug messages if debug mode is enabled """
        
        if self.in_debug:
            print('DEBUG:', msg)
            
    def generate_output_filename(self, output_dir, receptor):
        """ Generate an output filename based on the source
            name and the receptor email """
        
        file_in = self.get_badge_local_path()
        fbase = os.path.basename(file_in)
        fname, fext = os.path.splitext(fbase)
        fsuffix = receptor.replace('@','_').replace('.','_')
        
        return output_dir + fname + '_'+ fsuffix + fext

    def generate_openbadge_assertion(self):
        """ Generate and Sign and OpenBadge assertion """
        
        import jws
        
        header = self.generate_jose_header()
        payload = self.generate_jws_payload()

        # Read the keys from files
        kf = KeyFactory(self.conf)
        try:
            kf.read_private_key()
            kf.read_public_key()
        except:
            raise PrivateKeyReadError()
        
        signature = jws.sign(header, payload, kf.get_priv_key())             
        assertion = jws.utils.encode(header) + b'.' + jws.utils.encode(payload) + b'.' + jws.utils.to_base64(signature)                      
        
        # Verify the assertion just after the generation.
        vf = VerifyFactory(self.conf)  
        vf.load_pubkey_inline(kf.get_pub_key_pem())
        
        if not vf.verify_jws_signature(assertion, kf.get_pub_key()):
            return None
        else:
            self.debug('Assertion %s' % assertion)
            return assertion
    
    def get_badge_local_path(self):
        """ Return the path to the badge file """
        
        return self.badge['local_badge_path']
   
    def log(self, profile, msg):
        """ Log in a file the signature event """
        
        with open(profile['signedlog'], "ab") as log:
            entry = time.strftime("%d/%m/%Y %H:%M:%S").encode('utf-8') + b' ' + msg.encode('utf-8') + b'\n'
            log.write(entry)

class SignerRSA(SignerBase):
    def __init__(self, config, badgename, receptor, evidence, debug_enabled):
         SignerBase.__init__(self, config, badgename, receptor, evidence, debug_enabled)
         
    def generate_jose_header(self):
        """ Generate JOSE Header """
        
        jose_header = { 'alg': 'RS256' }        
        self.debug('JOSE HEADER %s ' % json.dumps(jose_header))
        
        return jose_header

class SignerECC(SignerBase):
    def __init__(self, config, badgename, receptor, evidence, debug_enabled):
         SignerBase.__init__(self, config, badgename, receptor, evidence, debug_enabled)
         
    def generate_jose_header(self):
        """ Generate JOSE Header """
        
        jose_header = { 'alg': 'ES256' }        
        self.debug('JOSE HEADER %s ' % json.dumps(jose_header))
        
        return jose_header
          