#!/usr/bin/env python3
#description     : Library for dealing with signing of badges
#author          : Luis G.F
#date            : 20141127
#version         : 0.2 

import hashlib
import os
import sys
import time
import json

from ecdsa import SigningKey, VerifyingKey, NIST256p, BadSignatureError
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler
from urllib.parse import urlparse
from ssl import SSLContext, CERT_NONE, VERIFY_CRL_CHECK_CHAIN, PROTOCOL_TLSv1, SSLError
from xml.dom.minidom import parse, parseString

# Local imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "./3dparty/")))
import jws.utils

class GenPrivateKeyError(Exception):
    pass

class GenPublicKeyError(Exception):
    pass

class HashError(Exception):
    pass

class PrivateKeySaveError(Exception):
    pass
    
class PublicKeySaveError(Exception):
    pass
    
class PrivateKeyExists(Exception):
    pass

class PrivateKeyReadError(Exception):
    pass

class PublicKeyReadError(Exception):
    pass

class KeyFactoryBase(object):       
    def __init__(self, config, key_type, key_size, hash_algo, curve_type=None):        
        self.conf = config         
        self.key_type = key_type
        self.key_size = key_size
        self.hash_algo = hash_algo 
        self.curve_type = curve_type
        self.priv_key = None              # crypto Object
        self.pub_key = None               # crypto Object
        self.private_key_file = ''
        self.public_key_file = ''

    def generate_key_filenames(self):
        """ Generate the names for the keys files """
        
        self.private_key_file = self.conf.keygen['private_key_path'].encode('utf-8') + sha1_string(self.conf.issuer['name'].encode('utf-8')) + b'.pem'
        self.public_key_file = self.conf.keygen['public_key_path'].encode('utf-8') + sha1_string(self.conf.issuer['name'].encode('utf-8')) + b'_pub.pem'               


    def get_privkey_path(self):
        """ Return de path to the private key """
        return self.private_key_file.decode('utf-8')
    
    def get_pubkey_path(self):
        """ Return de path to the public key """
        return self.public_key_file.decode('utf-8')
    
    def save_keypair(self, private_key_pem, public_key_pem):      
        """ Save keypair to file """        
        try:
            with open(self.get_privkey_path(), "wb") as priv:
                priv.write(private_key_pem)
                priv.close()                
        except:
             raise PrivateKeySaveError()
         
        try:
            with open(self.get_pubkey_path(), "wb") as pub:
                pub.write(public_key_pem)                    
                pub.close()                
        except:
             raise PublicKeySaveError() 

    def has_key(self):
        """ Check if a private key is already generated """
        
        if os.path.isfile(self.private_key_file):
            raise PrivateKeyExists(self.get_privkey_path())   

class KeyFactoryRSA(KeyFactoryBase):
    
    def __init__(self, config, key_type='RSA', key_size=2048, hash_algo='SHA256'):  
        KeyFactoryBase.__init__(self, config, key_type, key_size, hash_algo)      
            
    def generate_keypair(self):
        """ Generate a RSA Key, returning in PEM Format """
        from Crypto.PublicKey import RSA   
        
        # Generation the names for the keys
        self.generate_key_filenames() 
        
        # Check if a key exists
        self.has_key()
        
        # RSA Key Generation
        try:
            self.priv_key = RSA.generate(self.key_size) 
            priv_key_pem = self.priv_key.exportKey('PEM')
        except:
            raise GenPrivateKeyError()
        
        try:
            self.pub_key = self.priv_key.publickey()
            pub_key_pem = self.pub_key.exportKey('PEM')
        except:
            raise GenPublicKeyError()
        
        self.save_keypair(priv_key_pem, pub_key_pem)

        print('[+] RSA(%d) Private Key generated at %s' % (self.key_size, self.get_privkey_path()))
        print('[+] RSA(%d) Public Key generated at %s' % (self.key_size, self.get_pubkey_path()))  
        
        return True
   
class KeyFactoryECC(KeyFactoryBase):
    """ Elliptic Curve Cryptography Factory class """
    
    def __init__(self, config, key_type='EC', key_size=None, hash_algo='SHA256', curve_type=NIST256p):  
        KeyFactoryBase.__init__(self, config, key_type, key_size, hash_algo, curve_type)            

    def generate_keypair(self):
        """ Generate a ECDSA keypair """       

        # Generation the names for the keys
        self.generate_key_filenames() 

        # If the issuer has a key, stop a new key generation
        self.has_key()
        
        # Private key generation
        try:
            self.priv_key = SigningKey.generate(curve=NIST256p) 
            priv_key_pem = self.priv_key.to_pem()
        except:
            raise GenPrivateKeyError()
        
        # Public Key name is the hash of the public key
        try:
            self.pub_key = self.priv_key.get_verifying_key()
            pub_key_pem = self.pub_key.to_pem()
        except:
            raise GenPublicKeyError()
        
        # Save the keypair
        self.save_keypair(priv_key_pem, pub_key_pem)
        
        print('[+] ECC(%s) Private Key generated at %s' % (self.curve_type.name, self.get_privkey_path()))
        print('[+] ECC(%s) Public Key generated at %s' % (self.curve_type.name, self.get_pubkey_path()))  

    def read_private_key(self, private_key_file): 
        """ Read the private key from files """
        try:
            with open(private_key_file, "rb") as priv:
                self.private_key_file = private_key_file
                self.private_key = SigningKey.from_pem(priv.read())
                priv.close()
                
            return True 
        except:
            raise PrivateKeyReadError('Error reading private key: %s' % self.private_key_file)
            return False
        
    def read_public_key(self, public_key_file): 
        """ Read the public key from files """
        try:
            with open(public_key_file, "rb") as pub:
                self.public_key_file = public_key_file
                self.public_key = VerifyingKey.from_pem(pub.read())
                pub.close()
                
            return True 
        except:
            raise PublicKeyReadError('Error reading public key: %s' % self.public_key_file)
            return False                                

""" Signer Exceptions """

class BadgeNotFound(Exception):
    pass

class FileToSignNotExists(Exception):
    pass

class ErrorSigningFile(Exception):
    pass

class SignerFactory():
    """ JWS Signer Factory """
    
    def __init__(self, conf, badgename, receptor, debug_enabled=False):
        self.conf = conf                              # Access to config.py values                
        self.receptor = receptor                      # Receptor of the badge
        self.in_debug = debug_enabled
        
        try:
            if conf.badges[badgename]:
                self.badge = conf.badges[badgename]
        except KeyError:
            raise BadgeNotFound()
        
    def generate_uid(self):
        """ Generate a UID for a signed badge """
        
        return sha1_string((self.conf.issuer['name'] + self.badge['name']).encode('utf-8') + self.receptor)
    
    def generate_jose_header(self):
        """ Generate JOSE Header """
        
        jose_header = { 'alg': 'ES256' }        
        self.debug('JOSE HEADER %s ' % json.dumps(jose_header))
        
        return jose_header
    
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
        
        self.debug('JWS Payload %s ' % json.dumps(payload))
        
        return payload
    
    def generate_openbadge_assertion(self):
        """ Generate and Sign and OpenBadge assertion """
        
        import jws
        
        priv_key_file = self.conf.keygen['private_key_path'] + sha1_string(self.conf.issuer['name'].encode('utf-8')) + b'.pem'
        
        header = self.generate_jose_header()
        payload = self.generate_jws_payload()

        try:
            with open(priv_key_file, "rb") as key_file:
                sign_key = SigningKey.from_pem(key_file.read())
                pub_key = sign_key.get_verifying_key()
                
        except:
            raise PrivateKeyReadError()
        
        signature = jws.sign(header, payload, sign_key)             
        assertion = jws.utils.encode(header) + b'.' + jws.utils.encode(payload) + b'.' + jws.utils.to_base64(signature)                      
        
        # Verify the assertion just after the generation.
        vf = VerifyFactory(self.conf, pub_key.to_pem(), key_inline=True)  
        
        if not vf.verify_signature(assertion):
            return None
        else:
            self.debug('Assertion %s' % assertion)
            return assertion
        
    def sign_svg_file(self, file_in, file_out, assertion_data):
        """ Add the Assertion information into the SVG file
        assertion_data MUST by a str. The assertion_data input
        as bytes but MUST be converted tu str """
    
        if not os.path.exists(file_in):
            raise FileToSignNotExists()
    
        try:
            # Parse de SVG XML
            svg_doc = parse(file_in)  
                    
            # Assertion
            xml_tag = svg_doc.createElement("openbadges:assertion")
            xml_tag.attributes['xmlns:openbadges'] = 'http://openbadges.org'
            svg_doc.childNodes[1].appendChild(xml_tag) 
            xml_tag.attributes['verify']= assertion_data.decode('utf-8')
            svg_doc.childNodes[1].appendChild(xml_tag) 
            
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
            
    def generate_output_filename(self, file_in, output_dir, receptor):
        """ Generate an output filename based on the source
            name and the receptor email """
        
        fbase = os.path.basename(file_in)
        fname, fext = os.path.splitext(fbase)
        fsuffix = receptor.replace('@','_').replace('.','_')
        
        return output_dir + fname + '_'+ fsuffix + fext

class PayloadFormatIncorrect(Exception):
    pass

class AssertionFormatIncorrect(Exception):
    pass

class NotIdentityInAssertion(Exception):
    pass

class NoPubKeySpecified(Exception):
    pass

class ErrorParsingFile(Exception):
    pass

""" Signature Verification Factory """
class VerifyFactory():
    """ JWS Signature Verifier Factory """
    
    def __init__(self, conf, pub_key=None, key_inline=False):
        self.conf = conf                              # Access to config.py values  
        self.pub_key = pub_key                        # Local PubKey file
        self.vk = None                                # VerifyingKey() Object
                
        # If the pubkey is not passed as parameter, i can obtaint it via private_key
        if pub_key and not key_inline:
            # The pubkey is in a file
            try:
                with open(pub_key, "rb") as key_file:
                    self.vk = VerifyingKey.from_pem(key_file.read())
                    
                print('[+] Badge will be validated with local key:', pub_key)
            except:
                raise PublicKeyReadError()
            
        elif pub_key and key_inline:
            # The pub key is passed as string in pub_key
            try:
                self.vk = VerifyingKey.from_pem(pub_key)
            except:
                raise PublicKeyReadError()            
        
    def verify_signature(self, assertion):
        """ Verify the JWS Signature, Return True if the signature block is Good """
                
        return jws.verify_block(assertion, self.vk)                               
    
    def verify_signature_inlocal(self, assertion, receptor):
        """ Verify that a signature is valid and has emitted for a given receptor """
        import json
        
        # Check if the JWS assertion is valid
        try:
            self.verify_signature(assertion) 
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
         self.vk = VerifyingKey.from_pem(pub_key_pem)         
         
         try:
            signature_valid = self.verify_signature(assertion)
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
     
    def is_svg_signature_valid(self, file_in, receptor, inline_data=False):
        """ This function return True/False if the signature in the
             file is correct or no """
        
        if not inline_data:
            if not os.path.exists(file_in):
                raise FileToSignNotExists()     
            else:
                with open(file_in, "rb") as f:
                    svg_data = f.read()
        else:    
            svg_data = file_in
             
        try:    
            assertion = self.extract_svg_signature(svg_data)  
            
            # If pub_key exist, the verification use the local key
            if self.pub_key:
                return self.verify_signature_inlocal(assertion, receptor)
            else:
                return self.verify_signature_inverse(assertion, receptor)
            
        except ErrorParsingFile:
           print('[!] SVG format incorrect or this badge has not assertion signature embeded')

     
""" Shared Utils """

def sha1_string(string):
    """ Calculate SHA1 digest of a string """
    try:
        hash = hashlib.new('sha1')
        hash.update(string)
        return hash.hexdigest().encode('utf-8')     # hexdigest() return an 'str' not bytes.
    except:
        raise HashError() 

def sha256_string(string):
    """ Calculate SHA256 digest of a string """
    try:
        hash = hashlib.new('sha256')
        hash.update(string)
        return hash.hexdigest().encode('utf-8')     # hexdigest() return an 'str' not bytes.
    except:
        raise HashError() 
                
if __name__ == '__main__':
    unittest.main()
