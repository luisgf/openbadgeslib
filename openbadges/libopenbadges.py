#!/usr/bin/env python3
#description     : Library for dealing with signing of badges
#author          : Luis G.F
#date            : 20141125
#version         : 0.1 

import hashlib
import os
import sys
import time

from ecdsa import SigningKey, VerifyingKey, NIST256p, BadSignatureError

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
   
class KeyFactory():
    """ ECDSA Factory class """
    
    def __init__(self, conf):
        self.private_key = None
        self.public_key = None
        self.issuer = None
        self.private_key_file = conf.keygen['private_key_path']
        self.public_key_file = conf.keygen['public_key_path']

        self.issuer = conf.issuer['name']

    def has_key(self):
        """ Check if a issuer has a private key generated """
       
        key_path = self.private_key_file + sha1_string(self.issuer) + b'.pem'
        
        if os.path.isfile(key_path):
            raise PrivateKeyExists(key_path)        

    def generate_keypair(self):
        """ Generate a ECDSA keypair """       

        # If the issuer has a key, stop a new key generation
        self.has_key()
        
        # Private key generation
        try:
            self.private_key = SigningKey.generate(curve=NIST256p)            
            self.private_key_file += sha1_string(self.issuer) + b'.pem'
        except:
            raise GenPrivateKeyError()
        
        # Public Key name is the hash of the public key
        try:
            self.public_key = self.private_key.get_verifying_key()
            self.public_key_file += sha1_string(self.get_public_key_pem()) + b'.pem'
        except:
            raise GenPublicKeyError()

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
                        
    def save_keypair(self):      
        """ Save keypair to file """        
        try:
            with open(self.private_key_file, "wb") as priv:
                priv.write(self.get_private_key_pem())
                priv.close()                
        except:
             raise PrivateKeySaveError()
         
        try:
            with open(self.public_key_file, "wb") as pub:
                pub.write(self.get_public_key_pem())                    
                pub.close()                
        except:
             raise PublicKeySaveError() 

    def get_private_key_pem(self):
        """ Return private key in PEM format """
        return self.private_key.to_pem()
    
    def get_public_key_pem(self):
        """ Return public key in PEM format """
        return self.public_key.to_pem()    

""" Signer Exceptions """

class BadgeNotFound(Exception):
    pass

class SignerFactory():
    """ JWS Signer Factory """
    
    def __init__(self, conf, badgename, receptor):
        self.conf = conf                              # Access to config.py values                
        self.receptor = receptor                      # Receptor of the badge
        
        try:
            if conf.badges[badgename]:
                self.badge = conf.badges[badgename]
        except KeyError:
            raise BadgeNotFound()
        
    def generate_uid(self):
        """ Generate a UID for a signed badge, Return a str """
        
        return sha1_string(self.conf.issuer['name'] + self.badge['name'] + self.receptor).decode('utf-8')

    
    def generate_jose_header(self):
        """ Generate de JOSE Header """
        
        return { 'alg': 'ES256' }
    
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
        
        return dict(
                        uid = self.generate_uid(),
                        recipient = recipient_data,
                        image = self.badge['image'],
                        badge = self.badge['json_url'],
                        verify = verify_data,
                        issuedOn = int(time.time())
                     )  
    
    def generate_openbadge_assertion(self):
        """ Generate and Sign and OpenBadge assertion """
        
        import jws
        
        priv_key_file = self.conf.keygen['private_key_path'] + sha1_string(self.conf.issuer['name']) + b'.pem'
        
        header = self.generate_jose_header()
        payload = self.generate_jws_payload()

        try:
            with open(priv_key_file, "rb") as key_file:
                sign_key = SigningKey.from_pem(key_file.read())
                
        except:
            raise PrivateKeyReadError()
        
        signature = jws.sign(header, payload, sign_key)             
        assertion = jws.utils.encode(header) + b'.' + jws.utils.encode(payload) + b'.' + jws.utils.to_base64(signature)                      
        
        # Verify the assertion just after the generation.
        vf = VerifyFactory(self.conf)  
        
        if not vf.verify_signature(assertion):
            return None
        else:
            return assertion

class PayloadFormatIncorrect(Exception):
    pass

""" Signature Verification Factory """
class VerifyFactory():
    """ JWS Signature Verifier Factory """
    
    def __init__(self, conf, pub_key=None):
        self.conf = conf                              # Access to config.py values  
        self.pub_key = pub_key
        self.vk = None                                # VerifyingKey() Object
                
        # If the pubkey is not passed as parameter, i can obtaint it via private_key
        if pub_key:        
            try:
                with open(pub_key, "rb") as key_file:
                    self.vk = VerifyingKey.from_pem(key_file.read())
                
            except:
                raise PublicKeyReadError()
        else:
            # Pubkey not passed. Using the private key to obtain one.
            try:
                priv_key_file = self.conf.keygen['private_key_path'] + sha1_string(self.conf.issuer['name']) + b'.pem'
                
                with open(priv_key_file, "rb") as key_file:
                    sign_key = SigningKey.from_pem(key_file.read())
                    self.vk = sign_key.get_verifying_key()
                    
            except:
                raise PrivateKeyReadError()
        
    def verify_signature(self, assertion):
        """ Verify the JWS Signature, Return True if the signature block is Good """
        
        try:
            return jws.verify_block(assertion, self.vk)            
        except:
            print('[!] Wrong Assertion Signature') 
            return False            
       
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
