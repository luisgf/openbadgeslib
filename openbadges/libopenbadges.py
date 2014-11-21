#!/usr/bin/env python3
#description     : Library for dealing with signing of badges
#author          : Luis G.F
#date            : 20141120
#version         : 0.1 

import hashlib
import os
import sys

from ecdsa import SigningKey, VerifyingKey, NIST256p
from config import badgesconf
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "./3dparty/jws/")))

class ECDSAPrivateKeyGenError(Exception):
    pass

class ECDSAPublicKeyGenError(Exception):
    pass

class HashError(Exception):
    pass

class ECDSASaveErrorPrivate(Exception):
    pass
    
class ECDSASaveErrorPublic(Exception):
    pass
    
class ECDSAKeyExists(Exception):
    pass

class ECDSAReadPrivKeyError(Exception):
    pass

class ECDSAReadPubKeyError(Exception):
    pass
    
class KeyFactory():
    """ ECDSA Factory class """
    
    def __init__(self, issuer):
        self.private_key = None
        self.public_key = None
        self.issuer = None
        self.private_key_file = badgesconf['private_key_path']
        self.public_key_file = badgesconf['public_key_path']

        self.issuer = issuer.encode('UTF-8')

    def has_key(self):
        """ Check if a issuer has a private key generated """
        
        key_path = self.private_key_file + self.sha1_string(self.issuer) + '.pem'
        if os.path.isfile(key_path):
            raise ECDSAKeyExists(key_path)        

    def generate_keypair(self):
        """ Generate a ECDSA keypair """       

        # If the issuer has a key, stop a new key generation
        self.has_key()
        
        # Private key generation
        try:
            self.private_key = SigningKey.generate(curve=NIST256p)
            self.private_key_file += self.sha1_string(self.issuer) + '.pem'
        except:
            raise ECDSAPrivateKeyGenError()
        
        # Public Key name is the hash of the public key
        try:
            self.public_key = self.private_key.get_verifying_key()
            self.public_key_file += self.sha1_string(self.get_public_pem()) + '.pem'
        except:
            raise ECDSAPublicKeyGenError()

    def read_private_key(self, private_key_file): 
        """ Read the private key from files """
        try:
            with open(private_key_file, "r") as priv:
                self.private_key_file = private_key_file
                self.private_key = SigningKey.from_pem(priv.read())
                priv.close()
                
            return True 
        except:
            raise ECDSAReadPrivKeyError('Error reading private key: %s' % self.private_key_file)
            return False
        
    def read_public_key(self, public_key_file): 
        """ Read the public key from files """
        try:
            with open(public_key_file, "r") as pub:
                self.public_key_file = public_key_file
                self.public_key = VerifyingKey.from_pem(pub.read())
                pub.close()
                
            return True 
        except:
            raise ECDSAReadPubKeyError('Error reading public key: %s' % self.public_key_file)
            return False        
                        
    def save_keypair(self):      
        """ Save keypair to file """        
        try:
            with open(self.private_key_file, "wb") as priv:
                priv.write(self.get_private_pem())
                priv.close()                
        except:
             raise ECDSASaveErrorPrivate()
         
        try:
            with open(self.public_key_file, "wb") as pub:
                pub.write(self.get_public_pem())                    
                pub.close()                
        except:
             raise ECDSASaveErrorPublic() 

    def get_private_pem(self):
        """ Return private key in PEM format """
        return self.private_key.to_pem()
    
    def get_public_pem(self):
        """ Return public key in PEM format """
        return self.public_key.to_pem()
    
    def sha1_string(self, string):
        """ Calculate digest of a string """
        try:
            hash = hashlib.new('sha1')
            hash.update(string)
            return hash.hexdigest()
        except:
            raise HashError() 


class SignerFactory():
    """ JWS Signer Factory """
    pass

class VerifyFactory():
    """ JWS Signature Verifier Factory """
    pass
                
if __name__ == '__main__':
    unittest.main()