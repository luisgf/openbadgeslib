#!/usr/bin/env python3
#description     : Library for dealing with signing of badges
#author          : Luis G.F
#date            : 20141120
#version         : 0.1 

import hashlib
import os
import sys

from ecdsa.util import PRNG
from ecdsa import SigningKey, NIST256p
from config import badgesconf

class ECDSAPrivateKeyGenError(Exception):
    def __init__(self):
        self.msg = 'Error during ECDSA private key generation'

    def __str__(self):
        return repr(self.msg)

class ECDSAPublicKeyGenError(Exception):
    def __init__(self):
        self.msg = 'Error during ECDSA public key generation'

    def __str__(self):
        return repr(self.msg)    

class HashError(Exception):
    def __init__(self):
        self.msg = 'Error during SHA1 calculation'

    def __str__(self):
        return repr(self.msg)

class ECDSASaveErrorPrivate(Exception):
    def __init__(self):
        self.msg = 'Error saving private key file'

    def __str__(self):
        return repr(self.msg)
    
class ECDSASaveErrorPublic(Exception):
    def __init__(self):
        self.msg = 'Error saving public key file'

    def __str__(self):
        return repr(self.msg)
    
class ECDSAKeyExists(Exception):
    def __init__(self, file):
        self.msg = 'An existing ECDSA key is present for this issuer (%s)' % file

    def __str__(self):
        return repr(self.msg)
    
    
class KeyFactory():
        
    def __init__(self, issuer):
        self.private_key = None
        self.public_key = None
        self.issuer = None
        self.private_key_file = badgesconf['private_key_path']
        self.public_key_file = badgesconf['public_key_path']

        self.issuer = issuer.encode('UTF-8')
        print(u"[!] Generating Issuer key for '%s'..." % self.issuer.decode('UTF-8'))

        # If the issuer has a key, stop a new key generation
        self.has_key()

    def has_key(self):
        """ Forbid issuers with 2 active keys """
        
        key_path = self.private_key_file + self.key_file
        if os.path.isfile(key_path):
            raise ECDSAKeyExists(key_path)        

    def generate_keypair(self):
        """ Generate a ECDSA keypair """
        
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

    def save_keypair(self):      
        """ Save keypair to file """
        
        try:
            open(self.private_key_file, "wb").write(self.get_private_pem())        
        except:
             raise ECDSASaveErrorPrivate()
         
        try:
            open(self.public_key_file, "wb").write(self.get_public_pem())        
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
                
if __name__ == '__main__':
    pass