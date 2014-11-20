#!/usr/bin/env python3
#title           : keygenerator.py
#description     : This will create a ECDSA key for a given issuer
#author          : Luis G.F
#date            : 20141120
#version         : 0.1
#python_version  : 3.4.0  

""" ECDSA Key Generator """

import hashlib
import os
import sys, argparse
from ecdsa.util import PRNG
from ecdsa import SigningKey, NIST256p

# Local imports
from exceptions import *
from config import *

class KeyFactory():
        
    def __init__(self, issuer):
        self.private_key = None
        self.public_key = None
        self.issuer = None
        self.private_key_file = badgesconf['private_key_path']
        self.public_key_file = badgesconf['public_key_path']

        self.issuer = issuer.encode('UTF-8')
        print(u"[!] Generating Issuer key for '%s'..." % self.issuer.decode('UTF-8'))
            
        try:
            issuer_hash = self.sha1_string(self.issuer)
            self.key_file = issuer_hash + ".pem"
        except:
             raise ECDSAHashError()

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
            raise ECDSAHashError()
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Key Generation Params')
    parser.add_argument('-i', '--issuer', required=True, help='Set the issuer for the key generation process')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1')

    args = parser.parse_args()

    kf = KeyFactory(args.issuer)   
    kf.generate_keypair()
    kf.save_keypair()
    
    print("Private Key Generated: %s" % kf.private_key_file)
    print("Public Key Generated: %s" % kf.public_key_file)

