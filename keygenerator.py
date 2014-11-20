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
        self.key = None
        self.issuer = None
        self.issuer_hash = None
        self.key_file = None

        try:
            self.issuer = issuer.encode('UTF-8')
            print(u"[!] Generating Issuer key for '%s'..." % self.issuer.decode('UTF-8'))
            hash = hashlib.new(badgesconf['issuer_algo'])
            hash.update(self.issuer)
            self.issuer_hash = hash.hexdigest()
            self.key_file = self.issuer_hash + ".pem"
        except:
             raise ECDSAHashError()

        # If the issuer has a key, stop a new key generation
        self.has_key()

    def has_key(self):
        key_path = badgesconf['issuer_key_path'] + self.key_file
        if os.path.isfile(key_path):
            raise ECDSAKeyExists(key_path)        

    def generate_key(self):
        try:
            self.key = SigningKey.generate(curve=NIST256p)
        except:
            raise ECDSAKeyGenError()

    def save_key(self):      
        try:
            key_path = badgesconf['issuer_key_path'] + self.key_file
            open(key_path, "w").write(self.get_pem())        
        except:
             raise ECDSASaveError()

    def get_pem(self):
        return self.key.to_pem().decode('UTF-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Key Generation Params')
    parser.add_argument('-i', '--issuer', required=True, help='Set the issuer for the key generation process')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1')

    args = parser.parse_args()

    kf = KeyFactory(args.issuer)   
    kf.generate_key()
    kf.save_key()
    print(kf.get_pem())

