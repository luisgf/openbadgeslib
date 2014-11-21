#!/usr/bin/env python3
#description     : Library for dealing with signing of badges
#author          : Luis G.F
#date            : 20141121
#version         : 0.1 

import unittest

# Para cargar las clases desde el directorio anterior
import os.path
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from libopenbadges import KeyFactory
from config import badgesconf
 
class TestKeyGenerator(unittest.TestCase):           
    
    def test_10_create_factory_object(self):
        try:
            kf = KeyFactory('TEST')
        except:
            self.fail('KeyFactory() object creation error')

    def test_11_check_key_paths(self):
        if not os.path.isdir(badgesconf['private_key_path']):
            self.fail('Private key folder not exist %s' % badgesconf['private_key_path'])
        
        if not os.path.isdir(badgesconf['public_key_path']):
            self.fail('Public key folder not exist %s' % badgesconf['public_key_path'])

    def test_12_gen_keypair(self):        
        try:
            kf = KeyFactory('TEST')
            kf.generate_keypair()            
        except:
            self.fail('Error during keypair generation')            
    
    def test_13_save_keypair(self):        
        try:
            kf = KeyFactory('TEST')
            kf.generate_keypair()            
            kf.save_keypair()
        except:
            self.fail('Error saving keypair to files')            
    
    def test_14_check_key_file_presence(self): 
        try:
            kf = KeyFactory('TEST')
            kf.private_key_file += kf.sha1_string(kf.issuer) + '.pem'
            
            if os.path.isfile(kf.private_key_file):
                pass
        except:
            self.fail('Error verifying private key presence')
        
    def test_15_check_private_key(self):  
        try:
            kf = KeyFactory('TEST')
            kf.private_key_file += kf.sha1_string(kf.issuer) + '.pem'
            
            if kf.read_private_key(kf.private_key_file) is not True:
                self.fail('Error, reading private key file %s' % kf.private_key_file)   
        except:
            self.fail('Error, reading private key file')   

    def test_16_check_pub_keys(self):
        try:
            kf = KeyFactory('TEST')
            filelist = [ f for f in os.listdir(badgesconf['public_key_path']) if f.endswith(".pem") ]
            for f in filelist:
                if kf.read_public_key(badgesconf['public_key_path'] + f) is not True:
                    self.fail('Error, reading public key file %s' % kf.public_key_file)   
        except:
            self.fail('Error, reading public key files') 
    
            
if __name__ == '__main__':
    unittest.main()
