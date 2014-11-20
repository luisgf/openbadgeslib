#!/usr/bin/env python3

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
        kf = KeyFactory('TEST')
        try:
            kf.generate_keypair()
        except:
            self.fail('Error during keypair generation')

    def test_13_check_private_key(self):  
        try:
            kf = KeyFactory('TEST')
            kf.private_key_file += kf.issuer_hash + '.pem'
        
            if not os.path.isfile(kf.private_key_file):
                raise
        except:
            self.fail('Error, private key not found in %s' % kf.private_key_file)   

            
if __name__ == '__main__':
    unittest.main()
