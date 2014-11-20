#!/usr/bin/env python3

import unittest

# Para cargar las clases desde el directorio anterior
import os.path
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

class TestKeyGenerator(unittest.TestCase):
          
    def test_01_python_version(self):
        if not sys.version_info[:2] == (3, 4):
            self.fail('Wrong Python version. Python >= 3.4.x is needed')
            
    def test_02_import_ecdsa(self):
        try:
            import ecdsa
        except:
            self.fail('ECDSA library missing')
            
    def test_03_import_hashlib(self):
        try:
            import hashlib
        except:
            self.fail('hashlib import failed')
    
    def test_04_import_keygenerator(self):
        try:
            import keygenerator
        except:
            self.fail('KeyGenerator import failed')           

    def test_05_create_factory_object(self):
        try:
            from keygenerator import KeyFactory
            kf = KeyFactory('TEST')
        except:
            self.fail('KeyFactory() object creation error')

    def test_06_check_key_paths(self):
        import os
        from config import badgesconf
        
        if not os.path.isdir(badgesconf['private_key_path']):
            self.fail('Private key folder not exist %s' % badgesconf['private_key_path'])
        
        if not os.path.isdir(badgesconf['public_key_path']):
            self.fail('Public key folder not exist %s' % badgesconf['public_key_path'])
        
            
if __name__ == '__main__':
    unittest.main()
