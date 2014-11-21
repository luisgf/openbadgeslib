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

class SelfTestGeneral(unittest.TestCase):
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