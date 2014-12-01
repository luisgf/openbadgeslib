#!/usr/bin/env python3
#description     : Test file for VerifyFactory() class
#author          : Luis G.F
#date            : 20141121
#version         : 0.1 

import unittest

# Para cargar las clases desde el directorio anterior
import os.path
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../3dparty/")))

from libopenbadges import VerifyFactory
import config

class TestVerifyFactory(unittest.TestCase): 
            
    def test_20_import_jws(self):
        try:
            import jws
        except:
            self.fail('Python-jws library missing https://pypi.python.org/pypi/jws/0.1.2')
    
    def test_21_create_factory_object(self):
        try:
            vf = VerifyFactory(config)
        except:
            self.fail('VerifyFactory() object creation failed')
            