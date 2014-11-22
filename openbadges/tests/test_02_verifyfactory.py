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
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../3dparty/jws/")))

from libopenbadges import SignerFactory
from config import badgesconf

class TestVerifyFactory(unittest.TestCase): 
            
    def test_20_import_jws(self):
        try:
            import jws
        except:
            self.fail('Python-jws library missing https://pypi.python.org/pypi/jws/0.1.2')
    