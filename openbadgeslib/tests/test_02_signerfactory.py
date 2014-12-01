#!/usr/bin/env python3
#description     : Test file for SignerFactory() class
#author          : Luis G.F
#date            : 20141127
#version         : 0.1 

import unittest

# Para cargar las clases desde el directorio anterior
import os.path
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../3dparty/")))

from libopenbadges import SignerFactory, BadgeNotFound
import config


class TestSignerFactory(unittest.TestCase): 
    
    def test_21_create_factory_object_without_params(self):        
        with self.assertRaises(TypeError): 
            sf = SignerFactory()
            self.fail('Error, this object can not be created with this params')
     
    def test_22_create_factory_object_without_all_params(self):        
        with self.assertRaises(TypeError):            
            sf = SignerFactory(config)
            self.fail('Error, this object can not be created with 1 param')
     
    def test_23_create_factory_object_wrong_badge(self):        
        with self.assertRaises(BadgeNotFound):            
            sf = SignerFactory(config, '__BADGENAME', '__BADGERECEPTOR')                        
            self.fail('Error, this object can not be created with this badgename')

    def test_24_create_factory_object_without_1params(self):        
        with self.assertRaises(TypeError):            
            sf = SignerFactory(config, '__BADGENAME', '__BADGERECEPTOR')                        
            self.fail('Error, this object can not be created with 3 params')            