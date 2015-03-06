import unittest
from unittest.mock import Mock, patch, mock_open, call

import functools, hashlib
import json

import test_common


from openbadgeslib import signer
from openbadgeslib.errors import UnknownKeyType
from openbadgeslib.confparser import ConfParser
from openbadgeslib.util import md5_string
from openbadgeslib.logs import Logger
from openbadgeslib.keys import KeyType
from openbadgeslib.badge import Badge, BadgeType, BadgeImgType
from openbadgeslib.confparser import ConfParser

class check_badge(unittest.TestCase) :
    def test_check_testconf(self):
        """ Badge entry in config.ini """
        
        cf = ConfParser('./config1.ini')
        self.assertIsInstance(cf, ConfParser)
        conf = cf.read_conf()
        self.assertIsNotNone(conf)

    def test_badge_creation(self):
        """ Badge object creation """
        
        badge = Badge()
        self.assertIsInstance(badge, Badge)

    def test_badge_creation(self):
        """ Test Manual Badge creation """
        
        cf = ConfParser('./config1.ini')
        conf = cf.read_conf()
        badge = 'badge_test_1'
        badge = Badge(ini_name=badge,
                         name=conf[badge]['name'],
                         description=conf[badge]['description'],
                         image_type=BadgeImgType.SVG,
                         image=None,
                         image_url=conf[badge]['image'],
                         criteria_url=conf[badge]['criteria'],
                         json_url=conf[badge]['badge'],
                         verify_key_url=conf[badge]['verify_key'],
                         key_type=KeyType.RSA,
                         privkey_pem=None,
                         pubkey_pem=None)
                         
        self.assertEqual(badge.ini_name, 'badge_test_1')
        self.assertEqual(badge.name, 'OpenBadgesLib TEST SVG RSA Badge')
        self.assertEqual(badge.description, 'TEST SVG RSA Badge')
        self.assertEqual(badge.image_type, BadgeImgType.SVG)
        self.assertEqual(badge.image_url, 'https://openbadges.luisgf.es/issuer/badge_1/badge.svg')
        self.assertEqual(badge.criteria_url, 'https://openbadges.luisgf.es/issuer/badge_1/criteria.html')
        self.assertEqual(badge.json_url, 'https://openbadges.luisgf.es/issuer/badge_1/badge.json')
        self.assertEqual(badge.verify_key_url, 'https://openbadges.luisgf.es/issuer/badge_1/verify_rsa_key.pem')
        self.assertEqual(badge.key_type, KeyType.RSA)
        self.assertEqual(conf['badge_test_1']['local_image'], 'sample1.svg')    
        self.assertTrue(badge.image_url.endswith('.svg'))

    def test_badge1(self):
        """ Testing SVG RSA Badge """
        
        cf = ConfParser('./config1.ini')
        conf = cf.read_conf()
        badge = Badge.create_from_conf(conf, 'badge_test_1')
        self.assertEqual(badge.ini_name, 'badge_test_1')
        self.assertEqual(badge.name, 'OpenBadgesLib TEST SVG RSA Badge')
        self.assertEqual(badge.description, 'TEST SVG RSA Badge')
        self.assertEqual(badge.image_type, BadgeImgType.SVG)
        self.assertEqual(badge.image_url, 'https://openbadges.luisgf.es/issuer/badge_1/badge.svg')
        self.assertEqual(badge.criteria_url, 'https://openbadges.luisgf.es/issuer/badge_1/criteria.html')
        self.assertEqual(badge.json_url, 'https://openbadges.luisgf.es/issuer/badge_1/badge.json')
        self.assertEqual(badge.verify_key_url, 'https://openbadges.luisgf.es/issuer/badge_1/verify_rsa_key.pem')
        self.assertEqual(badge.key_type, KeyType.RSA)
        self.assertEqual(conf['badge_test_1']['local_image'], 'sample1.svg')    
        self.assertTrue(badge.image_url.endswith('.svg'))   
    
    def test_badge2(self):
        """ Testing SVG ECC Badge """
        
        cf = ConfParser('./config1.ini')
        conf = cf.read_conf()
        badge = Badge.create_from_conf(conf, 'badge_test_2')
        self.assertEqual(badge.ini_name, 'badge_test_2')
        self.assertEqual(badge.name, 'OpenBadgesLib TEST SVG ECC Badge')
        self.assertEqual(badge.description, 'TEST SVG ECC Badge')
        self.assertEqual(badge.image_type, BadgeImgType.SVG)
        self.assertEqual(badge.image_url, 'https://openbadges.luisgf.es/issuer/badge_1/badge.svg')
        self.assertEqual(badge.criteria_url, 'https://openbadges.luisgf.es/issuer/badge_1/criteria.html')
        self.assertEqual(badge.json_url, 'https://openbadges.luisgf.es/issuer/badge_1/badge.json')
        self.assertEqual(badge.verify_key_url, 'https://openbadges.luisgf.es/issuer/badge_1/verify_ecc_key.pem')
        self.assertEqual(badge.key_type, KeyType.ECC)
        self.assertEqual(conf['badge_test_2']['local_image'], 'sample1.svg')    
        self.assertTrue(badge.image_url.endswith('.svg'))   
     
    def test_badge3(self):
        """ Testing PNG RSA Badge """
        
        cf = ConfParser('./config1.ini')
        conf = cf.read_conf()
        badge = Badge.create_from_conf(conf, 'badge_test_3')
        self.assertEqual(badge.ini_name, 'badge_test_3')
        self.assertEqual(badge.name, 'OpenBadgesLib TEST PNG RSA Badge')
        self.assertEqual(badge.description, 'TEST PNG RSA Badge')
        self.assertEqual(badge.image_type, BadgeImgType.PNG)
        self.assertEqual(badge.image_url, 'https://openbadges.luisgf.es/issuer/badge_1/badge.png')
        self.assertEqual(badge.criteria_url, 'https://openbadges.luisgf.es/issuer/badge_1/criteria.html')
        self.assertEqual(badge.json_url, 'https://openbadges.luisgf.es/issuer/badge_1/badge.json')
        self.assertEqual(badge.verify_key_url, 'https://openbadges.luisgf.es/issuer/badge_1/verify_rsa_key.pem')
        self.assertEqual(badge.key_type, KeyType.RSA)
        self.assertEqual(conf['badge_test_3']['local_image'], 'sample1.png')    
        self.assertTrue(badge.image_url.endswith('.png'))   
    
    def test_badge4(self):
        """ Testing PNG ECC Badge """
        
        cf = ConfParser('./config1.ini')
        conf = cf.read_conf()
        badge = Badge.create_from_conf(conf, 'badge_test_4')
        self.assertEqual(badge.ini_name, 'badge_test_4')
        self.assertEqual(badge.name, 'OpenBadgesLib TEST PNG ECC Badge')
        self.assertEqual(badge.description, 'TEST PNG ECC Badge')
        self.assertEqual(badge.image_type, BadgeImgType.PNG)
        self.assertEqual(badge.image_url, 'https://openbadges.luisgf.es/issuer/badge_1/badge.png')
        self.assertEqual(badge.criteria_url, 'https://openbadges.luisgf.es/issuer/badge_1/criteria.html')
        self.assertEqual(badge.json_url, 'https://openbadges.luisgf.es/issuer/badge_1/badge.json')
        self.assertEqual(badge.verify_key_url, 'https://openbadges.luisgf.es/issuer/badge_1/verify_ecc_key.pem')
        self.assertEqual(badge.key_type, KeyType.ECC)
        self.assertEqual(conf['badge_test_4']['local_image'], 'sample1.png')    
        self.assertTrue(badge.image_url.endswith('.png'))      
     
    def test_check_badge1_testkey(self):
        """ Key in config.ini are the same that the key in the test folder """
        
        cf = ConfParser('./config1.ini')
        conf = cf.read_conf()
        badge = Badge.create_from_conf(conf, 'badge_test_1')
        with open(conf['badge_test_1']['public_key'], 'rb') as f:
            key_pem = f.read()
        self.assertEqual(badge.pubkey_pem, key_pem)   
    
    def test_check_badge2_testkey(self):
        """ Key in config.ini are the same that the key in the test folder """
        
        cf = ConfParser('./config1.ini')
        conf = cf.read_conf()
        badge = Badge.create_from_conf(conf, 'badge_test_2')
        with open(conf['badge_test_2']['public_key'], 'rb') as f:
            key_pem = f.read()
        self.assertEqual(badge.pubkey_pem, key_pem)   
        
    def test_check_badge3_testkey(self):
        """ Key in config.ini are the same that the key in the test folder """
        
        cf = ConfParser('./config1.ini')
        conf = cf.read_conf()
        badge = Badge.create_from_conf(conf, 'badge_test_3')
        with open(conf['badge_test_3']['public_key'], 'rb') as f:
            key_pem = f.read()
        self.assertEqual(badge.pubkey_pem, key_pem)   
        
    def test_check_badge4_testkey(self):
        """ Key in config.ini are the same that the key in the test folder """
        
        cf = ConfParser('./config1.ini')
        conf = cf.read_conf()
        badge = Badge.create_from_conf(conf, 'badge_test_4')
        with open(conf['badge_test_4']['public_key'], 'rb') as f:
            key_pem = f.read()
        self.assertEqual(badge.pubkey_pem, key_pem)   

class check_signer(unittest.TestCase):
    @classmethod
    def setUpClass(cls) :
        cf = ConfParser('./config1.ini')
        cls.conf = cf.read_conf()
        cls.sign = signer.Signer()        
        
    def test_signer_uid_generation(self):
        """ Testing Serial Number generation """
        
        uid = self.sign.generate_uid()
        self.assertEqual(len(uid), 40)
