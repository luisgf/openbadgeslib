import unittest
from unittest.mock import Mock, patch, mock_open, call

import functools, hashlib
import json

import test_common

from openbadgeslib import signer
from openbadgeslib.errors import UnknownKeyType
from openbadgeslib.confparser import ConfParser

class check_signer_factory(unittest.TestCase) :               
    def test_rsa(self) :
        sign = signer.SignerFactory('RSA')
        self.assertIsInstance(sign, signer.SignerRSA)

    def test_ec(self) :
        sign = signer.SignerFactory('ECC')
        self.assertIsInstance(sign, signer.SignerECC)

    def test_unknown(self) :
        self.assertRaises(UnknownKeyType, signer.SignerFactory, 'XXX')
        
class check_signer_methods(unittest.TestCase):
    maxDiff = None
    
    @classmethod
    def setUpClass(cls) :
        cls.signer = signer.SignerBase()
        cls.signer._receptor = b'test@test.es'
        cls.signer._verify_key_url = 'https://url.notexists/verify_test.pem'
        cls.signer._badge_image_url = 'https://url.notexists/image.svg'
        cls.signer._badge_json_url = 'https://url.notexists/badge.json'
        
    def test_signer_uid_generation(self):
        uid = self.signer.generate_uid()
        self.assertEqual(len(uid), 40)
    
    def test_generate_output_filename(self):
        out = self.signer.generate_output_filename('badge.svg','/tmp/','test@test.es')
        self.assertEqual(out, '/tmp/badge_test_test_es.svg')
    
    def test_rsa_jose_header(self):        
        jose = signer.SignerRSA().generate_jose_header()
        jose_json = json.dumps(jose, sort_keys=True)
        self.assertEqual(jose_json, '{"alg": "RS256"}')
        
    def test_ecc_jose_header(self):        
        jose = signer.SignerECC().generate_jose_header()
        jose_json = json.dumps(jose, sort_keys=True)
        self.assertEqual(jose_json, '{"alg": "ES256"}')
    
    def test_payload_generation(self):
        payload = self.signer.generate_jws_payload(deterministic=True)
        payload_json = json.dumps(payload, sort_keys=True)
        self.assertEqual(payload_json, '{"badge": "https://url.notexists/badge.json",'+
        ' "image": "https://url.notexists/image.svg", "issuedOn": 0,'+
        ' "recipient": {"hashed": "true", "identity": "sha256$513e6874856ed5eb4d9adcb39171e1c1270bdc79cf5428d8f46b8940a0e4533a"'+
        ', "type": "email"}, "uid": 0, "verify": {"type": "signed", "url":'+
        ' "https://url.notexists/verify_test.pem"}}')

    def test_rsa_assertion_generation(self):
        self.signer = signer.SignerRSA()
        with open('test_sign_rsa.pem') as f:
            priv_key = f.read()
            
        with open('test_verify_rsa.pem') as f:
            pub_key = f.read()
        
        assertion = self.signer.generate_openbadge_assertion(priv_key, pub_key)
        self.assertEqual(assertion, b'eyJhbGciOiAiUlMyNTYifQ.eyJpc3N1ZWRPbiI6ID' +
        'E0MTgyMTEzOTYsICJ1aWQiOiAiZGFmMDFhODM3ZmQ2YzdiY2E1M2UyN2UxM2E0MDZlNzhi' +
        'YTAyMTJhMyIsICJ2ZXJpZnkiOiB7InVybCI6IG51bGwsICJ0eXBlIjogInNpZ25lZCJ9LC' +
        'AicmVjaXBpZW50IjogeyJoYXNoZWQiOiAidHJ1ZSIsICJ0eXBlIjogImVtYWlsIiwgImlk' +
        'ZW50aXR5IjogInNoYTI1NiRlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YW' +
        'U0MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1In0sICJiYWRnZSI6IG51bGwsICJpbWFn' +
        'ZSI6IG51bGx9.O6jzaCbRxRLXdsiLHLV7gkOKl-Q9BU2ZJozhsfcXG9qaPIykb4zMhteYb' +
        'uKZqozmW_Bm0ub10SLx0J_xxNSi79A28RTzjc4q5nQFKriE6DvnbcdfhRrHLbcWLHhpjwj' +
        '2Fa5ir2Sc7BDYwWHGZJfSb4PSRInDWe7psVLutH4YFz2Xa_4nTqcP7rBT2X-XV-KFrsL6l' +
        '8nI5UwZ001JCXiK9MTO9s87tS8sftvyDjubkWCcAkIspR4qxK6Vg8wt2lKifXSmZ9c-Dag' +
        'uWFJdMwn12RxgT0oNBzkWsn0hN_5sUmaYcexRs7ESDHMa7gd4IuW1JWN5Hxm8fOUkqUszD' +
        'T2zVg')
                
        