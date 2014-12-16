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
        cls.signer.receptor = b'test@test.es'
        cls.signer.verify_key_url = 'https://url.notexists/verify_test.pem'
        cls.signer.badge_image_url = 'https://url.notexists/image.svg'
        cls.signer.badge_json_url = 'https://url.notexists/badge.json'
        cls.signer.deterministic = True

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
        payload = self.signer.generate_jws_payload()
        payload_json = json.dumps(payload, sort_keys=True)
        self.assertEqual(payload_json, '{"badge": "https://url.notexists/badge.json", "image": "https://url.notexists/image.svg", "issuedOn": 0, "recipient": {"hashed": "true", "identity": "sha256$7ed8851c0477a4b8a2673e695d251d4a5018cf57fc8cc7307c96698bee960429", "salt": "s4lt3d", "type": "email"}, "uid": 0, "verify": {"type": "signed", "url": "https://url.notexists/verify_test.pem"}}')

    def test_rsa_assertion_generation(self):
        self.signer = signer.SignerRSA()
        with open('test_sign_rsa.pem') as f:
            priv_key = f.read()

        with open('test_verify_rsa.pem') as f:
            pub_key = f.read()

        assertion = self.signer.generate_openbadge_assertion(priv_key, pub_key)
        self.assertEqual(assertion, b'eyJhbGciOiAiUlMyNTYifQ.eyJyZWNpcGllbnQiOiB7ImlkZW50aXR5IjogInNoYTI1NiRlMTEzNDA5YTA5ZWM0ZDg1NWFiMTQzNWU2NWU4Y2E3YjE4MGI3Y2FkYzZkYWZjOWEwNTZiNDZlZGZiNTEyZDgxIiwgImhhc2hlZCI6ICJ0cnVlIiwgInNhbHQiOiAiOTNlZGM1OTE1MTI2YWY3ODA4Njc1ZjNmN2ZjYWY2ZDQiLCAidHlwZSI6ICJlbWFpbCJ9LCAidmVyaWZ5IjogeyJ1cmwiOiBudWxsLCAidHlwZSI6ICJzaWduZWQifSwgImlzc3VlZE9uIjogMTQxODc2MDg3NCwgImJhZGdlIjogbnVsbCwgImltYWdlIjogbnVsbCwgInVpZCI6ICIwYzczM2UxMmM2YTkxOWM4NDU0MDAxZmEzMDI2YWVkZGRlNzY0YzNiIn0.vuZ8YTFHzxYx7mgn899HM4jZen33lqqvftw0d1SS39-AcUGSg0Sc-3wGz4cDcIOqzjiIN28Ntfyot-wLuN9Vnhr-nWWWZCw5-vssklsQB0hGyNBeRlAHEQNFoKzahd0MDTc6L3b8ynDuU3M2PG4b2LpXkq3uduq8MOz-DSLE0Xat1bgL3hhGZT55vMbIGhPQCPOJQJ67MeeL0cJaMhDl6orBM6AVxUEBBzvEb4jxxvf0BAJA2eDB4dGVTkU7BMJMZIe5Y-xraNgkOqG59-j0XzryP81YDZgyUdf9etbNtHebxQ8CXNMlhSHOLKTjhzMYmWxiiMKNNMZFw6D6AL_nWA')