import unittest
from unittest.mock import Mock, patch, mock_open, call

import functools, hashlib
import json

import test_common

from openbadgeslib import signer
from openbadgeslib.errors import UnknownKeyType
from openbadgeslib.confparser import ConfParser
from openbadgeslib.util import md5_string

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

    def test_sign_svg_with_xml_header(self):
        with open('withxmlheader.svg','rb') as f:
                svg_in = f.read()
        assertion = b'<openbadges:assertion verify="ASSERTION_TEST" xmlns:openbadges="http://openbadges.org"/>'
        svg_out = self.signer.sign_svg(svg_in, assertion)
        self.assertEqual(md5_string(svg_out.encode('utf-8')), b'f3e54fb6157f0b4f9e4a45a5e90ee140')

    def test_sign_svg_without_xml_header(self):
        """ xml.dom.minidom add always <xml ...> tag at output... :-? """
        with open('withoutxmlheader.svg','rb') as f:
                svg_in = f.read()
        assertion = b'<openbadges:assertion verify="ASSERTION_TEST" xmlns:openbadges="http://openbadges.org"/>'
        svg_out = self.signer.sign_svg(svg_in, assertion)
        self.assertEqual(md5_string(svg_out.encode('utf-8')), b'f3e54fb6157f0b4f9e4a45a5e90ee140')

    def test_sign_big_header(self):
        """ SVG problem reported by Julio Antonio Soto """
        with open('userimage01.svg','rb') as f:
                svg_in = f.read()
        assertion = b'<openbadges:assertion verify="ASSERTION_TEST" xmlns:openbadges="http://openbadges.org"/>'
        svg_out = self.signer.sign_svg(svg_in, assertion)
        self.assertEqual(md5_string(svg_out.encode('utf-8')), b'bbca55bddb426825197dd713435d9259')
