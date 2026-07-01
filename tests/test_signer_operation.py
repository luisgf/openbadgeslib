import unittest

import pytest

from openbadgeslib import signer
from openbadgeslib.signer import Signer
from openbadgeslib.confparser import ConfParser
from openbadgeslib.keys import KeyType
from openbadgeslib.openbadges_signer import _safe_filename_component
from openbadgeslib.badge import (Badge, BadgeType, BadgeImgType, Assertion,
                                 BadgeSigned, extract_svg_assertion,
                                 extract_png_assertion)
from openbadgeslib.errors import ErrorSigningFile, PrivateKeyReadError, PublicKeyReadError


class check_badge(unittest.TestCase):
    def test_check_testconf(self):
        """ Badge entry in config.ini """

        cf = ConfParser('./config1.ini')
        self.assertIsInstance(cf, ConfParser)
        conf = cf.read_conf()
        self.assertIsNotNone(conf)

    def test_badge_object_creation(self):
        """ Badge object creation """

        badge = Badge()
        self.assertIsInstance(badge, Badge)

    def test_assertion_creation(self):
        """ Test Assertion Object creation """

        assertion = Assertion()
        self.assertIsInstance(assertion, Assertion)

    def test_badgesigned_creation(self):
        """ Test BadgeSigned object creation """

        badge = BadgeSigned()
        self.assertIsInstance(badge, BadgeSigned)

    def test_badge_creation(self):
        """ Test Manual Badge creation """

        badge = Badge(ini_name='badge_test_1',
                      name='OpenBadgesLib TEST SVG RSA Badge',
                      description='TEST SVG RSA Badge',
                      image_type=BadgeImgType.SVG,
                      image=None,
                      image_url='https://openbadges.luisgf.es/issuer/badge_1/badge.svg',
                      criteria_url='https://openbadges.luisgf.es/issuer/badge_1/criteria.html',
                      json_url='https://openbadges.luisgf.es/issuer/badge_1/badge.json',
                      verify_key_url='https://openbadges.luisgf.es/issuer/badge_1/verify_rsa_key.pem',
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

    def test_assertion_decoding(self):
        """ Test the assertion decoding and reconstruct """

        payload = b'IkhFQURFUiI.IkJPRFki.IlNJR05BVFVSRSI'
        decode = Assertion.decode(payload)
        self.assertIsInstance(decode, Assertion)

    def test_decode_jws_header(self):
        payload = b'IkhFQURFUiI.IkJPRFki.IlNJR05BVFVSRSI'
        decode = Assertion.decode(payload)
        self.assertEqual(decode.decode_header(), 'HEADER')

    def test_decode_jws_body(self):
        payload = b'IkhFQURFUiI.IkJPRFki.IlNJR05BVFVSRSI'
        decode = Assertion.decode(payload)
        self.assertEqual(decode.decode_body(), 'BODY')

    def test_get_complete_assertion(self):
        payload = b'IkhFQURFUiI.IkJPRFki.IlNJR05BVFVSRSI'
        decode = Assertion.decode(payload)
        self.assertEqual(decode.get_assertion(), payload)


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


# ── pytest-style tests using session fixtures from conftest.py ─────────────────


class TestCreateFromConfMissingKeyFile:
    """create_from_conf() must not leak a raw FileNotFoundError/OSError when a
    configured key path is missing — it must raise the same LibOpenBadgesException
    subclass Badge.__init__ already raises for corrupt-but-present key material."""

    def test_missing_private_key_file_raises_clean_error(self):
        cf = ConfParser('./config1.ini')
        conf = cf.read_conf()
        conf['badge_test_1']['private_key'] = '/nonexistent/priv.pem'
        with pytest.raises(PrivateKeyReadError):
            Badge.create_from_conf(conf, 'badge_test_1')

    def test_missing_public_key_file_raises_clean_error(self):
        cf = ConfParser('./config1.ini')
        conf = cf.read_conf()
        conf['badge_test_1']['public_key'] = '/nonexistent/pub.pem'
        with pytest.raises(PublicKeyReadError):
            Badge.create_from_conf(conf, 'badge_test_1')


class TestSignBadgeRoundTrip:
    """Full sign → extract → compare cycle for each badge type."""

    def _fresh_signer(self, identity='test@example.com'):
        return Signer(identity=identity, badge_type=BadgeType.SIGNED, deterministic=True)

    def test_sign_svg_rsa_embeds_assertion(self, svg_rsa_badge):
        signed = self._fresh_signer().sign_badge(svg_rsa_badge)
        assert signed.signed is not None
        assert signed.get_assertion() is not None

    def test_signed_assertion_verifies_against_pubkey(self, svg_rsa_badge):
        # End-to-end: the embedded assertion must actually verify with the
        # matching public key, not merely exist.
        from openbadgeslib.verifier import Verifier
        from openbadgeslib.badge import BadgeStatus
        signed = self._fresh_signer().sign_badge(svg_rsa_badge)
        v = Verifier(verify_key=svg_rsa_badge.pubkey_pem)
        assert v.check_jws_signature(signed).status is BadgeStatus.VALID

    def test_sign_svg_ecc_embeds_assertion(self, svg_ecc_badge):
        signed = self._fresh_signer().sign_badge(svg_ecc_badge)
        assert signed.signed is not None
        assert signed.get_assertion() is not None

    def test_sign_png_rsa_embeds_assertion(self, png_rsa_badge):
        signed = self._fresh_signer().sign_badge(png_rsa_badge)
        assert signed.signed is not None
        assert len(signed.signed) > len(png_rsa_badge.image)

    def test_sign_png_ecc_embeds_assertion(self, png_ecc_badge):
        signed = self._fresh_signer().sign_badge(png_ecc_badge)
        assert signed.signed is not None
        assert len(signed.signed) > len(png_ecc_badge.image)

    def test_svg_assertion_survives_roundtrip(self, svg_rsa_badge):
        signed = self._fresh_signer().sign_badge(svg_rsa_badge)
        extracted = extract_svg_assertion(signed.signed)
        assert extracted.get_assertion() == signed.assertion.get_assertion()

    def test_png_assertion_survives_roundtrip(self, png_rsa_badge):
        signed = self._fresh_signer().sign_badge(png_rsa_badge)
        extracted = extract_png_assertion(signed.signed)
        assert extracted.get_assertion() == signed.assertion.get_assertion()

    def test_deterministic_produces_same_payload(self, svg_rsa_badge):
        s1 = self._fresh_signer().sign_badge(svg_rsa_badge)
        s2 = self._fresh_signer().sign_badge(svg_rsa_badge)
        b1 = s1.assertion.decode_body()
        b2 = s2.assertion.decode_body()
        assert b1['uid'] == b2['uid']
        assert b1['issuedOn'] == b2['issuedOn']

    def test_non_deterministic_produces_different_serial_nums(self, svg_rsa_badge):
        s1 = Signer(identity='a@b.com', badge_type=BadgeType.SIGNED, deterministic=False)
        s2 = Signer(identity='a@b.com', badge_type=BadgeType.SIGNED, deterministic=False)
        r1 = s1.sign_badge(svg_rsa_badge)
        r2 = s2.sign_badge(svg_rsa_badge)
        assert r1.serial_num != r2.serial_num


class TestHasAssertion:
    def test_unsigned_svg_has_no_assertion(self, svg_rsa_badge):
        s = Signer(identity='a@b.com', badge_type=BadgeType.SIGNED)
        assert s.has_assertion(svg_rsa_badge) is False

    def test_unsigned_png_has_no_assertion(self, png_rsa_badge):
        s = Signer(identity='a@b.com', badge_type=BadgeType.SIGNED)
        assert s.has_assertion(png_rsa_badge) is False

    def test_signed_svg_has_assertion(self, signed_svg_rsa, svg_rsa_badge):
        # Construct a Badge whose image is the signed SVG content
        from openbadgeslib.badge import Badge
        from openbadgeslib.keys import KeyType
        badge_with_sig = Badge(
            image_type=BadgeImgType.SVG,
            image=signed_svg_rsa.signed,
            key_type=KeyType.RSA,
        )
        s = Signer(identity='a@b.com', badge_type=BadgeType.SIGNED)
        assert s.has_assertion(badge_with_sig) is True

    def test_signed_png_has_assertion(self, signed_png_rsa, png_rsa_badge):
        from openbadgeslib.badge import Badge
        from openbadgeslib.keys import KeyType
        badge_with_sig = Badge(
            image_type=BadgeImgType.PNG,
            image=signed_png_rsa.signed,
            key_type=KeyType.RSA,
        )
        s = Signer(identity='a@b.com', badge_type=BadgeType.SIGNED)
        assert s.has_assertion(badge_with_sig) is True


class TestSignAlreadySigned:
    def test_signing_signed_svg_raises(self, signed_svg_rsa, svg_rsa_badge):
        from openbadgeslib.badge import Badge
        from openbadgeslib.keys import KeyType
        badge_with_sig = Badge(
            image_type=BadgeImgType.SVG,
            image=signed_svg_rsa.signed,
            key_type=KeyType.RSA,
        )
        s = Signer(identity='a@b.com', badge_type=BadgeType.SIGNED)
        with pytest.raises(ErrorSigningFile):
            s.sign_badge(badge_with_sig)

    def test_signing_signed_png_raises(self, signed_png_rsa):
        from openbadgeslib.badge import Badge
        from openbadgeslib.keys import KeyType
        badge_with_sig = Badge(
            image_type=BadgeImgType.PNG,
            image=signed_png_rsa.signed,
            key_type=KeyType.RSA,
        )
        s = Signer(identity='a@b.com', badge_type=BadgeType.SIGNED)
        with pytest.raises(ErrorSigningFile):
            s.sign_badge(badge_with_sig)


class TestSignerOutputFilenameValidation:
    @pytest.mark.parametrize('value', [
        'badge_1',
        'recipient@example.com',
        'recipient+label@example.com',
    ])
    def test_safe_filename_component_accepts_plain_values(self, value):
        assert _safe_filename_component(value, 'field') == value

    @pytest.mark.parametrize('value', [
        '',
        '.',
        '..',
        '../recipient@example.com',
        'recipient/../../outside',
        r'recipient\outside',
        'C:recipient',
        'recipient\x00@example.com',
    ])
    def test_safe_filename_component_rejects_path_values(self, value):
        with pytest.raises(ValueError):
            _safe_filename_component(value, 'field')


class TestSignMalformedImage:
    """Malformed carrier images must raise ErrorSigningFile, not a raw
    baking-library exception (mirrors ob2/badge.py's extract_*_assertion)."""

    def test_has_svg_assertion_on_non_xml_raises_error_signing_file(self):
        badge = Badge(image_type=BadgeImgType.SVG, image=b'not even xml <<<', key_type=KeyType.RSA)
        s = Signer(identity='a@b.com', badge_type=BadgeType.SIGNED)
        with pytest.raises(ErrorSigningFile):
            s.has_assertion(badge)

    def test_has_png_assertion_on_non_png_raises_error_signing_file(self):
        badge = Badge(image_type=BadgeImgType.PNG, image=b'not a png at all', key_type=KeyType.RSA)
        s = Signer(identity='a@b.com', badge_type=BadgeType.SIGNED)
        with pytest.raises(ErrorSigningFile):
            s.has_assertion(badge)

    def test_sign_svg_without_svg_root_raises_error_signing_file(self, rsa_priv_pem, rsa_pub_pem):
        # Well-formed XML but no <svg> root: has_svg_assertion succeeds (no
        # baked assertion found), but bake_svg itself fails since there is
        # no <svg> element to attach the assertion to.
        badge = Badge(
            image_type=BadgeImgType.SVG,
            image=b'<?xml version="1.0"?><root><child/></root>',
            key_type=KeyType.RSA,
            privkey_pem=rsa_priv_pem,
            pubkey_pem=rsa_pub_pem,
        )
        s = Signer(identity='a@b.com', badge_type=BadgeType.SIGNED, deterministic=True)
        with pytest.raises(ErrorSigningFile):
            s.sign_badge(badge)
