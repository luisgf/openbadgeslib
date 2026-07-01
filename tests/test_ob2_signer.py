"""Tests for the strict OpenBadges 2.0 signer (openbadgeslib.ob2.signer)."""
from datetime import datetime, timezone

import pytest

from openbadgeslib._jws import utils as jws_utils
from openbadgeslib.ob2 import (
    OB2Signer, OB2Verifier, Assertion, IdentityObject, Verification,
)


def _signed_assertion(image='https://example.com/badge.svg'):
    return Assertion(
        recipient=IdentityObject.create('recipient@example.com', salt='s4lt3d'),
        badge='https://example.com/badge.json',
        verification=Verification(type='SignedBadge',
                                  creator='https://example.com/key.json'),
        issued_on=datetime(2026, 1, 1, tzinfo=timezone.utc),
        image=image,
    )


def _decode_payload(token):
    return jws_utils.decode(token.split('.')[1].encode('ascii'))


class TestSignPayloadShape:
    def test_payload_is_strict_ob2(self, rsa_priv_pem):
        signer = OB2Signer(privkey_pem=rsa_priv_pem, algorithm='RS256')
        token = signer.sign(_signed_assertion())
        body = _decode_payload(token)
        assert body['@context'] == 'https://w3id.org/openbadges/v2'
        assert body['type'] == 'Assertion'
        assert body['id'].startswith('urn:uuid:')
        assert body['recipient']['hashed'] is True
        assert body['issuedOn'] == '2026-01-01T00:00:00Z'
        assert body['verification']['type'] == 'SignedBadge'
        assert 'uid' not in body and 'verify' not in body

    def test_unsupported_algorithm_rejected(self, rsa_priv_pem):
        with pytest.raises(ValueError):
            OB2Signer(privkey_pem=rsa_priv_pem, algorithm='HS256')


class TestSignRoundTripSVG:
    @pytest.mark.parametrize('key_fixture,pub_fixture,alg', [
        ('rsa_priv_pem', 'rsa_pub_pem', 'RS256'),
        ('ecc_priv_pem', 'ecc_pub_pem', 'ES256'),
        ('ed25519_priv_pem', 'ed25519_pub_pem', 'EdDSA'),
    ])
    def test_sign_bake_extract_verify_svg(self, request, svg_image, key_fixture, pub_fixture, alg):
        priv = request.getfixturevalue(key_fixture)
        pub = request.getfixturevalue(pub_fixture)
        signer = OB2Signer(privkey_pem=priv, algorithm=alg)
        baked = signer.sign_into_svg(_signed_assertion(), svg_image)
        token = OB2Verifier.extract_token_from_svg(baked)
        result = OB2Verifier(pubkey_pem=pub).verify(
            token, expected_recipient='recipient@example.com')
        assert result.verification.type == 'SignedBadge'


class TestSignRoundTripPNG:
    @pytest.mark.parametrize('key_fixture,pub_fixture,alg', [
        ('rsa_priv_pem', 'rsa_pub_pem', 'RS256'),
        ('ecc_priv_pem', 'ecc_pub_pem', 'ES256'),
    ])
    def test_sign_bake_extract_verify_png(self, request, png_image, key_fixture, pub_fixture, alg):
        priv = request.getfixturevalue(key_fixture)
        pub = request.getfixturevalue(pub_fixture)
        signer = OB2Signer(privkey_pem=priv, algorithm=alg)
        baked = signer.sign_into_png(
            _signed_assertion(image='https://example.com/badge.png'), png_image)
        token = OB2Verifier.extract_token_from_png(baked)
        result = OB2Verifier(pubkey_pem=pub).verify(token)
        assert result.verification.type == 'SignedBadge'


class TestSignHosted:
    def test_hosted_assertion_keeps_url_id(self, rsa_priv_pem, svg_image):
        hosted = Assertion(
            id='https://example.com/assertions/abc.json',
            recipient=IdentityObject.create('r@example.com', salt='s'),
            badge='https://example.com/badge.json',
            verification=Verification(type='HostedBadge'),
            issued_on=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        signer = OB2Signer(privkey_pem=rsa_priv_pem, algorithm='RS256')
        token = OB2Verifier.extract_token_from_svg(signer.sign_into_svg(hosted, svg_image))
        body = _decode_payload(token)
        assert body['id'] == 'https://example.com/assertions/abc.json'
        assert body['verification'] == {'type': 'HostedBadge'}
