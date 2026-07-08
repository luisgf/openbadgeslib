"""#169 — targeted error-branch coverage for the OB 2.0 signer and verifier
(the crypto-sensitive paths). Offline: no branch here touches the network.
"""
import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from openbadgeslib._jws import utils as jws_utils
from openbadgeslib.ob2 import (Assertion, IdentityObject, OB2Signer,
                               OB2Verifier, OB2VerificationError, Verification)
from openbadgeslib.errors import ErrorParsingFile, ErrorSigningFile


def _assertion(**kw):
    base = dict(
        recipient=IdentityObject.create('r@example.com', salt='s'),
        badge='https://example.com/badge.json',
        verification=Verification(type='SignedBadge',
                                  creator='https://example.com/key.json'))
    base.update(kw)
    return Assertion(**base)


def _token(priv_pem, **kw):
    return OB2Signer(privkey_pem=priv_pem, algorithm='RS256').sign(_assertion(**kw))


# ── OB2Signer error wrappers ─────────────────────────────────────────────────

class TestSignerErrors:
    def test_sign_with_unusable_key_raises(self):
        with pytest.raises(ErrorSigningFile, match='Could not sign'):
            OB2Signer(privkey_pem=b'-----BEGIN PRIVATE KEY-----\nnope\n',
                      algorithm='RS256').sign(_assertion())

    def test_sign_into_svg_bad_image_raises(self, rsa_priv_pem):
        with pytest.raises(ErrorSigningFile, match='SVG'):
            OB2Signer(privkey_pem=rsa_priv_pem,
                      algorithm='RS256').sign_into_svg(_assertion(), b'not svg')

    def test_sign_into_png_bad_image_raises(self, rsa_priv_pem):
        with pytest.raises(ErrorSigningFile, match='PNG'):
            OB2Signer(privkey_pem=rsa_priv_pem,
                      algorithm='RS256').sign_into_png(_assertion(), b'not png')


# ── OB2Verifier decode / structure errors ───────────────────────────────────

class TestVerifierDecode:
    def test_token_not_three_parts(self, rsa_pub_pem):
        with pytest.raises(OB2VerificationError, match='Malformed JWS'):
            OB2Verifier(pubkey_pem=rsa_pub_pem).verify('only.two')

    def test_token_bad_payload_base64(self, rsa_pub_pem):
        with pytest.raises(OB2VerificationError, match='Malformed JWS payload'):
            OB2Verifier(pubkey_pem=rsa_pub_pem).verify('aGVhZA.@@@.c2ln')

    def test_payload_not_a_valid_assertion(self, rsa_pub_pem):
        # header.payload.sig with an empty-object payload: decodes, but is not a
        # conformant Assertion → "Malformed OB 2.0 assertion".
        token = b'.'.join([jws_utils.encode({'alg': 'RS256'}),
                           jws_utils.encode({}),
                           jws_utils.to_base64(b'sig')]).decode('ascii')
        with pytest.raises(OB2VerificationError, match='Malformed OB 2.0 assertion'):
            OB2Verifier(pubkey_pem=rsa_pub_pem).verify(token)


# ── OB2Verifier semantic checks (trusted key, no network) ────────────────────

class TestVerifierChecks:
    def test_expired_assertion(self, rsa_priv_pem, rsa_pub_pem):
        token = _token(rsa_priv_pem,
                       expires=datetime(2000, 1, 1, tzinfo=timezone.utc))
        with pytest.raises(OB2VerificationError, match='expired'):
            OB2Verifier(pubkey_pem=rsa_pub_pem).verify(token, check_revocation=False)

    def test_not_yet_valid_assertion(self, rsa_priv_pem, rsa_pub_pem):
        token = _token(rsa_priv_pem,
                       issued_on=datetime(2999, 1, 1, tzinfo=timezone.utc))
        with pytest.raises(OB2VerificationError, match='not yet valid'):
            OB2Verifier(pubkey_pem=rsa_pub_pem).verify(token, check_revocation=False)

    def test_recipient_mismatch(self, rsa_priv_pem, rsa_pub_pem):
        token = _token(rsa_priv_pem)
        with pytest.raises(OB2VerificationError, match='Recipient mismatch'):
            OB2Verifier(pubkey_pem=rsa_pub_pem).verify(
                token, expected_recipient='other@example.com',
                check_revocation=False)

    def test_bad_signature(self, rsa_priv_pem, ecc_pub_pem):
        # A token signed with the RSA key but verified against an unrelated key.
        token = _token(rsa_priv_pem)
        with pytest.raises(OB2VerificationError, match='signature'):
            OB2Verifier(pubkey_pem=ecc_pub_pem).verify(token, check_revocation=False)


# ── token extraction errors ──────────────────────────────────────────────────

class TestExtractErrors:
    def test_svg_unparseable(self):
        with pytest.raises(ErrorParsingFile, match='Could not parse SVG'):
            OB2Verifier.extract_token_from_svg(b'<svg><unclosed')

    def test_svg_without_assertion(self, svg_image):
        with pytest.raises(OB2VerificationError, match='No openbadges'):
            OB2Verifier.extract_token_from_svg(svg_image)

    def test_png_unparseable(self):
        with pytest.raises(ErrorParsingFile, match='Could not parse PNG'):
            OB2Verifier.extract_token_from_png(b'not a png at all')

    def test_png_without_itxt(self, png_image):
        with pytest.raises(OB2VerificationError, match='No openbadges'):
            OB2Verifier.extract_token_from_png(png_image)


# ── network fetch + revocation branches (download_file mocked) ───────────────

class TestFetchAndRevocation:
    def _fetch(self, rsa_pub_pem, url='https://x/doc.json', **patch_kw):
        v = OB2Verifier(pubkey_pem=rsa_pub_pem)
        with patch('openbadgeslib.ob2.verifier.download_file', **patch_kw):
            v._fetch_json(url, 'thing')

    def test_fetch_download_error(self, rsa_pub_pem):
        with pytest.raises(OB2VerificationError, match='Could not fetch'):
            self._fetch(rsa_pub_pem, side_effect=OSError('boom'))

    def test_fetch_empty(self, rsa_pub_pem):
        with pytest.raises(OB2VerificationError, match='Empty'):
            self._fetch(rsa_pub_pem, return_value=b'')

    def test_fetch_not_json(self, rsa_pub_pem):
        with pytest.raises(OB2VerificationError, match='not valid JSON'):
            self._fetch(rsa_pub_pem, return_value=b'not json')

    def test_fetch_not_object(self, rsa_pub_pem):
        with pytest.raises(OB2VerificationError, match='not a JSON object'):
            self._fetch(rsa_pub_pem, return_value=b'[1, 2, 3]')

    def test_revocation_list_not_a_string(self, rsa_priv_pem, rsa_pub_pem):
        token = _token(rsa_priv_pem)

        def dl(url, *a, **k):
            # BadgeClass carries an embedded issuer Profile with a bad type.
            return json.dumps(
                {'issuer': {'id': 'https://i', 'revocationList': 123}}).encode()

        with patch('openbadgeslib.ob2.verifier.download_file', side_effect=dl):
            with pytest.raises(OB2VerificationError,
                               match='revocationList must be a string'):
                OB2Verifier(pubkey_pem=rsa_pub_pem).verify(
                    token, check_revocation=True)

    def test_revoked_assertion_is_rejected(self, rsa_priv_pem, rsa_pub_pem):
        token = _token(rsa_priv_pem, id='urn:uuid:revoked-1')

        def dl(url, *a, **k):
            if url.endswith('badge.json'):
                return json.dumps({'issuer': 'https://i/issuer.json'}).encode()
            if url.endswith('issuer.json'):
                return json.dumps({'id': 'https://i/issuer.json',
                                   'revocationList': 'https://i/rev.json'}).encode()
            return json.dumps(
                {'revokedAssertions': [{'id': 'urn:uuid:revoked-1',
                                        'revocationReason': 'test'}]}).encode()

        with patch('openbadgeslib.ob2.verifier.download_file', side_effect=dl):
            with pytest.raises(OB2VerificationError, match='revoked'):
                OB2Verifier(pubkey_pem=rsa_pub_pem).verify(
                    token, check_revocation=True)
