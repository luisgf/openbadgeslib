"""Hostile input: a verifier handed attacker-controlled JSON answers with the
library's typed failure, never a bare RecursionError / UnicodeEncodeError /
OverflowError / TypeError.

Every case here is a document or token that parses (so the parser's own errors
do not cover it) and whose signature is never reached: the failure is
unauthenticated. Each test names the shape that used to escape. See
openbadgeslib/_safejson.py for the bound the parsers share.
"""
import json
from pathlib import Path

import pytest

from openbadgeslib import baking
from openbadgeslib._jws import utils as jws_utils
from openbadgeslib._jws import verify_block
from openbadgeslib._jws.exceptions import SignatureError

TESTS_DIR = Path(__file__).parent

#: Deep enough to exceed json.loads' recursion limit before Python 3.14 and the
#: shared bound everywhere; 3.14+ parses it, and then the bound is what answers.
DEEP = 2000
#: Past what even Python 3.14's C-stack parser takes.
DEEPER = 200000


def _b64(raw: bytes) -> str:
    return jws_utils.base64url_encode(raw).decode('ascii')


def _nested(depth: int, bracket: str = '[') -> str:
    closer = ']' if bracket == '[' else '}'
    return bracket * depth + closer * depth


def _unsigned_token(header, payload, signature=b'\x00' * 64) -> str:
    """A compact JWS whose segments are raw JSON text (so they can be hostile)."""
    def segment(part):
        return _b64(part if isinstance(part, bytes) else json.dumps(part).encode())
    return '%s.%s.%s' % (segment(header), segment(payload), _b64(signature))


def _bake_svg(token: str, tmp_path, name='badge.svg') -> str:
    svg = (TESTS_DIR / 'withoutxmlheader.svg').read_bytes()
    path = tmp_path / name
    path.write_bytes(baking.bake_svg(svg, token))
    return str(path)


# ── native JWS engine (OB1 and OB2 signed badges) ─────────────────────────────

class TestJwsHeader:
    """F3: _jws.verify_block caught ValueError/TypeError around the header
    decode, so a header nested past the parser's recursion limit escaped."""

    @pytest.mark.parametrize('depth', [DEEP, DEEPER])
    def test_nested_header_is_a_signature_error(self, ecc_pub_pem, depth):
        header = b'{"alg":"ES256","x":' + _nested(depth).encode() + b'}'
        with pytest.raises(SignatureError, match='Malformed JWS header'):
            verify_block(_unsigned_token(header, {'a': 1}), ecc_pub_pem)

    @pytest.mark.parametrize('header', [
        b'{"alg":"ES256","x":"\\ud800"}',      # a lone surrogate
        b'{"alg":"ES256","x":1e999}',          # Infinity
        b'{"alg":"ES256","crit":' + _nested(DEEP).encode() + b'}',
    ], ids=['surrogate', 'infinity', 'nested-crit'])
    def test_unrepresentable_header_is_a_signature_error(self, ecc_pub_pem, header):
        with pytest.raises(SignatureError):
            verify_block(_unsigned_token(header, {'a': 1}), ecc_pub_pem)

    def test_token_with_a_lone_surrogate_is_a_signature_error(self, ecc_pub_pem):
        with pytest.raises(SignatureError, match='Malformed JWS'):
            verify_block('\ud800.e30.e30', ecc_pub_pem)


def _ob2_token_with_header(priv_pem, header: bytes) -> str:
    """A well-formed, signed OB 2.0 SignedBadge whose protected header is
    swapped for *header* (the signature then no longer matters: it is never
    reached)."""
    from datetime import datetime, timezone
    from openbadgeslib.ob2 import (Assertion, IdentityObject, OB2Signer,
                                   Verification)
    assertion = Assertion(
        recipient=IdentityObject.create('r@example.com', salt='s4lt3d'),
        badge='https://example.com/badge.json',
        verification=Verification(type='SignedBadge',
                                  creator='https://example.com/key.json'),
        issued_on=datetime(2026, 1, 1, tzinfo=timezone.utc))
    token = OB2Signer(privkey_pem=priv_pem, algorithm='RS256').sign(assertion)
    _, payload, signature = token.split('.')
    return '%s.%s.%s' % (_b64(header), payload, signature)


class TestOB2Signed:
    def test_nested_header_is_a_verification_error(self, rsa_priv_pem, rsa_pub_pem):
        from openbadgeslib.ob2 import OB2VerificationError, OB2Verifier
        header = b'{"alg":"RS256","x":' + _nested(DEEPER).encode() + b'}'
        token = _ob2_token_with_header(rsa_priv_pem, header)
        with pytest.raises(OB2VerificationError):
            OB2Verifier(pubkey_pem=rsa_pub_pem).verify(token)

    def test_verify_badge_reports_it_as_invalid(self, rsa_priv_pem, rsa_pub_pem):
        from openbadgeslib.verify import verify_badge
        header = b'{"alg":"RS256","x":' + _nested(DEEPER).encode() + b'}'
        svg = (TESTS_DIR / 'withoutxmlheader.svg').read_bytes()
        data = baking.bake_svg(svg, _ob2_token_with_header(rsa_priv_pem, header))
        result = verify_badge(data, '2', pubkey_pem=rsa_pub_pem)
        assert result.valid is False


class TestOB1Signature:
    def test_nested_header_is_a_signature_error(self, badge_for_verify_rsa):
        from openbadgeslib.ob1.badge import BadgeStatus
        from openbadgeslib.ob1.verifier import Verifier
        badge, identity = badge_for_verify_rsa
        badge.assertion.header = _b64(
            b'{"alg":"RS256","x":' + _nested(DEEPER).encode() + b'}').encode()
        result = Verifier(identity=identity).check_jws_signature(badge)
        assert result.status is BadgeStatus.SIGNATURE_ERROR
