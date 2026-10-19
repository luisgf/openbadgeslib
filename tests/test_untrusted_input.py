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


# ── OB1 ──────────────────────────────────────────────────────────────────────

def _ob1_body(extra: str = '', **override) -> bytes:
    body = {'uid': 'a', 'recipient': {'identity': 'sha256$x', 'salt': 's'},
            'image': 'i', 'badge': 'b',
            'verify': {'url': 'https://127.0.0.1:1/k.pem'}, 'issuedOn': 1}
    body.update(override)
    text = json.dumps(body)
    if extra:
        text = text[:-1] + ', ' + extra + '}'
    return text.encode()


class TestOB1Body:
    """F5: BadgeSigned.read_from_file only mapped ValueError/TypeError around
    the body decode and (KeyError, TypeError, AttributeError) around the field
    reads, so a nested body (RecursionError) and a lone surrogate in the
    recipient (UnicodeEncodeError at .encode) escaped, and the CLI printed a
    traceback."""

    def _read(self, body: bytes, tmp_path):
        from openbadgeslib.ob1.badge import BadgeSigned
        token = _unsigned_token({'alg': 'RS256'}, body)
        return BadgeSigned.read_from_file(_bake_svg(token, tmp_path))

    @pytest.mark.parametrize('depth', [DEEP, DEEPER])
    def test_nested_body(self, tmp_path, depth):
        from openbadgeslib.errors import AssertionFormatIncorrect
        with pytest.raises(AssertionFormatIncorrect):
            self._read(_ob1_body('"a": ' + _nested(depth)), tmp_path)

    @pytest.mark.parametrize('field', ['identity', 'salt'])
    def test_lone_surrogate_in_the_recipient(self, tmp_path, field):
        from openbadgeslib.errors import AssertionFormatIncorrect
        recipient = {'identity': 'sha256$x', 'salt': 's', field: '\ud800'}
        with pytest.raises(AssertionFormatIncorrect):
            self._read(_ob1_body(recipient=recipient), tmp_path)

    @pytest.mark.parametrize('expires', ['1e999', '-1e999', 'NaN'])
    def test_expiry_that_is_not_a_finite_number(self, tmp_path, expires):
        from openbadgeslib.errors import AssertionFormatIncorrect
        with pytest.raises(AssertionFormatIncorrect):
            self._read(_ob1_body('"expires": ' + expires), tmp_path)

    def test_an_ordinary_body_still_reads(self, tmp_path):
        badge = self._read(_ob1_body('"expires": 1893456000'), tmp_path)
        assert badge.expiration == 1893456000
        assert badge.get_serial_num() == 'a'


class TestOB1Expiration:
    """F12: check_expiration formatted a long-expired timestamp with gmtime,
    which raises OverflowError for -1e300 or -10**30 -- after the signature
    verified, so get_badge_status (documented to return a VerifyInfo) raised."""

    @pytest.mark.parametrize('expires', [-1e300, -10 ** 30, -2 ** 70])
    def test_check_expiration_types_an_unformattable_timestamp(self, expires):
        from openbadgeslib.errors import AssertionFormatIncorrect
        from openbadgeslib.ob1.badge import BadgeSigned
        from openbadgeslib.ob1.verifier import Verifier
        with pytest.raises(AssertionFormatIncorrect, match='not a valid timestamp'):
            Verifier().check_expiration(BadgeSigned(expiration=expires))

    def test_get_badge_status_returns_a_verdict(self, badge_for_verify_rsa):
        from unittest.mock import patch
        from openbadgeslib.ob1.badge import BadgeStatus
        from openbadgeslib.ob1.verifier import Verifier
        badge, identity = badge_for_verify_rsa
        badge.expiration = -10 ** 30
        verifier = Verifier(identity=identity)
        with patch.object(Verifier, 'check_revocation', return_value=None):
            info = verifier.get_badge_status(badge)
        assert info.status is BadgeStatus.SIGNATURE_ERROR
        assert 'not a valid timestamp' in info.msg

    def test_an_expired_badge_is_still_reported_with_its_date(self):
        from openbadgeslib.ob1.badge import BadgeSigned
        from openbadgeslib.ob1.verifier import Verifier
        text = Verifier().check_expiration(BadgeSigned(expiration=86400))
        assert text == 'Fri, 02 Jan 1970 00:00:00 +0000'


class TestOB1RemoteDocuments:
    """The badge, issuer and revocation list an OB1 verifier fetches are parsed
    with the same bounded loader: a revocation reason nested 100 000 deep
    raised RecursionError from str(reason) on Python 3.14."""

    def test_nested_revocation_list(self, badge_for_verify_rsa):
        from unittest.mock import patch
        from openbadgeslib.errors import AssertionFormatIncorrect
        from openbadgeslib.ob1.verifier import Verifier
        badge, identity = badge_for_verify_rsa
        badge.source.json_url = 'https://example.com/badge.json'
        docs = {
            'https://example.com/badge.json': b'{"issuer": "https://example.com/issuer.json"}',
            'https://example.com/issuer.json': b'{"revocationList": "https://example.com/rev.json"}',
            'https://example.com/rev.json':
                ('{"%s": %s}' % (badge.serial_num, _nested(100000))).encode(),
        }
        with patch('openbadgeslib.ob1.verifier.download_file', side_effect=docs.__getitem__):
            with pytest.raises(AssertionFormatIncorrect, match='format incorrect'):
                Verifier(identity=identity).check_revocation(badge)


# ── OB2 ──────────────────────────────────────────────────────────────────────

def _ob2_hosted_payload(**override) -> dict:
    from datetime import datetime, timezone
    from openbadgeslib.ob2 import Assertion, IdentityObject, Verification
    payload = Assertion(
        id='https://attacker.example/a/1',
        recipient=IdentityObject.create('r@example.com', salt='s4lt3d'),
        badge='https://attacker.example/badge.json',
        verification=Verification(type='HostedBadge'),
        issued_on=datetime(2026, 1, 1, tzinfo=timezone.utc)).to_dict()
    payload.update(override)
    return payload


class TestOB2Dates:
    """F6: _parse_iso accepted 9999-12-31T23:59:59-23:59 (aware datetimes
    compare fine) and Assertion.to_dict() then overflowed converting it to
    UTC -- in _verify_hosted, after the attacker's URL had been fetched."""

    EXTREME = ['9999-12-31T23:59:59-23:59', '0001-01-01T00:00:00+23:59']

    @pytest.mark.parametrize('field', ['issuedOn', 'expires'])
    @pytest.mark.parametrize('value', EXTREME)
    def test_verify_refuses_it_before_fetching_anything(self, field, value):
        from openbadgeslib.ob2 import OB2VerificationError, OB2Verifier
        fetched = []

        def download(url):
            fetched.append(url)
            return b'{"anything": 1}'

        token = _unsigned_token({'alg': 'none'},
                                _ob2_hosted_payload(**{field: value}))
        with pytest.raises(OB2VerificationError, match='out of range'):
            OB2Verifier(download=download).verify(token)
        assert fetched == []

    @pytest.mark.parametrize('value', EXTREME)
    def test_verify_badge_reports_it_as_invalid(self, monkeypatch, value):
        from openbadgeslib.verify import verify_badge
        monkeypatch.setattr('openbadgeslib.ob2.verifier.download_file',
                            lambda url: b'{"anything": 1}')
        svg = (TESTS_DIR / 'withoutxmlheader.svg').read_bytes()
        token = _unsigned_token({'alg': 'none'}, _ob2_hosted_payload(issuedOn=value))
        result = verify_badge(baking.bake_svg(svg, token), '2')
        assert result.valid is False

    def test_a_valid_offset_still_parses_to_the_same_instant(self):
        from openbadgeslib._jsonmodel import _parse_iso
        parsed = _parse_iso('2026-01-01T01:00:00+01:00')
        assert parsed.utcoffset().total_seconds() == 3600
        assert parsed.isoformat() == '2026-01-01T01:00:00+01:00'
        # The edges of the representable range are fine.
        _parse_iso('9999-12-31T23:59:59Z')
        _parse_iso('0001-01-01T00:00:00Z')


class TestOB2RemoteKey:
    """F13: a lone surrogate in a CryptographicKey's publicKeyPem raised
    UnicodeEncodeError when verify() encoded the PEM, including on the hosted
    path that is documented never to fail the verdict."""

    def test_a_remote_key_document_with_a_lone_surrogate(self, rsa_priv_pem):
        from openbadgeslib.ob2 import OB2VerificationError, OB2Verifier
        token = _ob2_token_with_header(rsa_priv_pem, b'{"alg":"RS256"}')
        key_doc = {'type': 'CryptographicKey', 'id': 'https://example.com/key.json',
                   'owner': 'https://example.com/organization.json',
                   'publicKeyPem': '\ud800'}
        verifier = OB2Verifier(download=lambda url: json.dumps(key_doc).encode())
        with pytest.raises(OB2VerificationError, match='not valid JSON'):
            verifier.verify(token)
