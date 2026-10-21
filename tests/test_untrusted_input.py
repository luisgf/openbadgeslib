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


#: Aware timestamps that are valid ISO 8601 and compare fine, but whose UTC
#: instant is past what ``datetime`` holds (9999-12-31T23:59:59-05:00 is
#: 10000-01-01T04:59:59Z): converting them to UTC raises OverflowError.
PAST_THE_LATE_END = ['9999-12-31T23:59:59-05:00', '9999-12-31T23:59:59-00:01',
                     '9999-12-31T23:59:59-23:59']
PAST_THE_EARLY_END = ['0001-01-01T00:00:00+05:00', '0001-01-01T00:00:00+23:59']
NO_UTC_DATETIME = PAST_THE_LATE_END + PAST_THE_EARLY_END


class TestOB2Dates:
    """9999-12-31T23:59:59-23:59 parsed (aware datetimes compare fine) and
    Assertion.to_dict() then overflowed converting it to UTC, in
    _verify_hosted, after the attacker's URL had been fetched. The parser keeps
    accepting such a timestamp, as 4.6.2 did; what converts to UTC (_iso) now
    writes it with its own offset."""

    ISSUER = 'https://attacker.example/org.json'

    def _verify(self, payload):
        from openbadgeslib.ob2 import OB2Verifier
        docs = {payload['id']: payload,
                payload['badge']: {'issuer': self.ISSUER},
                self.ISSUER: {'id': self.ISSUER}}
        fetched = []

        def download(url):
            fetched.append(url)
            return json.dumps(docs[url]).encode()

        token = _unsigned_token({'alg': 'none'}, payload)
        return OB2Verifier(download=download).verify(token), fetched

    @pytest.mark.parametrize('value', PAST_THE_LATE_END)
    def test_a_late_expiry_is_never_expires(self, value):
        assertion, fetched = self._verify(_ob2_hosted_payload(expires=value))
        assert assertion.expires.isoformat() == value
        assert len(fetched) == 3                    # the whole hosted walk ran
        assert assertion.to_dict()['expires'] == value

    @pytest.mark.parametrize('value', PAST_THE_EARLY_END)
    def test_an_early_issue_date_is_issued(self, value):
        assertion, _ = self._verify(_ob2_hosted_payload(issuedOn=value))
        assert assertion.issued_on.isoformat() == value
        assert assertion.to_dict()['issuedOn'] == value

    @pytest.mark.parametrize('value', PAST_THE_EARLY_END)
    def test_an_early_expiry_has_expired(self, value):
        from openbadgeslib.ob2 import OB2VerificationError
        with pytest.raises(OB2VerificationError, match='Assertion has expired'):
            self._verify(_ob2_hosted_payload(expires=value))

    @pytest.mark.parametrize('value', PAST_THE_LATE_END)
    def test_a_late_issue_date_is_not_yet_valid(self, value):
        from openbadgeslib.ob2 import OB2VerificationError
        with pytest.raises(OB2VerificationError, match='not yet valid'):
            self._verify(_ob2_hosted_payload(issuedOn=value))

    @pytest.mark.parametrize('value', PAST_THE_LATE_END)
    def test_the_signer_writes_it(self, rsa_priv_pem, value):
        from datetime import datetime, timezone
        from openbadgeslib.ob2 import (Assertion, IdentityObject, OB2Signer,
                                       Verification)
        expires = datetime.fromisoformat(value)
        token = OB2Signer(privkey_pem=rsa_priv_pem, algorithm='RS256').sign(
            Assertion(recipient=IdentityObject.create('r@example.com', salt='s'),
                      badge='https://example.com/badge.json',
                      verification=Verification(type='SignedBadge',
                                                creator='https://example.com/key.json'),
                      issued_on=datetime(2026, 1, 1, tzinfo=timezone.utc),
                      expires=expires))
        payload = json.loads(jws_utils.base64url_decode(token.split('.')[1]))
        assert payload['expires'] == value

    def test_a_valid_offset_still_parses_to_the_same_instant(self):
        from openbadgeslib._jsonmodel import _parse_iso
        parsed = _parse_iso('2026-01-01T01:00:00+01:00')
        assert parsed.utcoffset().total_seconds() == 3600
        assert parsed.isoformat() == '2026-01-01T01:00:00+01:00'
        # The edges of the representable range are fine.
        _parse_iso('9999-12-31T23:59:59Z')
        _parse_iso('0001-01-01T00:00:00Z')


class TestOB3Dates:
    """The validity window and a proof's created/expires take the same
    timestamps: a late validUntil with a negative offset is the "never
    expires" some tools write, and 4.6.2 verified it."""

    FIELD_CLAIM = {'validUntil': 'exp', 'validFrom': 'nbf'}

    @pytest.mark.parametrize('field, value', (
        [('validUntil', v) for v in PAST_THE_LATE_END]
        + [('validFrom', v) for v in PAST_THE_EARLY_END]))
    def test_a_jwt_verifies_and_serialises_back(self, did_key_signer, field, value):
        from datetime import datetime
        from openbadgeslib.ob3 import OB3Verifier
        signer, did = did_key_signer
        token = _signed_jwt(signer, did, lambda p: p.update({field: value}))
        credential = OB3Verifier.for_issuer_did(did).verify(token)
        assert credential.to_vc()[field] == value
        claim = self.FIELD_CLAIM[field]
        assert credential.to_jwt_payload()[claim] == int(
            datetime.fromisoformat(value).timestamp())

    @pytest.mark.parametrize('field, value, message', (
        [('validFrom', v, 'not yet valid') for v in PAST_THE_LATE_END]
        + [('validUntil', v, 'expired') for v in PAST_THE_EARLY_END]))
    def test_a_jwt_outside_its_window_is_refused_for_that(self, did_key_signer,
                                                          field, value, message):
        from openbadgeslib.ob3 import OB3VerificationError, OB3Verifier
        signer, did = did_key_signer
        token = _signed_jwt(signer, did, lambda p: p.update({field: value}))
        with pytest.raises(OB3VerificationError, match=message):
            OB3Verifier.for_issuer_did(did).verify(token)

    @pytest.mark.parametrize('field, value', (
        [('validUntil', v) for v in PAST_THE_LATE_END]
        + [('validFrom', v) for v in PAST_THE_EARLY_END]))
    def test_a_data_integrity_credential_verifies_and_serialises_back(
            self, ob3_credential, ed25519_keypair, field, value):
        pytest.importorskip('pyld')
        from ldp_helpers import did_key, sign_ldp
        from openbadgeslib.ob3.ldp import OB3LdpVerifier
        priv, pub = ed25519_keypair
        document = ob3_credential.to_vc()
        document['issuer'] = {'id': did_key(pub), 'type': ['Profile'], 'name': 'I'}
        document[field] = value
        credential = OB3LdpVerifier().verify(sign_ldp(document, priv, pub))
        assert credential.to_vc()[field] == value

    def test_a_proof_with_such_timestamps_is_well_formed(self):
        from openbadgeslib.ob3.ldp import _validate_proof
        _validate_proof({'proofPurpose': 'assertionMethod',
                         'verificationMethod': 'did:key:z6Mk#z6Mk',
                         'created': PAST_THE_EARLY_END[0],
                         'expires': PAST_THE_LATE_END[0]}, 'assertionMethod')


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


# ── OB3 JWT-VC ───────────────────────────────────────────────────────────────

@pytest.fixture()
def did_key_signer(ed25519_keypair):
    """An Ed25519 signer bound to its own did:key: the self-asserted issuer
    --resolve-did accepts, so the attacker needs no trust to sign a payload."""
    from openbadgeslib.ob3 import OB3Signer
    from openbadgeslib.ob3.did import did_key_from_pem
    priv, pub = ed25519_keypair
    return OB3Signer(privkey_pem=priv, algorithm='EdDSA'), did_key_from_pem(pub)


def _did_credential(did, **kwargs):
    from openbadgeslib.ob3 import Achievement, Issuer, OpenBadgeCredential
    return OpenBadgeCredential(
        id='urn:uuid:00000000-0000-0000-0000-0000000000c3',
        issuer=Issuer(id=did, name='Self'),
        recipient_id='mailto:r@example.com',
        achievement=Achievement(id='https://a.example/1', name='A',
                                description='d', criteria_narrative='c'),
        **kwargs)


def _signed_jwt(signer, did, mutate=None) -> str:
    payload = _did_credential(did).to_jwt_payload()
    if mutate is not None:
        mutate(payload)
    return signer.sign_payload(payload)


class TestOB3JwtHeader:
    """F4: PyJWT raises InvalidTokenError (DecodeError's parent) for a header
    it validates -- a non-string kid, an invalid crit -- and the verifier only
    caught DecodeError."""

    @pytest.mark.parametrize('header', [
        {'alg': 'EdDSA', 'kid': 5},
        {'alg': 'EdDSA', 'crit': 5},
        {'alg': 'EdDSA', 'crit': []},
    ], ids=['kid-5', 'crit-5', 'crit-empty'])
    def test_header_pyjwt_rejects(self, ed25519_pub_pem, header):
        from openbadgeslib.ob3 import OB3VerificationError, OB3Verifier
        token = _unsigned_token(header, {'a': 1})
        with pytest.raises(OB3VerificationError):
            OB3Verifier(ed25519_pub_pem).verify(token)

    def test_verify_endorsement_jwt(self, ed25519_pub_pem):
        from openbadgeslib.ob3 import OB3VerificationError
        from openbadgeslib.ob3.verifier import verify_endorsement_jwt
        token = _unsigned_token({'alg': 'EdDSA', 'kid': 5}, {'a': 1})
        with pytest.raises(OB3VerificationError):
            verify_endorsement_jwt(token, endorser_pubkey_pem=ed25519_pub_pem)

    def test_verify_badge_reports_it_as_invalid(self, ed25519_pub_pem):
        from openbadgeslib.verify import verify_badge
        svg = (TESTS_DIR / 'withoutxmlheader.svg').read_bytes()
        token = _unsigned_token({'alg': 'EdDSA', 'kid': 5}, {'a': 1})
        data = baking.bake_svg(svg, token, element=baking.SVG_ELEMENT_OB3,
                               namespace=baking.SVG_NS_OB3)
        result = verify_badge(data, '3', pubkey_pem=ed25519_pub_pem)
        assert result.valid is False

    def test_a_status_list_with_such_a_header(self, ed25519_pub_pem):
        """The status list's own JWT goes through the same decode."""
        from openbadgeslib.ob3.status import _verify_list_proof
        from openbadgeslib.ob3 import OB3VerificationError
        token = _unsigned_token({'alg': 'EdDSA', 'kid': 5}, {'a': 1})
        with pytest.raises(OB3VerificationError, match='proof is invalid'):
            _verify_list_proof(token.encode(), {'issuer': 'did:x'}, 'https://l/1',
                               'did:x', lambda url: b'', ed25519_pub_pem)

    def test_a_str_token_with_a_lone_surrogate(self, ed25519_pub_pem):
        """F15: PyJWT encodes a str token to UTF-8 and raised UnicodeEncodeError."""
        from openbadgeslib.ob3 import OB3VerificationError, OB3Verifier
        from openbadgeslib.ob3.verifier import verify_endorsement_jwt
        from openbadgeslib.verify import issuer_did_from_token
        with pytest.raises(OB3VerificationError):
            OB3Verifier(ed25519_pub_pem).verify('\ud800.e30.e30')
        with pytest.raises(OB3VerificationError):
            verify_endorsement_jwt('\ud800.e30.e30',
                                   endorser_pubkey_pem=ed25519_pub_pem)
        with pytest.raises(OB3VerificationError):
            issuer_did_from_token('\ud800.e30.e30')


class TestOB3JwtNesting:
    """F10: on Python 3.14 json.loads takes about 116 000 levels, repr() about
    70 000: a value nested between is parsed and then turns into a
    RecursionError the moment an error message formats it."""

    @pytest.mark.parametrize('depth', [5000, 100000])
    def test_alg_nested_in_the_header(self, ed25519_pub_pem, depth):
        from openbadgeslib.ob3 import OB3VerificationError, OB3Verifier
        header = b'{"alg":' + _nested(depth).encode() + b'}'
        with pytest.raises(OB3VerificationError):
            OB3Verifier(ed25519_pub_pem).verify(_unsigned_token(header, {'a': 1}))

    @pytest.mark.parametrize('depth', [5000, 100000])
    def test_issuer_nested_in_the_unverified_payload(self, depth):
        from openbadgeslib.ob3 import OB3VerificationError
        from openbadgeslib.verify import issuer_did_from_token
        payload = b'{"iss":' + _nested(depth).encode() + b'}'
        with pytest.raises(OB3VerificationError):
            issuer_did_from_token(_unsigned_token({'alg': 'EdDSA'}, payload))

    @pytest.mark.parametrize('depth', [5000, 100000])
    def test_endorsement_with_a_nested_issuer(self, ed25519_pub_pem, depth):
        from openbadgeslib.ob3 import OB3VerificationError
        from openbadgeslib.ob3.verifier import verify_endorsement_jwt
        payload = b'{"issuer":' + _nested(depth).encode() + b'}'
        with pytest.raises(OB3VerificationError):
            verify_endorsement_jwt(_unsigned_token({'alg': 'EdDSA'}, payload),
                                   endorser_pubkey_pem=ed25519_pub_pem)

    def test_a_signed_payload_nested_past_the_bound(self, did_key_signer, ed25519_pub_pem):
        # Signed by a key the attacker holds (a did:key is the presenter's
        # own): validFrom nested past the bound must not reach the model.
        from openbadgeslib.ob3 import OB3VerificationError, OB3Verifier
        signer, did = did_key_signer
        deep = []
        for _ in range(200):
            deep = [deep]
        token = _signed_jwt(signer, did, lambda p: p.update(validFrom=deep))
        with pytest.raises(OB3VerificationError, match='nested more than'):
            OB3Verifier(ed25519_pub_pem).verify(token)


class TestOB3Numbers:
    """F8/F9/F14: a number the payload carries that no float or int can hold."""

    @staticmethod
    def _achievement(payload):
        return payload['credentialSubject']['achievement']

    @pytest.mark.parametrize('field', ['creditsAvailable', 'creditsEarned'])
    def test_an_integer_past_the_float_range(self, did_key_signer, field):
        from openbadgeslib.ob3 import OB3VerificationError, OB3Verifier
        signer, did = did_key_signer

        def mutate(payload):
            target = (self._achievement(payload) if field == 'creditsAvailable'
                      else payload['credentialSubject'])
            target[field] = 10 ** 400

        token = _signed_jwt(signer, did, mutate)
        with pytest.raises(OB3VerificationError, match='Malformed credential'):
            OB3Verifier.for_issuer_did(did).verify(token)

    @pytest.mark.parametrize('value', [float('inf'), float('-inf'), float('nan')],
                             ids=['inf', '-inf', 'nan'])
    def test_credits_that_are_not_finite(self, did_key_signer, value):
        from openbadgeslib.ob3 import OB3VerificationError, OB3Verifier
        signer, did = did_key_signer
        token = _signed_jwt(
            signer, did, lambda p: self._achievement(p).update(creditsAvailable=value))
        with pytest.raises(OB3VerificationError):
            OB3Verifier.for_issuer_did(did).verify(token)

    def test_model_refuses_a_number_past_the_float_range(self):
        from openbadgeslib.ob3.credential import _float_or_none
        with pytest.raises(ValueError, match='out of range'):
            _float_or_none(10 ** 400)
        with pytest.raises(ValueError, match='not finite'):
            _float_or_none(float('inf'))
        assert _float_or_none(3) == 3.0 and _float_or_none(True) is None
        assert _float_or_none('3') is None and _float_or_none(2.5) == 2.5

    @pytest.mark.parametrize('field', ['statusListIndex', 'statusSize'])
    @pytest.mark.parametrize('value', [float('inf'), float('-inf')])
    def test_a_status_entry_with_an_infinite_number(self, field, value):
        from openbadgeslib.ob3 import OB3VerificationError, check_credential_status
        entry = {'id': 'https://l.example/1#0', 'type': 'BitstringStatusListEntry',
                 'statusPurpose': 'revocation', 'statusListIndex': '0',
                 'statusListCredential': 'https://l.example/1'}
        entry[field] = value
        credential = _did_credential('did:key:z6Mk', credential_status=[entry])
        with pytest.raises(OB3VerificationError, match='invalid status'):
            check_credential_status(credential, download=lambda url: b'{}')

    def test_signed_status_index_of_infinity(self, did_key_signer):
        from openbadgeslib.ob3 import OB3VerificationError, OB3Verifier
        signer, did = did_key_signer
        entry = {'id': 'https://l.example/1#0', 'type': 'BitstringStatusListEntry',
                 'statusPurpose': 'revocation', 'statusListIndex': float('inf'),
                 'statusListCredential': 'https://l.example/1'}
        token = _signed_jwt(signer, did, lambda p: p.update(credentialStatus=entry))
        with pytest.raises(OB3VerificationError):
            OB3Verifier.for_issuer_did(did).verify(token, check_status=True,
                                                   download=lambda url: b'{}')


# ── OB3 Data Integrity (LDP) ─────────────────────────────────────────────────

@pytest.fixture()
def ldp_signed(ed25519_keypair):
    """(signed document, pinned public key PEM). Needs the [ldp] extra."""
    pytest.importorskip('pyld')
    from openbadgeslib.ob3 import (Achievement, Issuer, OpenBadgeCredential,
                                   add_data_integrity_proof)
    from openbadgeslib.ob3.did import did_key_from_pem
    priv, pub = ed25519_keypair
    did = did_key_from_pem(pub)
    vc = OpenBadgeCredential(
        issuer=Issuer(id='https://issuer.example', name='I'),
        recipient_id='mailto:r@example.com',
        achievement=Achievement(id='https://a.example/1', name='A',
                                description='d', criteria_narrative='c')).to_vc()
    return (add_data_integrity_proof(vc, priv, '%s#%s' % (did, did[len('did:key:'):])),
            pub)


class TestLdpProof:
    """F1: proof.cryptosuite that is a JSON array or object is unhashable and
    raised a bare TypeError at the membership test."""

    @pytest.mark.parametrize('cryptosuite', [['x'], {'a': 1}, [], 5, None, True],
                             ids=['list', 'dict', 'empty-list', 'int', 'null', 'bool'])
    def test_cryptosuite_that_is_not_a_string(self, ldp_signed, cryptosuite):
        from openbadgeslib.ob3 import (OB3LdpVerifier, OB3VerificationError,
                                       verify_data_integrity_proof)
        doc, pub = ldp_signed
        doc['proof']['cryptosuite'] = cryptosuite
        with pytest.raises(OB3VerificationError, match='no supported Data Integrity proof'):
            OB3LdpVerifier(pubkey_pem=pub).verify(json.dumps(doc))
        with pytest.raises(OB3VerificationError, match='no supported Data Integrity proof'):
            verify_data_integrity_proof(doc, pub)

    def test_the_message_names_the_string_cryptosuites_found(self, ldp_signed):
        from openbadgeslib.ob3 import OB3VerificationError, verify_data_integrity_proof
        doc, pub = ldp_signed
        doc['proof']['cryptosuite'] = 'made-up-2099'
        with pytest.raises(OB3VerificationError, match='made-up-2099'):
            verify_data_integrity_proof(doc, pub)

    def test_a_signed_document_still_verifies(self, ldp_signed):
        from openbadgeslib.ob3 import OB3LdpVerifier
        doc, pub = ldp_signed
        assert OB3LdpVerifier(pubkey_pem=pub).verify(json.dumps(doc))


class TestLdpDocument:
    """F2/F16/F17: what the document holds, checked once on parse."""

    def _verify(self, doc, pub):
        from openbadgeslib.ob3 import OB3LdpVerifier
        return OB3LdpVerifier(pubkey_pem=pub).verify(doc)

    def test_a_lone_surrogate_in_any_string(self, ldp_signed):
        # F2: json.dumps writes it as an ASCII \ud800 escape, so the document
        # survives baking; hashing it raised UnicodeEncodeError before any
        # signature was checked.
        from openbadgeslib.ob3 import OB3VerificationError
        doc, pub = ldp_signed
        doc['credentialSubject']['achievement']['description'] = 'x\ud800y'
        for payload in (json.dumps(doc), doc):
            with pytest.raises(OB3VerificationError, match='surrogate'):
                self._verify(payload, pub)

    def test_a_lone_surrogate_in_a_key_or_the_proof(self, ldp_signed):
        from openbadgeslib.ob3 import OB3VerificationError
        doc, pub = ldp_signed
        doc['proof']['\ud800'] = 'x'
        with pytest.raises(OB3VerificationError, match='surrogate'):
            self._verify(json.dumps(doc), pub)

    @pytest.mark.parametrize('depth', [900, 5000])
    def test_low_level_verify_of_a_nested_dict(self, ldp_signed, depth):
        # F16: verify_data_integrity_proof deep-copies the document; it raised
        # RecursionError at about 900 nested levels on every Python.
        from openbadgeslib.ob3 import OB3VerificationError, verify_data_integrity_proof
        doc, pub = ldp_signed
        node = doc['credentialSubject']['achievement']
        for _ in range(depth):
            node['x'] = {}
            node = node['x']
        with pytest.raises(OB3VerificationError, match='nested more than'):
            verify_data_integrity_proof(doc, pub)

    @pytest.mark.parametrize('depth', [20000, 100000])
    def test_nested_document_is_refused_before_any_walk(
            self, ldp_signed, monkeypatch, depth):
        # F17: _check_nested_contexts rebuilds an O(depth) path per node, so
        # 160 KB of nesting cost 3 s of CPU before any signature check. The
        # bound on parse means the walk never sees such a document.
        from openbadgeslib.ob3 import OB3VerificationError
        doc, pub = ldp_signed
        doc['credentialSubject']['achievement']['description'] = None
        text = json.dumps(doc).replace('"description": null',
                                       '"description": ' + _nested(depth))

        def walked(*args, **kwargs):
            raise AssertionError('the context walk ran on a document that deep')

        monkeypatch.setattr('openbadgeslib.ob3.ldp._check_json_ld_form', walked)
        with pytest.raises(OB3VerificationError, match='nested too deeply'):
            self._verify(text, pub)

    def test_the_depth_a_real_credential_has_is_far_from_the_bound(self, ldp_signed):
        from openbadgeslib._safejson import MAX_JSON_DEPTH, nested_deeper_than
        doc, _ = ldp_signed
        assert not nested_deeper_than(doc, 12) and MAX_JSON_DEPTH > 12


# ── openbadges-verifier ───────────────────────────────────────────────────────

def _run_cli(argv, capsys):
    """Run the verifier CLI; return (exit code, the one JSON object it printed,
    parsed strictly: Infinity and NaN are not JSON)."""
    import sys
    from unittest.mock import patch
    from openbadgeslib import openbadges_verifier

    def refuse(token):
        raise ValueError('not JSON: %s' % token)

    with patch.object(sys, 'argv', ['openbadges-verifier'] + argv):
        with pytest.raises(SystemExit) as exc:
            openbadges_verifier.main()
    out = capsys.readouterr().out
    return exc.value.code, json.loads(out, parse_constant=refuse)


class TestVerifierCli:
    """F4/F5/F14: a hostile file was a traceback and rc=1 with no JSON, or a
    JSON line with Infinity in it."""

    def test_ob3_header_pyjwt_rejects(self, tmp_path, capsys, ed25519_pub_pem):
        svg = (TESTS_DIR / 'withoutxmlheader.svg').read_bytes()
        token = _unsigned_token({'alg': 'EdDSA', 'kid': 5}, {'a': 1})
        badge = tmp_path / 'b.svg'
        badge.write_bytes(baking.bake_svg(svg, token, element=baking.SVG_ELEMENT_OB3,
                                          namespace=baking.SVG_NS_OB3))
        key = tmp_path / 'k.pem'
        key.write_bytes(ed25519_pub_pem)
        code, result = _run_cli(['-i', str(badge), '-r', 'a@b.c', '-k', str(key),
                                 '--json'], capsys)
        assert code == 1 and result['valid'] is False

    def test_ob1_nested_body(self, tmp_path, capsys, rsa_pub_pem):
        token = _unsigned_token({'alg': 'RS256'},
                                _ob1_body('"a": ' + _nested(DEEPER)))
        key = tmp_path / 'k.pem'
        key.write_bytes(rsa_pub_pem)
        code, result = _run_cli(['-V', '1', '-i', _bake_svg(token, tmp_path),
                                 '-r', 'a@b.c', '-k', str(key), '--json'], capsys)
        assert code == 1 and result['valid'] is False
        assert 'not valid base64url JSON' in result['reason']

    def test_ob3_credits_of_infinity_is_not_a_json_infinity(
            self, tmp_path, capsys, did_key_signer):
        signer, did = did_key_signer
        token = _signed_jwt(signer, did, lambda p: p['credentialSubject'][
            'achievement'].update(creditsAvailable=float('inf')))
        svg = (TESTS_DIR / 'withoutxmlheader.svg').read_bytes()
        badge = tmp_path / 'b.svg'
        badge.write_bytes(baking.bake_svg(svg, token, element=baking.SVG_ELEMENT_OB3,
                                          namespace=baking.SVG_NS_OB3))
        code, result = _run_cli(['-i', str(badge), '-r', 'r@example.com',
                                 '--resolve-did', '--json'], capsys)
        assert code == 1 and result['valid'] is False

    def test_finish_never_prints_a_non_finite_number(self, capsys):
        import argparse
        from openbadgeslib.openbadges_verifier import _finish
        result = {'valid': True, 'trusted': True, 'credits_available': float('inf'),
                  'credits_earned': float('nan'), 'ok': 2.5}
        with pytest.raises(SystemExit):
            _finish(argparse.Namespace(json=True), result)
        printed = json.loads(capsys.readouterr().out)
        assert printed['credits_available'] is None
        assert printed['credits_earned'] is None and printed['ok'] == 2.5
