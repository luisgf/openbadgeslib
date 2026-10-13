"""Strict base64url decoding (openbadgeslib._jws.utils.base64url_decode).

base64.urlsafe_b64decode() drops characters outside the alphabet, accepts
'+'/'/' as aliases of '-'/'_' (Python 3.15 warns that this will change), and
ignores extra '=' and non-zero pad bits. Every decode site passes it untrusted
input, so the shared helper accepts only the canonical encoding. The
end-to-end cases check that each site maps the rejection to its own error.
"""
import base64
import binascii
import gzip
import json
import warnings

import pytest

from openbadgeslib._jws import sign, verify_block
from openbadgeslib._jws.exceptions import SignatureError
from openbadgeslib._jws.utils import base64url_decode, base64url_encode
from openbadgeslib.keys import KeyRSA
from openbadgeslib.ob1.badge import Assertion
from openbadgeslib.ob3.eudi import EudiError, _issuer_jwt_has_x5c
from openbadgeslib.ob3.status import decode_encoded_list
from openbadgeslib.oid4vci.memory_store import InMemoryOID4VCIStore
from openbadgeslib.oid4vci.nonce import NonceIssuer

# The same bytes in the standard alphabet: what a lenient decoder still accepts.
_TO_STANDARD = str.maketrans('-_', '+/')


def _b64u(raw):
    return base64url_encode(raw).decode('ascii')


class TestBase64urlDecode:
    @pytest.mark.parametrize('raw', [b'', b'a', b'ab', b'abc', bytes(range(256))])
    def test_round_trip(self, raw):
        assert base64url_decode(base64url_encode(raw)) == raw
        assert base64url_decode(_b64u(raw)) == raw
        # Canonically padded, as base64.urlsafe_b64encode writes it.
        assert base64url_decode(base64.urlsafe_b64encode(raw)) == raw

    @pytest.mark.parametrize('data, raw', [
        ('YQ', b'a'), ('YQ==', b'a'), ('YWI', b'ab'), ('YWI=', b'ab'),
        (b'YWJj', b'abc'), (bytearray(b'YWJj'), b'abc'),
        (memoryview(b'YWJj'), b'abc'), ('Pz8_', b'???'),
    ])
    def test_padding_is_optional(self, data, raw):
        assert base64url_decode(data) == raw

    @pytest.mark.parametrize('data', [
        '++8', 'Pz8/', b'Pz8/',             # standard alphabet
        'Y Q', 'YQ\n', 'YW*Jj',             # whitespace, junk
        'Y=Q', '=YQ', 'YQ==YQ==',           # '=' before the end
        'YQ=', 'YQ===', b'YWJj=', '=', '====',  # not the canonical padding
        'YR', 'Yf', 'YWK', 'YR==',          # non-zero pad bits (RFC 4648 §3.5)
        'YéQ', b'YQ\x80',              # non-ASCII
        'Y', 'YWJjZ', 'YWJjZ===',           # length 1 mod 4
    ])
    def test_non_canonical_input_is_rejected(self, data):
        with pytest.raises(binascii.Error):
            base64url_decode(data)

    @pytest.mark.parametrize('data', [None, 12, ['YQ']])
    def test_non_str_bytes_input_raises_type_error(self, data):
        # TypeError, which every caller's (ValueError, TypeError) catches.
        with pytest.raises(TypeError):
            base64url_decode(data)

    def test_no_warning_escapes(self):
        # Python 3.15's urlsafe_b64decode warns (FutureWarning) on '+' and '/'.
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            for data in ('-+8', b'Pz8/'):
                with pytest.raises(binascii.Error):
                    base64url_decode(data)
            assert base64url_decode('-_8') == b'\xfb\xff'


def _rs256_token(rsa_priv_pem, rsa_pub_pem):
    """(signing input, signature segment, public key) of an RS256 JWS."""
    key = KeyRSA()
    key.read_private_key(rsa_priv_pem)
    key.read_public_key(rsa_pub_pem)
    header, payload = {'alg': 'RS256'}, {'uid': 'b64url'}
    signing_input = (_b64u(json.dumps(header).encode()) + '.'
                     + _b64u(json.dumps(payload).encode()))
    sig = _b64u(sign(header, payload, key=key.get_priv_key()))
    return signing_input, sig, key.get_pub_key()


class TestDecodeSites:
    def test_jws_signature_in_standard_alphabet_does_not_verify(
            self, rsa_priv_pem, rsa_pub_pem):
        signing_input, sig, pub = _rs256_token(rsa_priv_pem, rsa_pub_pem)
        assert '-' in sig or '_' in sig     # RS256 is deterministic
        assert verify_block(signing_input + '.' + sig, key=pub)
        with pytest.raises(SignatureError, match='Malformed JWS signature'):
            verify_block(signing_input + '.' + sig.translate(_TO_STANDARD),
                         key=pub)

    def test_jws_signature_has_one_accepted_encoding(
            self, rsa_priv_pem, rsa_pub_pem):
        signing_input, sig, pub = _rs256_token(rsa_priv_pem, rsa_pub_pem)
        # A 256-byte RS256 signature leaves 4 unused bits in its last
        # character: only the zero-bit spelling decodes to these bytes.
        assert len(sig) % 4 == 2
        alphabet = ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
                    '0123456789-_')
        variants = [sig[:-1] + c for c in alphabet
                    if c != sig[-1] and alphabet.index(c) >> 4
                    == alphabet.index(sig[-1]) >> 4]
        assert len(variants) == 15
        for spelling in variants + [sig + '=', sig + '===', sig + '=' * 50]:
            with pytest.raises(SignatureError, match='Malformed JWS signature'):
                verify_block(signing_input + '.' + spelling, key=pub)
        assert verify_block(signing_input + '.' + sig + '==', key=pub)

    @pytest.mark.parametrize('around', ['\n', '\r\n', ' ', '\t\n'])
    def test_whitespace_around_the_token_is_ignored(
            self, rsa_priv_pem, rsa_pub_pem, around):
        signing_input, sig, pub = _rs256_token(rsa_priv_pem, rsa_pub_pem)
        token = signing_input + '.' + sig
        assert verify_block(around + token + around, key=pub)
        assert verify_block((token + around).encode('ascii'), key=pub)
        # ... but not inside a segment.
        with pytest.raises(SignatureError, match='Malformed JWS signature'):
            verify_block(token[:-4] + around + token[-4:], key=pub)

    def test_ob1_assertion_ignores_whitespace_around_the_token(
            self, rsa_priv_pem, rsa_pub_pem):
        # OB1 decodes header and body itself before verify_block sees them.
        signing_input, sig, _ = _rs256_token(rsa_priv_pem, rsa_pub_pem)
        token = (signing_input + '.' + sig).encode('ascii')
        assertion = Assertion.decode(b' ' + token + b'\r\n')
        assert assertion.get_assertion() == token
        assert assertion.decode_header() == {'alg': 'RS256'}

    def test_encoded_list_alphabet(self):
        bitstring = bytes(2048)
        # mtime 0xFFFF lands in the gzip header, so the encoding always carries
        # '__' whatever zlib build compressed the body.
        encoded = _b64u(gzip.compress(bitstring, mtime=0xFFFF))
        assert '__' in encoded
        assert decode_encoded_list('u' + encoded) == bitstring
        # The multibase 'u' form is base64url only (Bitstring Status List).
        with pytest.raises(ValueError, match='invalid encodedList'):
            decode_encoded_list('u' + encoded.translate(_TO_STANDARD))
        # A bare (StatusList2021) list may use the standard alphabet, padded
        # or not: that spec only says "base-64 encoded [RFC4648]".
        assert decode_encoded_list(encoded) == bitstring
        assert decode_encoded_list(encoded.translate(_TO_STANDARD)) == bitstring

    def test_bare_encoded_list_in_standard_base64_is_read(self):
        # What base64.b64encode() emits for a real list: '+', '/' and '='.
        bitstring = bytearray(16384)
        bitstring[1234] = 0x80
        standard = base64.b64encode(
            gzip.compress(bytes(bitstring), mtime=0xFFFF)).decode('ascii')
        assert '/' in standard
        with warnings.catch_warnings():
            warnings.simplefilter('error')  # no 3.15 FutureWarning either
            assert decode_encoded_list(standard) == bytes(bitstring)

    def test_sd_jwt_header_peek_in_standard_alphabet_raises(self):
        header = _b64u(json.dumps(
            {'alg': 'ES256', 'kid': '???', 'x5c': ['MIIB']}).encode())
        assert '_' in header
        assert _issuer_jwt_has_x5c(header + '.e30.c2ln~') is True
        with pytest.raises(EudiError, match='issuer JWT header'):
            _issuer_jwt_has_x5c(header.translate(_TO_STANDARD) + '.e30.c2ln~')

    def test_oid4vci_nonce_with_junk_is_invalid_and_not_spent(self):
        issuer = NonceIssuer(InMemoryOID4VCIStore(), ttl_s=120)
        nonce = issuer.mint()
        # Four junk characters keep the padding a lenient decoder computes
        # right, so it would drop them and spend the genuine nonce.
        assert issuer.consume(nonce[:20] + '****' + nonce[20:]) is False
        assert issuer.consume(nonce) is True
