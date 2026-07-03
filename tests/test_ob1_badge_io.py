"""Tests for badge image embedding and extraction (SVG / PNG)."""
from struct import pack
from unittest.mock import patch
from zlib import crc32

import pytest
from png import Reader, signature as png_signature

from openbadgeslib import baking
from openbadgeslib.badge import (
    Assertion, extract_svg_assertion, extract_png_assertion, BadgeSigned, Badge,
)
from openbadgeslib.keys import KeyType
from openbadgeslib.errors import (
    BadgeImgFormatUnsupported, AssertionFormatIncorrect, PrivateKeyReadError, ErrorParsingFile,
)


def _png_with_inserted_chunk(png_bytes, tag, data, index=1):
    chunks = list(Reader(bytes=png_bytes).chunks())
    chunks.insert(index, (tag, data))

    out = png_signature
    for chunk_tag, chunk_data in chunks:
        out += pack("!I", len(chunk_data))
        if isinstance(chunk_tag, str):
            chunk_tag = chunk_tag.encode('iso8859-1')
        out += chunk_tag + chunk_data
        checksum = crc32(chunk_tag)
        checksum = crc32(chunk_data, checksum) & 0xFFFFFFFF
        out += pack("!I", checksum)
    return out


class TestAssertionObject:
    def test_decode_valid(self):
        payload = b'IkhFQURFUiI.IkJPRFki.IlNJR05BVFVSRSI'
        a = Assertion.decode(payload)
        assert a.header == b'IkhFQURFUiI'
        assert a.body == b'IkJPRFki'
        assert a.signature == b'IlNJR05BVFVSRSI'

    def test_decode_preserves_roundtrip(self):
        payload = b'IkhFQURFUiI.IkJPRFki.IlNJR05BVFVSRSI'
        assert Assertion.decode(payload).get_assertion() == payload

    def test_decode_body_returns_dict(self):
        payload = b'IkhFQURFUiI.IkJPRFki.IlNJR05BVFVSRSI'
        body = Assertion.decode(payload).decode_body()
        assert body == 'BODY'

    def test_decode_header_returns_value(self):
        payload = b'IkhFQURFUiI.IkJPRFki.IlNJR05BVFVSRSI'
        assert Assertion.decode(payload).decode_header() == 'HEADER'

    def test_str_representation(self):
        a = Assertion(header=b'H', body=b'B', signature=b'S')
        s = str(a)
        assert 'H' in s and 'B' in s and 'S' in s


class TestExtractSVGAssertion:
    def test_extract_from_signed_svg(self, signed_svg_rsa):
        assertion = extract_svg_assertion(signed_svg_rsa.signed)
        assert isinstance(assertion, Assertion)

    def test_extracted_assertion_matches_original(self, signed_svg_rsa):
        extracted = extract_svg_assertion(signed_svg_rsa.signed)
        assert extracted.get_assertion() == signed_svg_rsa.assertion.get_assertion()

    def test_extract_ecc_svg(self, signed_svg_ecc):
        assertion = extract_svg_assertion(signed_svg_ecc.signed)
        assert isinstance(assertion, Assertion)

    def test_invalid_svg_raises(self):
        with pytest.raises(Exception):
            extract_svg_assertion(b'this is not svg xml')

    def test_element_without_verify_attribute_returns_none(self):
        # A well-formed SVG whose openbadges element lacks a verify attribute
        # is not a signed badge; extract_svg returns None rather than raising
        # a raw KeyError.
        svg = (b'<svg xmlns:openbadges="http://openbadges.org">'
               b'<openbadges:assertion/></svg>')
        assert baking.extract_svg(svg) is None

    def test_text_content_baking_round_trips(self, svg_image):
        # OB 3.0 §5.3 bakes a Data Integrity credential as the element's TEXT
        # content (a JSON document), not the verify attribute.
        doc = '{"@context": ["https://www.w3.org/ns/credentials/v2"], "proof": {}}'
        baked = baking.bake_svg(svg_image, doc,
                                element=baking.SVG_ELEMENT_OB3,
                                namespace=baking.SVG_NS_OB3, as_text=True)
        # Default extraction (attribute-only) must keep returning None...
        assert baking.extract_svg(baked, element=baking.SVG_ELEMENT_OB3) is None
        # ...while the text fallback recovers the document verbatim.
        assert baking.extract_svg(baked, element=baking.SVG_ELEMENT_OB3,
                                  text_fallback=True) == doc

    def test_text_fallback_empty_element_still_none(self):
        svg = (b'<svg xmlns:openbadges="https://purl.imsglobal.org/ob/v3p0">'
               b'<openbadges:credential>  </openbadges:credential></svg>')
        assert baking.extract_svg(svg, element=baking.SVG_ELEMENT_OB3,
                                  text_fallback=True) is None

    def test_text_fallback_prefers_verify_attribute(self, svg_image):
        # A JWT baked in the verify attribute wins even with the fallback on:
        # the attribute is the primary OB3 carrier.
        baked = baking.bake_svg(svg_image, 'h.p.s',
                                element=baking.SVG_ELEMENT_OB3,
                                namespace=baking.SVG_NS_OB3)
        assert baking.extract_svg(baked, element=baking.SVG_ELEMENT_OB3,
                                  text_fallback=True) == 'h.p.s'


class TestExtractPNGAssertion:
    def test_extract_from_signed_png(self, signed_png_rsa):
        assertion = extract_png_assertion(signed_png_rsa.signed)
        assert isinstance(assertion, Assertion)

    def test_extracted_assertion_matches_original(self, signed_png_rsa):
        extracted = extract_png_assertion(signed_png_rsa.signed)
        assert extracted.get_assertion() == signed_png_rsa.assertion.get_assertion()

    def test_extract_ecc_png(self, signed_png_ecc):
        assertion = extract_png_assertion(signed_png_ecc.signed)
        assert isinstance(assertion, Assertion)

    def test_unsigned_png_raises(self, png_image):
        # Unsigned PNG has no openbadges iTXt chunk → clean error, not None.
        from openbadgeslib.errors import AssertionFormatIncorrect
        with pytest.raises(AssertionFormatIncorrect):
            extract_png_assertion(png_image)

    def test_ignores_unrelated_itxt_before_assertion(self, signed_png_rsa):
        png_with_comment = _png_with_inserted_chunk(
            signed_png_rsa.signed,
            'iTXt',
            b'comment\x00\x00\x00\x00\x00not-an-openbadges-assertion',
        )

        extracted = extract_png_assertion(png_with_comment)

        assert extracted.get_assertion() == signed_png_rsa.assertion.get_assertion()

    def test_returns_clean_error_for_only_prefixed_non_keyword_itxt(self, png_image):
        from openbadgeslib.errors import AssertionFormatIncorrect
        png_with_comment = _png_with_inserted_chunk(
            png_image,
            'iTXt',
            b'openbadgesevil\x00\x00\x00\x00\x00not-an-assertion',
        )

        with pytest.raises(AssertionFormatIncorrect):
            extract_png_assertion(png_with_comment)

    def test_garbage_bytes_raise_clean_error(self):
        # Not PNG at all: baking.extract_png's underlying chunk reader raises
        # its own exception; that must not leak out raw (mirrors the SVG
        # counterpart's try/except around baking.extract_svg).
        from openbadgeslib.errors import ErrorParsingFile
        with pytest.raises(ErrorParsingFile):
            extract_png_assertion(b'this is not a png file at all')


class TestBakingPNGAssertionDetection:
    def test_has_png_detects_baked_assertion(self, png_image):
        assert baking.has_png(baking.bake_png(png_image, 'header.payload.sig')) is True

    def test_has_png_ignores_prefixed_non_keyword_itxt(self, png_image):
        png_with_comment = _png_with_inserted_chunk(
            png_image,
            'iTXt',
            b'openbadgesevil\x00\x00\x00\x00\x00not-an-assertion',
        )

        assert baking.has_png(png_with_comment) is False


class TestSvgHeaderVariants:
    """Baking must round-trip whether or not the SVG carries an <?xml?>
    declaration (and a DOCTYPE), which defusedxml must tolerate."""

    @pytest.mark.parametrize('fixture', ['withxmlheader.svg', 'withoutxmlheader.svg'])
    def test_bake_extract_roundtrip(self, fixture):
        from pathlib import Path
        from openbadgeslib import baking
        data = (Path(__file__).parent / fixture).read_bytes()
        baked = baking.bake_svg(data, 'header.payload.sig')
        assert baking.extract_svg(baked) == 'header.payload.sig'


class TestBadgeSignedReadFromFile:
    """Test read_from_file using temp files and mocked network calls."""

    def _write_temp(self, tmp_path, data, suffix):
        p = tmp_path / f'badge{suffix}'
        p.write_bytes(data)
        return str(p)

    def _pub_key_bytes(self, key_type, pub_pem):
        return pub_pem

    def test_read_signed_svg_rsa(self, tmp_path, signed_svg_rsa, rsa_pub_pem):
        path = self._write_temp(tmp_path, signed_svg_rsa.signed, '.svg')
        with patch('openbadgeslib.ob1.badge.download_file', return_value=rsa_pub_pem):
            badge = BadgeSigned.read_from_file(path)
        assert badge.assertion is not None
        assert badge.source.key_type is not None

    def test_read_signed_png_rsa(self, tmp_path, signed_png_rsa, rsa_pub_pem):
        path = self._write_temp(tmp_path, signed_png_rsa.signed, '.png')
        with patch('openbadgeslib.ob1.badge.download_file', return_value=rsa_pub_pem):
            badge = BadgeSigned.read_from_file(path)
        assert badge.assertion is not None

    def test_unsupported_format_raises(self, tmp_path):
        p = tmp_path / 'badge.gif'
        p.write_bytes(b'GIF89a')
        with pytest.raises(BadgeImgFormatUnsupported):
            BadgeSigned.read_from_file(str(p))

    def test_read_signed_svg_ecc(self, tmp_path, signed_svg_ecc, ecc_pub_pem):
        from openbadgeslib.keys import KeyType
        path = self._write_temp(tmp_path, signed_svg_ecc.signed, '.svg')
        with patch('openbadgeslib.ob1.badge.download_file', return_value=ecc_pub_pem):
            badge = BadgeSigned.read_from_file(path)
        assert badge.source.key_type is KeyType.ECC

    def test_verify_key_download_failure_raises(self, tmp_path, signed_svg_rsa):
        from openbadgeslib.errors import ErrorParsingFile
        path = self._write_temp(tmp_path, signed_svg_rsa.signed, '.svg')
        with patch('openbadgeslib.ob1.badge.download_file',
                   side_effect=ValueError('unreachable')):
            with pytest.raises(ErrorParsingFile):
                BadgeSigned.read_from_file(path)

    def test_get_serial_num_after_read_is_str(self, tmp_path, signed_svg_rsa, rsa_pub_pem):
        # Regression for the str/bytes bug: get_serial_num must not crash on a
        # badge reconstructed from a file (serial is the JSON 'uid').
        path = self._write_temp(tmp_path, signed_svg_rsa.signed, '.svg')
        with patch('openbadgeslib.ob1.badge.download_file', return_value=rsa_pub_pem):
            badge = BadgeSigned.read_from_file(path)
        assert isinstance(badge.get_serial_num(), str)

    def _badge_with_tampered_body(self, tmp_path, signed_svg_rsa, svg_image, mutate):
        from openbadgeslib._jws import utils as jws_utils

        assertion = extract_svg_assertion(signed_svg_rsa.signed)
        body = assertion.decode_body()
        mutate(body)
        new_body_b64 = jws_utils.encode(body)
        tampered = assertion.header + b'.' + new_body_b64 + b'.' + assertion.signature

        baked = baking.bake_svg(svg_image, tampered.decode('utf-8'))
        return self._write_temp(tmp_path, baked, '.svg')

    def test_missing_recipient_field_raises_clean_error(self, tmp_path, signed_svg_rsa, svg_image, rsa_pub_pem):
        path = self._badge_with_tampered_body(
            tmp_path, signed_svg_rsa, svg_image, lambda body: body.pop('recipient'))
        with patch('openbadgeslib.ob1.badge.download_file', return_value=rsa_pub_pem):
            with pytest.raises(AssertionFormatIncorrect):
                BadgeSigned.read_from_file(path)

    def test_missing_uid_field_raises_clean_error(self, tmp_path, signed_svg_rsa, svg_image, rsa_pub_pem):
        path = self._badge_with_tampered_body(
            tmp_path, signed_svg_rsa, svg_image, lambda body: body.pop('uid'))
        with patch('openbadgeslib.ob1.badge.download_file', return_value=rsa_pub_pem):
            with pytest.raises(AssertionFormatIncorrect):
                BadgeSigned.read_from_file(path)

    def test_missing_verify_field_raises_clean_error(self, tmp_path, signed_svg_rsa, svg_image, rsa_pub_pem):
        # The except clause used to re-reference body['verify']['url'] while
        # formatting its own error message, raising a fresh unwrapped
        # KeyError instead of ErrorParsingFile.
        path = self._badge_with_tampered_body(
            tmp_path, signed_svg_rsa, svg_image, lambda body: body.pop('verify'))
        with patch('openbadgeslib.ob1.badge.download_file', return_value=rsa_pub_pem):
            with pytest.raises(ErrorParsingFile):
                BadgeSigned.read_from_file(path)

    def test_non_dict_verify_field_raises_clean_error(self, tmp_path, signed_svg_rsa, svg_image, rsa_pub_pem):
        path = self._badge_with_tampered_body(
            tmp_path, signed_svg_rsa, svg_image, lambda body: body.__setitem__('verify', 'not-a-dict'))
        with patch('openbadgeslib.ob1.badge.download_file', return_value=rsa_pub_pem):
            with pytest.raises(ErrorParsingFile):
                BadgeSigned.read_from_file(path)

    def _badge_with_raw_body(self, tmp_path, signed_svg_rsa, svg_image, raw_body):
        """Bake a badge whose JWS body is an arbitrary (possibly non-object)
        JSON value, not a mutated copy of the original dict."""
        from openbadgeslib._jws import utils as jws_utils

        assertion = extract_svg_assertion(signed_svg_rsa.signed)
        new_body_b64 = jws_utils.encode(raw_body)
        tampered = assertion.header + b'.' + new_body_b64 + b'.' + assertion.signature
        baked = baking.bake_svg(svg_image, tampered.decode('utf-8'))
        return self._write_temp(tmp_path, baked, '.svg')

    @pytest.mark.parametrize('raw_body', [[1, 2, 3], 'just-a-string', 42, None, True])
    def test_non_object_body_raises_clean_error(
        self, tmp_path, signed_svg_rsa, svg_image, rsa_pub_pem, raw_body
    ):
        # A body that decodes to a valid-JSON non-object must not leak a raw
        # TypeError/AttributeError from the field accesses before the guarded
        # construction block.
        path = self._badge_with_raw_body(tmp_path, signed_svg_rsa, svg_image, raw_body)
        with patch('openbadgeslib.ob1.badge.download_file', return_value=rsa_pub_pem):
            with pytest.raises(AssertionFormatIncorrect):
                BadgeSigned.read_from_file(path)


class TestBadgeInitCorruptKey:
    """A corrupt/mismatched private key must not leak a raw ValueError/binascii.Error."""

    def test_rsa_corrupt_private_key_raises_clean_error(self, rsa_pub_pem):
        with pytest.raises(PrivateKeyReadError):
            Badge(key_type=KeyType.RSA, privkey_pem=b'not a real PEM key', pubkey_pem=rsa_pub_pem)

    def test_ecc_corrupt_private_key_raises_clean_error(self, ecc_pub_pem):
        with pytest.raises(PrivateKeyReadError):
            Badge(key_type=KeyType.ECC, privkey_pem=b'not a real PEM key', pubkey_pem=ecc_pub_pem)

    def test_badge_without_pems_exposes_none_keys(self):
        # A Badge built with a key_type but no PEMs must expose priv_key/pub_key
        # as None, not leave them undefined (a later access would otherwise be a
        # raw AttributeError instead of a clean "no key material" case).
        badge = Badge(key_type=KeyType.RSA)
        assert badge.priv_key is None
        assert badge.pub_key is None
