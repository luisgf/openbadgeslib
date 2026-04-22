"""Tests for badge image embedding and extraction (SVG / PNG)."""
import pytest
from unittest.mock import patch

from openbadgeslib.badge import (
    Assertion, extract_svg_assertion, extract_png_assertion, BadgeSigned,
)
from openbadgeslib.errors import BadgeImgFormatUnsupported


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

    def test_returns_none_for_unsigned_png(self, png_image):
        # Unsigned PNG has no iTXt chunk → returns None
        result = extract_png_assertion(png_image)
        assert result is None


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
        with patch('openbadgeslib.ob2.badge.download_file', return_value=rsa_pub_pem):
            badge = BadgeSigned.read_from_file(path)
        assert badge.assertion is not None
        assert badge.source.key_type is not None

    def test_read_signed_png_rsa(self, tmp_path, signed_png_rsa, rsa_pub_pem):
        path = self._write_temp(tmp_path, signed_png_rsa.signed, '.png')
        with patch('openbadgeslib.ob2.badge.download_file', return_value=rsa_pub_pem):
            badge = BadgeSigned.read_from_file(path)
        assert badge.assertion is not None

    def test_unsupported_format_raises(self, tmp_path):
        p = tmp_path / 'badge.gif'
        p.write_bytes(b'GIF89a')
        with pytest.raises(BadgeImgFormatUnsupported):
            BadgeSigned.read_from_file(str(p))
