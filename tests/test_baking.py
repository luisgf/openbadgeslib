"""#169 — dedicated tests for openbadgeslib.baking, the token carrier shared by
every OB1/OB2/OB3 signer and verifier. Focus: the embed→extract round-trip
invariants per format, plus the iTXt structure/limit edge cases that only a
crafted image exercises.
"""
import zlib

import pytest
from png import Reader

from openbadgeslib import baking
from openbadgeslib.baking import (DecompressionLimitExceeded, ITXT_KEYWORD,
                                  bake_png, bake_svg, extract_png, extract_svg,
                                  has_png, has_svg)

OB3_ELEMENT = 'openbadges:credential'
OB3_KEYWORD = b'openbadgecredential'
TOKEN = 'eyJhbGciOiJSUzI1NiJ9.payload.sig'


# ── SVG ──────────────────────────────────────────────────────────────────────

class TestSvg:
    def test_round_trip_verify_attribute(self, svg_image):
        assert not has_svg(svg_image)
        assert extract_svg(svg_image) is None
        baked = bake_svg(svg_image, TOKEN)
        assert has_svg(baked)
        assert extract_svg(baked) == TOKEN

    def test_as_text_round_trip_is_ob3_ldp_carrier(self, svg_image):
        # OB 3.0 §5.3 bakes a Data Integrity credential (a JSON document) as the
        # element's text, not the verify attribute.
        doc = '{"@context": [], "proof": {}}'
        baked = bake_svg(svg_image, doc, as_text=True)
        assert extract_svg(baked) is None                 # no verify attribute
        assert extract_svg(baked, text_fallback=True) == doc

    def test_custom_element_and_comment(self, svg_image):
        baked = bake_svg(svg_image, TOKEN, comment='issued by test',
                         element=OB3_ELEMENT)
        assert has_svg(baked, element=OB3_ELEMENT)
        assert extract_svg(baked, element=OB3_ELEMENT) == TOKEN
        assert b'issued by test' in baked                 # XML comment present

    def test_element_without_verify_is_not_a_token(self, svg_image):
        # A well-formed element with neither verify nor (fallback) text is None.
        baked = bake_svg(svg_image, '   ', as_text=True)  # whitespace-only text
        assert extract_svg(baked, text_fallback=True) is None

    def test_malformed_xml_raises(self):
        with pytest.raises(Exception):
            extract_svg(b'<svg><unclosed>')


# ── PNG ──────────────────────────────────────────────────────────────────────

def _png_with_itxt(png_bytes, itxt_data):
    """Insert a raw iTXt chunk (before IEND) into a PNG, for crafting the
    structures bake_png does not itself produce (compressed, malformed)."""
    chunks = list(Reader(bytes=png_bytes).chunks())
    chunks.insert(len(chunks) - 1, ('iTXt', itxt_data))
    return baking._serialize_png(chunks)


def _tag(tag):
    return tag.decode('ascii') if isinstance(tag, bytes) else tag


def _png_with_many_small_idat(png_bytes, chunk_size=16):
    """Re-chunk a PNG's IDAT stream into many small IDAT chunks in place.

    A PNG's compressed image data is a single byte stream that may be split
    across any number of IDAT chunks at arbitrary boundaries; libpng and
    Photoshop routinely emit hundreds of small (~8 KB) ones. That is the
    pathological input for the old O(n^2) ``out += chunk`` serializer (#216), so
    this splits the image data into ``chunk_size``-byte IDATs (13 584 bytes / 16
    -> ~849 chunks, in the ballpark of the issue's 832) while leaving every
    other chunk untouched, producing a still-valid PNG."""
    chunks = list(Reader(bytes=png_bytes).chunks())
    idat = b''.join(data for tag, data in chunks if _tag(tag) == 'IDAT')
    rebuilt = []
    inserted = False
    for tag, data in chunks:
        if _tag(tag) == 'IDAT':
            if not inserted:      # replace the run of IDATs with many small ones
                rebuilt.extend(('IDAT', idat[i:i + chunk_size])
                               for i in range(0, len(idat), chunk_size))
                inserted = True
            continue
        rebuilt.append((_tag(tag), data))
    return baking._serialize_png(rebuilt)


class TestPng:
    def test_round_trip(self, png_image):
        assert not has_png(png_image)
        assert extract_png(png_image) is None
        baked = bake_png(png_image, TOKEN)
        assert has_png(baked)
        assert extract_png(baked) == TOKEN

    def test_custom_keyword_and_comment(self, png_image):
        baked = bake_png(png_image, TOKEN, text_comment='hi', keyword=OB3_KEYWORD)
        assert has_png(baked, keyword=OB3_KEYWORD)
        assert not has_png(baked)                         # default keyword absent
        assert extract_png(baked, keyword=OB3_KEYWORD) == TOKEN

    def test_compressed_itxt_is_inflated(self, png_image):
        # compression flag set, zlib payload — a conformant tool may bake this.
        itxt = ITXT_KEYWORD + bytes([0, 1, 0, 0, 0]) + zlib.compress(TOKEN.encode())
        baked = _png_with_itxt(png_image, itxt)
        assert extract_png(baked) == TOKEN

    def test_compressed_bomb_hits_the_limit(self, png_image):
        payload = zlib.compress(b'A' * 100_000)
        itxt = ITXT_KEYWORD + bytes([0, 1, 0, 0, 0]) + payload
        baked = _png_with_itxt(png_image, itxt)
        with pytest.raises(DecompressionLimitExceeded):
            extract_png(baked, max_decompressed=1024)

    def test_malformed_itxt_without_separators_is_skipped(self, png_image):
        # keyword + flag/method but no language/translated-keyword NULs: the
        # chunk is not a valid iTXt token, so extraction skips it (returns None).
        itxt = ITXT_KEYWORD + bytes([0, 0]) + b'no-null-separators'
        baked = _png_with_itxt(png_image, itxt)
        assert extract_png(baked) is None

    def test_foreign_itxt_keyword_is_ignored(self, png_image):
        itxt = b'SomeOtherKeyword' + bytes([0, 0, 0, 0, 0]) + b'data'
        baked = _png_with_itxt(png_image, itxt)
        assert extract_png(baked) is None
        assert not has_png(baked)

    def test_many_small_idat_chunks_round_trip(self, png_image):
        # #216: _serialize_png must stay correct (and O(n)) when the image data
        # is spread over hundreds of small IDAT chunks. Bake into such a PNG and
        # extract the token back — the O(n^2) regression this guards against was
        # a performance one, so correctness under the pathological shape is the
        # invariant to lock.
        many = _png_with_many_small_idat(png_image, chunk_size=16)
        n_idat = sum(1 for tag, _ in Reader(bytes=many).chunks() if _tag(tag) == 'IDAT')
        assert n_idat > 500                               # genuinely many chunks

        # The re-chunked PNG is still a valid image: pypng decodes it and the
        # pixels are identical to the original (splitting IDATs at arbitrary
        # byte offsets must not corrupt the compressed stream).
        w0, h0, rows0, _ = Reader(bytes=png_image).read()
        w1, h1, rows1, _ = Reader(bytes=many).read()
        assert (w0, h0) == (w1, h1)
        assert [list(r) for r in rows0] == [list(r) for r in rows1]

        # Round-trip: the token bakes in and comes back out unchanged, and the
        # many-IDAT structure survives baking.
        assert not has_png(many)
        baked = bake_png(many, TOKEN)
        assert has_png(baked)
        assert extract_png(baked) == TOKEN
        assert sum(1 for tag, _ in Reader(bytes=baked).chunks()
                   if _tag(tag) == 'IDAT') == n_idat
