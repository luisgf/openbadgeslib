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

    def test_script_and_handlers_are_stripped_from_the_carrier(self):
        # A baked badge is opened as an image; leftover active content in the
        # source SVG would run in the recipient's browser (#328).
        src = (
            b'<svg xmlns="http://www.w3.org/2000/svg">'
            b'<script>alert(1)</script>'
            b'<rect id="mark" onclick="alert(1)" opacity="0.5" width="1" height="1"/>'
            b'<a href="javascript:alert(1)">x</a>'
            b'<image href="data:image/png;base64,AAAA"/>'
            b'</svg>'
        )
        baked = bake_svg(src, TOKEN)
        assert b'<script' not in baked.lower()
        assert b'onclick' not in baked.lower()
        assert b'javascript:' not in baked.lower()
        assert b'opacity="0.5"' in baked
        assert b'data:image/png;base64,AAAA' in baked
        assert extract_svg(baked) == TOKEN

    def test_foreignobject_and_data_html_are_stripped(self):
        src = (
            b'<svg xmlns="http://www.w3.org/2000/svg">'
            b'<foreignObject><body xmlns="http://www.w3.org/1999/xhtml">'
            b'<p>x</p></body></foreignObject>'
            b'<a href="data:text/html,%3Cscript%3Ealert(1)%3C/script%3E">x</a>'
            b'</svg>'
        )
        baked = bake_svg(src, TOKEN)
        assert b'foreignObject' not in baked and b'foreignobject' not in baked.lower()
        assert b'data:text/html' not in baked.lower()
        assert extract_svg(baked) == TOKEN


_SVG_NS = b'xmlns="http://www.w3.org/2000/svg"'
_OB3_NS = 'https://purl.imsglobal.org/ob/v3p0'


def _svg(body, attrs=b''):
    return b'<svg ' + _SVG_NS + attrs + b'>' + body + b'</svg>'


class TestSvgActiveContentFilter:
    """#340 — the #328 filter walked only the first element named ``svg`` and
    tested the URL scheme without the normalisation a browser applies, so a
    plain ``<script>`` outside that subtree, an ``xml-stylesheet`` processing
    instruction, ``java&#10;script:`` and a SMIL animation of ``href`` all
    reached the baked carrier."""

    # ── the document must be an SVG, and the whole of it is filtered ─────────

    @pytest.mark.parametrize('src', [
        # A document of another vocabulary that merely contains an <svg>: the
        # script is the root's child, outside the subtree the old walk covered.
        b'<h:html xmlns:h="http://www.w3.org/1999/xhtml">'
        b'<h:script>alert(1)</h:script>'
        b'<svg ' + _SVG_NS + b'><rect/></svg></h:html>',
        b'<?xml version="1.0"?><root><child/></root>',
        b'<root xmlns="http://www.w3.org/2000/svg"><svg/></root>',
        # No namespace at all: not an SVG to any renderer.
        b'<svg><rect/></svg>',
        b'<svg xmlns="http://www.w3.org/1999/xhtml"><rect/></svg>',
    ], ids=['xhtml-root', 'unknown-root', 'svg-namespace-wrong-name',
            'svg-without-namespace', 'svg-name-wrong-namespace'])
    def test_a_document_that_is_not_an_svg_is_refused(self, src):
        from openbadgeslib.errors import (BadgeImgFormatUnsupported,
                                          LibOpenBadgesException)
        with pytest.raises(BadgeImgFormatUnsupported) as excinfo:
            bake_svg(src, TOKEN)
        assert isinstance(excinfo.value, LibOpenBadgesException)
        assert 'SVG' in str(excinfo.value)

    def test_script_outside_the_first_unprefixed_svg_is_stripped(self):
        # The root is an SVG written with a prefix; the first element *named*
        # "svg" is a nested one, and the script sits beside it.
        src = (b'<svg:svg xmlns:svg="http://www.w3.org/2000/svg" ' + _SVG_NS + b'>'
               b'<svg:script>alert(1)</svg:script><svg><rect/></svg></svg:svg>')
        baked = bake_svg(src, TOKEN)
        assert b'alert(1)' not in baked
        assert b'script' not in baked.lower()
        assert b'<svg><rect/></svg>' in baked             # the drawing survives
        assert has_svg(baked) and extract_svg(baked) == TOKEN
        # The token hangs from the document element, not from the nested svg.
        assert baked.endswith(b'verify="' + TOKEN.encode() + b'"/></svg:svg>')

    @pytest.mark.parametrize('kwargs, extract_kwargs', [
        ({}, {}),
        ({'element': OB3_ELEMENT, 'namespace': _OB3_NS, 'comment': ' c '},
         {'element': OB3_ELEMENT}),
        ({'element': OB3_ELEMENT, 'namespace': _OB3_NS, 'as_text': True},
         {'element': OB3_ELEMENT, 'text_fallback': True}),
    ], ids=['ob2-verify', 'ob3-jwt-verify', 'ob3-data-integrity-text'])
    def test_prefixed_svg_root_bakes_and_round_trips(self, kwargs, extract_kwargs):
        # Used to die with AttributeError: getElementsByTagName('svg') finds
        # nothing when the root is spelled <s:svg>.
        src = (b'<s:svg xmlns:s="http://www.w3.org/2000/svg">'
               b'<s:rect width="1" height="1"/></s:svg>')
        element = kwargs.get('element', 'openbadges:assertion')
        assert not has_svg(src, element=element)
        baked = bake_svg(src, TOKEN, **kwargs)
        assert has_svg(baked, element=element)
        assert extract_svg(baked, **extract_kwargs) == TOKEN
        assert b'<s:rect width="1" height="1"/>' in baked
        assert baked.rstrip().endswith(b'</s:svg>')

    # ── namespace declarations are neither handlers nor links ───────────────

    @pytest.mark.parametrize('kwargs, extract_kwargs', [
        ({}, {}),
        ({'element': OB3_ELEMENT, 'namespace': _OB3_NS, 'comment': ' c '},
         {'element': OB3_ELEMENT}),
        ({'element': OB3_ELEMENT, 'namespace': _OB3_NS, 'as_text': True},
         {'element': OB3_ELEMENT, 'text_fallback': True}),
    ], ids=['ob2-verify', 'ob3-jwt-verify', 'ob3-data-integrity-text'])
    def test_root_prefix_that_reads_like_a_handler_keeps_its_binding(
            self, kwargs, extract_kwargs):
        # xmlns:ont is a declaration of the prefix "ont", not an on* handler:
        # removing it left the baked file with an unbound prefix, unreadable.
        src = b'<ont:svg xmlns:ont="http://www.w3.org/2000/svg"><ont:rect/></ont:svg>'
        baked = bake_svg(src, TOKEN, **kwargs)
        assert b'<ont:svg xmlns:ont="http://www.w3.org/2000/svg"><ont:rect/>' in baked
        assert has_svg(baked, element=kwargs.get('element', 'openbadges:assertion'))
        assert extract_svg(baked, **extract_kwargs) == TOKEN

    @pytest.mark.parametrize('prefix', [b'ont', b'onload', b'href', b'src', b'action'])
    def test_metadata_prefix_named_like_a_filtered_attribute_survives(self, prefix):
        decl = b' xmlns:' + prefix + b'="data:text/x-vocabulary,terms"'
        src = _svg(b'<metadata><' + prefix + b':term/></metadata>', attrs=decl)
        baked = bake_svg(src, TOKEN)
        assert decl in baked
        assert extract_svg(baked) == TOKEN                # still well-formed

    def test_rebinding_a_prefix_cannot_smuggle_xhtml(self):
        # The inner declaration looked like an active URL in an attribute
        # called "href" and was removed after <href:link> had been judged by
        # it, so on re-parse the element fell back to the outer, XHTML binding.
        from defusedxml.minidom import parseString
        src = _svg(
            b'<g xmlns:href="javascript:">'
            b'<href:link rel="stylesheet" href="https://evil.example/x.css"/>'
            b'</g><rect/>',
            attrs=b' xmlns:href="http://www.w3.org/1999/xhtml"')
        baked = bake_svg(src, TOKEN)
        doc = parseString(baked)
        try:
            pending, seen = [doc.documentElement], []
            while pending:
                el = pending.pop()
                seen.append((el.namespaceURI, el.localName))
                pending.extend(child for child in el.childNodes
                               if child.nodeType == child.ELEMENT_NODE)
        finally:
            doc.unlink()
        assert ('http://www.w3.org/2000/svg', 'rect') in seen
        assert all(ns != 'http://www.w3.org/1999/xhtml' for ns, _ in seen)
        # The bindings the filter judged are the bindings it wrote.
        assert ('javascript:', 'link') in seen
        assert extract_svg(baked) == TOKEN

    def test_token_hangs_from_the_document_element(self):
        # Same place as before for an ordinary image with a nested <svg>.
        src = _svg(b'<g><svg><rect/></svg></g><circle/>')
        baked = bake_svg(src, TOKEN)
        assert b'<g><svg><rect/></svg></g><circle/><openbadges:assertion' in baked
        assert extract_svg(baked) == TOKEN

    # ── processing instructions and the DOCTYPE's internal subset ────────────

    def test_xml_stylesheet_processing_instruction_is_dropped(self):
        src = (b'<?xml version="1.0"?>'
               b'<?xml-stylesheet type="text/xsl" href="data:text/xml,alert(1)"?>'
               + _svg(b'<rect/>') +
               b'<?xml-stylesheet type="text/css" href="after.css"?>')
        baked = bake_svg(src, TOKEN)
        assert b'xml-stylesheet' not in baked
        assert b'alert(1)' not in baked and b'after.css' not in baked
        assert baked.startswith(b'<?xml version="1.0" ?><svg ')
        assert extract_svg(baked) == TOKEN

    def test_processing_instructions_inside_the_tree_are_dropped(self):
        src = _svg(b'<?xml-stylesheet href="alert(1)"?>'
                   b'<g><?anything alert(1)?><rect/></g>')
        baked = bake_svg(src, TOKEN)
        assert b'alert(1)' not in baked
        assert b'<g><rect/></g>' in baked
        assert baked.count(b'<?') == 1                    # the XML declaration

    def test_other_top_level_nodes_are_kept(self):
        # Only xml-stylesheet is a hazard among the prolog's nodes; a comment
        # and a PUBLIC doctype (every Illustrator/Inkscape export) stay put.
        doctype = (b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
                   b'"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">')
        src = (b'<?xml version="1.0"?><!-- drawn by hand -->' + doctype
               + b'<?app-hint keep?>' + _svg(b'<rect/>'))
        baked = bake_svg(src, TOKEN)
        assert b'<!-- drawn by hand -->' in baked
        assert b'<!DOCTYPE svg' in baked
        assert b'-//W3C//DTD SVG 1.1//EN' in baked and b'/DTD/svg11.dtd' in baked
        assert b'<?app-hint keep?>' in baked
        assert extract_svg(baked) == TOKEN

    def test_doctype_internal_subset_is_dropped(self):
        # An ATTLIST default puts the handler back on the element when the
        # baked file is parsed again, after the filter removed it from the DOM.
        src = (b'<!DOCTYPE svg [<!ATTLIST svg onload CDATA "alert(1)">]>'
               + _svg(b'<rect/>'))
        baked = bake_svg(src, TOKEN)
        assert b'alert(1)' not in baked
        assert b'ATTLIST' not in baked and b'onload' not in baked
        assert b'<!DOCTYPE svg>' in baked
        assert extract_svg(baked) == TOKEN

    # ── URL scheme, as a browser reads it ────────────────────────────────────

    @pytest.mark.parametrize('href', [
        b'java&#10;script:alert(1)',
        b'java&#9;script:alert(1)',
        b'java&#13;script:alert(1)',
        b'&#9;&#10; javascript:alert(1)',
        b'j a v a s c r i p t :alert(1)',
        b'JaVa&#10;ScRiPt&#9;:alert(1)',
        b'vb&#10;script:alert(1)',
        b'da&#10;ta:text/html,alert(1)',
        b'data:&#10;image/svg+xml,alert(1)',
    ])
    @pytest.mark.parametrize('attr', [b'href', b'xlink:href'])
    def test_whitespace_inside_the_scheme_does_not_hide_it(self, attr, href):
        src = _svg(b'<a ' + attr + b'="' + href + b'">x</a>',
                   attrs=b' xmlns:xlink="http://www.w3.org/1999/xlink"')
        baked = bake_svg(src, TOKEN)
        assert b'alert(1)' not in baked
        assert b'<a>x</a>' in baked                       # only the URL goes
        assert extract_svg(baked) == TOKEN

    def test_is_active_url(self):
        active = baking._is_active_url
        assert active('javascript:alert(1)')
        assert active('java\nscript:alert(1)')
        assert active('\x01\x1f javascript:alert(1)')
        assert active(' javascript:alert(1)')        # str.strip() still applies
        assert active('data:text/html,x')
        assert active('data:image/svg+xml,x')
        assert not active('data:image/png;base64,AAAA')
        assert not active('data:\timage/png;base64,AA\nAA')
        assert not active('https://example.org/java script:')
        assert not active('#local')
        assert not active('')

    # ── SMIL animation of a URL or handler attribute ─────────────────────────

    @pytest.mark.parametrize('animation', [
        b'<set attributeName="href" to="javascript:alert(1)"/>',
        b'<animate attributeName="xlink:href" values="javascript:alert(1)" dur="1s"/>',
        b'<animate attributeName=" HREF&#10;" from="javascript:alert(1)" to="#"/>',
        b'<animateTransform attributeName="href" to="javascript:alert(1)"/>',
        b'<animateMotion attributeName="src" to="javascript:alert(1)"/>',
        b'<animateColor attributeName="action" to="javascript:alert(1)"/>',
        b'<svg:set xmlns:svg="http://www.w3.org/2000/svg" attributeName="href"'
        b' to="javascript:alert(1)"/>',
        b'<set attributeName="onclick" to="alert(1)"/>',
    ], ids=['set-href', 'animate-xlink-href', 'animate-padded-name',
            'animateTransform', 'animateMotion', 'animateColor',
            'prefixed-set', 'set-handler'])
    def test_animation_of_a_url_attribute_is_dropped(self, animation):
        src = _svg(b'<a>' + animation + b'<text>x</text></a>')
        baked = bake_svg(src, TOKEN)
        assert b'alert(1)' not in baked
        assert b'<a><text>x</text></a>' in baked
        assert extract_svg(baked) == TOKEN

    # ── XHTML is active content wherever it appears ──────────────────────────

    def test_xhtml_namespace_elements_are_dropped(self):
        src = _svg(
            b'<h:img xmlns:h="http://www.w3.org/1999/xhtml" src="x" title="alert(1)"/>'
            b'<g><body xmlns="http://www.w3.org/1999/xhtml"><p>alert(1)</p></body></g>'
            b'<rect/>')
        baked = bake_svg(src, TOKEN)
        assert b'alert(1)' not in baked
        assert b'1999/xhtml' not in baked
        assert b'<g/><rect/>' in baked
        assert extract_svg(baked) == TOKEN

    # ── what must survive ────────────────────────────────────────────────────

    def test_legitimate_content_is_baked_untouched(self):
        body = (
            b'<style>rect{fill:red}</style>'
            b'<defs><rect id="r" width="1" height="1"/></defs>'
            b'<use href="#r"/><use xlink:href="#r"/>'
            b'<rect opacity="0.5">'
            b'<animate attributeName="opacity" values="0;1" dur="1s"/>'
            b'<animate attributeName="fill" from="red" to="blue" dur="1s"/>'
            b'<set attributeName="visibility" to="hidden"/>'
            b'<animateTransform attributeName="transform" type="rotate"'
            b' from="0" to="360" dur="1s"/>'
            b'<animateMotion path="M0,0 L1,1" dur="1s"/>'
            b'</rect>'
            b'<image href="data:image/png;base64,AAAA"/>'
            b'<image xlink:href="data:image/jpeg;base64,AAAA"/>'
            b'<a href="https://example.org/badge">x</a>'
            b'<metadata><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/>'
            b'</metadata>'
        )
        attrs = b' xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 1 1"'
        baked = bake_svg(_svg(body, attrs), TOKEN)
        assert baked == (
            b'<?xml version="1.0" ?><svg ' + _SVG_NS + attrs + b'>' + body
            + b'<openbadges:assertion xmlns:openbadges="http://openbadges.org"'
            b' verify="' + TOKEN.encode() + b'"/></svg>')

    def test_carriers_of_earlier_versions_still_extract(self):
        # extract_svg/has_svg keep finding the element wherever a legitimate
        # badge carries it, whatever wrote it.
        old = (b'<?xml version="1.0" ?><svg ' + _SVG_NS + b'><rect/>'
               b'<openbadges:assertion xmlns:openbadges="http://openbadges.org"'
               b' verify="' + TOKEN.encode() + b'"/>'
               b'<!-- Signed with OpenBadgesLib 4.6.3 --></svg>')
        assert has_svg(old) and extract_svg(old) == TOKEN
        bare = (b'<svg><openbadges:assertion xmlns:openbadges="http://openbadges.org"'
                b' verify="' + TOKEN.encode() + b'"/></svg>')
        assert has_svg(bare) and extract_svg(bare) == TOKEN

    def test_entities_are_still_refused(self):
        # The filter rides on defusedxml: an entity declaration never parses.
        src = (b'<!DOCTYPE svg [<!ENTITY x "alert(1)">]>' + _svg(b'<text>&x;</text>'))
        with pytest.raises(Exception) as excinfo:
            bake_svg(src, TOKEN)
        assert type(excinfo.value).__name__ == 'EntitiesForbidden'


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
