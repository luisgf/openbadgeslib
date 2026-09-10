"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es
        Copyright (c) 2014-2026, Jesús Cea Avión, jcea@jcea.es

        All rights reserved.

        This library is free software; you can redistribute it and/or
        modify it under the terms of the GNU Lesser General Public
        License as published by the Free Software Foundation; either
        version 3.0 of the License, or (at your option) any later version.

        This library is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
        Lesser General Public License for more details.

        You should have received a copy of the GNU Lesser General Public
        License along with this library.
"""

# Version-agnostic carrier format for embedding an OpenBadges token (an OB 2.0
# JWS or an OB 3.0 JWT-VC) into an SVG or PNG badge image, and extracting it
# back out. OB2 and OB3 share the exact on-disk format; keeping a single
# implementation here stops the two paths from drifting (e.g. two PNG readers,
# one fixed-offset and one structured).

from struct import pack
from zlib import crc32

from typing import Any, List, Optional, Tuple, Union, cast

from defusedxml.minidom import parseString
from png import Reader, signature as _png_signature

# DecompressionLimitExceeded lives in openbadgeslib.errors (anchored under
# LibOpenBadgesException). Re-exported explicitly (X as X, so mypy --strict
# accepts it as a real export) — `baking.DecompressionLimitExceeded` and
# `from openbadgeslib.baking import DecompressionLimitExceeded` keep working.
from .errors import DecompressionLimitExceeded as DecompressionLimitExceeded

# OB 2.0 document-format identifiers.
ITXT_KEYWORD = b'openbadges'
SVG_ELEMENT = 'openbadges:assertion'
SVG_NS = 'http://openbadges.org'

# OB 3.0 document-format identifiers (differ from OB 2.0). Selected via the
# keyword-only args below so OB2 and OB3 bake/extract their own carriers.
ITXT_KEYWORD_OB3 = b'openbadgecredential'
SVG_ELEMENT_OB3 = 'openbadges:credential'
SVG_NS_OB3 = 'https://purl.imsglobal.org/ob/v3p0'

# Maximum bytes a compressed iTXt token is allowed to inflate to. A JWS/JWT-VC
# is a few KB; this cap stops a crafted zlib bomb from exhausting memory during
# extraction (which runs on untrusted input, before any signature check).
MAX_ITXT_DECOMPRESSED = 256 * 1024


def _split_openbadges_itxt(data: bytes, keyword: bytes = ITXT_KEYWORD) -> Optional[bytes]:
    chunk_keyword, sep, rest = data.partition(b'\x00')
    if sep != b'\x00' or chunk_keyword != keyword or len(rest) < 2:
        return None
    return rest


def _bounded_inflate(data: bytes, limit: int = MAX_ITXT_DECOMPRESSED) -> bytes:
    import zlib
    inflator = zlib.decompressobj()
    out = inflator.decompress(data, limit)
    if inflator.unconsumed_tail:
        raise DecompressionLimitExceeded(
            "Compressed token exceeds the %d-byte limit" % limit)
    return out


# ── SVG ─────────────────────────────────────────────────────────────────────

# Active content stripped from the carrier at bake time. A baked badge is an
# image a recipient may open in a browser; leaving <script>, on* handlers or
# javascript: URLs in the source SVG would execute in that context (#328).
# `opacity` is the one SVG presentation attribute whose local name starts
# with "on" and is not an event handler.
_ACTIVE_SVG_ELEMENTS = frozenset({
    'script', 'foreignobject', 'iframe', 'embed', 'object', 'handler',
})
_URL_ATTRS = frozenset({'href', 'src', 'action'})
_SAFE_DATA_IMAGE_TYPES = (
    'image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp',
)


def _svg_local_name(node: Any) -> str:
    return str(node.tagName).split(':')[-1].lower()


def _iter_svg_elements(node: Any) -> List[Any]:
    found: List[Any] = []
    if getattr(node, 'nodeType', None) == node.ELEMENT_NODE:
        found.append(node)
        for child in list(node.childNodes):
            found.extend(_iter_svg_elements(child))
    return found


def _is_active_url(value: str) -> bool:
    """True for javascript:/vbscript: and for data: that is not a raster image."""
    lowered = value.strip().lower()
    if lowered.startswith('javascript:') or lowered.startswith('vbscript:'):
        return True
    if not lowered.startswith('data:'):
        return False
    payload = lowered[5:]
    return not any(payload.startswith(kind) for kind in _SAFE_DATA_IMAGE_TYPES)


def _strip_svg_active_content(root: Any) -> None:
    """Drop script-class elements, on* handlers and active URLs under *root*."""
    if root is None:
        return
    for el in _iter_svg_elements(root):
        if _svg_local_name(el) in _ACTIVE_SVG_ELEMENTS:
            parent = el.parentNode
            if parent is not None:
                parent.removeChild(el)
    for el in _iter_svg_elements(root):
        attrs = el.attributes
        if attrs is None:
            continue
        for name in list(attrs.keys()):
            local = name.split(':')[-1].lower()
            if local.startswith('on') and local != 'opacity':
                el.removeAttribute(name)
                continue
            if local in _URL_ATTRS and _is_active_url(attrs[name].value):
                el.removeAttribute(name)


def bake_svg(image_bytes: bytes, token: str, comment: Optional[str] = None, *,
             element: str = SVG_ELEMENT, namespace: str = SVG_NS,
             as_text: bool = False) -> bytes:
    """Return *image_bytes* with an ``<element verify=token>`` node (and an
    optional XML comment) appended to the root ``<svg>``. *element*/*namespace*
    default to the OB 2.0 identifiers; OB 3.0 passes its own.

    With ``as_text=True`` the token is stored as the element's text content
    instead of the ``verify`` attribute — the OB 3.0 carrier for credentials
    secured with a Data Integrity proof, whose payload is a JSON document
    rather than a compact JWT (OB 3.0 §5.3).

    Active content in the source SVG (``<script>``, event-handler attributes,
    ``javascript:`` / hostile ``data:`` URLs) is stripped before the token is
    attached, so the baked carrier is not an XSS gadget (#328).
    """
    svg_doc = parseString(image_bytes)
    try:
        svg_tag = svg_doc.getElementsByTagName('svg').item(0)
        _strip_svg_active_content(svg_tag)
        node = svg_doc.createElement(element)
        node.attributes['xmlns:openbadges'] = namespace
        if as_text:
            node.appendChild(svg_doc.createTextNode(token))
        else:
            node.attributes['verify'] = token
        svg_tag.appendChild(node)
        if comment:
            svg_tag.appendChild(svg_doc.createComment(comment))
        return cast(bytes, svg_doc.toxml().encode('utf-8'))
    finally:
        svg_doc.unlink()


def has_svg(image_bytes: bytes, *, element: str = SVG_ELEMENT) -> bool:
    """Return True if *image_bytes* already carries an *element* node."""
    svg_doc = parseString(image_bytes)
    try:
        return bool(svg_doc.getElementsByTagName(element))
    finally:
        svg_doc.unlink()


def extract_svg(image_bytes: bytes, *, element: str = SVG_ELEMENT,
                text_fallback: bool = False) -> Optional[str]:
    """Return the embedded token string, or None if the badge carries no token.

    None covers both a missing *element* node and a present element with no
    ``verify`` attribute (a well-formed SVG that simply isn't a signed badge).
    Malformed XML still raises (left to the caller to map to its own error type).

    With ``text_fallback=True``, an element without a ``verify`` attribute
    falls back to its text content — where OB 3.0 §5.3 bakes a credential
    secured with a Data Integrity proof (a JSON document, not a compact JWT).
    An empty/whitespace-only text content still yields None.
    """
    svg_doc = None
    try:
        svg_doc = parseString(image_bytes)
        nodes = svg_doc.getElementsByTagName(element)
        if not nodes:
            return None
        attrs = nodes[0].attributes
        if 'verify' in attrs:
            return cast(Optional[str], attrs['verify'].nodeValue)
        if not text_fallback:
            return None
        text = ''.join(
            child.data for child in nodes[0].childNodes
            if child.nodeType in (child.TEXT_NODE, child.CDATA_SECTION_NODE)
        ).strip()
        return text or None
    finally:
        if svg_doc is not None:
            svg_doc.unlink()


# ── PNG ─────────────────────────────────────────────────────────────────────

def _serialize_png(chunks: List[Tuple[Union[str, bytes], bytes]]) -> bytes:
    # Accumulate the pieces in a list and join once at the end. Building the
    # result with ``out += piece`` is O(n^2) in the number of chunks: a PNG
    # whose image data is split across hundreds of small IDAT chunks (8 KB, as
    # libpng and Photoshop emit) reallocated and recopied the whole growing
    # buffer on every chunk — 101 ms for 6.6 MB / 832 chunks, versus 0.49 ms
    # with a single ``b''.join`` (#216). The emitted bytes are byte-identical.
    parts: List[bytes] = [_png_signature]
    for tag, data in chunks:
        if isinstance(tag, str):
            tag = tag.encode('iso8859-1')
        checksum = crc32(tag)
        checksum = crc32(data, checksum) & 0xFFFFFFFF
        parts.append(pack("!I", len(data)))
        parts.append(tag + data)
        parts.append(pack("!I", checksum))
    return b''.join(parts)


def bake_png(image_bytes: bytes, token: str, text_comment: Optional[str] = None, *,
             keyword: bytes = ITXT_KEYWORD) -> bytes:
    """Return *image_bytes* with the token stored in a *keyword* iTXt chunk (and
    an optional ``tEXt`` comment chunk) inserted before IEND. *keyword* defaults
    to the OB 2.0 identifier; OB 3.0 passes ``openbadgecredential``."""
    chunks = list(Reader(bytes=image_bytes).chunks())
    itxt_data = keyword + pack('BBBBB', 0, 0, 0, 0, 0) + token.encode('utf-8')
    chunks.insert(len(chunks) - 1, ('iTXt', itxt_data))
    if text_comment:
        chunks.insert(len(chunks) - 1, ('tEXt', text_comment.encode('utf-8')))
    return _serialize_png(chunks)


def has_png(image_bytes: bytes, *, keyword: bytes = ITXT_KEYWORD) -> bool:
    """Return True if *image_bytes* already carries a *keyword* iTXt chunk."""
    for tag, data in Reader(bytes=image_bytes).chunks():
        tag_str = tag.decode('ascii') if isinstance(tag, bytes) else tag
        if tag_str == 'iTXt' and _split_openbadges_itxt(data, keyword) is not None:
            return True
    return False


def extract_png(image_bytes: bytes, max_decompressed: int = MAX_ITXT_DECOMPRESSED, *,
                keyword: bytes = ITXT_KEYWORD) -> Optional[str]:
    """Return the embedded token string, or None if there is no *keyword*
    iTXt chunk.

    Parses the iTXt structure (keyword, compression flag/method, language tag,
    translated keyword, then text) rather than a fixed byte offset, so tokens
    baked by any conformant tool — including compressed ones — are recovered.
    Raises :class:`DecompressionLimitExceeded` if a compressed token inflates
    beyond *max_decompressed*.
    """
    for tag, data in Reader(bytes=image_bytes).chunks():
        tag_str = tag.decode('ascii') if isinstance(tag, bytes) else tag
        if tag_str != 'iTXt':
            continue

        rest = _split_openbadges_itxt(data, keyword)
        if rest is None:
            continue
        compression_flag = rest[0]
        _, sep_lang, rest = rest[2:].partition(b'\x00')   # drop language tag
        _, sep_trans, text = rest.partition(b'\x00')      # drop translated keyword
        if sep_lang != b'\x00' or sep_trans != b'\x00':
            continue
        if compression_flag:
            text = _bounded_inflate(text, max_decompressed)
        return text.decode('utf-8')

    return None
