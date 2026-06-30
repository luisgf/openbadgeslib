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

from typing import List, Optional, Tuple, Union

from defusedxml.minidom import parseString
from png import Reader, signature as _png_signature

ITXT_KEYWORD = b'openbadges'
SVG_ELEMENT = 'openbadges:assertion'

# Maximum bytes a compressed iTXt token is allowed to inflate to. A JWS/JWT-VC
# is a few KB; this cap stops a crafted zlib bomb from exhausting memory during
# extraction (which runs on untrusted input, before any signature check).
MAX_ITXT_DECOMPRESSED = 256 * 1024


class DecompressionLimitExceeded(Exception):
    """Raised when a compressed iTXt token inflates beyond the allowed size."""


def _split_openbadges_itxt(data: bytes) -> Optional[bytes]:
    keyword, sep, rest = data.partition(b'\x00')
    if sep != b'\x00' or keyword != ITXT_KEYWORD or len(rest) < 2:
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

def bake_svg(image_bytes: bytes, token: str, comment: Optional[str] = None) -> bytes:
    """Return *image_bytes* with an ``<openbadges:assertion verify=token>``
    element (and an optional XML comment) appended to the root ``<svg>``."""
    svg_doc = parseString(image_bytes)
    try:
        svg_tag = svg_doc.getElementsByTagName('svg').item(0)
        node = svg_doc.createElement(SVG_ELEMENT)
        node.attributes['xmlns:openbadges'] = 'http://openbadges.org'
        node.attributes['verify'] = token
        svg_tag.appendChild(node)
        if comment:
            svg_tag.appendChild(svg_doc.createComment(comment))
        return svg_doc.toxml().encode('utf-8')
    finally:
        svg_doc.unlink()


def has_svg(image_bytes: bytes) -> bool:
    """Return True if *image_bytes* already carries an OpenBadges assertion."""
    svg_doc = parseString(image_bytes)
    try:
        return bool(svg_doc.getElementsByTagName(SVG_ELEMENT))
    finally:
        svg_doc.unlink()


def extract_svg(image_bytes: bytes) -> Optional[str]:
    """Return the embedded token string, or None if there is no assertion node.

    Raises on malformed XML (left to the caller to map to its own error type).
    """
    svg_doc = None
    try:
        svg_doc = parseString(image_bytes)
        nodes = svg_doc.getElementsByTagName(SVG_ELEMENT)
        if not nodes:
            return None
        return nodes[0].attributes['verify'].nodeValue
    finally:
        if svg_doc is not None:
            svg_doc.unlink()


# ── PNG ─────────────────────────────────────────────────────────────────────

def _serialize_png(chunks: List[Tuple[Union[str, bytes], bytes]]) -> bytes:
    out = _png_signature
    for tag, data in chunks:
        out += pack("!I", len(data))
        if isinstance(tag, str):
            tag = tag.encode('iso8859-1')
        out += tag + data
        checksum = crc32(tag)
        checksum = crc32(data, checksum) & 0xFFFFFFFF
        out += pack("!I", checksum)
    return out


def bake_png(image_bytes: bytes, token: str, text_comment: Optional[str] = None) -> bytes:
    """Return *image_bytes* with the token stored in an ``openbadges`` iTXt
    chunk (and an optional ``tEXt`` comment chunk) inserted before IEND."""
    chunks = list(Reader(bytes=image_bytes).chunks())
    itxt_data = ITXT_KEYWORD + pack('BBBBB', 0, 0, 0, 0, 0) + token.encode('utf-8')
    chunks.insert(len(chunks) - 1, ('iTXt', itxt_data))
    if text_comment:
        chunks.insert(len(chunks) - 1, ('tEXt', text_comment.encode('utf-8')))
    return _serialize_png(chunks)


def has_png(image_bytes: bytes) -> bool:
    """Return True if *image_bytes* already carries an OpenBadges iTXt chunk."""
    for tag, data in Reader(bytes=image_bytes).chunks():
        tag_str = tag.decode('ascii') if isinstance(tag, bytes) else tag
        if tag_str == 'iTXt' and _split_openbadges_itxt(data) is not None:
            return True
    return False


def extract_png(image_bytes: bytes, max_decompressed: int = MAX_ITXT_DECOMPRESSED) -> Optional[str]:
    """Return the embedded token string, or None if there is no openbadges
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

        rest = _split_openbadges_itxt(data)
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
