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

from struct import pack
from xml.dom.minidom import parseString
from zlib import crc32

import jwt
from png import Reader, signature as _png_signature

from .credential import OpenBadgeCredential, _SUPPORTED_ALGORITHMS
from ..util import __version__


def _to_pem(key):
    """Convert a pycryptodome or ecdsa key object to PEM bytes; pass through bytes/str."""
    try:
        from Crypto.PublicKey import RSA as _RSA
        if isinstance(key, _RSA.RsaKey):
            return key.export_key('PEM')
    except ImportError:
        pass
    try:
        from ecdsa import SigningKey as _SK, VerifyingKey as _VK
        if isinstance(key, (_SK, _VK)):
            return key.to_pem()
    except ImportError:
        pass
    if isinstance(key, (bytes, str)):
        return key
    raise TypeError(f"Unsupported key type: {type(key)}")


class OB3Signer:
    """Signs OpenBadges 3.0 credentials as JWT-VCs.

    Args:
        privkey_pem: PEM-encoded private key (bytes, str, or a pycryptodome /
                     ecdsa key object).  RSA keys produce RS256 tokens;
                     EC keys produce ES256 tokens.
        algorithm:   JWS algorithm identifier.  Defaults to 'RS256'.
                     Supported: RS256/384/512, ES256/384/512.
    """

    def __init__(self, privkey_pem, algorithm: str = 'RS256') -> None:
        if algorithm not in _SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm {algorithm!r}. "
                f"Choose from: {sorted(_SUPPORTED_ALGORITHMS)}"
            )
        self.privkey_pem = _to_pem(privkey_pem)
        self.algorithm = algorithm

    # ── core signing ───────────────────────────────────────────────────────────

    def sign(self, credential: OpenBadgeCredential) -> str:
        """Sign a credential and return a compact JWT-VC string."""
        payload = credential.to_jwt_payload()
        return jwt.encode(payload, self.privkey_pem, algorithm=self.algorithm)

    # ── image baking ───────────────────────────────────────────────────────────

    def sign_into_svg(self, credential: OpenBadgeCredential, svg_bytes: bytes) -> bytes:
        """Embed a signed credential into an SVG badge image.

        The JWT-VC is stored in an ``<openbadges:assertion verify="…"/>``
        element, matching the OB 2.0 baking format so that existing badge
        viewers can extract the token regardless of version.
        """
        token = self.sign(credential)
        svg_doc = parseString(svg_bytes)
        svg_tag = svg_doc.getElementsByTagName('svg').item(0)

        node = svg_doc.createElement("openbadges:assertion")
        node.attributes['xmlns:openbadges'] = 'http://openbadges.org'
        node.attributes['verify'] = token
        svg_tag.appendChild(node)
        svg_tag.appendChild(
            svg_doc.createComment(
                ' Signed with OpenBadgesLib %s (OB 3.0 JWT-VC) ' % __version__
            )
        )

        result = svg_doc.toxml().encode('utf-8')
        svg_doc.unlink()
        return result

    def sign_into_png(self, credential: OpenBadgeCredential, png_bytes: bytes) -> bytes:
        """Embed a signed credential into a PNG badge image.

        The JWT-VC is stored in an ``iTXt`` chunk with keyword ``openbadges``,
        matching the OB 2.0 baking format.
        """
        token = self.sign(credential)

        chunks = list(Reader(bytes=png_bytes).chunks())
        itxt_data = (
            b'openbadges'
            + pack('BBBBB', 0, 0, 0, 0, 0)
            + token.encode('utf-8')
        )
        # Insert before the final IEND chunk
        chunks.insert(len(chunks) - 1, ('iTXt', itxt_data))

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
