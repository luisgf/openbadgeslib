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

from typing import Any

import jwt

from .credential import OpenBadgeCredential, _SUPPORTED_ALGORITHMS
from ..util import __version__
from ..keys import key_to_pem
from ..errors import ErrorSigningFile
from .. import baking


class OB3Signer:
    """Signs OpenBadges 3.0 credentials as JWT-VCs.

    Args:
        privkey_pem: PEM-encoded private key (bytes, str, or a pycryptodome /
                     ecdsa key object).  RSA keys produce RS256 tokens;
                     EC keys produce ES256 tokens.
        algorithm:   JWS algorithm identifier.  Defaults to 'RS256'.
                     Supported: RS256/384/512, ES256/384/512.
    """

    def __init__(self, privkey_pem: Any, algorithm: str = 'RS256') -> None:
        if algorithm not in _SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm {algorithm!r}. "
                f"Choose from: {sorted(_SUPPORTED_ALGORITHMS)}"
            )
        self.privkey_pem = key_to_pem(privkey_pem)
        self.algorithm = algorithm

    # ── core signing ───────────────────────────────────────────────────────────

    def sign(self, credential: OpenBadgeCredential) -> str:
        """Sign a credential and return a compact JWT-VC string."""
        payload = credential.to_jwt_payload()
        try:
            return jwt.encode(payload, self.privkey_pem, algorithm=self.algorithm)
        except jwt.exceptions.PyJWTError as exc:
            raise ErrorSigningFile(
                "Could not sign credential with algorithm %s: %s" % (self.algorithm, exc)) from exc

    # ── image baking ───────────────────────────────────────────────────────────

    def sign_into_svg(self, credential: OpenBadgeCredential, svg_bytes: bytes) -> bytes:
        """Embed a signed credential into an SVG badge image.

        The JWT-VC is stored in an ``<openbadges:assertion verify="…"/>``
        element, matching the OB 2.0 baking format so that existing badge
        viewers can extract the token regardless of version.
        """
        token = self.sign(credential)
        try:
            return baking.bake_svg(
                svg_bytes, token,
                comment=' Signed with OpenBadgesLib %s (OB 3.0 JWT-VC) ' % __version__)
        except Exception as exc:
            raise ErrorSigningFile('Unable to bake SVG assertion: %s' % exc) from exc

    def sign_into_png(self, credential: OpenBadgeCredential, png_bytes: bytes) -> bytes:
        """Embed a signed credential into a PNG badge image.

        The JWT-VC is stored in an ``iTXt`` chunk with keyword ``openbadges``,
        matching the OB 2.0 baking format.
        """
        token = self.sign(credential)
        try:
            return baking.bake_png(png_bytes, token)
        except Exception as exc:
            raise ErrorSigningFile('Unable to bake PNG assertion: %s' % exc) from exc
