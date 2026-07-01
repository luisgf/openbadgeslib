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

import json

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
                     ecdsa / cryptography key object).  RSA keys produce RS256
                     tokens; EC keys produce ES256; Ed25519 keys produce EdDSA
                     (pass ``algorithm='EdDSA'``).
        algorithm:   JWS algorithm identifier.  Defaults to 'RS256'.
                     Supported: RS256/384/512, ES256/384/512, EdDSA.
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
        """Sign a credential and return a compact JWT-VC string.

        OB 3.0 §8.2.3 requires the JOSE header to convey the verification key
        via ``kid`` or ``jwk``; this embeds the issuer's public key as a ``jwk``
        (public parameters only — never the private ``d``).
        """
        payload = credential.to_jwt_payload()
        headers = {"jwk": self._public_jwk()}
        try:
            return jwt.encode(payload, self.privkey_pem, algorithm=self.algorithm,
                              headers=headers)
        except jwt.exceptions.PyJWTError as exc:
            raise ErrorSigningFile(
                "Could not sign credential with algorithm %s: %s" % (self.algorithm, exc)) from exc

    def _public_jwk(self) -> dict:
        """Return the public JWK for the JOSE header, derived from the signing
        key. Loaded via ``cryptography`` (which reads the RSA/EC/Ed25519 PEMs
        this library produces) and serialised with PyJWT's algorithm; only
        public parameters are included."""
        from cryptography.hazmat.primitives import serialization as _ser
        from jwt.algorithms import RSAAlgorithm, ECAlgorithm, OKPAlgorithm
        pem = self.privkey_pem.encode('utf-8') if isinstance(self.privkey_pem, str) \
            else self.privkey_pem
        try:
            # public_key() is a broad union; we dispatch on self.algorithm, so
            # the concrete type matches the chosen to_jwk. Treat as Any for mypy.
            pub: Any = _ser.load_pem_private_key(pem, password=None).public_key()
            if self.algorithm.startswith('RS'):
                jwk_json = RSAAlgorithm.to_jwk(pub)
            elif self.algorithm.startswith('ES'):
                jwk_json = ECAlgorithm.to_jwk(pub)
            else:   # EdDSA / Ed25519
                jwk_json = OKPAlgorithm.to_jwk(pub)
        except Exception as exc:
            raise ErrorSigningFile("Could not derive the public JWK: %s" % exc) from exc
        return json.loads(jwk_json)

    # ── image baking ───────────────────────────────────────────────────────────

    def sign_into_svg(self, credential: OpenBadgeCredential, svg_bytes: bytes) -> bytes:
        """Embed a signed credential into an SVG badge image.

        The JWT-VC is stored in the OB 3.0 ``<openbadges:credential verify="…"/>``
        element (namespace ``https://purl.imsglobal.org/ob/v3p0``).
        """
        token = self.sign(credential)
        try:
            return baking.bake_svg(
                svg_bytes, token,
                comment=' Signed with OpenBadgesLib %s (OB 3.0 JWT-VC) ' % __version__,
                element=baking.SVG_ELEMENT_OB3, namespace=baking.SVG_NS_OB3)
        except Exception as exc:
            raise ErrorSigningFile('Unable to bake SVG credential: %s' % exc) from exc

    def sign_into_png(self, credential: OpenBadgeCredential, png_bytes: bytes) -> bytes:
        """Embed a signed credential into a PNG badge image.

        The JWT-VC is stored in an ``iTXt`` chunk with the OB 3.0 keyword
        ``openbadgecredential``.
        """
        token = self.sign(credential)
        try:
            return baking.bake_png(png_bytes, token, keyword=baking.ITXT_KEYWORD_OB3)
        except Exception as exc:
            raise ErrorSigningFile('Unable to bake PNG credential: %s' % exc) from exc
