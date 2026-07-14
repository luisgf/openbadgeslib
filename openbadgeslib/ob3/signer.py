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

from typing import Any, Optional, cast

import jwt

from .credential import OpenBadgeCredential, _SUPPORTED_ALGORITHMS
from ..util import __version__
from ..keys import key_to_pem
from ..errors import ErrorSigningFile, UnsupportedAlgorithm
from .. import baking


class OB3Signer:
    """Signs OpenBadges 3.0 credentials as JWT-VCs.

    Args:
        privkey_pem: PEM-encoded private key (bytes, str, or a ``cryptography``
                     key object).  RSA keys produce RS256 tokens; EC keys
                     produce ES256; Ed25519 keys produce EdDSA (pass
                     ``algorithm='EdDSA'``).
        algorithm:   JWS algorithm identifier.  Defaults to 'RS256'.
                     Supported: RS256/384/512, ES256/384/512, EdDSA.
    """

    def __init__(self, privkey_pem: Any, algorithm: str = 'RS256') -> None:
        if algorithm not in _SUPPORTED_ALGORITHMS:
            raise UnsupportedAlgorithm(
                f"Unsupported algorithm {algorithm!r}. "
                f"Choose from: {sorted(_SUPPORTED_ALGORITHMS)}"
            )
        self.privkey_pem = key_to_pem(privkey_pem)
        self.algorithm = algorithm
        # Parse the PEM into a cryptography key object once per signer and reuse
        # it for every signature. ``load_pem_private_key`` on an RSA-2048 PEM
        # costs ~45 ms, and the old path paid it twice per badge — once in
        # ``_public_jwk()`` and once inside ``jwt.encode()`` — which dominated
        # batch signing (86 ms/badge for RSA). Both the key object and the
        # derived public JWK are memoised lazily on first use (#215).
        self._privkey_obj: Any = None
        self._public_jwk_cache: Optional[dict[str, Any]] = None

    # ── core signing ───────────────────────────────────────────────────────────

    def _load_privkey(self) -> Any:
        """Load and memoise the ``cryptography`` private-key object.

        Parsed once from ``self.privkey_pem`` and shared by ``sign_payload``
        (handed straight to ``jwt.encode``, which accepts a key object) and
        ``_public_jwk`` — so a signer parses its PEM a single time regardless of
        how many credentials it signs (#215)."""
        if self._privkey_obj is None:
            from cryptography.hazmat.primitives import serialization as _ser
            pem = self.privkey_pem.encode('utf-8') \
                if isinstance(self.privkey_pem, str) else self.privkey_pem
            self._privkey_obj = _ser.load_pem_private_key(pem, password=None)
        return self._privkey_obj

    def sign(self, credential: OpenBadgeCredential) -> str:
        """Sign a credential and return a compact JWT-VC string.

        OB 3.0 §8.2.3 requires the JOSE header to convey the verification key
        via ``kid`` or ``jwk``; this embeds the issuer's public key as a ``jwk``
        (public parameters only — never the private ``d``).
        """
        return self.sign_payload(credential.to_jwt_payload())

    def sign_payload(self, payload: dict[str, Any]) -> str:
        """Sign an arbitrary JWT payload with the same JOSE header (embedded
        public ``jwk``) used for credentials. Lets the issuer sign auxiliary
        VCs — e.g. a BitstringStatusListCredential — with one key setup."""
        headers = {"jwk": self._public_jwk()}
        try:
            return jwt.encode(payload, self._load_privkey(), algorithm=self.algorithm,
                              headers=headers)
        except jwt.exceptions.PyJWTError as exc:
            raise ErrorSigningFile(
                "Could not sign credential with algorithm %s: %s" % (self.algorithm, exc)) from exc

    def _public_jwk(self) -> dict[str, Any]:
        """Return the public JWK for the JOSE header, derived from the signing
        key. Derived from the memoised private-key object (which reads the
        RSA/EC/Ed25519 PEMs this library produces) and serialised with PyJWT's
        algorithm; only public parameters are included. Computed once and cached
        per signer (#215)."""
        cached = self._public_jwk_cache
        if cached is not None:
            return cached
        from jwt.algorithms import RSAAlgorithm, ECAlgorithm, OKPAlgorithm
        try:
            # public_key() is a broad union; we dispatch on self.algorithm, so
            # the concrete type matches the chosen to_jwk. Treat as Any for mypy.
            pub: Any = self._load_privkey().public_key()
            if self.algorithm.startswith('RS'):
                jwk_json = RSAAlgorithm.to_jwk(pub)
            elif self.algorithm.startswith('ES'):
                jwk_json = ECAlgorithm.to_jwk(pub)
            else:   # EdDSA / Ed25519
                jwk_json = OKPAlgorithm.to_jwk(pub)
        except Exception as exc:
            raise ErrorSigningFile("Could not derive the public JWK: %s" % exc) from exc
        jwk = cast(dict[str, Any], json.loads(jwk_json))
        self._public_jwk_cache = jwk
        return jwk

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
