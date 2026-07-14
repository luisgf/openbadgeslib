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

from .models import Assertion, _SUPPORTED_ALGORITHMS
from ..util import __version__
from ..keys import key_to_pem
from ..errors import ErrorSigningFile, UnsupportedAlgorithm
from .._jws import sign as jws_sign
from .._jws import utils as jws_utils
from .. import baking


class OB2Signer:
    """Signs OpenBadges 2.0 Assertions as JWS compact serializations.

    Unlike OB 3.0 (a JWT-VC), an OB 2.0 signed Assertion is a JWS whose payload
    is the Assertion JSON document itself (``header.payload.signature``). The
    resulting token is baked into an SVG/PNG image with the OB 2.0 carrier
    identifiers (``openbadges:assertion`` / the ``openbadges`` iTXt keyword).

    Args:
        privkey_pem: PEM-encoded private key (bytes, str, or a ``cryptography``
                     key object).
        algorithm:   JWS algorithm identifier bound to the key type — RS256 for
                     RSA, ES256 for ECC P-256, EdDSA for Ed25519. Defaults to
                     'RS256'. Supported: RS256/384/512, ES256/384/512, EdDSA.
    """

    def __init__(self, privkey_pem: Any, algorithm: str = 'RS256') -> None:
        if algorithm not in _SUPPORTED_ALGORITHMS:
            raise UnsupportedAlgorithm(
                "Unsupported algorithm %r. Choose from: %s"
                % (algorithm, sorted(_SUPPORTED_ALGORITHMS)))
        self.privkey_pem = key_to_pem(privkey_pem)
        self.algorithm = algorithm

    # ── core signing ────────────────────────────────────────────────────────────

    def sign(self, assertion: Assertion) -> str:
        """Sign an Assertion and return the compact JWS string.

        The payload is the full Assertion JSON-LD document (``@context``,
        ``type``, ``id``, ``verification``, …); the JOSE header carries only
        the ``alg``. A HostedBadge assertion is still signed here (the baked
        JWS provides tamper-evidence), but its trust anchor on verification is
        the HTTPS retrieval of its ``id``, not this signature.
        """
        header = {'alg': self.algorithm}
        payload = assertion.to_dict()
        try:
            signature = jws_sign(header, payload, self.privkey_pem)
        except Exception as exc:
            raise ErrorSigningFile(
                "Could not sign assertion with algorithm %s: %s" % (self.algorithm, exc)) from exc
        token = (jws_utils.encode(header) + b'.' + jws_utils.encode(payload)
                 + b'.' + jws_utils.to_base64(signature))
        return token.decode('ascii')

    # ── image baking ─────────────────────────────────────────────────────────────

    def sign_into_svg(self, assertion: Assertion, svg_bytes: bytes) -> bytes:
        """Embed a signed Assertion into an SVG badge image.

        The JWS is stored in the OB 2.0 ``<openbadges:assertion verify="…"/>``
        element (namespace ``http://openbadges.org``).
        """
        token = self.sign(assertion)
        try:
            return baking.bake_svg(
                svg_bytes, token,
                comment=' Signed with OpenBadgesLib %s (OB 2.0 JWS) ' % __version__)
        except Exception as exc:
            raise ErrorSigningFile('Unable to bake SVG assertion: %s' % exc) from exc

    def sign_into_png(self, assertion: Assertion, png_bytes: bytes) -> bytes:
        """Embed a signed Assertion into a PNG badge image.

        The JWS is stored in an ``iTXt`` chunk with the OB 2.0 keyword
        ``openbadges``.
        """
        token = self.sign(assertion)
        try:
            return baking.bake_png(
                png_bytes, token,
                text_comment='Signed with OpenBadgesLib %s (OB 2.0 JWS)' % __version__)
        except Exception as exc:
            raise ErrorSigningFile('Unable to bake PNG assertion: %s' % exc) from exc
