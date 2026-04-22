#!/usr/bin/env python3
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

# ── OpenBadges 2.0 ─────────────────────────────────────────────────────────────
from .ob2 import (
    Signer, Verifier, VerifyInfo,
    Badge, BadgeSigned, Assertion,
    BadgeStatus, BadgeImgType, BadgeType,
    extract_svg_assertion, extract_png_assertion,
)

# ── OpenBadges 3.0 ─────────────────────────────────────────────────────────────
from .ob3 import (
    OB3Signer, OB3Verifier, OB3VerificationError,
    OpenBadgeCredential, Achievement, Issuer,
)

# ── Shared utilities ────────────────────────────────────────────────────────────
from .keys import KeyFactory, KeyRSA, KeyECC
from .util import __version__
