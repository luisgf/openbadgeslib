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

# Strict OpenBadges 2.0 (JWS-signed / hosted Assertions with conformant
# JSON-LD Badge Objects). The legacy pre-2.0 format lives in openbadgeslib.ob1.

from .models import (
    OB2_CONTEXT,
    Assertion, IdentityObject, Verification,
    BadgeClass, Profile, CryptographicKey, RevocationList,
    hash_identity,
)
from .signer import OB2Signer
from .verifier import OB2Verifier, OB2VerificationError

__all__ = [
    'OB2_CONTEXT',
    'Assertion', 'IdentityObject', 'Verification',
    'BadgeClass', 'Profile', 'CryptographicKey', 'RevocationList',
    'hash_identity',
    'OB2Signer', 'OB2Verifier', 'OB2VerificationError',
]
