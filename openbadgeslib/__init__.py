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

from typing import Any

# ── Submodule entry points ───────────────────────────────────────────────────
# Bind ob2 / ob3 / errors as attributes so they are part of the explicit public
# surface (and `from openbadgeslib import *`): ob2 (strict OB 2.0), ob3 (OB 3.0,
# incl. ob3.eudi and ob3.OB3Ldp*), and the errors hierarchy rooted at
# LibOpenBadgesException.
from . import ob2, ob3, errors  # noqa: F401

# ── OpenBadges 2.0 (strict) ──────────────────────────────────────────────────
from .ob2 import (  # noqa: F401
    OB2Signer, OB2Verifier, OB2VerificationError,
)

# ── OpenBadges 3.0 ─────────────────────────────────────────────────────────────
from .ob3 import (  # noqa: F401
    OB3Signer, OB3Verifier, OB3VerificationError,
    OpenBadgeCredential, Achievement, Issuer,
)

# ── Shared utilities ────────────────────────────────────────────────────────────
# KeyEd25519 is the recommended key type for OB 3.0 / LDP (eddsa-rdfc-2022).
from .keys import KeyFactory, KeyRSA, KeyECC, KeyEd25519  # noqa: F401
from .util import __version__  # noqa: F401


# ── Issuance / verification API ──────────────────────────────────────────────
# "Issue badge X to Y per config" / "verify this badge" as library calls — the
# orchestration the CLIs wrap, returning a SignResult / VerifyResult instead of
# doing I/O (openbadgeslib.issue, openbadgeslib.verify). Resolved lazily (PEP
# 562, below) so a bare `import openbadgeslib` stays lightweight;
# `from openbadgeslib.issue import ...` / `.verify import ...` work directly.
_ISSUE_API = {
    'IssuanceError': 'issue', 'SignResult': 'issue', 'issue_from_conf': 'issue',
    'verify_badge': 'verify',
}


# ── OpenBadges 1.0 (legacy) ──────────────────────────────────────────────────
# The unprefixed OB1 names (Signer, Verifier, Badge, …) stay importable from
# the top-level package for backward compatibility. They are the legacy
# OpenBadges 1.0 surface: accessing one emits a DeprecationWarning steering new
# work to openbadgeslib.ob2 / openbadgeslib.ob3. OB 1.0 itself remains supported
# (no removal planned). They are resolved lazily from the ob1 leaf modules (PEP
# 562), so a bare `import openbadgeslib` neither warns nor drags in the ob1
# package.
_OB1_API = {
    'Signer': 'signer', 'Verifier': 'verifier', 'VerifyInfo': 'verifier',
    'Badge': 'badge', 'BadgeSigned': 'badge', 'Assertion': 'badge',
    'BadgeStatus': 'badge', 'BadgeImgType': 'badge', 'BadgeType': 'badge',
    'extract_svg_assertion': 'badge', 'extract_png_assertion': 'badge',
}


def __getattr__(name: str) -> Any:
    if name in _ISSUE_API:
        # The modern issuance / verification API — lazy so a bare import stays
        # lightweight, but warning-free (unlike the OB1 names below).
        import importlib
        return getattr(
            importlib.import_module('.' + _ISSUE_API[name], __name__), name)
    module = _OB1_API.get(name)
    if module is None:
        raise AttributeError(
            'module %r has no attribute %r' % (__name__, name))
    import importlib
    import warnings
    warnings.warn(
        'openbadgeslib.%s is the legacy OpenBadges 1.0 API; prefer '
        'openbadgeslib.ob2 (strict OB 2.0) or openbadgeslib.ob3 (OB 3.0) for '
        'new work. OpenBadges 1.0 remains supported (no removal planned). See '
        'the "OpenBadges 1.0 lifecycle" wiki page.' % name,
        DeprecationWarning, stacklevel=2)
    return getattr(importlib.import_module('.ob1.' + module, __name__), name)


# The stable, supported top-level surface (the "public contract" — see the
# "Stable API vs internals" wiki/doc page). Everything else (the ob1.* legacy
# names resolved lazily above, and any underscore-prefixed name) is internal.
# The issuance/verification facades are resolved lazily by __getattr__ but are
# part of the contract, so they are listed here for pdoc and `import *`.
__all__ = [
    '__version__',
    # Subpackage entry points.
    'ob2', 'ob3', 'errors',
    # OpenBadges 2.0 (strict).
    'OB2Signer', 'OB2Verifier', 'OB2VerificationError',
    # OpenBadges 3.0.
    'OB3Signer', 'OB3Verifier', 'OB3VerificationError',
    'OpenBadgeCredential', 'Achievement', 'Issuer',
    # Keys (KeyEd25519 is the recommended OB 3.0 / LDP key type).
    'KeyFactory', 'KeyRSA', 'KeyECC', 'KeyEd25519',
    # Programmatic issue / verify facades (resolved lazily).
    'issue_from_conf', 'verify_badge', 'IssuanceError', 'SignResult',
]
