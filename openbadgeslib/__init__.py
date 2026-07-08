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
from .keys import KeyFactory, KeyRSA, KeyECC  # noqa: F401
from .util import __version__  # noqa: F401


# ── Issuance API ─────────────────────────────────────────────────────────────
# "Issue badge X to Y per config" as a library call — the orchestration the CLI
# wraps, returning a SignResult instead of writing files (openbadgeslib.issue).
# Resolved lazily (PEP 562, below) because openbadgeslib.issue pulls in the
# shared Badge model from the ob1 leaf module; a bare `import openbadgeslib`
# must not drag that in. `from openbadgeslib.issue import ...` works directly.
_ISSUE_API = ('IssuanceError', 'SignResult', 'issue_from_conf')


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
        # The modern issuance API — lazy so a bare import stays ob1-free, but
        # warning-free (unlike the OB1 names below).
        import importlib
        return getattr(importlib.import_module('.issue', __name__), name)
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
