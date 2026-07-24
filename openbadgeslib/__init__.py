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
# Bind ob2 / ob3 / errors / issue / verify as attributes so they are part of the
# explicit public surface (and `from openbadgeslib import *`): ob2 (strict
# OB 2.0), ob3 (OB 3.0, incl. ob3.eudi and ob3.OB3Ldp*), the errors hierarchy
# rooted at LibOpenBadgesException, and the issuance/verification facades.
from . import ob2, ob3, errors, issue, verify  # noqa: F401

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

# The OB1 legacy name table, shared with openbadgeslib.ob1 (single source,
# #235). Importing it is cheap and does not pull in the ob1 subpackage, so a
# bare `import openbadgeslib` stays ob1-free (see __getattr__ below).
from ._ob1_api import OB1_API as _OB1_API  # noqa: F401


# ── Issuance / verification API ──────────────────────────────────────────────
# "Issue badge X to Y per config" / "verify this badge" as library calls — the
# orchestration the CLIs wrap, returning a SignResult / VerifyResult instead of
# doing I/O (openbadgeslib.issue, openbadgeslib.verify).
#
# Imported eagerly, unlike the OB1 names below. These were resolved lazily (PEP
# 562) to keep a bare `import openbadgeslib` light, and listed in __all__ "for
# pdoc" — but pdoc reads the module dict, so it could not resolve them and
# published each as a content-free stub with no signature, type or docstring,
# while openbadgeslib.issue / .verify got no page at all (#267). The laziness
# bought ~1.7 ms against an ~80 ms import that already pulls ob2, ob3 and keys
# (hence cryptography) — inside the run-to-run noise — so the documentation of
# the recommended modern API is worth more than it.
from .issue import (  # noqa: F401
    IssuanceError, SignResult, issue_from_conf,
)
from .verify import verify_badge  # noqa: F401


# ── OpenBadges 1.0 (legacy) ──────────────────────────────────────────────────
# The unprefixed OB1 names (Signer, Verifier, Badge, …) stay importable from
# the top-level package for backward compatibility. They are the legacy
# OpenBadges 1.0 surface: accessing one emits a DeprecationWarning steering new
# work to openbadgeslib.ob2 / openbadgeslib.ob3. OB 1.0 itself remains supported
# (no removal planned). They are resolved lazily from the ob1 leaf modules (PEP
# 562) using the shared _OB1_API table imported above, so a bare
# `import openbadgeslib` neither warns nor drags in the ob1 package.


def __getattr__(name: str) -> Any:
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
# Every name here is a real module attribute, so pdoc documents all of them —
# see tests/test_public_api.py, which fails if one becomes unresolvable again.
__all__ = [
    '__version__',
    # Subpackage / module entry points.
    'ob2', 'ob3', 'errors', 'issue', 'verify',
    # OpenBadges 2.0 (strict).
    'OB2Signer', 'OB2Verifier', 'OB2VerificationError',
    # OpenBadges 3.0.
    'OB3Signer', 'OB3Verifier', 'OB3VerificationError',
    'OpenBadgeCredential', 'Achievement', 'Issuer',
    # Keys (KeyEd25519 is the recommended OB 3.0 / LDP key type).
    'KeyFactory', 'KeyRSA', 'KeyECC', 'KeyEd25519',
    # Programmatic issue / verify facades.
    'issue_from_conf', 'verify_badge', 'IssuanceError', 'SignResult',
]
