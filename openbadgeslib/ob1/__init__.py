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

# OpenBadges 1.0 is an old format (Mozilla Backpack shut down in 2019), but it
# remains supported as a legacy surface — no removal is planned (see the
# "OpenBadges 1.0 lifecycle" wiki page). Reaching the OB1 API *through this
# package* — `from openbadgeslib.ob1 import Signer`, `openbadgeslib.ob1.Badge` —
# emits a DeprecationWarning that steers new work to openbadgeslib.ob2 (strict
# OB 2.0) or openbadgeslib.ob3 (OB 3.0); OB 1.0 itself is not going away.
#
# The symbols are resolved lazily (PEP 562) from their leaf modules, so the
# warning fires on the legacy *package* surface only. Library internals that
# still need the shared, config-driven badge model import it straight from
# openbadgeslib.ob1.badge (BadgeImgType, Badge) and stay silent.
import importlib
import warnings
from typing import Any

#: Public OB1 name -> the leaf submodule that defines it.
_OB1_API = {
    'BadgeStatus': 'badge', 'BadgeImgType': 'badge', 'BadgeType': 'badge',
    'Assertion': 'badge', 'Badge': 'badge', 'BadgeSigned': 'badge',
    'extract_svg_assertion': 'badge', 'extract_png_assertion': 'badge',
    'Signer': 'signer', 'Verifier': 'verifier', 'VerifyInfo': 'verifier',
}

__all__ = list(_OB1_API)

_OB1_LEGACY_NOTICE = (
    'openbadgeslib.ob1 is the legacy OpenBadges 1.0 API; prefer '
    'openbadgeslib.ob2 (strict OB 2.0) or openbadgeslib.ob3 (OB 3.0) for new '
    'work. OpenBadges 1.0 remains supported (no removal planned). See the '
    '"OpenBadges 1.0 lifecycle" wiki page.'
)


def __getattr__(name: str) -> Any:
    module = _OB1_API.get(name)
    if module is None:
        raise AttributeError(
            'module %r has no attribute %r' % (__name__, name))
    warnings.warn(_OB1_LEGACY_NOTICE, DeprecationWarning, stacklevel=2)
    return getattr(importlib.import_module('.' + module, __name__), name)
