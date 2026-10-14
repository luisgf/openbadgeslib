"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es

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

# The runtime side of the "Supported Python versions" policy (CONTRIBUTING.md):
# a CPython that is still supported but past (or in its final months before)
# end of life is deprecated — importing openbadgeslib on it emits a
# DeprecationWarning — and is dropped only at the next major release.
#
# Python 3.10 reached CPython end of life on 2026-10-01 (PEP 619); it is
# deprecated since 4.6.0 and dropped in 5.0 (#242). That drop raises
# requires-python, the mypy python_version and DEPRECATED_BELOW together,
# rewording DEPRECATION_MESSAGE for the next deprecated version — or deletes
# this module (and its call in __init__) if none is pending removal.

import sys
import warnings
from typing import Tuple

#: Importing openbadgeslib on a Python older than this emits the warning below.
DEPRECATED_BELOW = (3, 11)

DEPRECATION_MESSAGE = (
    'Python 3.10 is deprecated in openbadgeslib (CPython end of life: '
    '2026-10-01); openbadgeslib 5.0 will require Python 3.11 or newer.')


def warn_if_deprecated(version_info: Tuple[object, ...] = sys.version_info) -> None:
    """Emit DEPRECATION_MESSAGE if *version_info* is a deprecated Python.

    Called once from the package ``__init__``; tests pass a fake version.
    """
    if version_info < DEPRECATED_BELOW:
        # stacklevel=3 skips this helper and the package __init__ (warnings
        # also skips importlib's bootstrap frames, bpo-24305), so the warning
        # is attributed to the code that imported openbadgeslib: PEP 565 then
        # shows it for a script (__main__) and hides it for a library import.
        warnings.warn(DEPRECATION_MESSAGE, DeprecationWarning, stacklevel=3)
