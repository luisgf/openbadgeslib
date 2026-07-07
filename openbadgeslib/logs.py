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

import logging
from typing import Any


def enable_debug_logging(debug: bool = False) -> None:
    """Route library log messages to the console for the CLI tools.

    With ``debug=True`` DEBUG-level messages are shown; otherwise only INFO and
    above. Idempotent — safe to call once per CLI invocation (it will not stack
    duplicate console handlers).
    """
    root = logging.getLogger()
    if not any(getattr(h, '_obl_console', False) for h in root.handlers):
        handler: Any = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
        handler._obl_console = True
        root.addHandler(handler)
    root.setLevel(logging.DEBUG if debug else logging.INFO)
