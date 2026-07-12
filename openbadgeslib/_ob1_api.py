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

# Single source of the OpenBadges 1.0 public-name -> leaf-module map (#235).
#
# Both the top-level package (openbadgeslib.__getattr__, which lazily resolves
# the unprefixed OB1 names) and openbadgeslib.ob1 (which resolves its own
# attribute access) map the same 11 names to the same three leaf modules. They
# used to keep two hand-maintained copies of the table; this is the one they
# now share.
#
# Kept deliberately tiny — a plain dict, no imports of the ob1 leaf modules and
# no warnings — so importing it at package load costs nothing and never drags in
# the ob1 subpackage (a bare ``import openbadgeslib`` must stay ob1-free).

#: OpenBadges 1.0 public name -> the ob1 leaf submodule that defines it.
OB1_API = {
    'BadgeStatus': 'badge', 'BadgeImgType': 'badge', 'BadgeType': 'badge',
    'Assertion': 'badge', 'Badge': 'badge', 'BadgeSigned': 'badge',
    'extract_svg_assertion': 'badge', 'extract_png_assertion': 'badge',
    'Signer': 'signer', 'Verifier': 'verifier', 'VerifyInfo': 'verifier',
}
