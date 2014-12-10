#!/usr/bin/env python3
"""
        OpenBadges Library

        Copyright (c) 2014, Luis González Fernández, luisgf@luisgf.es
        Copyright (c) 2014, Jesús Cea Avión, jcea@jcea.es

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

import hashlib

def _hash_string(hash_name, string) :
    h = hashlib.new(hash_name)
    h.update(string)
    return h.hexdigest().encode('latin-1')

def sha1_string(string) :
    return _hash_string('sha1', string)

def sha256_string(string):
    return _hash_string('sha256', string)

