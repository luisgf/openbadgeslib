#!/usr/bin/env python3
"""
        OpenBadges Library

        Copyright (c) 2014, Luis Gonzalez Fernandez, All rights reserved.

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
"""    
        Library for dealing with Openbadges signature and verification process.
    
        Author:   Luis Gonzalez Fernandez <luisgf@luisgf.es>
        Date:     20141201
        Version:  0.1
"""
from openbadgeslib.keys import KeyFactory, KeyRSA, KeyECC
from openbadgeslib.signer import SignerFactory, SignerRSA, SignerECC
from openbadgeslib.verifier import VerifyFactory, VerifyRSA, VerifyECC

