#!/usr/bin/env python3
"""
        OpenBadges Library

        Copyright (c) 2015, Luis González Fernández, luisgf@luisgf.es
        Copyright (c) 2015, Jesús Cea Avión, jcea@jcea.es

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

from ecdsa import BadSignatureError

class LibOpenBadgesException(Exception):
    pass

""" Exception base classes """
class KeyGenExceptions(LibOpenBadgesException):
    pass

class SignerExceptions(LibOpenBadgesException):
    pass

class VerifierExceptions(LibOpenBadgesException):
    pass


""" User-defined Exceptions """

class GenPrivateKeyError(KeyGenExceptions):
    pass

class GenPublicKeyError(KeyGenExceptions):
    pass

class PrivateKeySaveError(KeyGenExceptions):
    pass

class PublicKeySaveError(KeyGenExceptions):
    pass

class PrivateKeyReadError(KeyGenExceptions):
    pass

class PublicKeyReadError(KeyGenExceptions):
    pass

class UnknownKeyType(KeyGenExceptions):
    pass

""" Signer Exceptions """

class FileToSignNotExists(SignerExceptions):
    pass

class ErrorSigningFile(SignerExceptions):
    pass

class BadgeSignedFileExists(SignerExceptions):
    pass

""" Verifier Exceptions """

class PayloadFormatIncorrect(VerifierExceptions):
    pass

class AssertionFormatIncorrect(VerifierExceptions):
    pass

class NotIdentityInAssertion(VerifierExceptions):
    pass

class NoPubKeySpecified(VerifierExceptions):
    pass

class ErrorParsingFile(VerifierExceptions):
    pass

""" Badge Object Exceptios """

class BadgeNotExists(LibOpenBadgesException):
    pass

class BadgeImgFormatUnsupported(LibOpenBadgesException):
    pass

