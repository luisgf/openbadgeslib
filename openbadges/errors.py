#!/usr/bin/env python3

"""
    Lib OpenBadges.
    
    Exceptions of the library.
    
    Author:   Luis G.F <luisgf@luisgf.es>
    Date:     20141201
    Verison:  0.1

"""

class GenPrivateKeyError(Exception):
    pass

class GenPublicKeyError(Exception):
    pass

class HashError(Exception):
    pass

class PrivateKeySaveError(Exception):
    pass
    
class PublicKeySaveError(Exception):
    pass
    
class PrivateKeyExists(Exception):
    pass

class PrivateKeyReadError(Exception):
    pass

class PublicKeyReadError(Exception):
    pass

class UnknownKeyType(Exception):
    pass

""" Signer Exceptions """

class BadgeNotFound(Exception):
    pass

class FileToSignNotExists(Exception):
    pass

class ErrorSigningFile(Exception):
    pass

class BadgeSignedFileExists(Exception):
    pass

class PayloadFormatIncorrect(Exception):
    pass

class AssertionFormatIncorrect(Exception):
    pass

class NotIdentityInAssertion(Exception):
    pass

class NoPubKeySpecified(Exception):
    pass

class ErrorParsingFile(Exception):
    pass

