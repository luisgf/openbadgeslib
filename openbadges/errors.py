#!/usr/bin/env python3

"""
    Lib OpenBadges.
    
    Exceptions of the library.
    
    Author:   Luis G.F <luisgf@luisgf.es>
    Date:     20141201
    Verison:  0.1

"""

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

class HashError(KeyGenExceptions):
    pass

class PrivateKeySaveError(KeyGenExceptions):
    pass
    
class PublicKeySaveError(KeyGenExceptions):
    pass
    
class PrivateKeyExists(KeyGenExceptions):
    pass

class PrivateKeyReadError(KeyGenExceptions):
    pass

class PublicKeyReadError(KeyGenExceptions):
    pass

class UnknownKeyType(KeyGenExceptions):
    pass

""" Signer Exceptions """

class BadgeNotFound(SignerExceptions):
    pass

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

