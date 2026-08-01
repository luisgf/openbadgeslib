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


class LibOpenBadgesException(Exception):
    """Root of the library exception hierarchy.

    Every error this library raises deliberately derives from this class, so a
    caller can trap them all with a single ``except LibOpenBadgesException``.
    The full map (children in their own modules noted inline)::

        LibOpenBadgesException
        ├── KeyGenExceptions          (alias: KeyGenException)
        │   ├── GenPrivateKeyError / GenPublicKeyError
        │   ├── PrivateKeySaveError / PublicKeySaveError
        │   ├── PrivateKeyReadError / PublicKeyReadError
        │   └── UnknownKeyType
        ├── SignerExceptions          (alias: SignerException)
        │   ├── ErrorSigningFile
        │   └── UnsupportedAlgorithm  (also ValueError)
        ├── VerifierExceptions        (alias: VerifierException)
        │   ├── AssertionFormatIncorrect
        │   ├── NotIdentityInAssertion
        │   └── ErrorParsingFile
        ├── BadgeImgFormatUnsupported
        ├── ConfigError               (also ValueError)
        ├── IssuanceError
        ├── DecompressionLimitExceeded
        ├── StatusError               (issuer-side revocation)
        │   └── StatusListFull / UnknownCredential / AlreadyRevoked
        │       / AlreadySuspended / NotSuspended / RegistryCorrupt
        ├── PublishError              (openbadgeslib.ob3.publish)
        │   └── CredentialNotFound / AmbiguousCredential
        ├── OB2VerificationError      (openbadgeslib.ob2.verifier)
        └── OB3VerificationError      (openbadgeslib.ob3.verifier)

    ``ConfigError`` and ``UnsupportedAlgorithm`` also inherit ``ValueError`` so
    that code (and tests) catching the historical ``ValueError`` keep working
    while the errors are now reachable through the library root too.
    """
    pass


""" Exception base classes """


class KeyGenExceptions(LibOpenBadgesException):
    pass


class SignerExceptions(LibOpenBadgesException):
    pass


class VerifierExceptions(LibOpenBadgesException):
    pass


# Singular aliases for the plural base names, so callers can name a family in
# the natural singular ("except SignerException") without the historical typo.
KeyGenException = KeyGenExceptions
SignerException = SignerExceptions
VerifierException = VerifierExceptions


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


class ErrorSigningFile(SignerExceptions):
    pass


class UnsupportedAlgorithm(SignerExceptions, ValueError):
    """A signer was asked for a JWS algorithm it does not support.

    Also a ``ValueError`` for backward compatibility with callers that trap the
    historical bare ``ValueError`` from the signer constructors.
    """
    pass


""" Verifier Exceptions """


class AssertionFormatIncorrect(VerifierExceptions):
    pass


class NotIdentityInAssertion(VerifierExceptions):
    pass


class ErrorParsingFile(VerifierExceptions):
    pass


""" Badge Object Exceptions """


class BadgeImgFormatUnsupported(LibOpenBadgesException):
    pass


""" Configuration Exceptions """


class ConfigError(LibOpenBadgesException, ValueError):
    """A configuration file is missing, malformed, or has an invalid value.

    Also a ``ValueError`` for backward compatibility: the config helpers raised
    a bare ``ValueError`` historically, and ``read_config_or_exit`` (plus the
    tests) still catch that. Anchoring it under ``LibOpenBadgesException`` too
    lets a caller trap every library error with one ``except``.
    """
    pass


""" Issuance Exceptions """


class IssuanceError(LibOpenBadgesException):
    """Raised when a badge cannot be issued (bad config, unsupported key, a
    policy violation such as a did:key issuer that is not the signing key, or a
    status-registry failure). The CLI catches it and presents it; a library
    caller handles it programmatically. Messages carry no ``[!]`` prefix — the
    presentation layer adds one."""
    pass


""" Baking Exceptions """


class DecompressionLimitExceeded(LibOpenBadgesException):
    """Raised when a compressed iTXt token inflates beyond the allowed size."""
    pass


""" OB3 Credential Status Exceptions """


class StatusError(LibOpenBadgesException):
    """Base class for issuer-side credential status (revocation) errors."""
    pass


class StatusListFull(StatusError):
    pass


class UnknownCredential(StatusError):
    pass


class AlreadyRevoked(StatusError):
    pass


class AlreadySuspended(StatusError):
    pass


class NotSuspended(StatusError):
    pass


class RegistryCorrupt(StatusError):
    pass
