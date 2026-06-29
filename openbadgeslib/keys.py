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

from typing import Any, Optional, Tuple, Union
from .errors import UnknownKeyType
from ecdsa import SigningKey, VerifyingKey, NIST256p
from Crypto.PublicKey import RSA
from enum import Enum
import logging
logger = logging.getLogger(__name__)


class KeyType(Enum):
    RSA = 'RSA 2048'
    ECC = 'ECC NIST256p'


def KeyFactory(key_type: 'KeyType' = KeyType.RSA) -> 'Union[KeyRSA, KeyECC]':
    """ Key Factory Object, Return a Given object type passing a name
        to the constructor. """
    if key_type == KeyType.ECC:
        return KeyECC()
    if key_type == KeyType.RSA:
        return KeyRSA()
    else:
        raise UnknownKeyType()


class KeyBase():
    def __init__(self) -> None:
        self.priv_key: Any = None         # crypto Object
        self.pub_key: Any = None          # crypto Object

    def get_priv_key(self) -> Any:
        """ Return the crypto object """
        return self.priv_key

    def get_pub_key(self) -> Any:
        """ Return the crypto object """
        return self.pub_key


class KeyRSA(KeyBase):
    def __init__(self, key_size: int = 2048) -> None:
        self._key_size = key_size
        super().__init__()

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """ Generate a RSA Key, returning in PEM Format """

        # RSA Key Generation
        self.priv_key = RSA.generate(self._key_size)
        priv_key_pem = self.priv_key.export_key('PEM')
        self.pub_key = self.priv_key.publickey()
        pub_key_pem = self.pub_key.export_key('PEM')

        return priv_key_pem, pub_key_pem

    def read_private_key(self, key_pem: Any = None) -> None:
        """ Read the private key from param in PEM format """
        self.priv_key = RSA.import_key(key_pem)

    def read_public_key(self, key_pem: Any = None) -> None:
        """ Read the public key from param in PEM format """
        self.pub_key = RSA.import_key(key_pem)

    def get_priv_key_pem(self) -> bytes:
        return self.priv_key.export_key('PEM')

    def get_pub_key_pem(self) -> bytes:
        return self.pub_key.export_key('PEM')


class KeyECC(KeyBase):
    """ Elliptic Curve Cryptography Factory class """

    def __init__(self, key_curve: Any = NIST256p) -> None:
        self._key_curve = key_curve
        super().__init__()

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """ Generate a ECDSA keypair """

        # Private key generation
        self.priv_key = SigningKey.generate(curve=self._key_curve)
        priv_key_pem = self.priv_key.to_pem()

        # Derive the public (verifying) key from the private key.
        self.pub_key = self.priv_key.get_verifying_key()
        pub_key_pem = self.pub_key.to_pem()

        return priv_key_pem, pub_key_pem

    def read_private_key(self, key_pem: Optional[Union[str, bytes]] = None) -> None:
        """ Read the private key from param in PEM format """
        self.priv_key = SigningKey.from_pem(key_pem)

    def read_public_key(self, key_pem: Optional[Union[str, bytes]] = None) -> None:
        """ Read the public key from param in PEM format """
        self.pub_key = VerifyingKey.from_pem(key_pem)

    def get_priv_key_pem(self) -> bytes:
        return self.priv_key.to_pem()

    def get_pub_key_pem(self) -> bytes:
        return self.pub_key.to_pem()


def alg_for_key_type(key_type: 'KeyType') -> str:
    """Return the JWS algorithm the library signs with for a given key type."""
    if key_type is KeyType.RSA:
        return 'RS256'
    if key_type is KeyType.ECC:
        return 'ES256'
    raise UnknownKeyType('No signing algorithm for key type: %r' % (key_type,))


def key_to_pem(key: Any) -> Union[str, bytes]:
    """Convert a pycryptodome RSA or ecdsa key object to PEM bytes.

    Bytes/str are passed through unchanged. Centralised here so the OB2 JWS
    layer and both OB3 signer/verifier share one implementation instead of
    three hand-maintained copies.
    """
    if isinstance(key, RSA.RsaKey):
        return key.export_key('PEM')
    if isinstance(key, (SigningKey, VerifyingKey)):
        return key.to_pem()
    if isinstance(key, (bytes, str)):
        return key
    raise UnknownKeyType('Unsupported key object type: %r' % type(key))


def detect_key_type(pem_data: Union[str, bytes]) -> 'KeyType':
    """ Positive Key type detection """

    try:
        RSA.import_key(pem_data)
        return KeyType.RSA
    except Exception:
        pass

    try:
        VerifyingKey.from_pem(pem_data)
        return KeyType.ECC
    except Exception:
        pass

    try:
        SigningKey.from_pem(pem_data)
        return KeyType.ECC
    except Exception:
        pass

    raise UnknownKeyType('Unable to guess Key type')
