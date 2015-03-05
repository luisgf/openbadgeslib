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

import logging
logger = logging.getLogger(__name__)

import os
import sys

from enum import Enum
from Crypto.PublicKey import RSA
from ecdsa import SigningKey, VerifyingKey, NIST256p

from .errors import UnknownKeyType, PrivateKeySaveError, \
        PublicKeySaveError, GenPrivateKeyError, \
        GenPublicKeyError, PrivateKeyReadError, PublicKeyReadError

class KeyType(Enum):
    RSA = 'RSA 2048'
    ECC = 'ECC NIST256p'

def KeyFactory(key_type=KeyType.RSA):
    """ Key Factory Object, Return a Given object type passing a name
        to the constructor. """
    if key_type == KeyType.ECC:
        return KeyECC()
    if key_type == KeyType.RSA:
        return KeyRSA()
    else:
        raise UnknownKeyType()

class KeyBase():
    def __init__(self):
        self.priv_key = None              # crypto Object
        self.pub_key = None               # crypto Object

    def get_priv_key(self):
        """ Return the crypto object """
        return self.priv_key

    def get_pub_key(self):
        """ Return the crypto oject """
        return self.pub_key

class KeyRSA(KeyBase):
    def __init__(self, key_size=2048):
        self._key_size = key_size
        super().__init__()

    def generate_keypair(self):
        """ Generate a RSA Key, returning in PEM Format """

        # RSA Key Generation
        self.priv_key = RSA.generate(self._key_size)
        priv_key_pem = self.priv_key.exportKey('PEM')
        self.pub_key = self.priv_key.publickey()
        pub_key_pem = self.pub_key.exportKey('PEM')

        return priv_key_pem, pub_key_pem

    def read_private_key(self, key_pem=None):
        """ Read the private key from param in PEM format """
        self.priv_key = RSA.importKey(key_pem)

    def read_public_key(self, key_pem=None):
        """ Read the public key from file """
        self.pub_key = RSA.importKey(key_pem)

    def get_priv_key_pem(self):
        return self.priv_key.exportKey('PEM')

    def get_pub_key_pem(self):
        return self.pub_key.exportKey('PEM')

class KeyECC(KeyBase):
    """ Elliptic Curve Cryptography Factory class """

    def __init__(self, key_curve=NIST256p):
        self._key_curve = key_curve
        super().__init__()

    def generate_keypair(self):
        """ Generate a ECDSA keypair """

        # Private key generation
        self.priv_key = SigningKey.generate(curve=self._key_curve)
        priv_key_pem = self.priv_key.to_pem()

        # Public Key name is the hash of the public key
        self.pub_key = self.priv_key.get_verifying_key()
        pub_key_pem = self.pub_key.to_pem()

        return priv_key_pem, pub_key_pem

    def read_private_key(self, key_pem=None):
        """ Read the private key from files """
        self.priv_key = SigningKey.from_pem(key_pem)

    def read_public_key(self, key_pem=None):
        """ Read the public key from files """
        self.pub_key = VerifyingKey.from_pem(key_pem)

    def get_priv_key_pem(self):
        return self.priv_key.to_pem()

    def get_pub_key_pem(self):
        return self.pub_key.to_pem()

def detect_key_type(pem_data):
    """ Positive Key type detection """

    try:
        RSA.importKey(pem_data)
        return KeyType.RSA
    except:
        pass

    try:
        VerifyingKey.from_pem(pem_data)
        return KeyType.ECC
    except:
        pass

    raise UnknownKeyType('Unable to guess Key type')