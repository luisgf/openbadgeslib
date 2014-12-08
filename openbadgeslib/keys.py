#!/usr/bin/env python3
"""
        OpenBadges Library

        Copyright (c) 2014, Luís González Fernández, luisgf@luisgf.es
        Copyright (c) 2014, Jesús Cea Avión, jcea@jcea.es

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

from Crypto.PublicKey import RSA
from ecdsa import SigningKey, VerifyingKey, NIST256p

from .errors import UnknownKeyType, PrivateKeySaveError, \
        PublicKeySaveError, PrivateKeyExists, GenPrivateKeyError, \
        GenPublicKeyError, PrivateKeyReadError, PublicKeyReadError

def KeyFactory(config):
    """ Key Factory Object, Return a Given object type passing a name
        to the constructor. """
    if config['keys']['crypto'] == 'ECC':
        return KeyECC(config)
    if config['keys']['crypto'] == 'RSA':
        return KeyRSA(config)
    else:
        raise UnknownKeyType()

class KeyBase():
    def __init__(self, config):
        self.conf = config
        self.priv_key = None              # crypto Object
        self.pub_key = None               # crypto Object

    def get_privkey_path(self):
        """ Return the path to the private key """
        return self.conf['keys']['private']

    def get_pubkey_path(self):
        """ Return the path to the public key """
        return self.conf['keys']['public']

    def save_keypair(self, private_key_pem, public_key_pem):
        """ Save keypair to file """
        # Lets save public first, just in case.
        with open(self.get_pubkey_path(), "wb") as pub:
                pub.write(public_key_pem)
        with open(self.get_privkey_path(), "wb") as priv:
                priv.write(private_key_pem)
   
    def get_priv_key(self):
        """ Return the crypto object """
        return self.priv_key

    def get_pub_key(self):
        """ Return the crypto oject """
        return self.pub_key

class KeyRSA(KeyBase):
    def __init__(self, config):
        super().__init__(config)

    def generate_keypair(self):
        """ Generate a RSA Key, returning in PEM Format """

        # RSA Key Generation
        self.priv_key = RSA.generate(self.conf['keys']['size'])
        priv_key_pem = self.priv_key.exportKey('PEM')
        self.pub_key = self.priv_key.publickey()
        pub_key_pem = self.pub_key.exportKey('PEM')

        self.save_keypair(priv_key_pem, pub_key_pem)

        logger.info('[+] RSA(%d) Private Key generated at %s' % (self.conf['keys']['size'], self.get_privkey_path()))
        logger.info('[+] RSA(%d) Public Key generated at %s' % (self.conf['keys']['size'], self.get_pubkey_path()))

    def read_private_key(self):
        """ Read the private key from file """
        try:
            with open(self.get_privkey_path(), "rb") as priv:
                self.priv_key = RSA.importKey(priv.read())
        except Exception as e:
            raise PrivateKeyReadError('Error reading private key: %s - %s' %
                    (self.get_privkey_path(), e))

    def read_public_key(self):
        """ Read the public key from file """
        try:
            with open(self.get_pubkey_path(), "rb") as pub:
                self.pub_key = RSA.importKey(pub.read())
        except Exception as e :
            raise PublicKeyReadError('Error reading public key: %s - %s' %
                    (self.get_pubkey_path(), e))

    def get_priv_key_pem(self):
        return self.priv_key.exportKey('PEM')

    def get_pub_key_pem(self):
        return self.pub_key.exportKey('PEM')

class KeyECC(KeyBase):
    """ Elliptic Curve Cryptography Factory class """

    def __init__(self, config):
        super().__init__(config)

    def generate_keypair(self):
        """ Generate a ECDSA keypair """

        # Private key generation
        self.priv_key = SigningKey.generate(curve=NIST256p)
        priv_key_pem = self.priv_key.to_pem()

        # Public Key name is the hash of the public key
        self.pub_key = self.priv_key.get_verifying_key()
        pub_key_pem = self.pub_key.to_pem()

        # Save the keypair
        self.save_keypair(priv_key_pem, pub_key_pem)

        logger.info('[+] ECC(%s) Private Key generated at %s' % (self.conf['keys']['curve'], self.get_privkey_path()))
        logger.info('[+] ECC(%s) Public Key generated at %s' % (self.conf['keys']['curve'], self.get_pubkey_path()))

    def read_private_key(self):
        """ Read the private key from files """
        try:
            with open(self.get_privkey_path(), "rb") as priv:
                self.priv_key = SigningKey.from_pem(priv.read())
        except Exception as e:
            raise PrivateKeyReadError('Error reading private key: %s - %s' %
                    (self.get_privkey_path(), e))

    def read_public_key(self):
        """ Read the public key from files """
        try:
            with open(self.get_pubkey_path(), "rb") as pub:
                self.pub_key = VerifyingKey.from_pem(pub.read())
        except:
            raise PublicKeyReadError('Error reading public key: %s - %s' %
                    (self.get_pubkey_path(), e))

    def get_priv_key_pem(self):
        return self.priv_key.to_pem()

    def get_pub_key_pem(self):
        return self.pub_key.to_pem()

