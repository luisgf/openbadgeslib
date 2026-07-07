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

from typing import Any, Optional, Tuple, Union, cast
from .errors import PublicKeyReadError, UnknownKeyType
from ecdsa import SigningKey, VerifyingKey, NIST256p
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization as _crypto_serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from enum import Enum
import logging
logger = logging.getLogger(__name__)


class KeyType(Enum):
    RSA = 'RSA 2048'
    ECC = 'ECC NIST256p'
    ED25519 = 'Ed25519'


def KeyFactory(key_type: 'KeyType' = KeyType.RSA) -> 'Union[KeyRSA, KeyECC, KeyEd25519]':
    """ Key Factory Object, Return a Given object type passing a name
        to the constructor. """
    if key_type == KeyType.ECC:
        return KeyECC()
    if key_type == KeyType.RSA:
        return KeyRSA()
    if key_type == KeyType.ED25519:
        return KeyEd25519()
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
        return cast(bytes, self.priv_key.export_key('PEM'))

    def get_pub_key_pem(self) -> bytes:
        return cast(bytes, self.pub_key.export_key('PEM'))


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
        return cast(bytes, self.priv_key.to_pem())

    def get_pub_key_pem(self) -> bytes:
        return cast(bytes, self.pub_key.to_pem())


def _pem_bytes(key_pem: Union[str, bytes]) -> bytes:
    return key_pem.encode('utf-8') if isinstance(key_pem, str) else key_pem


def _load_ed25519_private_key(key_pem: Optional[Union[str, bytes]]) -> Ed25519PrivateKey:
    if key_pem is None:
        raise UnknownKeyType('No Ed25519 private key PEM provided')
    key = _crypto_serialization.load_pem_private_key(_pem_bytes(key_pem), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise UnknownKeyType('PEM is not an Ed25519 private key')
    return key


def _load_ed25519_public_key(key_pem: Optional[Union[str, bytes]]) -> Ed25519PublicKey:
    if key_pem is None:
        raise UnknownKeyType('No Ed25519 public key PEM provided')
    key = _crypto_serialization.load_pem_public_key(_pem_bytes(key_pem))
    if not isinstance(key, Ed25519PublicKey):
        raise UnknownKeyType('PEM is not an Ed25519 public key')
    return key


class KeyEd25519(KeyBase):
    """Edwards-curve Ed25519 (EdDSA) key class, backed by ``cryptography``.

    Kept separate from KeyECC: Ed25519 is an EdDSA curve, not an ECDSA NIST
    curve. It maps to the JWS ``EdDSA`` algorithm, and the ``ecdsa`` library
    used for the NIST curves would misread its PEM (see detect_key_type).
    """

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """ Generate an Ed25519 keypair, returning PEM (private, public). """
        self.priv_key = Ed25519PrivateKey.generate()
        self.pub_key = self.priv_key.public_key()
        return self.get_priv_key_pem(), self.get_pub_key_pem()

    def read_private_key(self, key_pem: Optional[Union[str, bytes]] = None) -> None:
        """ Read the private key from param in PEM format """
        self.priv_key = _load_ed25519_private_key(key_pem)

    def read_public_key(self, key_pem: Optional[Union[str, bytes]] = None) -> None:
        """ Read the public key from param in PEM format """
        self.pub_key = _load_ed25519_public_key(key_pem)

    def get_priv_key_pem(self) -> bytes:
        return cast(bytes, self.priv_key.private_bytes(
            _crypto_serialization.Encoding.PEM,
            _crypto_serialization.PrivateFormat.PKCS8,
            _crypto_serialization.NoEncryption()))

    def get_pub_key_pem(self) -> bytes:
        return cast(bytes, self.pub_key.public_bytes(
            _crypto_serialization.Encoding.PEM,
            _crypto_serialization.PublicFormat.SubjectPublicKeyInfo))


def alg_for_key_type(key_type: 'KeyType') -> str:
    """Return the JWS algorithm the library signs with for a given key type."""
    if key_type is KeyType.RSA:
        return 'RS256'
    if key_type is KeyType.ECC:
        return 'ES256'
    if key_type is KeyType.ED25519:
        return 'EdDSA'
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
        return cast(Union[str, bytes], key.to_pem())
    if isinstance(key, Ed25519PrivateKey):
        return key.private_bytes(
            _crypto_serialization.Encoding.PEM,
            _crypto_serialization.PrivateFormat.PKCS8,
            _crypto_serialization.NoEncryption())
    if isinstance(key, Ed25519PublicKey):
        return key.public_bytes(
            _crypto_serialization.Encoding.PEM,
            _crypto_serialization.PublicFormat.SubjectPublicKeyInfo)
    if isinstance(key, (bytes, str)):
        return key
    raise UnknownKeyType('Unsupported key object type: %r' % type(key))


def public_jwk_from_pem(pubkey_pem: Union[str, bytes]) -> dict[str, Any]:
    """Serialise a public key PEM as a public JWK dict.

    Counterpart of the OB3 signer's private-key-based JWK derivation, for
    when only the public half is at hand — e.g. publishing the badges'
    verification keys in a did:web DID document.
    """
    import json
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm
    try:
        pub = _crypto_serialization.load_pem_public_key(_pem_bytes(pubkey_pem))
        if isinstance(pub, rsa.RSAPublicKey):
            jwk_json = RSAAlgorithm.to_jwk(pub)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            jwk_json = ECAlgorithm.to_jwk(pub)
        elif isinstance(pub, Ed25519PublicKey):
            jwk_json = OKPAlgorithm.to_jwk(pub)
        else:
            raise PublicKeyReadError(
                'unsupported public key type: %r' % type(pub))
    except PublicKeyReadError:
        raise
    except Exception as exc:
        raise PublicKeyReadError(
            'could not read public key PEM: %s' % exc) from exc
    return cast(dict[str, Any], json.loads(jwk_json))


def ec_curve_from_pem(pem_data: Union[str, bytes]) -> Optional[str]:
    """Return the NIST curve name of an elliptic-curve key PEM, else ``None``.

    The name is ``cryptography``'s (``'secp256r1'`` for P-256, ``'secp384r1'``
    for P-384, …); ``None`` if the PEM is not an EC key (RSA, Ed25519 or
    unreadable). Accepts a public or private PEM. The SD-JWT VC (EUDI) track
    uses this to pick the ES256 vs ES384 signing backend — the ECDSA curve
    fixes the JOSE algorithm.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    data = _pem_bytes(pem_data)
    for load in (
        lambda: _crypto_serialization.load_pem_public_key(data),
        lambda: _crypto_serialization.load_pem_private_key(data, password=None),
    ):
        try:
            key = load()
        except Exception:
            continue
        if isinstance(key, (ec.EllipticCurvePublicKey,
                            ec.EllipticCurvePrivateKey)):
            return key.curve.name
        return None                                   # readable, but not EC
    return None


def _is_ed25519_pem(pem_data: Union[str, bytes]) -> bool:
    """True if pem_data is an Ed25519 public or private key.

    Probed before the RSA/ECC checks in detect_key_type: the ``ecdsa`` library's
    VerifyingKey/SigningKey.from_pem *accept* an Ed25519 PEM and would otherwise
    misclassify it as KeyType.ECC, pinning the wrong (ES*) algorithm family.
    ``cryptography``'s loaders are unambiguous about the key type.
    """
    data = _pem_bytes(pem_data)
    try:
        if isinstance(_crypto_serialization.load_pem_public_key(data), Ed25519PublicKey):
            return True
    except Exception:
        pass
    try:
        if isinstance(_crypto_serialization.load_pem_private_key(data, password=None),
                      Ed25519PrivateKey):
            return True
    except Exception:
        pass
    return False


def detect_key_type(pem_data: Union[str, bytes]) -> 'KeyType':
    """ Positive Key type detection """

    # Ed25519 first: see _is_ed25519_pem — the ecdsa library would otherwise
    # claim an Ed25519 PEM as ECC below.
    if _is_ed25519_pem(pem_data):
        return KeyType.ED25519

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
