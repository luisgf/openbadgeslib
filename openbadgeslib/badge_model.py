"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es

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

# The version-neutral badge config model, shared by every OpenBadges version.
#
# ``Badge`` and ``BadgeImgType`` map a ``[badge_*]`` config section (its name,
# description, image and signing key) onto the object the OB1/OB2/OB3 signers
# consume. They lived in ``ob1.badge`` for historical reasons, so every modern
# module imported the shared model out of the legacy package; they now live here
# in neutral territory (``ob1.badge`` re-exports them for compatibility).
#
# create_from_conf requires only the keys every version uses — name,
# description, the signing key pair and the local image. ``verify_key`` and
# ``criteria`` are OpenBadges 1.0 fields and are read optionally, so issuing an
# OB 3.0 badge no longer needs them (they are absent from a 3.0-only config).

import os
from enum import Enum
from typing import Any, Optional, Union

from .keys import KeyType, detect_key_type
from .errors import (BadgeImgFormatUnsupported, ErrorParsingFile,
                     UnknownKeyType, PrivateKeyReadError, PublicKeyReadError)
from .util import download_file


class BadgeImgType(Enum):
    SVG = 0
    PNG = 1


class Badge():
    def __init__(self, ini_name: Optional[str] = None, name: Optional[str] = None,
                 description: Optional[str] = None, image_type: Optional[BadgeImgType] = None,
                 image: Optional[bytes] = None, image_url: Optional[str] = None,
                 criteria_url: Optional[str] = None, json_url: Optional[str] = None,
                 verify_key_url: Optional[str] = None, key_type: Optional[KeyType] = None,
                 privkey_pem: Optional[Union[str, bytes]] = None,
                 pubkey_pem: Optional[Union[str, bytes]] = None) -> None:

        self.ini_name = ini_name
        self.name = name
        self.description = description
        self.image_type = image_type
        self.image = image                  # Binary contents of image file
        self.image_url = image_url
        self.criteria_url = criteria_url
        self.json_url = json_url
        self.verify_key_url = verify_key_url
        self.key_type = key_type
        self.privkey_pem = privkey_pem
        self.pubkey_pem = pubkey_pem

        # Default to no key material so a Badge built without PEMs exposes
        # priv_key/pub_key as None rather than leaving the attributes undefined
        # (which turns a later read in the signer/verifier into a confusing raw
        # AttributeError instead of a clean "no key material" case).
        self.priv_key: Any = None
        self.pub_key: Any = None

        # Load whatever key material was supplied. RSA/ECC used to go through
        # pycryptodome/python-ecdsa; all three families now share cryptography's
        # unambiguous PEM loaders (the #167 port), producing cryptography key
        # objects that the JWS layer serialises via keys.key_to_pem.
        if self.key_type in (KeyType.RSA, KeyType.ECC, KeyType.ED25519):
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key, load_pem_public_key)
            label = self.key_type.name
            if self.pubkey_pem:
                try:
                    pub_pem = self.pubkey_pem.encode('utf-8') \
                        if isinstance(self.pubkey_pem, str) else self.pubkey_pem
                    self.pub_key = load_pem_public_key(pub_pem)
                except Exception as exc:
                    raise PublicKeyReadError(
                        'Unable to read %s public key: %s' % (label, exc)) from exc
            if self.privkey_pem:
                try:
                    priv_pem = self.privkey_pem.encode('utf-8') \
                        if isinstance(self.privkey_pem, str) else self.privkey_pem
                    self.priv_key = load_pem_private_key(priv_pem, password=None)
                except Exception as exc:
                    raise PrivateKeyReadError(
                        'Unable to read %s private key: %s' % (label, exc)) from exc
        elif self.key_type is not None:
            # key_type=None is a valid "no key material yet" state; any other
            # value is an unsupported key type and must fail loudly.
            raise UnknownKeyType('Unsupported key type: %r' % (self.key_type,))

    @staticmethod
    def create_from_conf(conf: Any, badge: str) -> 'Badge':
        """Build a Badge from the ``[badge]`` config section.

        Required for every version: ``name``, ``description``, the signing key
        pair (``private_key``/``public_key``), ``local_image``, the badge
        ``image`` URL and the ``badge`` (achievement) URL. ``verify_key`` and
        ``criteria`` are OpenBadges 1.0 fields and optional here, so an OB 3.0
        config that omits them issues cleanly.

        Raises the key/image read errors on an unreadable file; a missing
        required config key raises ``KeyError``, which ``issue_from_conf`` maps
        to ``IssuanceError`` (the CLI presents it)."""
        section = conf[badge]

        try:
            with open(section['private_key'], 'rb') as key:
                privkey_pem = key.read()
        except OSError as exc:
            raise PrivateKeyReadError(
                'Unable to read private key file %s: %s'
                % (section['private_key'], exc)) from exc

        try:
            with open(section['public_key'], 'rb') as key:
                pubkey_pem = key.read()
        except OSError as exc:
            raise PublicKeyReadError(
                'Unable to read public key file %s: %s'
                % (section['public_key'], exc)) from exc

        key_type = detect_key_type(pubkey_pem)

        img_path = os.path.join(conf['paths']['base_image'], section['local_image'])
        if not os.path.isfile(img_path):
            raise ErrorParsingFile('Badge image file %s does not exist' % img_path)
        with open(img_path, 'rb') as file:
            img_content = file.read()

        if img_path.lower().endswith('.svg'):
            img_type = BadgeImgType.SVG
        elif img_path.lower().endswith('.png'):
            img_type = BadgeImgType.PNG
        else:
            raise BadgeImgFormatUnsupported(
                'The image format for %s is not supported' % badge)

        return Badge(ini_name=badge,
                     name=section['name'],
                     description=section['description'],
                     image_type=img_type,
                     image=img_content,
                     image_url=section['image'],
                     criteria_url=section.get('criteria'),      # OB 1.0; optional
                     json_url=section['badge'],
                     verify_key_url=section.get('verify_key'),  # OB 1.0; optional
                     key_type=key_type,
                     privkey_pem=privkey_pem,
                     pubkey_pem=pubkey_pem)

    def __str__(self) -> str:
        return (
            'INI Name: %s\nName: %s\nDescription: %s\nImage Type: %s\n'
            'Image Url: %s\nKey Type: %s\nVerify Key: %s\nJSON Url: %s\n'
            % (self.ini_name, self.name, self.description, self.image_type,
               self.image_url, self.key_type, self.verify_key_url, self.json_url)
        )

    def urls_has_problems(self) -> bool:
        """ Check if urls in Badge are corrects and online """

        error = False
        checks = [
            (self.image_url, 'OpenBadge Image'),
            (self.criteria_url, 'OpenBadge Criteria'),
            (self.json_url, 'OpenBadge JSon'),
            (self.verify_key_url, 'OpenBadge Verify key'),
        ]

        # 'data' is reset for every URL so a previous success can never mask a
        # later download failure.
        for url, label in checks:
            data = None
            try:
                data = download_file(url) if url else None
            except Exception:
                pass
            if not data:
                print('[!] %s at config file is pointing to a wrong url: %s' % (label, url))
                error = True

        return error
