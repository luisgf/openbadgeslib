OpenBadgesLib
=============

A Python library for signing and verifying `OpenBadges`_ assertions
embedded in SVG and PNG image files. Supports both **OpenBadges 2.0**
(JWS compact serialisation) and **OpenBadges 3.0** (W3C Verifiable
Credentials / JWT-VC).

.. _OpenBadges: https://www.imsglobal.org/activity/digital-badges


Features
--------

* Sign badge images (SVG and PNG) with a JWS assertion (OB 2.0)
* Issue and verify OpenBadges 3.0 JWT-VC credentials
* Bake OB 3.0 JWT tokens into SVG and PNG badge images
* RSA 2048-bit (RS256) and ECC NIST P-256 (ES256) key support
* SHA-256 hashed recipient identity with salt (OB 2.0)
* Expiration and revocation checking
* Command-line wrapper tools included


Requirements
------------

* Python >= 3.10
* pycryptodome >= 3.20
* ecdsa >= 0.19
* pypng >= 0.20220715.0
* PyJWT[crypto] >= 2.8


Installation
------------

::

    pip install openbadgeslib

All dependencies are installed automatically.

To install in development mode with the test suite::

    pip install -e ".[dev]"


Quick Start
-----------

**1. Initialize a configuration directory**::

    openbadges-init ./config/

**2. Generate a key pair for a badge**::

    openbadges-keygenerator -c ./config/config.ini -g 1

**3. Sign a badge**::

    # OpenBadges 2.0 (default)
    openbadges-signer -c ./config/config.ini -b 1 -r recipient@example.com -o /tmp/

    # OpenBadges 3.0
    openbadges-signer -c ./config/config.ini -b 1 -r recipient@example.com -o /tmp/ -V 3

**4. Verify a signed badge**::

    # OpenBadges 2.0 (default)
    openbadges-verifier -i /tmp/badge_1_recipient@example.com.svg -r recipient@example.com

    # OpenBadges 3.0 (supply public key directly)
    openbadges-verifier -i /tmp/badge_1_recipient@example.com.svg -r recipient@example.com \
        -V 3 -k ./config/keys/verify_rsa_key_1.pem


Using the library directly
--------------------------

::

    from openbadgeslib.badge import Badge, BadgeImgType
    from openbadgeslib.keys import KeyType
    from openbadgeslib.signer import Signer
    from openbadgeslib.badge import BadgeType

    # Load key material
    with open('sign.pem', 'rb') as f:
        priv_pem = f.read()
    with open('verify.pem', 'rb') as f:
        pub_pem = f.read()

    # Build a Badge descriptor
    badge = Badge(
        ini_name='my_badge',
        name='My Badge',
        description='Awarded for excellence',
        image_type=BadgeImgType.SVG,
        image=open('badge.svg', 'rb').read(),
        image_url='https://example.com/badge.svg',
        criteria_url='https://example.com/criteria.html',
        json_url='https://example.com/badge.json',
        verify_key_url='https://example.com/verify.pem',
        key_type=KeyType.RSA,
        privkey_pem=priv_pem,
        pubkey_pem=pub_pem,
    )

    # Sign
    signer = Signer(identity='recipient@example.com', badge_type=BadgeType.SIGNED)
    signed = signer.sign_badge(badge)
    signed.save_to_file('/tmp/signed_badge.svg')


OpenBadges 3.0 (JWT-VC)
-----------------------

::

    from openbadgeslib.ob3 import (
        Issuer, Achievement, OpenBadgeCredential,
        OB3Signer, OB3Verifier,
    )

    # Build the credential data model
    issuer = Issuer(id='https://example.com/issuer', name='Example Org')
    achievement = Achievement(
        id='https://example.com/achievements/python',
        name='Python Developer',
        description='Awarded for Python proficiency',
        criteria_narrative='Must pass the Python assessment',
    )
    credential = OpenBadgeCredential(
        issuer=issuer,
        recipient_id='mailto:recipient@example.com',
        achievement=achievement,
    )

    # Sign — returns a JWT-VC string
    with open('sign.pem', 'rb') as f:
        priv_pem = f.read()
    signer = OB3Signer(privkey_pem=priv_pem, algorithm='RS256')
    token = signer.sign(credential)

    # Bake the token into a badge image
    with open('badge.svg', 'rb') as f:
        svg_bytes = f.read()
    baked_svg = signer.sign_into_svg(credential, svg_bytes)

    # Verify
    with open('verify.pem', 'rb') as f:
        pub_pem = f.read()
    verifier = OB3Verifier(pubkey_pem=pub_pem)
    extracted_token = OB3Verifier.extract_token_from_svg(baked_svg)
    restored_credential = verifier.verify(extracted_token)
    print('Recipient:', restored_credential.recipient_id)


Running the test suite
----------------------

::

    pytest
    pytest --cov=openbadgeslib      # with coverage report


Documentation
-------------

Full documentation is in the ``docs/`` directory (Sphinx RST sources).

Build the HTML docs::

    pip install sphinx sphinx-rtd-theme
    sphinx-build -b html docs/ docs/_build/html/


Changelog
---------

**v1.0.1** (2026-04-22)

* **OpenBadges 3.0 support** — new ``openbadgeslib.ob3`` subpackage:
  ``OpenBadgeCredential``, ``Issuer``, ``Achievement`` data classes;
  ``OB3Signer`` (JWT-VC signing + SVG/PNG baking); ``OB3Verifier``
  (JWT-VC verification + token extraction from SVG/PNG)
* **OpenBadges 2.0 subpackage** — OB2 implementation moved to
  ``openbadgeslib.ob2``; top-level modules kept as backward-compatible
  shims so existing code requires no changes
* **``--ob-version`` flag** — all four CLI tools (keygenerator, signer,
  verifier, publish) accept ``-V {2,3}`` to select the specification
  version (default: ``2``)
* **``openbadges-verifier --pubkey``** — new ``-k FILE`` option to supply
  the PEM public key directly for OB3 verification
* Python 3.10+ compatibility: removed distutils, migrated packaging to
  ``pyproject.toml`` with ``setuptools.build_meta``
* Replaced abandoned ``pycrypto`` with ``pycryptodome >= 3.20``
* Replaced custom JWS engine (``3dparty/jws/``) with ``PyJWT[crypto]``
  algorithm classes (RS256/384/512, ES256/384/512); old ``3dparty/``
  directory removed
* Fixed TLS: removed deprecated ``PROTOCOL_TLSv1`` / ``CERT_NONE``;
  ``download_file`` now uses the system default TLS context
* Updated pypng API: renamed ``signature`` constant, bytes chunk tags
* Copyright year range updated to 2014-2026 across all source files
* Fixed verifier logic bug: ``check_jws_signature`` return value was
  compared with ``BadgeStatus`` via identity check, always evaluating True
* Added 203 unit tests, 89% line coverage

**v0.4.2** and earlier

* See git history at https://github.com/luisgf/openbadgeslib


License
-------

The library is licensed under the `GNU Lesser General Public License v3`_
(LGPLv3). The command-line wrapper tools are licensed under the
`BSD 2-Clause`_ license.

.. _GNU Lesser General Public License v3: https://opensource.org/licenses/lgpl-3.0.html
.. _BSD 2-Clause: https://opensource.org/licenses/BSD-2-Clause


Authors
-------

* Luis González Fernández <luisgf@luisgf.es>
* Jesús Cea Avión <jcea@jcea.es>
