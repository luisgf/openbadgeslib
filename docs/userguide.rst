User Guide
==========


First Steps
-----------

After installing the library, start by running ``openbadges-init`` to create
the configuration directory, and then ``openbadges-keygenerator`` to create
the cryptographic key pair required for signing.

.. warning::
    Keep your private key safe and back it up. If the private key is lost,
    no new badges can be signed. If the public key is lost, existing signed
    badges can no longer be verified.


Generating a key pair
---------------------

Key pairs consist of a private signing key and a public verification key,
both stored as PEM files. Pass the path to ``config.ini`` and the badge
section number (the digit in ``[badge_1]``, ``[badge_2]``, …):

.. code-block:: sh

    $ openbadges-keygenerator -c ./config/config.ini -g 1
    INFO - Generating OpenBadges 2 key pair for issuer 'My Organisation'
    INFO - Private key saved at: ./config/keys/sign_rsa_key_1.pem
    INFO - Public key saved at:  ./config/keys/verify_rsa_key_1.pem

The ``-V / --ob-version`` flag is accepted for consistency but key material
is identical for OB2 and OB3:

.. code-block:: sh

    $ openbadges-keygenerator -c ./config/config.ini -g 1 -V 3

.. note::
    RSA keys are 2048 bits. ECC keys use the NIST P-256 curve.

.. warning::
    The ECC (ES256) algorithm is supported by this library but interoperability
    with third-party badge validators may vary. RSA (RS256) is the safer choice
    for broad compatibility.


Signing a badge
---------------

The signing process takes a badge image (SVG or PNG) defined in ``config.ini``
and a recipient email address. Use ``-V / --ob-version`` to choose the
specification version (default: ``2``).

Optionally you can attach an **evidence URL** (a link to proof of the earned)
and an **expiration** in days (``-x DAYS``).

**OpenBadges 2.0 (JWS)**

.. code-block:: sh

    $ openbadges-signer -c ./config/config.ini -b 1 \
        -r recipient@example.com \
        -e https://example.com/proof \
        -o /tmp/
    2026-04-22T10:00:00 badge_1 SIGNED for recipient@example.com
    UID 73f8981f125ffc060b43847728c0bddcbb8e24f4
    Output: /tmp/badge_1_recipient@example.com.svg

The signed file embeds a :term:`JWS` :term:`Assertion`. For SVG the assertion
is stored as an ``<openbadges:assertion>`` XML element; for PNG it is stored in
an ``iTXt`` metadata chunk.

**OpenBadges 3.0 (JWT-VC)**

.. code-block:: sh

    $ openbadges-signer -c ./config/config.ini -b 1 \
        -r recipient@example.com \
        -o /tmp/ -V 3
    2026-04-22T10:00:00 badge_1 OB3 SIGNED for recipient@example.com
    at: /tmp/badge_1_recipient@example.com.svg

For OB3, the signer auto-detects the key algorithm (RS256 for RSA keys,
ES256 for ECC keys) and embeds a :term:`JWT-VC` token in the same
SVG/PNG format.


Verifying a badge
-----------------

Use ``-V / --ob-version`` to choose the specification version (default: ``2``).

**OpenBadges 2.0 (JWS)**

The verification tool extracts the embedded :term:`Assertion`, downloads the
issuer's public key from the URL in the assertion, checks the cryptographic
signature, and verifies the recipient identity.

.. code-block:: sh

    $ openbadges-verifier -i /tmp/badge_1_recipient@example.com.svg \
        -r recipient@example.com
    [+] Signature is correct for the identity recipient@example.com

The ``-s / --show`` flag prints the decoded assertion before the result.
Use ``-l BADGE`` to verify against a local config instead of downloading
the public key from the network.

The verification steps performed are:

1. Extract the JWS token from the badge image.
2. Download the public key from the ``verify.url`` field (or use ``-l``).
3. Verify the cryptographic signature (RS256 or ES256).
4. Check the badge has not been revoked.
5. Check the badge has not expired (if an expiry is set).
6. Hash the supplied email address with the salt from the assertion and
   compare against the hashed identity stored in the assertion.

**OpenBadges 3.0 (JWT-VC)**

OB3 credentials are self-contained; no network download is needed.
Supply the issuer's public key via ``-l BADGE`` (reads from ``config.ini``)
or ``-k / --pubkey FILE`` (path to a PEM file):

.. code-block:: sh

    # Verify using a PEM file directly
    $ openbadges-verifier -i /tmp/badge_1_recipient@example.com.svg \
        -r recipient@example.com -V 3 \
        -k ./config/keys/verify_rsa_key_1.pem
    [+] OB3 signature is valid for the identity recipient@example.com

    # Verify using local config
    $ openbadges-verifier -i /tmp/badge_1_recipient@example.com.svg \
        -r recipient@example.com -V 3 -l 1
    [+] OB3 signature is valid for the identity recipient@example.com

The ``-s / --show`` flag prints issuer name, achievement name, issuance
date, expiration date, and evidence URL.


Using the library programmatically
-----------------------------------

You can use the library directly without the CLI tools.

The top-level ``badge``, ``signer``, and ``verifier`` modules are
backward-compatible shims. New code can import from ``openbadgeslib.ob2``
directly — both paths are equivalent:

.. code-block:: python

    # Equivalent imports (shim and direct)
    from openbadgeslib.badge import Badge        # shim
    from openbadgeslib.ob2.badge import Badge    # direct

**Signing a badge**

.. code-block:: python

    from openbadgeslib.badge import Badge, BadgeImgType, BadgeType
    from openbadgeslib.keys import KeyType
    from openbadgeslib.signer import Signer

    with open('sign.pem', 'rb') as f:
        priv_pem = f.read()
    with open('verify.pem', 'rb') as f:
        pub_pem = f.read()
    with open('badge.svg', 'rb') as f:
        image_data = f.read()

    badge = Badge(
        ini_name='workshop_badge',
        name='Workshop Attendance',
        description='Awarded for attending the workshop',
        image_type=BadgeImgType.SVG,
        image=image_data,
        image_url='https://example.com/badge.svg',
        criteria_url='https://example.com/criteria.html',
        json_url='https://example.com/badge.json',
        verify_key_url='https://example.com/verify.pem',
        key_type=KeyType.RSA,
        privkey_pem=priv_pem,
        pubkey_pem=pub_pem,
    )

    signer = Signer(identity='recipient@example.com', badge_type=BadgeType.SIGNED)
    signed = signer.sign_badge(badge)
    signed.save_to_file('/tmp/signed_badge.svg')

**Reading a signed badge from file**

.. code-block:: python

    from openbadgeslib.badge import BadgeSigned

    badge_signed = BadgeSigned.read_from_file('/tmp/signed_badge.svg')
    body = badge_signed.assertion.decode_body()
    print('Issued on:', body['issuedOn'])
    print('Badge URL:', body['badge'])

**Verifying programmatically**

.. code-block:: python

    from openbadgeslib.verifier import Verifier
    from openbadgeslib.badge import BadgeSigned, BadgeStatus

    badge_signed = BadgeSigned.read_from_file('/tmp/signed_badge.svg')
    verifier = Verifier(identity='recipient@example.com')
    result = verifier.get_badge_status(badge_signed)

    if result.status is BadgeStatus.VALID:
        print('Badge is valid.')
    else:
        print('Badge invalid:', result.msg)


Generating keys programmatically
---------------------------------

.. code-block:: python

    from openbadgeslib.keys import KeyFactory, KeyType

    # Generate an RSA key pair
    key = KeyFactory(KeyType.RSA)
    priv_pem, pub_pem = key.generate_keypair()

    with open('sign.pem', 'wb') as f:
        f.write(priv_pem)
    with open('verify.pem', 'wb') as f:
        f.write(pub_pem)


OpenBadges 3.0
--------------

The ``openbadgeslib.ob3`` subpackage implements the
`IMS Global OpenBadges 3.0`_ specification using the
`W3C Verifiable Credentials`_ data model. Credentials are signed as
:term:`JWT-VC` tokens and can be baked directly into SVG or PNG badge images.

.. _IMS Global OpenBadges 3.0: https://www.imsglobal.org/spec/ob/v3p0/
.. _W3C Verifiable Credentials: https://www.w3.org/TR/vc-data-model/


Building a credential
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    from openbadgeslib.ob3 import Issuer, Achievement, OpenBadgeCredential

    issuer = Issuer(
        id='https://example.com/issuer',
        name='Example Organisation',
        url='https://example.com',
        email='badges@example.com',
    )

    achievement = Achievement(
        id='https://example.com/achievements/python',
        name='Python Developer',
        description='Awarded for demonstrating Python proficiency',
        criteria_narrative='Must pass the Python competency assessment',
        image_url='https://example.com/badge.svg',
        tags=['python', 'programming'],
    )

    credential = OpenBadgeCredential(
        issuer=issuer,
        recipient_id='mailto:recipient@example.com',
        achievement=achievement,
        evidence_url='https://example.com/proof/123',
    )

``OpenBadgeCredential`` auto-generates a ``urn:uuid:…`` identifier and
sets ``issuance_date`` to the current UTC time if not provided explicitly.


Signing
~~~~~~~

.. code-block:: python

    from openbadgeslib.ob3 import OB3Signer

    with open('sign.pem', 'rb') as f:
        priv_pem = f.read()

    signer = OB3Signer(privkey_pem=priv_pem, algorithm='RS256')

    # Sign to a JWT-VC string
    token = signer.sign(credential)

    # Bake into an SVG badge image
    with open('badge.svg', 'rb') as f:
        svg_bytes = f.read()
    baked_svg = signer.sign_into_svg(credential, svg_bytes)
    with open('signed_badge.svg', 'wb') as f:
        f.write(baked_svg)

    # Bake into a PNG badge image
    with open('badge.png', 'rb') as f:
        png_bytes = f.read()
    baked_png = signer.sign_into_png(credential, png_bytes)
    with open('signed_badge.png', 'wb') as f:
        f.write(baked_png)

Supported algorithms: ``RS256``, ``RS384``, ``RS512``, ``ES256``,
``ES384``, ``ES512``.

.. note::
    Use the same key-generation helpers as for OB 2.0 (``KeyFactory`` /
    ``KeyRSA`` / ``KeyECC``) to produce PEM files for OB 3.0 signing.


Verifying
~~~~~~~~~

.. code-block:: python

    from openbadgeslib.ob3 import OB3Verifier, OB3VerificationError

    with open('verify.pem', 'rb') as f:
        pub_pem = f.read()

    verifier = OB3Verifier(pubkey_pem=pub_pem)

    # Extract the token from a baked image
    with open('signed_badge.svg', 'rb') as f:
        svg_bytes = f.read()
    token = OB3Verifier.extract_token_from_svg(svg_bytes)

    # Verify and decode
    try:
        restored = verifier.verify(token)
        print('Recipient:', restored.recipient_id)
        print('Achievement:', restored.achievement.name)
        print('Issued by:', restored.issuer.name)
    except OB3VerificationError as exc:
        print('Verification failed:', exc)

``OB3Verifier.extract_token_from_png()`` works the same way for PNG badges.
``OB3VerificationError`` is raised for any failure: invalid signature,
expired credential, unsupported algorithm, or malformed payload.
