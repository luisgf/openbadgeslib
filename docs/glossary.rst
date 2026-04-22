.. _glossary:

Glossary
========

.. glossary::

   SVG
     Scalable Vector Graphics (SVG) is an XML-based vector image format for
     two-dimensional graphics with support for interactivity and animation.

     .. seealso:: https://en.wikipedia.org/wiki/Scalable_Vector_Graphics

   PNG
     Portable Network Graphics is a raster graphics file format that supports
     lossless data compression.

     .. seealso:: https://en.wikipedia.org/wiki/Portable_Network_Graphics

   Python
     A widely used, high-level, general-purpose programming language with an
     emphasis on code readability.

     .. seealso:: https://www.python.org

   OpenBadge
     The IMS Global Open Badges specification defines a standard for digital
     badges that carry verifiable metadata and cryptographic proofs of
     achievement. Originally created by Mozilla, the specification is now
     maintained by `IMS Global Learning Consortium`_.

     .. _IMS Global Learning Consortium: https://www.imsglobal.org/

     .. seealso:: * https://www.imsglobal.org/activity/digital-badges
                  * https://en.wikipedia.org/wiki/Mozilla_Open_Badges

   Assertion
     An OpenBadges Assertion is a JSON document that describes a badge award:
     who earned it, when, under what criteria, and how to verify the issuer's
     signature. In OpenBadges 2.0 signed badges, the assertion is serialised
     as a :term:`JWS` token and embedded inside the badge image.

     .. seealso:: https://www.imsglobal.org/sites/default/files/Badges/OBv2p0Final/index.html#Assertion

   JWS
     JSON Web Signature (JWS) is a standard (RFC 7515) for representing
     content secured with digital signatures using JSON-based data structures.
     OpenBadgesLib uses the compact serialisation format:
     ``BASE64URL(header).BASE64URL(payload).BASE64URL(signature)``.

     .. seealso:: https://datatracker.ietf.org/doc/html/rfc7515

   JWT
     JSON Web Token (JWT) is an application of :term:`JWS` where the payload
     is a JSON object containing a set of claims (RFC 7519). PyJWT implements
     the signing and verification algorithms used by this library.

     .. seealso:: https://datatracker.ietf.org/doc/html/rfc7519

   JWT-VC
     A JSON Web Token used as a `W3C Verifiable Credential`_ proof format.
     The JWT payload carries standard claims (``iss``, ``sub``, ``jti``,
     ``iat``, ``exp``) plus a ``vc`` claim containing the full Verifiable
     Credential object. OpenBadges 3.0 uses JWT-VC to sign
     ``OpenBadgeCredential`` documents.

     .. _W3C Verifiable Credential: https://www.w3.org/TR/vc-data-model/

     .. seealso:: https://www.w3.org/TR/vc-data-model/#json-web-token

   RSA
     A widely used public-key cryptosystem. This library uses RSA 2048-bit
     keys with PKCS#1 v1.5 padding and SHA-256 (algorithm identifier RS256).

     .. seealso:: https://en.wikipedia.org/wiki/RSA_(cryptosystem)

   ECC
     Elliptic Curve Cryptography. This library uses the NIST P-256 curve with
     ECDSA and SHA-256 (algorithm identifier ES256).

     .. seealso:: https://en.wikipedia.org/wiki/Elliptic_curve_cryptography

   Metadata
     Data embedded in a file that describes the file's content. In OpenBadges,
     the :term:`Assertion` is metadata embedded in the badge image.

     .. seealso:: https://en.wikipedia.org/wiki/Metadata

   pycryptodome
     A self-contained Python package of low-level cryptographic primitives,
     a maintained fork of the abandoned ``pycrypto`` package. Used by this
     library for RSA and ECC key generation and PEM serialisation.

     .. seealso:: https://pycryptodome.readthedocs.io/

   ecdsa
     A pure-Python implementation of ECDSA cryptography. Used by this library
     for ECC key generation, loading, and PEM serialisation.

     .. seealso:: https://pypi.org/project/ecdsa/

   PyJWT
     A Python library for encoding and decoding JSON Web Tokens (JWT / JWS).
     OpenBadgesLib uses ``jwt.algorithms.RSAAlgorithm`` and
     ``jwt.algorithms.ECAlgorithm`` for JWS signing and verification.
     Requires the ``cryptography`` package (installed via ``PyJWT[crypto]``).

     .. seealso:: https://pyjwt.readthedocs.io/

   pypng
     A pure-Python library for reading and writing PNG image files.

     .. seealso:: https://pypi.org/project/pypng/

   LGPL3
     The GNU Lesser General Public License, version 3 (LGPLv3). The
     OpenBadgesLib core library is released under this licence.

     .. seealso:: https://opensource.org/licenses/lgpl-3.0.html

   BSD 2-Clause
     The BSD 2-Clause License. The OpenBadgesLib command-line wrapper tools
     are released under this licence.

     .. seealso:: https://opensource.org/licenses/BSD-2-Clause

   Apache
     Open-source HTTP server.

     .. seealso:: https://httpd.apache.org/

   Nginx
     A lightweight HTTP server and reverse proxy.

     .. seealso:: https://nginx.org/

   IIS
     Internet Information Services, the web server bundled with Microsoft
     Windows Server.

     .. seealso:: https://www.iis.net/

   PEP8
     PEP 8 — Style Guide for Python Code. Defines the coding conventions
     followed by this project.

     .. seealso:: https://peps.python.org/pep-0008/
