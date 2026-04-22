Development
===========

This section covers the conventions and tooling used by the project.


Style guide
-----------

Code follows `PEP 8`_ conventions. Contributions should pass a PEP 8 linter
before being submitted.

.. _PEP 8: https://peps.python.org/pep-0008/


Source code
-----------

The canonical repository is on GitHub:

    https://github.com/luisgf/openbadgeslib

Active development happens on feature branches; finished work is merged
into ``master``. Feature branches used for 1.0.1:
``feature/python312-update`` (Python 3.10+ modernisation),
``feature/ob3-support`` (OB3 subpackage),
``feature/ob2-refactor`` (OB2 subpackage + CLI ``--ob-version`` flag).


Running the test suite
----------------------

Tests use `pytest`_. From the project root:

.. code-block:: sh

    # Run all tests
    pytest

    # With coverage report
    pytest --cov=openbadgeslib --cov-report=term-missing

    # Stop at first failure
    pytest -x

.. _pytest: https://docs.pytest.org/

Test files live in the ``tests/`` directory. Shared fixtures (key material,
badge objects, signed badges) are defined in ``tests/conftest.py`` and are
session-scoped for performance. Fixtures used by tests that mutate badge
state are function-scoped to prevent cross-test contamination.


Project layout
--------------

::

    openbadgeslib/
        __init__.py          unified public API (OB2 + OB3 + shared keys/util)
        badge.py             backward-compat shim → ob2.badge
        signer.py            backward-compat shim → ob2.signer
        verifier.py          backward-compat shim → ob2.verifier
        confparser.py        INI config file reader
        errors.py            custom exception hierarchy
        keys.py              KeyRSA, KeyECC, KeyFactory, detect_key_type
        util.py              hash helpers, download_file, __version__
        _jws/
            __init__.py      sign() and verify_block() backed by PyJWT
            exceptions.py    SignatureError, MissingKey, RouteMissingError, …
            utils.py         base64url and JSON helpers
        ob2/
            __init__.py      public API: Badge, BadgeSigned, Assertion,
                             Signer, Verifier, VerifyInfo, BadgeStatus, …
            badge.py         Badge, BadgeSigned, Assertion data classes (OB 2.0)
            signer.py        Signer — embeds JWS assertion in SVG/PNG
            verifier.py      Verifier, VerifyInfo — extracts and validates assertion
        ob3/
            __init__.py      public API: Achievement, Issuer, OpenBadgeCredential,
                             OB3Signer, OB3Verifier, OB3VerificationError
            credential.py    W3C VC data model: Issuer, Achievement,
                             OpenBadgeCredential (to_vc, to_jwt_payload,
                             from_jwt_payload)
            signer.py        OB3Signer — JWT-VC signing + SVG/PNG baking
            verifier.py      OB3Verifier — JWT-VC verification + token extraction
        openbadges_init.py        CLI: openbadges-init
        openbadges_keygenerator.py CLI: openbadges-keygenerator (-V flag)
        openbadges_signer.py       CLI: openbadges-signer (-V flag)
        openbadges_verifier.py     CLI: openbadges-verifier (-V flag, -k flag)
        openbadges_publish.py      CLI: openbadges-publish (-V flag)

    tests/
        conftest.py               shared pytest fixtures (OB 2.0 + OB 3.0)
        test_badge_io.py          Assertion encode/decode, SVG/PNG extraction
        test_jws.py               _jws sign/verify_block round-trips and edges
        test_key_operation.py     key generation, read/export, detect_key_type
        test_signer_operation.py  sign + has_assertion tests
        test_util.py              hash functions, download_file
        test_verify_operation.py  signature, identity, expiry, status
        test_ob3_credential.py    Issuer, Achievement, OpenBadgeCredential
                                  (to_vc, to_jwt_payload, from_jwt_payload)
        test_ob3_signer.py        OB3Signer construction, sign(), sign_into_svg/png()
        test_ob3_verifier.py      OB3Verifier verify(), extract_token_from_svg/png(),
                                  end-to-end RSA/ECC roundtrips


Architecture notes
------------------

**ob2/ subpackage and shims** — The OB2 implementation lives in
``openbadgeslib/ob2/``. The top-level ``badge.py``, ``signer.py``, and
``verifier.py`` are one-line re-export shims that preserve backward
compatibility: ``from openbadgeslib.badge import Badge`` continues to work
without modification. New code should prefer ``from openbadgeslib.ob2 import …``.

**JWS engine** — ``openbadgeslib/_jws/__init__.py`` is a thin shim around
``jwt.algorithms.RSAAlgorithm`` and ``jwt.algorithms.ECAlgorithm`` from
`PyJWT`_. Key objects (pycryptodome ``RsaKey``, ecdsa ``SigningKey`` /
``VerifyingKey``) are converted to PEM bytes before being handed to PyJWT's
``prepare_key()`` so that the ``cryptography`` package handles all low-level
crypto. The public interface — ``sign(header_dict, payload_dict, key)`` and
``verify_block(jws_bytes, key)`` — has not changed since v0.4.

.. _PyJWT: https://pyjwt.readthedocs.io/

**OpenBadges 3.0 (ob3/)** — ``OB3Signer`` wraps ``jwt.encode`` from PyJWT to
produce a JWT-VC string. ``OB3Verifier`` calls ``jwt.decode`` with
``verify_aud=False`` (OB3 credentials do not carry an ``aud`` claim). Both
SVG and PNG baking reuse the same embedding format as OB 2.0 (``<openbadges:assertion
verify="…"/>`` and ``iTXt openbadges``), so OB 2.0 and OB 3.0 badges are
distinguished by the presence of a ``vc`` claim in the decoded JWT payload.
``jwt.exceptions.InvalidKeyError`` is caught separately from
``InvalidTokenError`` because it is not a subclass of it in PyJWT ≥ 2.8.

**PNG embedding** — The JWS/JWT token is stored in an ``iTXt`` chunk with the
keyword ``openbadges``. Chunk tags in newer versions of ``pypng`` are
returned as ``bytes``; the library handles both ``str`` and ``bytes`` tags.

**Key persistence** — RSA keys are stored as PKCS#1 PEM files (``BEGIN RSA
PRIVATE KEY`` / ``BEGIN PUBLIC KEY``). ECC keys are stored in SEC1 / SubjectPublicKeyInfo PEM format (``BEGIN EC PRIVATE KEY`` / ``BEGIN PUBLIC KEY``).
``detect_key_type()`` in ``keys.py`` probes the PEM data with both
pycryptodome and ecdsa parsers to identify the key type automatically.


Building the documentation
--------------------------

The docs use `Sphinx`_ with the ``sphinx_rtd_theme``:

.. code-block:: sh

    pip install sphinx sphinx-rtd-theme
    sphinx-build -b html docs/ docs/_build/html/

.. _Sphinx: https://www.sphinx-doc.org/


Contributing
------------

1. Fork the repository on GitHub.
2. Create a feature branch: ``git checkout -b feature/my-change``
3. Write tests for your change.
4. Ensure ``pytest`` passes with no regressions.
5. Submit a pull request against ``master``.
