Installation
============

The library can be installed inside a virtual environment (recommended) or
into the system Python. Using a virtual environment keeps dependencies
isolated and avoids conflicts with other packages.


Requirements
------------

* **Python >= 3.10** (tested on 3.10, 3.11, 3.12, and 3.14)
* A web server (:term:`Apache`, :term:`Nginx`, or :term:`IIS`) and a valid
  TLS certificate if you intend to publish badge metadata online

Python package dependencies (installed automatically via pip):

* :term:`pycryptodome` >= 3.20 — RSA key generation and PEM handling
* :term:`ecdsa` >= 0.19 — ECC key generation and PEM handling
* :term:`pypng` >= 0.20220715.0 — PNG image manipulation
* :term:`PyJWT` [crypto] >= 2.8 — :term:`JWS` signing and verification
  (pulls in the ``cryptography`` package as a transitive dependency)


Install from PyPI
-----------------

::

    pip install openbadgeslib

All dependencies are resolved and installed automatically.


Install in a virtual environment
---------------------------------

.. code-block:: sh

    python -m venv venv
    source venv/bin/activate        # Windows: venv\Scripts\activate
    pip install openbadgeslib


Upgrade
-------

::

    pip install openbadgeslib --upgrade


Development install
-------------------

Clone the repository and install in editable mode together with the test
dependencies:

.. code-block:: sh

    git clone https://github.com/luisgf/openbadgeslib.git
    cd openbadgeslib
    pip install -e ".[dev]"

The ``[dev]`` extra installs ``pytest`` and ``pytest-cov``.


Post-installation: CLI tools
-----------------------------

After installation, five command-line tools are available in the active
Python environment's ``bin/`` directory (``Scripts/`` on Windows):

``openbadges-init``
    The first command to run. Creates a sample ``config.ini`` and the
    directory structure the library needs (``keys/``, ``images/``,
    ``log/``).

    .. code-block:: sh

        $ openbadges-init ./config/
        $ ls -l ./config/
        -rw-rw-r--  config.ini
        drwx------  images/
        drwx------  keys/
        drwx------  log/

``openbadges-keygenerator``
    Generates an RSA or ECC key pair for a badge section defined in
    ``config.ini``.

``openbadges-signer``
    Signs a badge image (SVG or PNG) for a given recipient email address.

``openbadges-verifier``
    Extracts and verifies the :term:`Assertion` embedded in a signed badge.

``openbadges-publish``
    Creates the directory structure required to publish badge metadata on a
    web server.


Sample config.ini
-----------------

``openbadges-init`` generates a template. The key sections are:

.. code-block:: ini

    ; Paths
    [paths]
    base         = .
    base_key     = ${base}/keys
    base_log     = ${base}/log
    base_image   = ${base}/images

    ; Log files
    [logs]
    general = general.log
    signer  = signer.log

    ; Issuer information
    [issuer]
    name           = My Organisation
    url            = https://badges.example.com
    image          = logo.png
    email          = badges@example.com
    publish_url    = https://badges.example.com/issuer/
    revocationList = revocation.json

    ; A badge definition (repeat for each badge)
    [badge_1]
    name        = Participation Badge
    description = Awarded for participating in the workshop
    local_image = badge1.svg
    image       = https://badges.example.com/badge_1/badge.svg
    criteria    = https://badges.example.com/badge_1/criteria.html
    verify_key  = https://badges.example.com/issuer/verify_rsa_key.pem
    badge       = https://badges.example.com/badge_1/badge.json
    private_key = ${paths:base_key}/sign_rsa_key_1.pem
    public_key  = ${paths:base_key}/verify_rsa_key_1.pem

.. note::

    The ``verify_key`` URL must be publicly accessible for badge verification
    to work. The file at that URL should contain the PEM-encoded public key
    that corresponds to the private key used for signing.
