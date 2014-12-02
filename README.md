==================
Openbadges Library
==================

This library implements the Mozilla OpenBadges specification and it's able to do the signature of a SVG file and its verification using RSA or ECC keys.

The current project version is **0.1** and is composed of three components:

 - A library
 - A config file
 - Wrappers tools around the library

The library and tools are written in python and works on **Python >= 3.4**. Running the library under Python 2.7 may work now but is not officially supported.

Dependencies
------------

The program use the following python internal modules:

 - hashlib
 - json
 - time
 - os
 - sys
 - xml.dom.minidom
 - ssl
 - urllib

And the following python external modules:

 - ecdsa
 - pycrypto
 - python-jws

License
-------

This project use LGPL (v3) license for the library and a BSD 2-clause license for the wrapper tools.
That's let you the freedom to do that you need with both.A copy of both licenses can be found in the “documents” folder of the project.

Author
------

The author of the library is Luis Gonzalez Fernandez and can be contacted in a address created specially for the project: openbadges@luisgf.es


Installation
------------

This program can be run inside a virtualenv environment and this is the recommended practice, but if you like to install in the main python library, you can do that.

The library is installed via pip and can be installed with the following command line:

::

     $ pip install openbadgeslib


That's will install the library and all the dependencies needed by the project.

Post-Installation
-----------------

After the library installation, the setup  process will create 3 wrapper programs in the binary folder (/usr/bin in UNIX or /virtualenv_folder/bin if you use a virtualenv):

- **openbadges_keygenerator.py**
- **openbadges_signer.py**
- **openbadges_verifier.py**


After the library installation you need to tune some things in order to start signing badges. The first thing that you need do is adjust the config.
There are a config.py in the library installation path, but here you have an example that you can use:

::

  """
        OpenBadges Library

        Copyright (c) 2014, Luis Gonzalez Fernandez, All rights reserved.

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
  """ 
    Please, don't enable this if you are not completly sure 
    that your are doing.
    
    Setting PLEASE_ENABLE_ECC to True makes the program able
    to use Elliptic Curve cryptography rather that RSA.
    
    JWS draft are not clear with ECC, don't use 
    in production systems, use at your own risk!
  """
  PLEASE_ENABLE_ECC = False
    
  """ Log signed badges in this file """
  sign_log = './openbadges-ecc_sign.log'

  """ Configuration of RSA Keys """
  rsa_keypair = dict(   
                    crypto    = 'RSA',
                    size      = 2048,
                    hash_algo = 'SHA256',
                    private = './private/test_sign_rsa.pem',
                    public  = './public/test_verify_rsa.pem'
                )

  """ Issuer Configuration """
  issuer_luisgf = dict(
    name = 'Badge Issuer',
    image = 'https://openbadges.luisgf.es/issuer/logo.png',
    url = 'https://www.luisgf.es',
    email = 'openbadges@luisgf.es',
    revocationList = 'https://openbadges.luisgf.es/issuer/revocation.json'
  )

  """ Badge Entry """
  badge_testrsa = dict(
                name = 'BadgeName',
                description = 'Badge Test signed with and RSA Key',
                image = 'https://openbadges.luisgf.es/issuer/badges/badge.svg',
                criteria = 'https://openbadges.luisgf.es/issuer/criteria.html',
                issuer = 'https://openbadges.luisgf.es/issuer/organization.json',
                json_url = 'https://openbadges.luisgf.es/issuer/badge-luisgf.json',
                evidence = 'https://openbadges.luisgf.es/evidence.html',
                url_key_verif = 'https://openbadges.luisgf.es/issuer/pubkeys/test_verify_rsa.pem',
                local_badge_path = './images/badge.svg'
            )

  """ Profile Composition. Here you can configure your settings per profile """
  profiles = {
        'RSA_PROFILE': { 'issuer':issuer_luisgf, 'badges':[badge_testrsa], 'keys':rsa_keypair, 'signedlog':sign_log }
  }

You need to copy this to file named **config.py** to a folder with read-writte permissions that the wrappers tools need to store some data like the keys and log. The wrapper tools will read this config.py from the **current folder**.

The next step, after library installation is the creation of a new keypair or importing existings one. This step is mandatory if you like to start signing badges.

Wrapper tools
-------------

The library comes with three tools that's exploit the library facilities:

 - **openbadges_keygenerator.py**  Let's the user create a new pair of RSA (2048) or ECC (NIST256p) keys.                                                                     
 - **openbadges_signer.py**        Let's the user sign a SVG badge with or without evidence
 - **openbadges_verifier.py**      Let's the user verifier the badge signature against a local key or with thekey embedded in the assertion (remote verification).                        

Library Usage
-------------

Below this you can found some code snippets that show you how to use the library.


Key Generation
==============
::

  (venv-openbadges)luisgf@NCC1701B:~/venv-openbadges/etc$ python3
  Python 3.4.0 (default, Apr 11 2014, 13:05:11) 
  [GCC 4.8.2] on linux
  Type "help", "copyright", "credits" or "license" for more information.
  >>> import openbadgeslib
  >>> from config import profiles
  >>> config = profiles['RSA_PROFILE']   # Select the profile from the config
  >>> key_factory = openbadgeslib.KeyFactory(config)
  >>> key_factory.generate_keypair()
  [+] RSA(2048) Private Key generated at ./private/test_sign_rsa.pem
  [+] RSA(2048) Public Key generated at ./public/test_verify_rsa.pem
  True
  >>> 

Signing a Badge
===============
::

  (venv-openbadges)luisgf@NCC1701B:~/venv-openbadges/etc$ python3
  Python 3.4.0 (default, Apr 11 2014, 13:05:11) 
  [GCC 4.8.2] on linux
  Type "help", "copyright", "credits" or "license" for more information.
  >>> import openbadgeslib
  >>> from config import profiles
  >>> config = profiles['RSA_PROFILE']
  >>> sign_factory = openbadgeslib.SignerFactory(config, 'Badge RSA', 'email@domain.es')
  >>> sign_factory.sign_svg_file('/tmp/badge_signed.svg')
  True
  >>>

Signing a badge with a user evidence
====================================
::

  Python 3.4.0 (default, Apr 11 2014, 13:05:11) 
  [GCC 4.8.2] on linux
  Type "help", "copyright", "credits" or "license" for more information.
  >>> import openbadgeslib
  >>> from config import profiles
  >>> config = profiles['RSA_PROFILE']
  >>> sign_factory = openbadgeslib.SignerFactory(config, 'Badge RSA', 'email@domain.es', evidence='https://www.luisgf.es/')
  >>> sign_factory.sign_svg_file('/tmp/badge_signed.svg')
  True
  >>> 

Verifying a badge with the key embedded in assertion
====================================================
::

  (venv-openbadges)luisgf@NCC1701B:~/venv-openbadges/etc$ python3
  Python 3.4.0 (default, Apr 11 2014, 13:05:11) 
  [GCC 4.8.2] on linux
  Type "help", "copyright", "credits" or "license" for more information.
  >>> import openbadgeslib
  >>> from config import profiles
  >>> config = profiles['RSA_PROFILE']
  >>> verify_factory = openbadgeslib.VerifyFactory(config)
  >>> if verify_factory.is_svg_signature_valid('/tmp/badge_signed.svg', 'email@domain.es'):
  ...    print('Signature Correct')
  ... else:
  ...    print('Signature Incorrect')
  ... 
  [+] The public key is in a server with TLS support. Good! https://openbadges.luisgf.es/issuer/pubkeys/test_verify_rsa.pem
  [+] This is the assertion content:
  {
    "badge": "https://openbadges.luisgf.es/issuer/badge-luisgf.json",
    "evidence": "https://www.luisgf.es/",
    "image": "https://openbadges.luisgf.es/issuer/badges/badge.svg",
    "issuedOn": 1417510230,
    "recipient": {
        "hashed": "true",
        "identity": "sha256$a11c1f2d3944df28e213cb7bf161890d9c600cc1fd54d0e0793917caa3f1c272",
        "type": "email"
    },
    "uid": "baba3a1428cf4bba4ca75da0a633a6a5465839bf",
    "verify": {
        "type": "signed",
        "url": "https://openbadges.luisgf.es/issuer/pubkeys/test_verify_rsa.pem"
    }
  }
  [+] Using an RSA Key of 2047 bits size
  Signature Correct
  >>>

Verify a badge using the local public key
=========================================
::

  (venv-openbadges)luisgf@NCC1701B:~/venv-openbadges/etc$ python3
  Python 3.4.0 (default, Apr 11 2014, 13:05:11) 
  [GCC 4.8.2] on linux
  Type "help", "copyright", "credits" or "license" for more information.
  >>> import openbadgeslib
  >>> from config import profiles
  >>> config = profiles['RSA_PROFILE']
  >>> verify_factory = openbadgeslib.VerifyFactory(config)
  >>> if verify_factory.is_svg_signature_valid('/tmp/badge_signed.svg', 'email@domain.es', local_verification=True):
  ...    print('Signature Correct')
  ... else:
  ...    print('Signature Incorrect')
  ... 
  [+] Using an RSA Key of 2047 bits size
  Signature Correct
  >>> 
