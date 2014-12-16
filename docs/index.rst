.. title: OpenBadges Lib
.. slug: index
.. date: 2014-12-10 16:04:55 UTC+01:00
.. tags: openbadgeslib, dev
.. link:
.. description: OpenBadges library documentation
.. type: text
.. nocomments: True

==================
OpenBadges Library
==================

This library implements the Mozilla OpenBadges specification and it's able to do the signature of a SVG file and its verification using RSA or ECC keys.

The current project package can be found in `Pypi`_ repository.

- A library
- A configuration file
- Wrappers tools around the library

The library and tools are written in Python and it required a **Python >= 3.4** version to work.

Development
-----------

The development process can be follow in the official `Mercurial repository`_.


Dependencies
------------

- ecdsa
- pycrypto

License
-------

This library is licensed under the terms of the `LGPL3`_ and the wrapper tools under the terms of `BSD 2-clause`_ license.
That's let you the freedom to do that you need with both. 

Authors
-------

Sorted alphabetically:

* Jesús Cea Avión         <jcea@jcea.es>
* Luis González Fernández <luisgf@luisgf.es>



Installation
------------

The library and tools can run inside a virtualenv environment and this is the recommended practice, but if you like to install in the main python library, you can do that.

The library is installed via pip with the following command line:

::
    
    $ pip install openbadgeslib

Upgrade
-------
If a new version of the library is available, you can upgrade to the lastest version with the following command:

::

    $ pip install opnebadgeslib --upgrade

Below commands will install the software and all the needed dependencies.

Post-Installation
-----------------

After the pip installation, the setup process should have created 4 wrapper programs in the binary folder (/usr/bin in UNIX or /virtualenv_folder/bin if you use a virtualenv):

Wrapper tools
-------------

The library comes with three tools that implement the following facilities:

- **openbadges-init**          Create a base config.ini example.
- **openbadges-keygenerator**  Allow the user to create a new pair.
- **openbadges-signer**        Allow the user to sign a SVG badge with or without evidence
- **openbadges-verifier**      Allow the user to verify the badge signature against a local key or with the embedded key in the assertion (remote verification).

A help description is available in all tools, to show simply pass the **parameter -h**. Example:
::

  luisgf:~$ ./openbadges-keygenerator -h

  usage: openbadges-keygenerator [-h] [-c CONFIG] [-g] [-v]

  Key Generation Parameters

  optional arguments:
    -h, --help            show this help message and exit
    -c CONFIG, --config CONFIG
                          Specify the config.ini file to use
    -g, --genkey          Generate a new Key pair. Key type is taken from
                          profile.
    -v, --version         show program's version number and exit


You need to tune some things in order to start signing badges. The first thing should be run openbadges-init, that will generate a default config.ini skel in your current directory, this file need further tunning before using it.

The configuration file that openbadges-init was generated should look like that:

::

  ;
  ; OpenBadges Lib configuration example for RSA keys.
  ;

  ; Paths to the keys and log
  [paths]
  base         = .
  base_key     = ${base}/keys
  base_log     = ${base}/log
  base_image   = ${base}/images

  ; Log configuration. Stored in ${base_log}
  [logs]
  general = general.log
  signer  = signer.log

  ;Key configuration. Stored in ${base_key}
  [keys]
  private   = ${paths:base_key}/sign_rsa_key.pem
  public    = ${paths:base_key}/verify_rsa_key.pem

  ; Configuration of the OpenBadges issuer.
  [issuer]
  name           = OpenBadge issuer
  url            = https://www.domain.com
  image          = issuer_logo.png
  email          = issuer_mail@domain.com
  publish_url    = https://openbadges.domain.com/issuer/
  revocationList = revoked.json

  ;Badge configuration sections.
  [badge_1]
  name        = Badge 1
  description = Given to any user that install this library
  local_image = image_badge1.svg
  image	      = https://www.domain.com/badge_1/badge.svg
  criteria    = https://www.domain.com/badge_1/criteria.html
  verify_key  = https://www.domain.com/issuer/badge_1/verify_rsa_key.pem
  badge       = https://www.domain.com/badge_1/badge.json
  ;alignement  =
  ;tags        =

  [badge_2]
  name        = Badge 2
  description = Given to any user that promote the usage of this library
  local_image = image_badge2.svg
  image       = https://www.domain.com/badge_2/badge.svg
  criteria    = https://www.domain.com/issuer/badge_2/criteria.html
  verify_key  = https://www.domain.com/issuer/badge_2/verify_rsa_key.pem
  badge       = https://www.domain.com/badge_2/badge.json
  ;alignement =
  ;tags       =

First Steps
-----------

After library installation the next step to follow is the creation of a new key pair or importing existing one. This step is mandatory if you want to sign badges. The keys will be stored in the folder specified in config.ini, please protect this. In case of private key lost, no new badge can be signed and ever worse for the public key, if public key was lost no badge verification can happen. 

**Please, backup your keys**.

Key Pair Generation
-------------------

A new keypair can be generated with openbadges-keygenerator with **parameter -g**. This program will create two files in "keys" folder representing both private and public keys. If the keys type selected is RSA the program will create a fixed **RSA 2048 bits**, if key type selected is ECC the key curve is fixed to **NIST256p**. 


Badge Signing
-------------

The badge signing process will take an input file (SVG only for now) to embed a signature inside. This signature can be validated with the openbadges-verifier tool in order to check if the badge is valid or has been tampered.

Badge Verification
------------------

The badge verification process consist in the lecture of the assertion embedded to check that has not been altered and validate that the same has been emitted for a given user.

The verification can be make in two forms. If you are the issuer, you can use your public key and make a local verification but if you try to verify the rest of badges, the verifier will download the appropriate key reading the file assertion.


.. _Pypi: https://pypi.python.org/pypi/openbadgeslib/
.. _Mercurial repository: https://hg.luisgf.es/openbadges/
.. _LGPL3: https://www.gnu.org/licenses/lgpl.html
.. _BSD 2-clause: http://en.wikipedia.org/wiki/BSD_licenses#2-clause_license_.28.22Simplified_BSD_License.22_or_.22FreeBSD_License.22.29 

