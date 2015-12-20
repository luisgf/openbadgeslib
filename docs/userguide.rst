User Guide
==========

First Steps
-----------

After library installation the next step to follow is the creation of a new key pair or importing existing one. This step is 
mandatory if you want to sign badges. The keys will be stored in the folder specified in config.ini, please protect this. 

.. warning::
  In case of private key lost, no new badge can be signed and ever worse for the public key, if public key was lost no badge verification can happen.

**Please, backup your keys.**

Generating a Key pair
---------------------

A key pair consist in a pair of files containing private and public key information. The key pair is mandatory for do 
cryptographic operations.

To generate one you can use **openbadges_keygenerator** wrapper passing the path to config.ini file and the badge id.

.. code-block:: sh

   $ openbadges-keygenerator -c ./config/config.ini -g 1
   INFO - Generating key pair for issuer 'OpenBadge issuer'
   INFO - Private key saved at: /openbadges/config/keys/sign_rsa_key_1.pem
   INFO - Public key saved at: /openbadges/config/keys/verify_rsa_key_1.pem
   $ 

.. note:: Generated RSA keys has a length of 2048 bits, and ECC keys has a curve type NIST-256p.

.. warning::
            ECC DISCLAIMER!
            The implementation of ECC in JWS Draft is not clear about the signature/verification process and may lead to 
            problems for you and others when verifying your badges.
                    
            See this: https://github.com/mozilla/openbadges-validator/issues/30
            


Signing a Badge
---------------

The badge signing process will take an input file (:term:`SVG` or :term:`PNG`) and an Identity (E-Mail address) to embed 
cryptographic :term:`Metadata` information inside the file, this metadata are called an :term:`Assertion`. 

The badge :term:`Assertion` can point to a proof of the earned, we call this an **Evidence**. The badge can be issued 
with an **expiration date** too.

.. code-block:: sh

   $ openbadges-signer -c ../conf/config.ini -b 1 -r luisXXX@lXXXX.es -e https://openbadges.luisgf.es -o /tmp/
   2015-03-11T11:47:09.289954 badge_1 SIGNED for luisXXX@lXXXX.es UID 73f8981f125ffc060b43847728c0bddcbb8e24f4 at: 
   /tmp/badge_1_luisXXX@lXXXX.es.svg
   
Verifying a Badge
-----------------

This :term:`Assertion` can be validated with the **openbadges-verifier** tool in order to check if the badge is 
valid or has been tampered. The verification process involve many operations like :term:`Assertion` extraction, download the 
badge public key and identity check. But fortunatelly all this can be done with one command:

.. code-block:: sh

  $ openbadges-verifier -i /tmp/badge_1_luisXXX\@lXXXX.es.svg -r luisXXX@lXXXX.es
  [+] This is the assertion content:
  {
    "badge": "https://openbadges.luisgf.es/issuer/badge_1/badge.json",
    "evidence": "https://openbadges.luisgf.es",
    "image": "https://openbadges.luisgf.es/issuer/badge_1/badge.svg",
    "issuedOn": 1426070829,
    "recipient": {
        "hashed": "true",
        "identity": "sha256$c608eb996ba46122d2b4319feee34f8eaf39fcffde8aff3155b4597260115849",
        "salt": "fc6bc3efc050ded1b6f4b686347ad903",
        "type": "email"
    },
    "uid": "73f8981f125ffc060b43847728c0bddcbb8e24f4",
    "verify": {
        "type": "signed",
        "url": "https://openbadges.luisgf.es/issuer/badge_1/verify_rsa_key.pem"
    }
  } 
  [+] Signature is correct for the identity luisXXX@lXXXX.es
  
  
  

