Installation
============

The library and tools can run inside a virtualenv environment and this is the recommended practice, but if you like to install in the main python library, you can do that.

Dependencies
------------

This project only run under Python 3, then a runtime of version >= 3.4 is needed. The project has some external dependencies 
that can be installed via pip.

Requirements:

 * Web server (:term:`Apache`, :term:`Nginx` or :term:`IIS`)
 * SSL Certificate
 * :term:`Python` 3.4 or superior
 * :term:`ecdsa`
 * :term:`pycrypto`
 * :term:`pypng`


The library is installed via pip with the following command line:

::
    
    $ pip install openbadgeslib

.. note::
    
    All external dependencies are installed automatically during library installation.


Upgrade
-------
If a new version of the library is available, you can upgrade to the lastest version with the following command:

::

    $ pip install openbadgeslib --upgrade

Below commands will install the software and all the needed dependencies.

Post-Installation
-----------------

After the pip installation, the setup process should have created 4 wrapper programs in the binary folder (/usr/bin in UNIX or /virtualenv_folder/bin if you use a virtualenv)

**openbadges-init** is the first command that you must run. This program will create the initial data that the library need, 
that is: a sample config and a directory structure to store both keys and logs.

.. code-block:: sh

   $ openbadges-init ./config/
   $ ls -l ./config/
   total 4
   -rw-rw-r-- 1 luisgf luisgf 1860 mar 11 09:55 config.ini
   drwx------ 1 luisgf luisgf    0 mar 11 09:55 images
   drwx------ 1 luisgf luisgf    0 mar 11 09:55 keys
   drwx------ 1 luisgf luisgf    0 mar 11 09:55 log
   

Sample config.ini
-----------------

In order to run the tools a config.ini file must be generated. This config file has the information about the issuer, 
badges, keys and logs that the library need to run.

Example:

::

  ;
  ; OpenBadges Lib configuration example.
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

  ; SMTP Configuration
  smtp_server = localhost
  smtp_port = 25
  use_ssl = False
  mail_from = no-reply@issuer.badge
  ; Uncomment this if your SMTP server needs authentication
  ;login =
  ;password =
  
  ; Configuration of the OpenBadges issuer.
  [issuer]
  name           = OpenBadge issuer
  url            = https://www.domain.com
  image          = issuer_logo.png
  email          = issuer_mail@domain.com
  publish_url    = https://openbadges.domain.com/issuer/
  revocationList = revocation.json

  ;Badge configuration sections.
  [badge_1]
  name        = Badge 1
  description = Given to any user that install this library
  local_image = image_badge1.svg
  image	      = https://www.domain.com/badge_1/badge.svg
  criteria    = https://www.domain.com/badge_1/criteria.html
  verify_key  = https://www.domain.com/issuer/badge_1/verify_rsa_key.pem
  badge       = https://www.domain.com/badge_1/badge.json
  private_key = ${paths:base_key}/sign_rsa_key_1.pem
  public_key  = ${paths:base_key}/verify_rsa_key_1.pem
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
  private_key = ${paths:base_key}/sign_rsa_key_2.pem
  public_key  = ${paths:base_key}/verify_rsa_key_2.pem
  ;alignement =
  ;tags       =

Wrapper tools
-------------

The library comes with three tools that implement the following facilities:

- **openbadges-init**          Create a base config.ini example.
- **openbadges-keygenerator**  Allow the user to create a new pair.
- **openbadges-signer**        Allow the user to sign a SVG badge with or without evidence
- **openbadges-verifier**      Allow the user to verify the badge signature against a local key or with the embedded key in the assertion (remote verification).
- **openbadges-publish**       Create the structure necessary to publish in a web server.

