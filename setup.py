#!/usr/bin/env python3

from distutils.core import setup

version = '0.4'

dependencies = [
        'ecdsa',
        'pycrypto',
        'pypng'
        ]

setup(
  name = 'openbadgeslib',
  packages = ['openbadgeslib'], # this must be the same as the name above
  version = version,
  description = 'A library to sign and verify OpenBadges',
  long_description = ('A library to sign and verify OpenBadges. If you need more info, here is our '
  '`Homepage <https://openbadges.luisgf.es/>`_ and the '
  '`contact email <openbadges@luisgf.es>`_.'
  ),
  author = 'Luis González Fernández, Jesús Cea Avión',
  author_email = 'luisgf@luisgf.es, jcea@jcea.es',
  url = 'https://openbadges.luisgf.es/',
  keywords = ['openbadges'], # arbitrary keywords
  classifiers = [
      'Development Status :: 3 - Alpha',
      'Intended Audience :: Developers',
      'Operating System :: OS Independent',
      'Programming Language :: Python :: 3.4',
      'Topic :: Software Development :: Libraries :: Python Modules',
      'Natural Language :: English',
      'Natural Language :: Spanish',
      'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)'
  ],
  license = 'LGPLv3',
  install_requires = dependencies,
  include_package_data = True,
  entry_points = {
    'console_scripts': [
        'openbadges-init = openbadgeslib.openbadges_init:main',
        'openbadges-keygenerator = openbadgeslib.openbadges_keygenerator:main',
        'openbadges-signer = openbadgeslib.openbadges_signer:main',
        'openbadges-verifier = openbadgeslib.openbadges_verifier:main',
        'openbadges-publish = openbadgeslib.openbadges_publish:main'
        ]
    }
)

