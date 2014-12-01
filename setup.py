 
from distutils.core import setup

with open('requirements.txt', 'r') as fh: 
    dependencies = [l.strip() for l in fh] 

setup(
  name = 'openbadgeslib',
  packages = ['openbadgeslib'], # this must be the same as the name above
  version = '0.1',
  description = 'A library to sign and verify OpenBadges',
  author = 'Luis Gonzalez Fernandez',
  author_email = 'openbadges@luisgf.es',
  url = 'https://openbadges.luisgf.es/', # use the URL to the github repo
  download_url = 'https://hg.luisgf.es/tarball/0.1/', # I'll explain this in a second
  keywords = ['openbadges'], # arbitrary keywords
  classifiers = [
      'Development Status :: 3 - Alpha',
      'Intended Audience :: Developers',
      'Operating System :: OS Independent',
      'Programming Language :: Python :: 3.4',
      'Topic :: Software Development :: Libraries :: Python Modules',
      'Natural Language :: English',
      'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)'
  ],
  license='LGPLv3',
  requires=['urllib','hashlib','ssl','xml','json','time','sys','os'],
  install_requires=dependencies,
  package_dir={'openbadgeslib': './openbadgeslib'},
  package_data={'openbadgeslib': ['./3dparty/jws/*.*','requirements.txt']},
  include_package_data=True,
  entry_points = {
          'console_scripts': [
          'openbadges-keygenerator = openbadgeslib.openbadges_keygenerator:main',
	        'openbadges-signer = openbadgeslib.openbadges_signer:main',
	        'openbadges-verifier = openbadgeslib.openbadges_verifier:main'
          ]
  }

)
