#!/usr/bin/env python3

"""
    Copyright (c) 2015, Luis González Fernández - luisgf@luisgf.es
    Copyright (c) 2015, Jesús Cea Avión - jcea@jcea.es

    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
"""

import argparse, os.path, sys

from .logs import Logger
from .keys import KeyFactory
from .errors import KeyGenExceptions
from .confparser import ConfParser
from .util import __version__
global log

# Entry Point
def main():
    parser = argparse.ArgumentParser(description='Key Generation Parameters')
    parser.add_argument('-c', '--config', default='config.ini',
            help='Specify the config.ini file to use')
    parser.add_argument('-g', '--genkey', metavar='BADGE',
            help=('Generate a new Key pair '
                'for the specified Badge. Key type is taken from profile.'))
    parser.add_argument('-v', '--version', action='version',
            version=__version__ )
    args = parser.parse_args()

    if not args.genkey:
        parser.print_help()
    else:
        cparser = ConfParser(args.config)
        conf = cparser.read_conf()

        badge = 'badge_' + args.genkey
        if conf:
            if badge not in conf :
                sys.exit("Badge '%s' doesn't exist in the configuration file"
                        %args.genkey)
            private_key = conf[badge]['private_key']
            public_key = conf[badge]['public_key']

            for i in (private_key, public_key) :
                if os.path.exists(i):
                    print('[!] Key file is present at %s' % i)
                    sys.exit(1)

            log = Logger(base_log=conf['paths']['base_log'],
                      general=conf['logs']['general'],
                      signer=conf['logs']['signer'])

            try:
                log.console.info("Generating key pair for issuer '%s'" % conf['issuer']['name'])

                kf = KeyFactory()
                priv_key_pem, pub_key_pem = kf.generate_keypair()

                with open(private_key, 'wb') as f:
                    f.write(priv_key_pem)

                with open(public_key, 'wb') as f:
                    f.write(pub_key_pem)

                log.console.info('Private key saved at: %s' % private_key)
                log.console.info('Public key saved at: %s' % public_key)

            except KeyGenExceptions:
                raise
        else:
            print('ERROR: Config file %s NOT exists or is empty' % args.config)

if __name__ == '__main__':
    main()

