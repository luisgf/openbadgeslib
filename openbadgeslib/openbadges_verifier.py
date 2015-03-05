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

import argparse
import sys, os

from .verifier import Verifier
from .errors import LibOpenBadgesException, VerifierExceptions
from .confparser import ConfParser
from .badge import BadgeSigned, BadgeStatus
from .util import __version__

# Entry Point
def main():
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-c', '--config', default='config.ini',
            help='Specify the config.ini file to use')
    parser.add_argument('-i', '--filein', required=True,
            help='Specify the input file to verify the signature')
    parser.add_argument('-r', '--receptor', required=True,
            help='Specify the email of the receptor of the badge')
    parser.add_argument('-l', '--local', metavar='BADGE',
            help='Do the verification using the local configuration')
    parser.add_argument('-v', '--version', action='version',
            version=__version__ )
    args = parser.parse_args()

    if args.filein and args.receptor:
        cf = ConfParser(args.config)
        conf = cf.read_conf()
        local_pubkey = None

        if not conf:
            print('[!] The config file %s NOT exists or is empty' % args.config)
            sys.exit(-1)

        try:
            if not os.path.isfile(args.filein):
                print('[!] Badge file %s NOT exists.' % args.filein)
                sys.exit(-1)
            
            if args.local:
                badge = 'badge_' + args.local
                if badge not in conf :
                    sys.exit('There is no "%s" badge in the configuration' %
                            args.local)
              
                with open(conf[badge]['public_key'], 'rb') as file:
                    local_pubkey = file.read()

            badge = BadgeSigned.read_from_file(args.filein)
            v = Verifier(verify_key=local_pubkey, identity=args.receptor)
            check = v.get_badge_status(badge) 
            
            if check.status is BadgeStatus.VALID:
                v.print_payload(badge)
                print('[+] Signature is correct for the identity %s' % v.get_identity())
            else:
                print('[-] ', check.msg)

        except VerifierExceptions:
            raise
    else:
        parser.print_help()

if __name__ == '__main__':
    main()

