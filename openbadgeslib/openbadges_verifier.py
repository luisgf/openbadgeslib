#!/usr/bin/env python3

"""
    Copyright (c) 2014, Luis González Fernández - luisgf@luisgf.es
    Copyright (c) 2014, Jesús Cea Avión - jcea@jcea.es

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

from .keys import detect_key_type
from .verifier import VerifyFactory, VerifyBase, BadgeStatus, KeyType
from .errors import LibOpenBadgesException, VerifierExceptions
from .confparser import ConfParser

# Entry Point
def main():
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-c', '--config', default='config.ini',
            help='Specify the config.ini file to use')
    parser.add_argument('-i', '--filein', required=True,
            help='Specify the input SVG file to verify the signature')
    parser.add_argument('-r', '--receptor', required=True,
            help='Specify the email of the receptor of the badge')
    parser.add_argument('-l', '--local', metavar='BADGE',
            help='Do the verification using the local configuration')
    parser.add_argument('-v', '--version', action='version',
            version='%(prog)s 0.3' )
    args = parser.parse_args()

    if args.filein and args.receptor:
        cf = ConfParser(args.config)
        conf = cf.read_conf()

        if not conf:
            print('[!] The config file %s NOT exists or is empty' % args.config)
            sys.exit(-1)

        try:
            if not os.path.isfile(args.filein):
                print('[!] SVG file %s NOT exists.' % args.filein)
                sys.exit(-1)

            with open(args.filein, "rb") as f:
                svg_data = f.read()

            if args.local:
                badge = 'badge_' + args.local
                if badge not in conf :
                    sys.exit('There is no "%s" badge in the configuration' %
                            args.local)

                with open(conf[badge]['public_key'],"rb") as f:
                    key_pem = f.read()
            else:
                key_pem = None

            key_type = detect_key_type(key_pem)
            assertion = VerifyBase.extract_svg_assertion(svg_data)

            vf = VerifyFactory(key_type=key_type, assertion=assertion,
                               identity=args.receptor, verify_key=key_pem)

            sign = vf.get_signature_status()

            if sign.status is BadgeStatus.VALID:
                vf.print_payload()
                print('[+] Signature is correct for the identity %s' % args.receptor)
            else:
                print('[-] ', sign.msg)
        except VerifierExceptions:
            raise
    else:
        parser.print_help()

if __name__ == '__main__':
    main()

