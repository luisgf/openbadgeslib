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

from .verifier import VerifyFactory
from .errors import LibOpenBadgesException, VerifierExceptions
from .confparser import ConfParser

# Entry Point
def main():
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-c', '--config', default='config.ini', help='Specify the config.ini file to use')
    parser.add_argument('-i', '--filein', required=True, help='Specify the input SVG file to verify the signature')
    parser.add_argument('-r', '--receptor', required=True, help='Specify the email of the receptor of the badge')
    parser.add_argument('-lk', '--localkey', action="store_true", help='Verify the badge with local pubkey passed as param otherwise, the key in assertion will be used.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.2' )
    args = parser.parse_args()

    if args.filein and args.receptor:
        cf = ConfParser(args.config)
        conf = cf.read_conf()

        if not conf:
            print('[!] The config file %s NOT exists or is empty' % args.config)
            sys.exit(-1)

        try:
            sf = VerifyFactory()
            receptor = args.receptor

            if not os.path.isfile(args.filein):
                print('[!] SVG file %s NOT exists.' % args.filein)
                sys.exit(-1)

            with open(args.filein, "rb") as f:
                svg_data = f.read()

            if args.localkey:
                with open(conf['keys']['public'],"rb") as f:
                    local_key_pem = f.read()
            else:
                local_key_pem = None

            if sf.is_svg_signature_valid(svg_data, receptor, local_key=local_key_pem):
                print('[+] The Badge Signature is Correct for the user:', args.receptor)
            else:
                print('[!] Badge signature is incorrect, corrupted or tampered for the user:', args.receptor)
        except VerifierExceptions:
            raise
    else:
        parser.print_help()

if __name__ == '__main__':
    main()

