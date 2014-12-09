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

from .signer import SignerFactory
from .errors import LibOpenBadgesException, SignerExceptions
from .confparser import ConfParser

# Entry Point
def main():
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-c', '--config', default='config.ini', help='Specify the config.ini file to use')
    parser.add_argument('-b', '--badge', required=True, help='Specify the badge name for sign')
    parser.add_argument('-r', '--receptor', required=True, help='Specify the receptor email of the badge')
    parser.add_argument('-o', '--output', required=True, help='Specify the output directory to save the badge.')
    parser.add_argument('-e', '--evidence', help='Set an url to the user evidence')
    parser.add_argument('-d', '--debug', action="store_true", help='Show debug messages in runtime.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.1' )
    args = parser.parse_args()

    if args.badge:
        cf = ConfParser(args.config)
        conf = cf.read_conf()

        if not conf:
            print('[!] The config file %s NOT exists or is empty' % args.config)
            sys.exit(-1)

        if not conf[args.badge]:
            print('%s is not defined in this config file' % args.badge)
            sys.exit(-1)

        try:
            _badge_file_in = conf['paths']['base_image'] + '/' + conf[args.badge]['image']
            _badge_svg_in = conf['issuer']['publish_url'] + '/' + conf[args.badge]['image']
            _badge_json_url = conf['issuer']['publish_url'] + '/' + args.badge + '.json'
            _badge_verify_key_url = conf[args.badge]['verify_key']
            _priv_key = conf['keys']['private']
            _pub_key = conf['keys']['public']

            if not os.path.isfile(_badge_file_in):
                print('[!] Badge file %s NOT exists.' % _badge_file_in)
                sys.exit(-1)

            """ Reading the SVG content """
            with open(_badge_file_in,"rb") as f:
                _badge_image_data = f.read()

            """ Reading the keys """
            with open(_priv_key,"rb") as f:
                _priv_key_pem = f.read()

            with open(_pub_key,"rb") as f:
                _pub_key_pem = f.read()

            sf = SignerFactory(key_type='RSA')
            print("[!] Generating signature for badge '%s'..." % args.badge)

            _badge_file_out = sf.generate_output_filename(_badge_file_in, args.output, args.receptor)
            _badge_assertion = sf.generate_openbadge_assertion(_priv_key_pem, _pub_key_pem)
            _badge_svg_out = sf.svg_sign(_badge_svg_in, _badge_assertion)

            if _badge_svg_out:
                print('[+] Badge Signed succesfully at: ', _badge_file_out)
            else:
                print('[-] An error has occurred during signing the badge.')
        except SignerExceptions:
            raise
        except LibOpenBadgesException:
            raise

if __name__ == '__main__':
    main()
