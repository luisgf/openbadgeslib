#!/usr/bin/env python3

"""
    Copyright (c) 2014-2026, Luis González Fernández - luisgf@luisgf.es
    Copyright (c) 2014-2026, Jesús Cea Avión - jcea@jcea.es

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
    parser = argparse.ArgumentParser(description='Badge Verifier Parameters')
    parser.add_argument('-c', '--config', default='config.ini',
            help='Specify the config.ini file to use')
    parser.add_argument('-i', '--filein', required=True,
            help='Specify the input file to verify the signature')
    parser.add_argument('-r', '--receptor', required=True,
            help='Specify the email of the receptor of the badge')
    parser.add_argument('-l', '--local', metavar='BADGE',
            help='Do the verification using the local configuration')
    parser.add_argument('-k', '--pubkey', metavar='FILE',
            help='(OB3) Path to the PEM public key file used for verification')
    parser.add_argument('-s', '--show', action='store_true',
            help='Show the assertion/credential of the OpenBadge being verified.')
    parser.add_argument('-V', '--ob-version', choices=['2', '3'], default='2',
            metavar='VERSION',
            help='OpenBadges specification version: 2 (default, JWS) or 3 (JWT-VC).')
    parser.add_argument('-v', '--version', action='version',
            version=__version__ )
    args = parser.parse_args()

    if not args.filein or not args.receptor:
        parser.print_help()
        return

    if not os.path.isfile(args.filein):
        print('[!] Badge file %s NOT exists.' % args.filein)
        sys.exit(-1)

    if args.ob_version == '3':
        _verify_ob3(args)
    else:
        _verify_ob2(args)


def _verify_ob2(args):
    """Verify a badge using OpenBadges 2.0 (JWS)."""
    conf = None
    if args.local:
        cf = ConfParser(args.config)
        conf = cf.read_conf()
        if not conf:
            print('[!] The config file %s NOT exists or is empty' % args.config)
            sys.exit(-1)

    try:
        badge = BadgeSigned.read_from_file(args.filein)

        if args.local:
            badge_name = 'badge_' + args.local
            if badge_name not in conf:
                sys.exit('There is no "%s" badge in the configuration' % args.local)
            with open(conf[badge_name]['public_key'], 'rb') as f:
                local_pubkey = f.read()
        else:
            local_pubkey = badge.get_signkey_pem()

        v = Verifier(verify_key=local_pubkey, identity=args.receptor)
        if args.show:
            v.print_payload(badge)

        check = v.get_badge_status(badge)

        if check.status is BadgeStatus.VALID:
            print('[+] Signature is correct for the identity %s' % v.get_identity())
        else:
            print('[-] ', check.msg)

    except VerifierExceptions:
        raise


def _verify_ob3(args):
    """Verify a badge using OpenBadges 3.0 (JWT-VC)."""
    from .ob3 import OB3Verifier, OB3VerificationError
    from .errors import ErrorParsingFile

    # Resolve the public key
    pub_pem = None
    if args.local:
        cf = ConfParser(args.config)
        conf = cf.read_conf()
        if not conf:
            print('[!] The config file %s NOT exists or is empty' % args.config)
            sys.exit(-1)
        badge_name = 'badge_' + args.local
        if badge_name not in conf:
            sys.exit('There is no "%s" badge in the configuration' % args.local)
        with open(conf[badge_name]['public_key'], 'rb') as f:
            pub_pem = f.read()
    elif args.pubkey:
        if not os.path.isfile(args.pubkey):
            print('[!] Public key file %s NOT exists.' % args.pubkey)
            sys.exit(-1)
        with open(args.pubkey, 'rb') as f:
            pub_pem = f.read()
    else:
        print('[!] OB3 verification requires --local BADGE or --pubkey FILE')
        sys.exit(-1)

    with open(args.filein, 'rb') as f:
        file_data = f.read()

    try:
        if args.filein.lower().endswith('.svg'):
            token = OB3Verifier.extract_token_from_svg(file_data)
        elif args.filein.lower().endswith('.png'):
            token = OB3Verifier.extract_token_from_png(file_data)
        else:
            print('[!] Unsupported file format for OB3 verification (use .svg or .png)')
            sys.exit(-1)
    except (OB3VerificationError, ErrorParsingFile) as exc:
        print('[-] Could not extract OB3 token: %s' % exc)
        sys.exit(-1)

    try:
        verifier = OB3Verifier(pubkey_pem=pub_pem)
        credential = verifier.verify(token)
    except OB3VerificationError as exc:
        print('[-] OB3 verification failed: %s' % exc)
        sys.exit(-1)

    expected_id = args.receptor if args.receptor.startswith('mailto:') \
                  else 'mailto:' + args.receptor

    if args.show:
        print('[+] Credential issuer  : %s' % credential.issuer.name)
        print('[+] Achievement        : %s' % credential.achievement.name)
        print('[+] Issued on          : %s' % credential.issuance_date.isoformat())
        if credential.expiration_date:
            print('[+] Expires            : %s' % credential.expiration_date.isoformat())
        if credential.evidence_url:
            print('[+] Evidence           : %s' % credential.evidence_url)

    if credential.recipient_id == expected_id:
        print('[+] OB3 signature is valid for the identity %s' % args.receptor)
    else:
        print('[-] Identity mismatch: credential is for %s, expected %s'
              % (credential.recipient_id, expected_id))
        sys.exit(-1)

if __name__ == '__main__':
    main()

