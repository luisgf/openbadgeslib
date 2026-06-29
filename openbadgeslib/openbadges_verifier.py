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
import logging
import sys
import os

from typing import Optional

from .errors import VerifierExceptions
from .confparser import read_config_or_exit, resolve_badge_section
from .logs import enable_debug_logging
from .ob2 import Verifier, BadgeSigned, BadgeStatus
from .util import __version__

logger = logging.getLogger(__name__)

# Entry Point


def _resolve_trusted_pubkey(args: argparse.Namespace) -> Optional[bytes]:
    """Return the operator-supplied trusted public key PEM, or None if neither
    --local nor --pubkey was given. Shared by the OB2 and OB3 verify paths."""
    if args.local:
        conf = read_config_or_exit(args.config)
        section = resolve_badge_section(conf, args.local)
        with open(conf[section]['public_key'], 'rb') as f:
            return f.read()
    if args.pubkey:
        if not os.path.isfile(args.pubkey):
            print('[!] Public key file %s NOT exists.' % args.pubkey)
            sys.exit(-1)
        with open(args.pubkey, 'rb') as f:
            return f.read()
    return None


def build_parser() -> argparse.ArgumentParser:
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
                        help='Path to the trusted PEM public key file used for '
                             'verification (OB2 and OB3)')
    parser.add_argument('-s', '--show', action='store_true',
                        help='Show the assertion/credential of the OpenBadge being verified.')
    parser.add_argument('-V', '--ob-version', choices=['2', '3'], default='2',
                        metavar='VERSION',
                        help='OpenBadges specification version: 2 (default, JWS) or 3 (JWT-VC).')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Show debug messages at runtime.')
    parser.add_argument('-v', '--version', action='version',
                        version=__version__)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    enable_debug_logging(args.debug)

    if not args.filein or not args.receptor:
        parser.print_help()
        return

    logger.debug("Verifying %s as OpenBadges %s for %s",
                 args.filein, args.ob_version, args.receptor)

    if not os.path.isfile(args.filein):
        print('[!] Badge file %s NOT exists.' % args.filein)
        sys.exit(-1)

    if args.ob_version == '3':
        _verify_ob3(args)
    else:
        _verify_ob2(args)


def _verify_ob2(args: argparse.Namespace) -> None:
    """Verify a badge using OpenBadges 2.0 (JWS)."""
    try:
        badge = BadgeSigned.read_from_file(args.filein)

        # A trusted key is one the operator supplied out-of-band (config or an
        # explicit file). Falling back to the key the badge itself points to
        # only proves the badge is internally consistent, NOT who issued it.
        trusted_pubkey = _resolve_trusted_pubkey(args)
        trusted = trusted_pubkey is not None
        local_pubkey = trusted_pubkey if trusted else badge.get_signkey_pem()
        logger.debug("OB2 verify: trusted_key=%s (source=%s)",
                     trusted, 'operator' if trusted else 'badge-embedded')

        v = Verifier(verify_key=local_pubkey, identity=args.receptor)
        if args.show:
            v.print_payload(badge)

        check = v.get_badge_status(badge)
        logger.debug("OB2 verify result: %s", check.status.name)

        if check.status is BadgeStatus.VALID:
            if trusted:
                print('[+] Signature is correct for the identity %s' % v.get_identity())
            else:
                print('[~] Signature is internally consistent for %s, but it was '
                      'verified against the key embedded in the badge itself, not a '
                      'trusted issuer key. This does NOT prove issuer identity. '
                      'Re-run with --local BADGE or --pubkey FILE to anchor trust.'
                      % v.get_identity())
        else:
            print('[-] ', check.msg)

    except VerifierExceptions as exc:
        print('[-] %s' % exc)
        sys.exit(-1)


def _verify_ob3(args: argparse.Namespace) -> None:
    """Verify a badge using OpenBadges 3.0 (JWT-VC)."""
    from .ob3 import OB3Verifier, OB3VerificationError
    from .errors import ErrorParsingFile

    pub_pem = _resolve_trusted_pubkey(args)
    if pub_pem is None:
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

    # Let the library own recipient binding (it normalises mailto:/DID and
    # compares), instead of re-implementing the comparison here.
    try:
        verifier = OB3Verifier(pubkey_pem=pub_pem)
        credential = verifier.verify(token, expected_recipient=args.receptor)
    except OB3VerificationError as exc:
        print('[-] OB3 verification failed: %s' % exc)
        sys.exit(-1)

    if args.show:
        print('[+] Credential issuer  : %s' % credential.issuer.name)
        print('[+] Achievement        : %s' % credential.achievement.name)
        issued = credential.issuance_date.isoformat() if credential.issuance_date else 'n/a'
        print('[+] Issued on          : %s' % issued)
        if credential.expiration_date:
            print('[+] Expires            : %s' % credential.expiration_date.isoformat())
        if credential.evidence_url:
            print('[+] Evidence           : %s' % credential.evidence_url)

    print('[+] OB3 signature is valid for the identity %s' % args.receptor)


if __name__ == '__main__':
    main()
