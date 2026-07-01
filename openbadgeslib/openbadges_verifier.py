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
import json
import logging
import sys
import os

from typing import Any, Dict, Optional

from .errors import LibOpenBadgesException
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
        key_path = conf[section]['public_key']
        if not os.path.isfile(key_path):
            print('[!] Public key file %s NOT exists.' % key_path)
            sys.exit(-1)
        with open(key_path, 'rb') as f:
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
    trusted_key_group = parser.add_mutually_exclusive_group()
    trusted_key_group.add_argument(
        '-l', '--local', metavar='BADGE',
        help='Do the verification using the local configuration')
    trusted_key_group.add_argument(
        '-k', '--pubkey', metavar='FILE',
        help='Path to the trusted PEM public key file used for '
             'verification (OB2 and OB3)')
    parser.add_argument('-s', '--show', action='store_true',
                        help='Show the assertion/credential of the OpenBadge being verified.')
    parser.add_argument('--check-status', action='store_true',
                        help='OB3 only: fetch the credentialStatus list and reject a '
                             'revoked/suspended credential (requires network access).')
    parser.add_argument('--resolve-did', action='store_true',
                        help='OB3 only: when no trusted key is supplied, resolve the '
                             'issuer DID (did:key/did:web) from the token to obtain the '
                             'verification key (did:web requires network access).')
    parser.add_argument('-V', '--ob-version', choices=['2', '3'], default='2',
                        metavar='VERSION',
                        help='OpenBadges specification version: 2 (default, JWS) or 3 (JWT-VC).')
    parser.add_argument('--json', action='store_true',
                        help='Emit a machine-readable JSON result instead of the human '
                             'output. Exits 0 when valid, non-zero otherwise.')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Show debug messages at runtime.')
    parser.add_argument('-v', '--version', action='version',
                        version=__version__)
    return parser


def _finish(args: argparse.Namespace, result: Dict[str, Any]) -> None:
    """Emit the verification result and set the process exit status.

    In --json mode a single JSON object is printed and the process exits 0 when
    valid, non-zero otherwise. Without --json the human lines have already been
    printed; the historical exit behaviour is preserved via result['_exit']
    (None means return without exiting, i.e. a normal exit 0)."""
    if args.json:
        payload = {k: v for k, v in result.items() if not k.startswith('_')}
        print(json.dumps(payload))
        sys.exit(0 if result.get('valid') else 1)
    code = result.get('_exit')
    if code is not None:
        sys.exit(code)


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
        if not args.json:
            print('[!] Badge file %s NOT exists.' % args.filein)
        _finish(args, {'ob_version': args.ob_version, 'recipient': args.receptor,
                       'valid': False,
                       'reason': 'Badge file %s does not exist' % args.filein,
                       '_exit': -1})
        return

    if args.ob_version == '3':
        _verify_ob3(args)
    else:
        _verify_ob2(args)


def _verify_ob2(args: argparse.Namespace) -> None:
    """Verify a badge using OpenBadges 2.0 (JWS)."""
    result: Dict[str, Any] = {'ob_version': '2', 'recipient': args.receptor, '_exit': None}
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
        if args.show and not args.json:
            v.print_payload(badge)

        check = v.get_badge_status(badge)
        logger.debug("OB2 verify result: %s", check.status.name)
        result['trusted'] = trusted
        result['status'] = check.status.name

        if check.status is BadgeStatus.VALID:
            result['valid'] = True
            if trusted:
                result['reason'] = None
                if not args.json:
                    print('[+] Signature is correct for the identity %s' % v.get_identity())
            else:
                result['reason'] = ('signature is internally consistent but verified against '
                                    'the badge-embedded key, not a trusted issuer key')
                if not args.json:
                    print('[~] Signature is internally consistent for %s, but it was '
                          'verified against the key embedded in the badge itself, not a '
                          'trusted issuer key. This does NOT prove issuer identity. '
                          'Re-run with --local BADGE or --pubkey FILE to anchor trust.'
                          % v.get_identity())
        else:
            result['valid'] = False
            result['reason'] = check.msg
            if not args.json:
                print('[-] ', check.msg)

    except LibOpenBadgesException as exc:
        # Present any library exception (unsupported image format, malformed
        # assertion, unreadable key material, …) as a clean CLI error rather
        # than an uncaught traceback. BadgeImgFormatUnsupported and the key-read
        # errors inherit LibOpenBadgesException but not VerifierExceptions.
        result['valid'] = False
        result['reason'] = str(exc)
        result['_exit'] = -1
        if not args.json:
            print('[-] %s' % exc)

    _finish(args, result)


def _issuer_did_from_token(token: str) -> str:
    """Read the issuer DID from an unverified JWT-VC (iss, or vc.issuer.id).

    Only used to anchor trust when --resolve-did is set: the DID is read from
    the untrusted token, resolved to a key, and the signature is then checked
    against that key (did:key is self-certifying; did:web trusts DNS+TLS)."""
    import jwt
    from .ob3 import OB3VerificationError
    try:
        payload = jwt.decode(token, options={'verify_signature': False})
    except jwt.exceptions.PyJWTError as exc:
        raise OB3VerificationError('could not read token issuer: %s' % exc) from exc
    iss = payload.get('iss')
    if not iss:
        vc = payload.get('vc')
        if not isinstance(vc, dict):
            vc = {}
        issuer = vc.get('issuer')
        iss = issuer.get('id') if isinstance(issuer, dict) else issuer
    if not isinstance(iss, str) or not iss.startswith('did:'):
        raise OB3VerificationError('token issuer is not a DID: %r' % (iss,))
    return iss


def _verify_ob3(args: argparse.Namespace) -> None:
    """Verify a badge using OpenBadges 3.0 (JWT-VC)."""
    from .ob3 import OB3Verifier, OB3VerificationError
    from .errors import ErrorParsingFile

    result: Dict[str, Any] = {'ob_version': '3', 'recipient': args.receptor,
                              'trusted': True, 'valid': False, '_exit': -1}

    pub_pem = _resolve_trusted_pubkey(args)
    if pub_pem is None and not args.resolve_did:
        result['reason'] = 'OB3 verification requires --local BADGE, --pubkey FILE, or --resolve-did'
        if not args.json:
            print('[!] %s' % result['reason'])
        _finish(args, result)
        return

    with open(args.filein, 'rb') as f:
        file_data = f.read()

    try:
        if args.filein.lower().endswith('.svg'):
            token = OB3Verifier.extract_token_from_svg(file_data)
        elif args.filein.lower().endswith('.png'):
            token = OB3Verifier.extract_token_from_png(file_data)
        else:
            result['reason'] = 'Unsupported file format for OB3 verification (use .svg or .png)'
            if not args.json:
                print('[!] %s' % result['reason'])
            _finish(args, result)
            return
    except (OB3VerificationError, ErrorParsingFile) as exc:
        result['reason'] = 'Could not extract OB3 token: %s' % exc
        if not args.json:
            print('[-] %s' % result['reason'])
        _finish(args, result)
        return

    # Let the library own recipient binding (it normalises mailto:/DID and
    # compares), instead of re-implementing the comparison here.
    try:
        if pub_pem is not None:
            verifier = OB3Verifier(pubkey_pem=pub_pem)
        else:
            issuer_did = _issuer_did_from_token(token)
            result['issuer_did'] = issuer_did
            if not args.json:
                print('[*] Resolving issuer DID %s' % issuer_did)
            verifier = OB3Verifier.for_issuer_did(issuer_did)
        credential = verifier.verify(token, expected_recipient=args.receptor,
                                     check_status=args.check_status)
    except OB3VerificationError as exc:
        result['reason'] = 'OB3 verification failed: %s' % exc
        if not args.json:
            print('[-] %s' % result['reason'])
        _finish(args, result)
        return

    result['valid'] = True
    result['reason'] = None
    result['_exit'] = None
    result['issuer'] = credential.issuer.name
    result['achievement'] = credential.achievement.name
    result['issued_on'] = credential.issuance_date.isoformat() if credential.issuance_date else None
    result['expires'] = (credential.expiration_date.isoformat()
                         if credential.expiration_date else None)
    result['evidence'] = credential.evidence_url

    if args.show and not args.json:
        print('[+] Credential issuer  : %s' % credential.issuer.name)
        print('[+] Achievement        : %s' % credential.achievement.name)
        issued = credential.issuance_date.isoformat() if credential.issuance_date else 'n/a'
        print('[+] Issued on          : %s' % issued)
        if credential.expiration_date:
            print('[+] Expires            : %s' % credential.expiration_date.isoformat())
        if credential.evidence_url:
            print('[+] Evidence           : %s' % credential.evidence_url)

    if not args.json:
        print('[+] OB3 signature is valid for the identity %s' % args.receptor)

    _finish(args, result)


if __name__ == '__main__':
    main()
