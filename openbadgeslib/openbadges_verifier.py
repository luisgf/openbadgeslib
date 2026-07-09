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
from .util import __version__

logger = logging.getLogger(__name__)

# Entry Point


def _resolve_trusted_pubkey(args: argparse.Namespace) -> Optional[bytes]:
    """Return the operator-supplied trusted public key PEM, or None if neither
    --local nor --pubkey was given. Shared by the OB2 and OB3 verify paths."""
    if args.local:
        conf = read_config_or_exit(args.config)
        section = resolve_badge_section(conf, args.local)
        if 'public_key' not in conf[section]:
            print("[!] [%s] is missing the required 'public_key' config key"
                  % section)
            sys.exit(-1)
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
    parser.add_argument('-V', '--ob-version', choices=['1', '2', '3'], default='3',
                        metavar='VERSION',
                        help='OpenBadges specification version: 1 (legacy JWS), '
                             '2 (strict OB 2.0 JWS), or 3 (default, JWT-VC).')
    parser.add_argument('--json', action='store_true',
                        help='Emit a machine-readable JSON result instead of the human '
                             'output. Exit status: 0 when the badge is valid AND the '
                             'issuer is trusted; 2 when the signature is valid but the '
                             'issuer is not anchored (untrusted); 1 on any failure.')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Show debug messages at runtime.')
    parser.add_argument('-v', '--version', action='version',
                        version=__version__)
    return parser


def _finish(args: argparse.Namespace, result: Dict[str, Any]) -> None:
    """Emit the verification result and set the process exit status.

    In --json mode a single JSON object is printed and the process exit status
    reflects issuer trust, not merely signature validity: 0 when the badge is
    valid AND trusted, 2 when the signature is valid but the issuer is not
    anchored (an OB2 badge-embedded key or a self-asserted did:key), and 1 on
    any failure. Collapsing 'valid but untrusted' into an exit-0 success would
    let automation gate on a signature that only proves internal consistency,
    not who issued the badge. Without --json the human lines have already been
    printed; the historical exit behaviour is preserved via result['_exit']
    (None means return without exiting, i.e. a normal exit 0)."""
    if args.json:
        payload = {k: v for k, v in result.items() if not k.startswith('_')}
        print(json.dumps(payload))
        if not result.get('valid'):
            sys.exit(1)
        sys.exit(0 if result.get('trusted') else 2)
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
    elif args.ob_version == '2':
        _verify_ob2(args)
    else:
        _verify_ob1(args)


def _verify_ob2(args: argparse.Namespace) -> None:
    """Verify a badge using strict OpenBadges 2.0 (SignedBadge JWS or HostedBadge)."""
    from .ob2 import OB2Verifier, OB2VerificationError
    from .errors import ErrorParsingFile

    # _exit starts non-zero and is cleared to None only on a valid verdict, so a
    # failed OB2 verification exits non-zero in human mode too (mirrors OB3 and
    # the --json path); a bare `None` init would exit 0 on an invalid badge.
    result: Dict[str, Any] = {'ob_version': '2', 'recipient': args.receptor,
                              'trusted': True, 'valid': False, '_exit': -1}

    pub_pem = _resolve_trusted_pubkey(args)

    with open(args.filein, 'rb') as f:
        file_data = f.read()

    try:
        if args.filein.lower().endswith('.svg'):
            token = OB2Verifier.extract_token_from_svg(file_data)
        elif args.filein.lower().endswith('.png'):
            token = OB2Verifier.extract_token_from_png(file_data)
        else:
            result['reason'] = 'Unsupported file format for OB2 verification (use .svg or .png)'
            result['_exit'] = -1
            if not args.json:
                print('[!] %s' % result['reason'])
            _finish(args, result)
            return
    except (OB2VerificationError, ErrorParsingFile) as exc:
        result['reason'] = 'Could not extract OB2 token: %s' % exc
        result['_exit'] = -1
        if not args.json:
            print('[-] %s' % result['reason'])
        _finish(args, result)
        return

    # check_revocation=True mirrors OB1's always-check-revocation pipeline; a
    # HostedBadge additionally fetches its id and issuer to anchor trust.
    verifier = OB2Verifier(pubkey_pem=pub_pem)
    try:
        assertion = verifier.verify(token, expected_recipient=args.receptor,
                                    check_revocation=True)
    except OB2VerificationError as exc:
        result['reason'] = 'OB2 verification failed: %s' % exc
        result['status'] = 'INVALID'
        if not args.json:
            print('[-] %s' % exc)
        _finish(args, result)
        return

    verification_type = assertion.verification.type
    # A HostedBadge is anchored by the (scope-checked) HTTPS retrieval of its id;
    # a SignedBadge is only trusted when the operator supplied the key.
    trusted = True if verification_type == 'HostedBadge' else (pub_pem is not None)
    result['valid'] = True
    result['_exit'] = None
    result['trusted'] = trusted
    result['status'] = 'VALID'
    result['verification_type'] = verification_type
    result['assertion_id'] = assertion.id
    result['badge'] = assertion.badge

    if args.show and not args.json:
        print('[+] Assertion:')
        print(json.dumps(assertion.to_dict(), sort_keys=True, indent=4))

    if trusted:
        result['reason'] = None
        if not args.json:
            if verification_type == 'HostedBadge':
                print('[+] Hosted assertion verified over HTTPS for the identity %s'
                      % args.receptor)
            else:
                print('[+] Signature is correct for the identity %s' % args.receptor)
    else:
        result['reason'] = ('signature is internally consistent but verified against the '
                            'badge-declared key, not a trusted issuer key')
        if not args.json:
            print('[~] Signature is internally consistent for %s, but it was verified '
                  'against the key the badge itself declares (verification.creator), not a '
                  'trusted issuer key. This does NOT prove issuer identity. Re-run with '
                  '--local BADGE or --pubkey FILE to anchor trust.' % args.receptor)

    _finish(args, result)


def _verify_ob1(args: argparse.Namespace) -> None:
    """Verify a badge using OpenBadges 1.0 (legacy JWS)."""
    from .ob1.verifier import Verifier
    from .ob1.badge import BadgeSigned, BadgeStatus

    if not args.json:
        print('[!] OpenBadges 1.0 (-V 1) is a legacy version, still supported; '
              'new badges are better issued and verified as OB 2.0 (-V 2) or '
              'OB 3.0 (-V 3).')

    # _exit starts non-zero and is cleared only on a VALID verdict (mirrors OB2
    # and OB3), so an invalid OB1 badge exits non-zero in human mode too.
    result: Dict[str, Any] = {'ob_version': '1', 'recipient': args.receptor, '_exit': -1}
    try:
        badge = BadgeSigned.read_from_file(args.filein)

        # A trusted key is one the operator supplied out-of-band (config or an
        # explicit file). Falling back to the key the badge itself points to
        # only proves the badge is internally consistent, NOT who issued it.
        trusted_pubkey = _resolve_trusted_pubkey(args)
        trusted = trusted_pubkey is not None
        local_pubkey = trusted_pubkey if trusted else badge.get_signkey_pem()
        logger.debug("OB1 verify: trusted_key=%s (source=%s)",
                     trusted, 'operator' if trusted else 'badge-embedded')

        v = Verifier(verify_key=local_pubkey, identity=args.receptor)
        if args.show and not args.json:
            v.print_payload(badge)

        check = v.get_badge_status(badge)
        logger.debug("OB1 verify result: %s", check.status.name)
        result['trusted'] = trusted
        result['status'] = check.status.name

        if check.status is BadgeStatus.VALID:
            result['valid'] = True
            result['_exit'] = None
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


def _issuer_did_from_document(document: str) -> str:
    """Read the issuer DID from an unverified Data Integrity credential.

    The LDP counterpart of _issuer_did_from_token, with the same trust
    caveat: the DID comes from the untrusted document and is only an anchor
    for --resolve-did."""
    import json
    from .ob3 import OB3VerificationError
    try:
        doc = json.loads(document)
    except ValueError as exc:
        raise OB3VerificationError(
            'could not read credential issuer: %s' % exc) from exc
    issuer = doc.get('issuer') if isinstance(doc, dict) else None
    iss = issuer.get('id') if isinstance(issuer, dict) else issuer
    if not isinstance(iss, str) or not iss.startswith('did:'):
        raise OB3VerificationError('credential issuer is not a DID: %r' % (iss,))
    return iss


def _verify_ob3(args: argparse.Namespace) -> None:
    """Verify a badge using OpenBadges 3.0 (JWT-VC or Data Integrity)."""
    from .ob3 import OB3LdpVerifier, OB3VerificationError, OB3Verifier
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

    # The baked payload is either a compact JWT-VC or (for the OB 3.0 Linked
    # Data Proof format) the credential JSON itself. Both verifiers share the
    # verify() signature, so only the construction differs.
    is_ldp = token.lstrip().startswith('{')
    result['proof_format'] = 'ldp' if is_ldp else 'vc-jwt'

    # Let the library own recipient binding (it normalises mailto:/DID and
    # compares), instead of re-implementing the comparison here.
    try:
        verifier: Any
        if pub_pem is not None:
            verifier = (OB3LdpVerifier(pubkey_pem=pub_pem) if is_ldp
                        else OB3Verifier(pubkey_pem=pub_pem))
        else:
            issuer_did = (_issuer_did_from_document(token) if is_ldp
                          else _issuer_did_from_token(token))
            result['issuer_did'] = issuer_did
            # The DID is read from the untrusted credential itself. A did:key
            # IS the presenter's chosen key, so resolving it proves only
            # internal consistency, not issuer identity — mark it untrusted,
            # mirroring OB2's badge-embedded-key case. did:web is anchored on
            # the issuer's DNS + TLS, so it stays trusted.
            result['trusted'] = issuer_did.startswith('did:web:')
            if not args.json:
                print('[*] Resolving issuer DID %s' % issuer_did)
            verifier = (OB3LdpVerifier.for_issuer_did(issuer_did) if is_ldp
                        else OB3Verifier.for_issuer_did(issuer_did))
        credential = verifier.verify(token, expected_recipient=args.receptor,
                                     check_status=args.check_status)
    except OB3VerificationError as exc:
        result['reason'] = 'OB3 verification failed: %s' % exc
        if not args.json:
            print('[-] %s' % result['reason'])
        _finish(args, result)
        return

    result['valid'] = True
    result['_exit'] = None
    result['issuer'] = credential.issuer.name
    result['achievement'] = credential.achievement.name
    result['issued_on'] = credential.issuance_date.isoformat() if credential.issuance_date else None
    result['expires'] = (credential.expiration_date.isoformat()
                         if credential.expiration_date else None)
    result['evidence'] = credential.evidence_url
    # Broadened OB 3.0 model (#162): surface the expressive fields so an
    # integrator reading --json sees them without re-parsing `raw`. Scalars go
    # as-is (None when absent); the repeatable structures as counts.
    result['achievement_type'] = credential.achievement.achievement_type
    result['credits_available'] = credential.achievement.credits_available
    result['credits_earned'] = credential.credits_earned
    result['alignments'] = len(credential.achievement.alignments)
    result['results'] = len(credential.results)
    result['identifiers'] = len(credential.identifiers)
    # Surface how many EndorsementCredential JWTs the credential carries (on
    # itself, its issuer or its achievement) so they are no longer invisible.
    # They are third-party VCs; verify each with ob3.verify_endorsement_jwt.
    endorsement_jwts = credential.all_endorsement_jwts()
    result['endorsements'] = len(endorsement_jwts)

    if args.show and not args.json:
        print('[+] Credential issuer  : %s' % credential.issuer.name)
        print('[+] Achievement        : %s' % credential.achievement.name)
        issued = credential.issuance_date.isoformat() if credential.issuance_date else 'n/a'
        print('[+] Issued on          : %s' % issued)
        if credential.expiration_date:
            print('[+] Expires            : %s' % credential.expiration_date.isoformat())
        if credential.evidence_url:
            print('[+] Evidence           : %s' % credential.evidence_url)
        if credential.achievement.achievement_type:
            print('[+] Achievement type   : %s'
                  % credential.achievement.achievement_type)
        if credential.achievement.credits_available is not None:
            print('[+] Credits available  : %s'
                  % credential.achievement.credits_available)
        if credential.credits_earned is not None:
            print('[+] Credits earned     : %s' % credential.credits_earned)
        if credential.achievement.alignments:
            print('[+] Alignments         : %d'
                  % len(credential.achievement.alignments))
        if credential.results:
            print('[+] Results            : %d' % len(credential.results))
        if endorsement_jwts:
            print('[+] Endorsements       : %d (verify with '
                  'ob3.verify_endorsement_jwt)' % len(endorsement_jwts))

    if result['trusted']:
        result['reason'] = None
        if not args.json:
            print('[+] OB3 signature is valid for the identity %s' % args.receptor)
    else:
        result['reason'] = ('signature is valid but verified against a key resolved '
                            'from the credential\'s own did:key (self-asserted), not a '
                            'trusted issuer key')
        if not args.json:
            print('[~] OB3 signature is internally consistent for %s, but it was '
                  'verified against a key resolved from the credential\'s own '
                  'did:key. This does NOT prove issuer identity. Supply --pubkey '
                  'FILE / --local BADGE, or anchor a did:web issuer, to establish '
                  'trust.' % args.receptor)

    _finish(args, result)


if __name__ == '__main__':
    main()
