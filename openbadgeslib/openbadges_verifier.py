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

from typing import Any, Dict, NoReturn, Optional

from .errors import ConfigError, LibOpenBadgesException
from .confparser import load_config
from .logs import enable_debug_logging
from .cli_common import (config_parser, debug_parser, json_parser,
                         version_parser)

logger = logging.getLogger(__name__)

# Entry Point


def _cli_fail(args: argparse.Namespace, message: str) -> NoReturn:
    """Abort the verifier CLI with a failure: human ``[!]`` line, or a single
    JSON object when ``--json`` is set.

    Trusted-key / config resolution runs before the per-version paths reach
    :func:`_finish`, so failures here must still honour the machine-output
    contract (exactly one JSON object on stdout, exit 1) rather than printing
    a bare ``[!]`` line that would break a consumer piping stdout to a JSON
    parser (#285).
    """
    if getattr(args, 'json', False):
        _finish(args, {
            'ob_version': getattr(args, 'ob_version', None),
            'recipient': getattr(args, 'receptor', None),
            'valid': False,
            'trusted': False,
            'reason': message,
        })
    print('[!] %s' % message)
    sys.exit(1)


def _resolve_trusted_pubkey(args: argparse.Namespace) -> Optional[bytes]:
    """Return the operator-supplied trusted public key PEM, or None if neither
    --local nor --pubkey was given. Shared by the OB2 and OB3 verify paths.

    On a missing key file, missing config key, or unreadable config this
    aborts via :func:`_cli_fail` (JSON-safe under ``--json``) and does not
    return.
    """
    if args.local:
        try:
            conf = load_config(args.config)
        except ConfigError as exc:
            _cli_fail(args, str(exc))
        section = 'badge_' + args.local
        if section not in conf:
            _cli_fail(args, 'There is no "%s" badge in the configuration'
                      % args.local)
        if 'public_key' not in conf[section]:
            _cli_fail(args, "[%s] is missing the required 'public_key' config key"
                      % section)
        key_path = conf[section]['public_key']
        if not os.path.isfile(key_path):
            _cli_fail(args, 'Public key file %s NOT exists.' % key_path)
        with open(key_path, 'rb') as f:
            return f.read()
    if args.pubkey:
        if not os.path.isfile(args.pubkey):
            _cli_fail(args, 'Public key file %s NOT exists.' % args.pubkey)
        with open(args.pubkey, 'rb') as f:
            return f.read()
    return None


def _image_format(filein: str) -> str:
    """The verify_badge image_format hint from the input filename: 'svg'/'png'
    keep the historical extension-based decision, anything else becomes an
    unsupported-format result (the facade rejects an unknown hint)."""
    low = filein.lower()
    if low.endswith('.svg'):
        return 'svg'
    if low.endswith('.png'):
        return 'png'
    return 'other'


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Badge Verifier Parameters',
        parents=[config_parser, debug_parser, json_parser, version_parser])
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
    parser.add_argument('--no-verify-status-list', action='store_true',
                        help='OB3 only: with --check-status, do NOT verify the status '
                             "list's own signature — trust the revocation bit on the "
                             'serving host\'s word alone. Only for issuers that serve an '
                             'unsigned status list; insecure otherwise.')
    parser.add_argument('--resolve-did', action='store_true',
                        help='OB3 only: when no trusted key is supplied, resolve the '
                             'issuer DID (did:key/did:web) from the token to obtain the '
                             'verification key (did:web requires network access).')
    parser.add_argument('-V', '--ob-version', choices=['1', '2', '3'], default='3',
                        metavar='VERSION',
                        help='OpenBadges specification version: 1 (legacy JWS), '
                             '2 (strict OB 2.0 JWS), or 3 (default, JWT-VC).')
    return parser


def _finish(args: argparse.Namespace, result: Dict[str, Any]) -> None:
    """Emit the verification result (in --json mode) and set the process exit
    status per the 0/1/2 contract — identically in both human and --json modes.

    The exit status reflects issuer trust, not merely signature validity: 0 when
    the badge is valid AND trusted, 2 when the signature is valid but the issuer
    is not anchored (an OB2 badge-embedded key or a self-asserted did:key), and
    1 on any failure. Collapsing 'valid but untrusted' into an exit-0 success
    would let automation gate on a signature that only proves internal
    consistency, not who issued the badge. Without --json the human lines have
    already been printed; only the status is set here (#233).

    Every caller seeds ``valid``/``trusted`` False and raises them only on a
    verdict, so the payload always carries both and ``trusted`` is never true
    for a badge that did not verify (#258) — the invariant a consumer reading
    the object rather than the exit status depends on."""
    code = 1 if not result.get('valid') else (0 if result.get('trusted') else 2)
    if args.json:
        payload = {k: v for k, v in result.items() if not k.startswith('_')}
        print(json.dumps(payload))
        sys.exit(code)
    # Human mode: the lines are already printed. Exit only on a non-zero status
    # (invalid -> 1, valid-but-untrusted -> 2); a valid, trusted badge falls
    # through to a normal exit 0 so an in-process caller need not trap it.
    if code:
        sys.exit(code)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    enable_debug_logging(args.debug)

    if not args.filein or not args.receptor:
        parser.print_help()
        return

    # OB3-only flags must not be silently dropped on -V 1/-V 2 (mirrors the
    # signer's --proof-format / -H guards). An operator who passed --check-status
    # with -V 2 would otherwise believe revocation was checked when it was not
    # (#286).
    if args.ob_version != '3':
        for enabled, flag in (
                (args.check_status, '--check-status'),
                (args.no_verify_status_list, '--no-verify-status-list'),
                (args.resolve_did, '--resolve-did')):
            if enabled:
                _cli_fail(args, '%s applies to OpenBadges 3.0 only (-V 3)'
                          % flag)
                return

    logger.debug("Verifying %s as OpenBadges %s for %s",
                 args.filein, args.ob_version, args.receptor)

    if not os.path.isfile(args.filein):
        if not args.json:
            print('[!] Badge file %s NOT exists.' % args.filein)
        _finish(args, {'ob_version': args.ob_version, 'recipient': args.receptor,
                       'valid': False, 'trusted': False,
                       'reason': 'Badge file %s does not exist' % args.filein})
        return

    if args.ob_version == '3':
        _verify_ob3(args)
    elif args.ob_version == '2':
        _verify_ob2(args)
    else:
        _verify_ob1(args)


def _verify_ob2(args: argparse.Namespace) -> None:
    """Verify a badge using strict OpenBadges 2.0, then present the result.

    The verification itself (token extraction, signature/revocation, hosted
    scope, trust classification) lives in :func:`openbadgeslib.verify.verify_badge`;
    this only turns its :class:`~openbadgeslib.verify.VerifyResult` into the
    historical human lines / --json payload and exit status."""
    from .verify import verify_badge

    # valid/trusted both default False and are raised only on a verdict, so
    # _finish exits 1 on any failure and 0/2 only once the badge verifies — and
    # the payload never claims a failed badge is trusted (#258).
    result: Dict[str, Any] = {'ob_version': '2', 'recipient': args.receptor,
                              'trusted': False, 'valid': False}

    pub_pem = _resolve_trusted_pubkey(args)

    with open(args.filein, 'rb') as f:
        file_data = f.read()

    res = verify_badge(file_data, '2', pubkey_pem=pub_pem,
                       expected_recipient=args.receptor,
                       image_format=_image_format(args.filein))

    if not res.valid:
        reason = res.reason or ''
        result['reason'] = res.reason
        if reason.startswith('OB2 verification failed: '):
            result['status'] = 'INVALID'
            if not args.json:                    # human line prints only the cause
                print('[-] %s' % reason[len('OB2 verification failed: '):])
        elif reason.startswith('Unsupported file format'):
            if not args.json:
                print('[!] %s' % reason)
        else:                                    # token-extraction failure
            if not args.json:
                print('[-] %s' % reason)
        _finish(args, result)
        return

    assertion = res.assertion
    assert assertion is not None           # res.valid is True, so it is present
    verification_type = assertion.verification.type
    result['valid'] = True
    result['trusted'] = res.trusted
    result['status'] = 'VALID'
    result['verification_type'] = verification_type
    result['assertion_id'] = assertion.id
    result['badge'] = assertion.badge

    if args.show and not args.json:
        print('[+] Assertion:')
        print(json.dumps(assertion.to_dict(), sort_keys=True, indent=4))

    if res.trusted:
        result['reason'] = None
        if not args.json:
            if verification_type == 'HostedBadge':
                print('[+] Hosted assertion verified over HTTPS for the identity %s'
                      % args.receptor)
            else:
                print('[+] Signature is correct for the identity %s' % args.receptor)
    else:
        result['reason'] = res.reason
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

    # valid/trusted both default False and are set only on a verdict (mirrors
    # OB2 and OB3), so an invalid OB1 badge exits 1 — and 'trusted' is seeded
    # here, not only inside the try, so a badge that fails to parse still emits
    # it instead of a payload missing the field (#258).
    result: Dict[str, Any] = {'ob_version': '1', 'recipient': args.receptor,
                              'valid': False, 'trusted': False}
    try:
        badge = BadgeSigned.read_from_file(args.filein)

        # A trusted key is one the operator supplied out-of-band (config or an
        # explicit file). Falling back to the key the badge itself points to
        # only proves the badge is internally consistent, NOT who issued it.
        trusted_pubkey = _resolve_trusted_pubkey(args)
        is_trusted = trusted_pubkey is not None
        local_pubkey = trusted_pubkey if is_trusted else badge.get_signkey_pem()
        # Log the key's provenance and nothing else. The flag itself used to be
        # an argument here, and CodeQL's sensitive-data heuristic — which
        # classifies an identifier containing `trusted` as a secret — reported
        # that as clear-text logging of a secret, even though the value is a
        # bool and the key it derives from is public (code-scanning alert #1).
        # What closes the flow is dropping the flag from the call; the `is_`
        # prefix on the name is belt and braces (and better naming for a bool).
        logger.debug("OB1 verify: key source=%s",
                     'operator' if is_trusted else 'badge-embedded')

        v = Verifier(verify_key=local_pubkey, identity=args.receptor)
        if args.show and not args.json:
            v.print_payload(badge)

        check = v.get_badge_status(badge)
        logger.debug("OB1 verify result: %s", check.status.name)
        result['status'] = check.status.name

        if check.status is BadgeStatus.VALID:
            result['valid'] = True
            # Set trusted only on the VALID branch, mirroring the OB2/OB3 paths:
            # the seeded trusted=False must persist for a badge that failed to
            # verify, so the payload never claims a bad signature is trusted
            # (#258) — the invariant _finish's docstring promises.
            result['trusted'] = is_trusted
            if is_trusted:
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
        if not args.json:
            print('[-] %s' % exc)

    _finish(args, result)


def _verify_ob3(args: argparse.Namespace) -> None:
    """Verify a badge using OpenBadges 3.0, then present the result.

    The verification (token extraction, JWT-VC/LDP auto-detection, DID
    resolution, trust classification, signature/status) lives in
    :func:`openbadgeslib.verify.verify_badge`; this only presents its
    :class:`~openbadgeslib.verify.VerifyResult`."""
    from .verify import verify_badge

    # valid/trusted both default False; see _verify_ob2 for the invariant (#258).
    result: Dict[str, Any] = {'ob_version': '3', 'recipient': args.receptor,
                              'trusted': False, 'valid': False}

    pub_pem = _resolve_trusted_pubkey(args)
    if pub_pem is None and not args.resolve_did:
        result['reason'] = 'OB3 verification requires --local BADGE, --pubkey FILE, or --resolve-did'
        if not args.json:
            print('[!] %s' % result['reason'])
        _finish(args, result)
        return

    with open(args.filein, 'rb') as f:
        file_data = f.read()

    res = verify_badge(
        file_data, '3', pubkey_pem=pub_pem, resolve_did=args.resolve_did,
        expected_recipient=args.receptor, check_status=args.check_status,
        verify_status_list=not args.no_verify_status_list,
        image_format=_image_format(args.filein))

    result['proof_format'] = res.proof_format
    # In --resolve-did mode the facade read the issuer DID from the credential;
    # surface it and the progress line before the verdict, as the CLI always has.
    if res.issuer_did is not None:
        result['issuer_did'] = res.issuer_did
        if not args.json:
            print('[*] Resolving issuer DID %s' % res.issuer_did)

    if not res.valid:
        result['reason'] = res.reason
        if not args.json:
            prefix = '[!]' if (res.reason or '').startswith('Unsupported file format') else '[-]'
            print('%s %s' % (prefix, res.reason))
        _finish(args, result)
        return

    credential = res.credential
    assert credential is not None          # res.valid is True, so it is present
    result['valid'] = True
    result['trusted'] = res.trusted
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

    if res.trusted:
        result['reason'] = None
        if not args.json:
            print('[+] OB3 signature is valid for the identity %s' % args.receptor)
    else:
        result['reason'] = res.reason
        if not args.json:
            print('[~] OB3 signature is internally consistent for %s, but it was '
                  'verified against a key resolved from the credential\'s own '
                  'did:key. This does NOT prove issuer identity. Supply --pubkey '
                  'FILE / --local BADGE, or anchor a did:web issuer, to establish '
                  'trust.' % args.receptor)

    _finish(args, result)


if __name__ == '__main__':
    main()
