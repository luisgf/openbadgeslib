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
import configparser
import logging
import sys
import os
import os.path
import time

from datetime import datetime
from typing import Any, Optional

from .keys import KeyType
from .confparser import read_config_or_exit, resolve_badge_section
from .logs import enable_debug_logging
# Badge (the config-driven badge model) is shared across all OB versions here,
# so it imports from the ob1 leaf module directly — reaching it through the
# deprecated openbadgeslib.ob1 package surface would warn. The genuinely
# OB1-only names (Signer, BadgeType) load lazily inside _sign_ob1.
from .ob1.badge import Badge
from .mail import BadgeMail
# Issuance orchestration lives in openbadgeslib.issue; this module is the CLI
# front end (flag parsing, I/O and display) over it.
from .issue import IssuanceError, issue_badge, output_basename
from .util import __version__, emit_cli_json

logger = logging.getLogger(__name__)

# Entry Point


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-c', '--config', default='config.ini', help='Specify the config.ini file to use')
    parser.add_argument('-b', '--badge', required=True, help='Specify the badge name for sign')
    parser.add_argument('-r', '--receptor', required=True, help='Specify the receptor email of the badge')
    parser.add_argument('-o', '--output', default=os.path.curdir,
                        help='Specify the output directory to save the badge.')
    parser.add_argument('-M', '--mail-badge', action='store_true', help='Send Badge to user mail')
    parser.add_argument('-H', '--hosted', action='store_true',
                        help="OB2 only (-V 2): use HostedBadge verification (publish the "
                             "assertion JSON at its own URL) instead of a SignedBadge JWS. "
                             "Requires 'hosted_assertions_base' in the badge config section.")
    parser.add_argument('-e', '--evidence', help='Set an URL to the user evidence')
    parser.add_argument('-E', '--no-evidence', action='store_true', help='Do not use evidence')
    parser.add_argument('-x', '--expires', type=int, help='Set badge expiration after x days.')
    parser.add_argument('-V', '--ob-version', choices=['1', '2', '3'], default='3',
                        metavar='VERSION',
                        help='OpenBadges specification version: 1 (legacy JWS), '
                             '2 (strict OB 2.0 JWS), or 3 (default, JWT-VC).')
    parser.add_argument('-P', '--proof-format', choices=['vc-jwt', 'ldp'],
                        metavar='FORMAT',
                        help="OB3 only (-V 3): proof format — 'vc-jwt' (compact "
                             "JWT-VC, the default) or 'ldp' (embedded W3C Data "
                             "Integrity proof, eddsa-rdfc-2022; needs an Ed25519 "
                             "key and the [ldp] extra). Overrides the badge's "
                             "'proof_format' config key.")
    parser.add_argument('-d', '--debug', action='store_true', help='Show debug messages in runtime.')
    parser.add_argument('--json', action='store_true',
                        help='Emit a machine-readable JSON result '
                             '{ob_version, badge_file, jti, status_index, '
                             'proof_format} instead of the human output. Exit '
                             'status: 0 on success, 1 on any error.')
    parser.add_argument('-v', '--version', action='version', version=__version__)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    enable_debug_logging(args.debug)
    if args.json:
        emit_cli_json(lambda: _run_sign(args))
        return
    _run_sign(args)


def _run_sign(args: argparse.Namespace) -> dict[str, Any]:
    """Sign one badge and return the machine-readable result (consumed by the
    --json path); the human output is printed as a side effect. Orchestration
    lives in openbadgeslib.issue — this is flag validation, I/O and display."""
    if bool(args.no_evidence) != (args.evidence is None):  # XOR
        sys.exit("Please, choose '-e' OR '-E'")

    if args.proof_format and args.ob_version != '3':
        sys.exit("[!] --proof-format applies to OpenBadges 3.0 only (-V 3)")

    evidence = args.evidence  # If no evidence, evidence=None

    # -b/--badge is required=True, so args.badge is always set here.
    logger.debug("Signing badge '%s' for %s (OB %s, output %s)",
                 args.badge, args.receptor, args.ob_version, args.output)
    conf = read_config_or_exit(args.config)
    badge = resolve_badge_section(conf, args.badge)
    badge_obj = Badge.create_from_conf(conf, badge)

    # The output filename and the already-signed check are resolved here (I/O),
    # before issuing, so a revocable OB3 badge does not burn a status-list index
    # only to then refuse to overwrite an existing file.
    try:
        fbase = output_basename(badge, args.receptor, badge_obj.image_type)
    except ValueError as exc:
        print('ERROR: %s' % exc)
        sys.exit(-1)

    badge_file_out = os.path.join(args.output, fbase)

    if os.path.isfile(badge_file_out):
        print('A %s OpenBadge has already signed for %s in %s' % (args.badge, args.receptor, badge_file_out))
        sys.exit(-1)

    if args.ob_version == '3':
        return _sign_ob3(args, conf, badge, badge_obj, badge_file_out, evidence)
    if args.ob_version == '2':
        return _sign_ob2(args, conf, badge, badge_obj, badge_file_out, evidence)
    return _sign_ob1(args, conf, badge, badge_obj, badge_file_out, evidence)


def _write_badge_and_log(conf: configparser.ConfigParser, badge_file_out: str,
                         badge_bytes: bytes, msg: str) -> None:
    """Persist the signed badge, append the audit line and print the location —
    the shared tail of every successful OB2/OB3 signing. A log-write failure is
    reported but does not lose the already-written badge."""
    with open(badge_file_out, 'wb') as f:
        f.write(badge_bytes)
    sign_log = os.path.join(conf['paths']['base_log'], conf['logs']['signer'])
    try:
        with open(sign_log, 'a') as file:
            file.write(msg + '\n')
    except OSError as err:
        print('[!] Could not write sign log: %s' % err)
    print('%s at: %s' % (msg, badge_file_out))


def _sign_ob2(args: argparse.Namespace, conf: configparser.ConfigParser, badge: str,
              badge_obj: Badge, badge_file_out: str,
              evidence: Optional[str]) -> dict[str, Any]:
    """Present a strict OpenBadges 2.0 signing: orchestrate via issue_badge,
    then write the badge, append the audit line, publish the hosted assertion
    JSON and report. Historical OB2 error convention: the message is the exit
    argument (status 1)."""
    try:
        result = issue_badge(conf, badge, args.receptor, badge_obj, '2',
                             evidence=evidence, expires=args.expires,
                             hosted=args.hosted)
    except IssuanceError as exc:
        sys.exit('[!] %s' % exc)

    msg = '%s %s OB2 SIGNED for %s' % (
        datetime.today().isoformat(), badge, args.receptor)
    _write_badge_and_log(conf, badge_file_out, result.badge_bytes, msg)

    if args.hosted and result.hosted_json is not None:
        hosted_out = os.path.splitext(badge_file_out)[0] + '.assertion.json'
        with open(hosted_out, 'w', encoding='ascii') as f:
            f.write(result.hosted_json)
        print('[i] Publish the hosted assertion JSON %s on your web server so it '
              'is retrievable at: %s' % (hosted_out, result.assertion_id))

    if args.mail_badge:
        print('[i] --mail-badge is not supported for -V 2 yet; the badge was saved '
              'but not emailed.')
    out: dict[str, Any] = {'ob_version': '2', 'badge_file': badge_file_out}
    if args.hosted:
        out['assertion_id'] = result.assertion_id
    return out


def _sign_ob1(args: argparse.Namespace, conf: configparser.ConfigParser, badge: str,
              badge_obj: Badge, badge_file_out: str,
              evidence: Optional[str]) -> dict[str, Any]:
    """Sign a badge using OpenBadges 1.0 (legacy JWS)."""
    from .ob1.signer import Signer
    from .ob1.badge import BadgeType

    print('[!] OpenBadges 1.0 (-V 1) is deprecated and will be removed in a '
          'future release; issue OB 2.0 (-V 2) or OB 3.0 (-V 3) instead.')

    if badge_obj.key_type not in (KeyType.RSA, KeyType.ECC):
        # The legacy JWS path predates Ed25519 support (RSA/ECC key objects).
        sys.exit('[!] OpenBadges 1.0 (-V 1) supports RSA and ECC keys only; '
                 '[%s] uses %s.' % (badge, badge_obj.key_type.value
                                    if badge_obj.key_type else 'no key'))
    if args.expires:
        expiration = int(time.time()) + args.expires * 86400
    else:
        expiration = None

    logger.debug("OB1 sign: key_type=%s image_type=%s expires=%s evidence=%s",
                 badge_obj.key_type, badge_obj.image_type, expiration, evidence)

    # Checking url reachability..
    if badge_obj.urls_has_problems():
        sys.exit(-1)

    sf = Signer(identity=args.receptor.encode('utf-8'), evidence=evidence,
                expiration=expiration, badge_type=BadgeType.SIGNED)
    badge_signed = sf.sign_badge(badge_obj)

    if badge_signed:
        # Persist the signed badge first, then append to the audit log. Writing
        # the log first and unguarded meant a missing/unwritable base_log raised
        # a raw OSError out of the CLI and lost the already-signed badge; mirror
        # the OB2 path — save, then log inside try/except.
        badge_signed.save_to_file(badge_file_out)

        sign_log = os.path.join(conf['paths']['base_log'], conf['logs']['signer'])
        msg = '%s %s SIGNED for %s UID %s' \
            % (datetime.today().isoformat(), badge,
               badge_signed.get_identity(), badge_signed.get_serial_num())
        try:
            with open(sign_log, 'a') as file:
                file.write(msg + '\n')
        except OSError as err:
            print('[!] Could not write sign log: %s' % err)

        if bool(args.mail_badge):
            try:
                server = conf['smtp']['smtp_server']
                port = int(conf['smtp']['smtp_port'])
                # configparser stores everything as strings; 'False' is truthy.
                use_ssl = conf['smtp'].getboolean('use_ssl', False)
                mail_from = conf['smtp']['mail_from']
                username = conf['smtp'].get('username')
                password = conf['smtp'].get('password')
                mail = BadgeMail(server, port, use_ssl, mail_from, username, password)
                subject, body = mail.get_mail_content(conf[badge]['mail'])
                mail.set_subject(subject)
                mail.set_body(body)
                mail.send(badge_signed)
            except (ValueError, OSError, KeyError) as err:
                # e.g. a missing [smtp] section or key (KeyError), a username
                # set without use_ssl=True (ValueError), or a missing/unreadable
                # mail template file (OSError) — the badge is already signed and
                # saved, so report the config error instead of crashing with a
                # traceback. The [smtp] reads are inside the try for that reason.
                print('[!] Could not send mail: %s' % err)

        print('%s at: %s' % (msg, badge_file_out))
        return {'ob_version': '1', 'badge_file': badge_file_out}

    sys.exit('[!] OpenBadges 1.0 signing produced no badge')


def _sign_ob3(args: argparse.Namespace, conf: configparser.ConfigParser, badge: str,
              badge_obj: Badge, badge_file_out: str,
              evidence: Optional[str]) -> dict[str, Any]:
    """Present an OpenBadges 3.0 signing: orchestrate via issue_badge, then
    write the badge, append the audit line and report. Historical OB3 error
    convention: the message is printed and the status is -1."""
    try:
        result = issue_badge(conf, badge, args.receptor, badge_obj, '3',
                             evidence=evidence, expires=args.expires,
                             proof_format=args.proof_format)
    except IssuanceError as exc:
        print('[!] %s' % exc)
        sys.exit(-1)

    # Informational hints (e.g. the self-asserted did:key warning for a non-DID
    # LDP issuer) precede the SIGNED line, as they did when printed mid-signing.
    for notice in result.notices:
        print('[i] %s' % notice)

    msg = '%s %s OB3 SIGNED for %s JTI %s' % (
        datetime.today().isoformat(), badge, args.receptor, result.jti)
    if result.proof_format == 'ldp':
        msg += ' PROOF ldp'
    if result.status_index is not None:
        msg += ' STATUS %d' % result.status_index
    _write_badge_and_log(conf, badge_file_out, result.badge_bytes, msg)

    if args.mail_badge:
        print('[i] --mail-badge is not supported for -V 3; the badge was saved '
              'but not emailed.')
    return {'ob_version': '3', 'badge_file': badge_file_out,
            'jti': result.jti, 'status_index': result.status_index,
            'proof_format': result.proof_format}


if __name__ == '__main__':
    main()
