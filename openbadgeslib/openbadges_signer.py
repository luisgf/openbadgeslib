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
import ntpath
import sys
import os
import os.path
import time

from datetime import datetime, timezone, timedelta
from typing import Optional

from .keys import detect_key_type, alg_for_key_type
from .errors import BadgeImgFormatUnsupported
from .confparser import read_config_or_exit, resolve_badge_section
from .logs import enable_debug_logging
from .ob1 import Signer, Badge, BadgeImgType, BadgeType
from .mail import BadgeMail
from .util import __version__, normalize_recipient_id

logger = logging.getLogger(__name__)

# Entry Point


def _safe_filename_component(value: str, field_name: str) -> str:
    if not value or value in ('.', '..') or '\x00' in value:
        raise ValueError('%s is not safe for use in an output filename' % field_name)
    if os.path.basename(value) != value or ntpath.basename(value) != value:
        raise ValueError('%s must not contain path separators' % field_name)
    return value


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
    parser.add_argument('-d', '--debug', action='store_true', help='Show debug messages in runtime.')
    parser.add_argument('-v', '--version', action='version', version=__version__)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    enable_debug_logging(args.debug)

    if bool(args.no_evidence) != (args.evidence is None):  # XOR
        sys.exit("Please, choose '-e' OR '-E'")

    evidence = args.evidence  # If no evidence, evidence=None

    if args.badge:
        logger.debug("Signing badge '%s' for %s (OB %s, output %s)",
                     args.badge, args.receptor, args.ob_version, args.output)
        conf = read_config_or_exit(args.config)
        badge = resolve_badge_section(conf, args.badge)
        try:
            safe_badge = _safe_filename_component(badge, 'badge')
            safe_receptor = _safe_filename_component(args.receptor, 'receptor')
        except ValueError as exc:
            print('ERROR: %s' % exc)
            sys.exit(-1)

        badge_obj = Badge.create_from_conf(conf, badge)

        if badge_obj.image_type is BadgeImgType.PNG:
            fbase = '%s_%s.png' % (safe_badge, safe_receptor)
        elif badge_obj.image_type is BadgeImgType.SVG:
            fbase = '%s_%s.svg' % (safe_badge, safe_receptor)
        else:
            raise BadgeImgFormatUnsupported(
                'Unsupported image type: %r' % (badge_obj.image_type,))

        badge_file_out = os.path.join(args.output, fbase)

        if os.path.isfile(badge_file_out):
            print('A %s OpenBadge has already signed for %s in %s' % (args.badge, args.receptor, badge_file_out))
            sys.exit(-1)

        if args.ob_version == '3':
            _sign_ob3(args, conf, badge, badge_obj, badge_file_out, evidence)
        elif args.ob_version == '2':
            _sign_ob2(args, conf, badge, badge_obj, badge_file_out, evidence)
        else:
            _sign_ob1(args, conf, badge, badge_obj, badge_file_out, evidence)


def _sign_ob2(args: argparse.Namespace, conf: configparser.ConfigParser, badge: str,
              badge_obj: Badge, badge_file_out: str, evidence: Optional[str]) -> None:
    """Sign a badge using strict OpenBadges 2.0 (SignedBadge JWS or HostedBadge)."""
    import json
    import uuid
    from urllib.parse import urljoin
    from .ob2 import OB2Signer, Assertion, IdentityObject, Verification

    badge_section = conf[badge]

    # create_from_conf always populates these for a valid badge section.
    assert (badge_obj.json_url is not None and badge_obj.key_type is not None
            and badge_obj.image is not None and badge_obj.privkey_pem is not None)

    # Recipient: hashed email + a fresh random salt.
    salt = os.urandom(16).hex()
    recipient = IdentityObject.create(args.receptor, salt=salt)

    if args.hosted:
        hosted_base = badge_section.get('hosted_assertions_base')
        if not hosted_base:
            sys.exit("[!] -V 2 -H (hosted) requires 'hosted_assertions_base' in the "
                     "badge's config section.")
        base = hosted_base if hosted_base.endswith('/') else hosted_base + '/'
        assertion_id: Optional[str] = urljoin(base, '%s.json' % uuid.uuid4().hex)
        verification = Verification(type='HostedBadge')
    else:
        creator = badge_section.get('crypto_key')
        if not creator:
            sys.exit("[!] -V 2 (signed) requires 'crypto_key' (the CryptographicKey URL) "
                     "in the badge's config section.")
        assertion_id = None   # auto-generated as urn:uuid:…
        verification = Verification(type='SignedBadge', creator=creator)

    issued_on = datetime.now(tz=timezone.utc)
    expires = issued_on + timedelta(days=args.expires) if args.expires else None

    assertion = Assertion(
        recipient=recipient,
        badge=badge_obj.json_url,
        verification=verification,
        id=assertion_id,
        issued_on=issued_on,
        expires=expires,
        image=badge_obj.image_url,
        evidence=evidence,
    )

    algorithm = alg_for_key_type(badge_obj.key_type)
    logger.debug("OB2 sign: key_type=%s algorithm=%s hosted=%s image_type=%s",
                 badge_obj.key_type, algorithm, args.hosted, badge_obj.image_type)

    signer = OB2Signer(privkey_pem=badge_obj.privkey_pem, algorithm=algorithm)
    if badge_obj.image_type is BadgeImgType.SVG:
        signed_bytes = signer.sign_into_svg(assertion, badge_obj.image)
    else:
        signed_bytes = signer.sign_into_png(assertion, badge_obj.image)

    with open(badge_file_out, 'wb') as f:
        f.write(signed_bytes)

    msg = '%s %s OB2 SIGNED for %s' % (datetime.today().isoformat(), badge, args.receptor)
    sign_log = os.path.join(conf['paths']['base_log'], conf['logs']['signer'])
    try:
        with open(sign_log, 'a') as file:
            file.write(msg + '\n')
    except OSError as err:
        print('[!] Could not write sign log: %s' % err)
    print('%s at: %s' % (msg, badge_file_out))

    if args.hosted:
        hosted_out = os.path.splitext(badge_file_out)[0] + '.assertion.json'
        with open(hosted_out, 'w', encoding='ascii') as f:
            f.write(json.dumps(assertion.to_dict(), sort_keys=True, ensure_ascii=True))
        print('[i] Publish the hosted assertion JSON %s on your web server so it is '
              'retrievable at: %s' % (hosted_out, assertion.id))

    if args.mail_badge:
        print('[i] --mail-badge is not supported for -V 2 yet; the badge was saved '
              'but not emailed.')


def _sign_ob1(args: argparse.Namespace, conf: configparser.ConfigParser, badge: str,
              badge_obj: Badge, badge_file_out: str, evidence: Optional[str]) -> None:
    """Sign a badge using OpenBadges 1.0 (legacy JWS)."""
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
            server = conf['smtp']['smtp_server']
            port = int(conf['smtp']['smtp_port'])
            # configparser stores everything as strings; 'False' would be truthy.
            use_ssl = conf['smtp'].getboolean('use_ssl', False)
            mail_from = conf['smtp']['mail_from']
            username = conf['smtp'].get('username')
            password = conf['smtp'].get('password')

            try:
                mail = BadgeMail(server, port, use_ssl, mail_from, username, password)
                subject, body = mail.get_mail_content(conf[badge]['mail'])
                mail.set_subject(subject)
                mail.set_body(body)
                mail.send(badge_signed)
            except (ValueError, OSError, KeyError) as err:
                # e.g. a username set without use_ssl=True (ValueError), a
                # missing/unreadable mail template file (OSError), or a badge
                # section with no 'mail' key (KeyError) — the badge is already
                # signed and saved, so report the config error instead of
                # crashing with a traceback.
                print('[!] Could not send mail: %s' % err)

        print('%s at: %s' % (msg, badge_file_out))


def _sign_ob3(args: argparse.Namespace, conf: configparser.ConfigParser, badge: str,
              badge_obj: Badge, badge_file_out: str, evidence: Optional[str]) -> None:
    """Sign a badge using OpenBadges 3.0 (JWT-VC)."""
    from .ob3 import OB3Signer, Issuer, Achievement, OpenBadgeCredential
    from .confparser import ob3_issuer_id, ob3_status_config

    issuer_section = conf['issuer']
    try:
        issuer_id = ob3_issuer_id(conf)
        status_conf = ob3_status_config(conf, badge)
    except ValueError as exc:
        print('[!] %s' % exc)
        sys.exit(-1)

    issuer = Issuer(
        id=issuer_id,
        name=issuer_section['name'],
        url=issuer_section.get('url'),
        email=issuer_section.get('email'),
    )

    badge_section = conf[badge]
    criteria_narrative = badge_section.get('criteria_narrative',
                                           badge_section.get('criteria', ''))
    achievement = Achievement(
        id=badge_section['badge'],
        name=badge_section['name'],
        description=badge_section['description'],
        criteria_narrative=criteria_narrative,
        image_url=badge_section.get('image'),
    )

    recipient_id = normalize_recipient_id(args.receptor)

    expiration_date = None
    if args.expires:
        expiration_date = datetime.now(tz=timezone.utc) + timedelta(days=args.expires)

    credential = OpenBadgeCredential(
        issuer=issuer,
        recipient_id=recipient_id,
        achievement=achievement,
        evidence_url=evidence,
        expiration_date=expiration_date,
    )

    status_index = None
    if status_conf is not None:
        from .errors import StatusError
        from .ob3.status_list import status_entry
        from .ob3.status_registry import StatusRegistry

        # The registry is persisted BEFORE the badge is signed and written:
        # a signing failure leaves a harmless orphan index, while a delivered
        # badge missing from the registry could never be revoked.
        try:
            registry = StatusRegistry.load(status_conf.registry_path,
                                           status_conf.size_bits)
            assert credential.id is not None \
                and credential.issuance_date is not None
            status_index = registry.allocate(credential.id, recipient_id,
                                             credential.issuance_date)
            registry.save()
        except (StatusError, OSError) as exc:
            print('[!] Could not allocate a status list index: %s' % exc)
            sys.exit(-1)
        credential.credential_status = [
            status_entry(status_conf.list_urls[p], p, status_index)
            for p in status_conf.purposes]

    # create_from_conf always populates these from the badge config section.
    assert badge_obj.privkey_pem is not None and badge_obj.image is not None

    key_type = detect_key_type(badge_obj.privkey_pem)
    algorithm = alg_for_key_type(key_type)
    logger.debug("OB3 sign: key_type=%s algorithm=%s recipient=%s",
                 key_type, algorithm, recipient_id)

    signer = OB3Signer(privkey_pem=badge_obj.privkey_pem, algorithm=algorithm)

    if badge_obj.image_type is BadgeImgType.SVG:
        signed_bytes = signer.sign_into_svg(credential, badge_obj.image)
    else:
        signed_bytes = signer.sign_into_png(credential, badge_obj.image)

    with open(badge_file_out, 'wb') as f:
        f.write(signed_bytes)

    msg = '%s %s OB3 SIGNED for %s JTI %s' % (
        datetime.today().isoformat(), badge, args.receptor, credential.id)
    if status_index is not None:
        msg += ' STATUS %d' % status_index
    sign_log = os.path.join(conf['paths']['base_log'], conf['logs']['signer'])
    try:
        with open(sign_log, 'a') as file:
            file.write(msg + '\n')
    except OSError as err:
        print('[!] Could not write sign log: %s' % err)
    print('%s at: %s' % (msg, badge_file_out))


if __name__ == '__main__':
    main()
