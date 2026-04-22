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
import sys
import os
import os.path
import time

from datetime import datetime, timezone, timedelta

from .keys import KeyType, detect_key_type
from .signer import Signer
from .errors import LibOpenBadgesException, SignerExceptions
from .confparser import ConfParser
from .badge import Badge, BadgeImgType, BadgeType
from .mail import BadgeMail
from .util import __version__

# Entry Point


def main():
    parser = argparse.ArgumentParser(description='Badge Signer Parameters')
    parser.add_argument('-c', '--config', default='config.ini', help='Specify the config.ini file to use')
    parser.add_argument('-b', '--badge', required=True, help='Specify the badge name for sign')
    parser.add_argument('-r', '--receptor', required=True, help='Specify the receptor email of the badge')
    parser.add_argument('-o', '--output', default=os.path.curdir,
                        help='Specify the output directory to save the badge.')
    parser.add_argument('-M', '--mail-badge', action='store_true', help='Send Badge to user mail')
    parser.add_argument('-e', '--evidence', help='Set an URL to the user evidence')
    parser.add_argument('-E', '--no-evidence', action='store_true', help='Do not use evidence')
    parser.add_argument('-x', '--expires', type=int, help='Set badge expiration after x days.')
    parser.add_argument('-V', '--ob-version', choices=['2', '3'], default='2',
                        metavar='VERSION',
                        help='OpenBadges specification version: 2 (default, JWS) or 3 (JWT-VC).')
    parser.add_argument('-d', '--debug', action='store_true', help='Show debug messages in runtime.')
    parser.add_argument('-v', '--version', action='version', version=__version__)
    args = parser.parse_args()

    if bool(args.no_evidence) != (args.evidence is None):  # XOR
        sys.exit("Please, choose '-e' OR '-E'")

    evidence = args.evidence  # If no evidence, evidence=None

    if args.badge:
        cf = ConfParser(args.config)
        conf = cf.read_conf()

        badge = 'badge_' + args.badge

        if not conf:
            print('ERROR: The config file %s NOT exists or is empty' % args.config)
            sys.exit(-1)

        if badge not in conf:
            print('ERROR: %s is not defined in this config file' % args.badge)
            sys.exit(-1)

        try:
            badge_obj = Badge.create_from_conf(conf, badge)

            if badge_obj.image_type is BadgeImgType.PNG:
                fbase = '%s_%s.png' % (badge, args.receptor)
            elif badge_obj.image_type is BadgeImgType.SVG:
                fbase = '%s_%s.svg' % (badge, args.receptor)

            badge_file_out = os.path.join(args.output, fbase)

            if os.path.isfile(badge_file_out):
                print('A %s OpenBadge has already signed for %s in %s' % (args.badge, args.receptor, badge_file_out))
                sys.exit(-1)

            if args.ob_version == '3':
                _sign_ob3(args, conf, badge, badge_obj, badge_file_out, evidence)
            else:
                _sign_ob2(args, conf, badge, badge_obj, badge_file_out, evidence)

        except SignerExceptions:
            raise
        except LibOpenBadgesException:
            raise


def _sign_ob2(args, conf, badge, badge_obj, badge_file_out, evidence):
    """Sign a badge using OpenBadges 2.0 (JWS)."""
    if args.expires:
        expiration = int(time.time()) + args.expires * 86400
    else:
        expiration = None

    # Checking url reachability..
    if badge_obj.urls_has_problems():
        sys.exit(-1)

    sf = Signer(identity=args.receptor.encode('utf-8'), evidence=evidence,
                expiration=expiration, badge_type=BadgeType.SIGNED)
    badge_signed = sf.sign_badge(badge_obj)

    if badge_signed:
        sign_log = os.path.join(conf['paths']['base_log'], conf['logs']['signer'])
        msg = '%s %s SIGNED for %s UID %s\n' \
            % (datetime.today().isoformat(), badge,
               badge_signed.get_identity(), badge_signed.get_serial_num())

        with open(sign_log, 'w') as file:
            file.write(msg)

        badge_signed.save_to_file(badge_file_out)

        if bool(args.mail_badge):
            server = conf['smtp']['smtp_server']
            port = conf['smtp']['smtp_port']
            use_ssl = conf['smtp']['use_ssl']
            mail_from = conf['smtp']['mail_from']
            username = conf['smtp'].get('username')
            password = conf['smtp'].get('password')

            mail = BadgeMail(server, port, use_ssl, mail_from, username, password)
            subject, body = mail.get_mail_content(conf[badge]['mail'])
            mail.set_subject(subject)
            mail.set_body(body)
            mail.send(badge_signed)

        print('%s at: %s' % (msg.strip('\n'), badge_file_out))


def _sign_ob3(args, conf, badge, badge_obj, badge_file_out, evidence):
    """Sign a badge using OpenBadges 3.0 (JWT-VC)."""
    from .ob3 import OB3Signer, Issuer, Achievement, OpenBadgeCredential

    issuer_section = conf['issuer']
    issuer_id = issuer_section.get('publish_url', issuer_section.get('url', ''))

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

    recipient_id = args.receptor
    if not recipient_id.startswith('mailto:'):
        recipient_id = 'mailto:' + recipient_id

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

    key_type = detect_key_type(badge_obj.privkey_pem)
    algorithm = 'RS256' if key_type is KeyType.RSA else 'ES256'

    signer = OB3Signer(privkey_pem=badge_obj.privkey_pem, algorithm=algorithm)

    if badge_obj.image_type is BadgeImgType.SVG:
        signed_bytes = signer.sign_into_svg(credential, badge_obj.image)
    else:
        signed_bytes = signer.sign_into_png(credential, badge_obj.image)

    with open(badge_file_out, 'wb') as f:
        f.write(signed_bytes)

    msg = '%s %s OB3 SIGNED for %s' % (datetime.today().isoformat(), badge, args.receptor)
    print('%s at: %s' % (msg, badge_file_out))


if __name__ == '__main__':
    main()
