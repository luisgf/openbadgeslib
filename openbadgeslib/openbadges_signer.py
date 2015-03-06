#!/usr/bin/env python3

"""
    Copyright (c) 2015, Luis González Fernández - luisgf@luisgf.es
    Copyright (c) 2015, Jesús Cea Avión - jcea@jcea.es

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
import sys, os, os.path, time

from datetime import datetime

from .logs import Logger
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
    parser.add_argument('-o', '--output', default=os.path.curdir, help='Specify the output directory to save the badge.')
    parser.add_argument('-M', '--mail-badge', action='store_true', help='Send Badge to user mail')
    parser.add_argument('-e', '--evidence', help='Set an URL to the user evidence')
    parser.add_argument('-E', '--no-evidence', action='store_true', help='Do not use evidence')
    parser.add_argument('-x', '--expires', type=int, help='Set badge expiration after x days.')
    parser.add_argument('-d', '--debug', action='store_true', help='Show debug messages in runtime.')
    parser.add_argument('-v', '--version', action='version', version=__version__ )
    args = parser.parse_args()

    if bool(args.no_evidence) != (args.evidence is None) :  # XOR
        sys.exit("Please, choose '-e' OR '-E'")

    evidence = args.evidence  # If no evidence, evidence=None

    if args.expires:
        expiration = int(time.time()) + args.expires*86400
    else:
        expiration = None

    if args.badge:
        cf = ConfParser(args.config)
        conf = cf.read_conf()

        badge = 'badge_' + args.badge

        if not conf:
            print('ERROR: The config file %s NOT exists or is empty' % args.config)
            sys.exit(-1)

        if not badge in conf:
            print('ERROR: %s is not defined in this config file' % args.badge)
            sys.exit(-1)

        try:
            sf = Signer(identity=args.receptor.encode('utf-8'), evidence=evidence,
                        expiration=expiration, badge_type=BadgeType.SIGNED)

            badge_obj = Badge.create_from_conf(conf, badge)

            if badge_obj.image_type is BadgeImgType.PNG:
                fbase = '%s_%s.png' % (badge, args.receptor)
            elif badge_obj.image_type is BadgeImgType.SVG:
                fbase = '%s_%s.svg' % (badge, args.receptor)

            badge_file_out = os.path.join(args.output, fbase)

            if os.path.isfile(badge_file_out):
                print('A %s OpenBadge has already signed for %s in %s' % (args.badge, args.receptor, badge_file_out))
                sys.exit(-1)

            print("Generating signature for badge '%s'..." % args.badge)

            badge_signed = sf.sign_badge(badge_obj)

            if badge_signed:
                sign_log = os.path.join(conf['paths']['base_log'], conf['logs']['signer'])
                # Date in ISO-8601 Format
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
                    login = None
                    password = None

                    if 'username' in conf['smtp']:
                        username = conf['smtp']['username']

                    if 'password' in conf['smtp']:
                        password = conf['smtp']['password']

                    mail = BadgeMail(server, port, use_ssl, mail_from, username,
                                     password)
                    subject, body = mail.get_mail_content(conf[badge]['mail'])
                    mail.set_subject(subject)
                    mail.set_body(body)
                    mail.send(badge_signed)

        except SignerExceptions:
            raise
        except LibOpenBadgesException:
            raise

if __name__ == '__main__':
    main()

