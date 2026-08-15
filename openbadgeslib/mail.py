#!/usr/bin/env python3
"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es
        Copyright (c) 2014-2026, Jesús Cea Avión, jcea@jcea.es

        All rights reserved.

        This library is free software; you can redistribute it and/or
        modify it under the terms of the GNU Lesser General Public
        License as published by the Free Software Foundation; either
        version 3.0 of the License, or (at your option) any later version.

        This library is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
        Lesser General Public License for more details.

        You should have received a copy of the GNU Lesser General Public
        License along with this library.
"""

import ssl
from typing import Any, Optional, Tuple
from smtplib import SMTP_SSL, SMTP, SMTPException
from os.path import basename
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
from email.header import Header
from .badge_model import BadgeImgType   # version-neutral model (was ob1.badge)
from .errors import BadgeImgFormatUnsupported


class BadgeMail():
    def __init__(self, smtp_server: str = 'localhost', smtp_port: int = 25,
                 use_ssl: bool = False, mail_from: Optional[str] = None,
                 username: Optional[str] = None,
                 password: Optional[str] = None) -> None:
        if username and not use_ssl:
            raise ValueError('SMTP authentication requires use_ssl=True')
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.use_ssl = use_ssl
        self.mail_from: Any = mail_from
        self.username: Any = username
        self.password: Any = password
        self.subject: Any = None
        self.body: Any = None

    def send(self, badge: Any) -> None:
        msg: Any = MIMEMultipart()
        msg['Subject'] = Header(self.subject, 'utf-8')
        msg['From'] = Header(self.mail_from, 'utf-8')
        msg['Date'] = formatdate(localtime=True)
        msg['To'] = Header(badge.get_identity(), 'utf-8')

        msg.attach(MIMEText(self.body, 'plain', 'utf-8'))

        if badge.source.image_type is BadgeImgType.SVG:
            mime_type = 'svg+xml'
        elif badge.source.image_type is BadgeImgType.PNG:
            mime_type = 'png'
        else:
            raise BadgeImgFormatUnsupported(
                'Unsupported image type: %r' % (badge.source.image_type,))

        image = MIMEImage(badge.source.image, _subtype=mime_type)
        # Keyword form so the filename is RFC 2231 encoded, never interpolated
        # into the header value as raw bytes (#316).
        image.add_header('Content-Disposition', 'attachment',
                         filename=basename(badge.file_out))
        image.add_header('Content-Description', 'Signed OpenBadge')
        msg.attach(image)

        try:
            smtp: Any
            if self.use_ssl:
                # Validate the server certificate and hostname. SMTP_SSL's
                # default context does neither (check_hostname=False,
                # CERT_NONE), which would let an on-path attacker intercept the
                # connection and capture the AUTH credentials sent below.
                smtp = SMTP_SSL(self.smtp_server, self.smtp_port,
                                context=ssl.create_default_context())
            else:
                smtp = SMTP(self.smtp_server, self.smtp_port)

            if self.username:
                smtp.login(self.username, self.password)

            smtp.sendmail(self.mail_from, badge.get_identity(), msg.as_string())
            smtp.quit()
        except (SMTPException, OSError, ValueError) as err:
            # Connection refused, DNS failure, TLS mismatch, SMTP protocol
            # errors, a failed AUTH (SMTPAuthenticationError is an
            # SMTPException), or a CR/LF in mail_from/recipient (smtplib
            # itself raises a bare ValueError as its header-injection guard) —
            # the badge is already signed and saved, so report the mail
            # failure instead of killing the caller's process. This method is
            # library code: it must never call sys.exit / raise SystemExit.
            print('[!] Error sending mail to: %s. %s' % (badge.get_identity(), err))

    def get_mail_content(self, file: str) -> Tuple[Optional[str], Optional[str]]:
        """ Return the Subject and Body of the Email. The first line of the file
        is used as Subject """

        with open(file, 'r') as f:
            data = f.readlines()

        if data:
            return data[0].strip('\n'), ''.join(data[1:])
        else:
            return None, None

    def set_subject(self, subject: Optional[str]) -> None:
        self.subject = subject

    def set_body(self, body: Optional[str]) -> None:
        self.body = body


if __name__ == '__main__':
    pass
