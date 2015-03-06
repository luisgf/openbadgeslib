#!/usr/bin/env python3
"""
        OpenBadges Library

        Copyright (c) 2015, Luis González Fernández, luisgf@luisgf.es
        Copyright (c) 2015, Jesús Cea Avión, jcea@jcea.es

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

import sys
from smtplib import SMTP_SSL, SMTP, SMTPAuthenticationError, SMTPDataError
from os.path import basename
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from email.header import Header
from .badge import BadgeImgType

class BadgeMail():
    def __init__(self, smtp_server='localhost', smtp_port=25, use_ssl=False,
                 mail_from=None, username=None, password=None):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.use_ssl = use_ssl
        self.mail_from = mail_from
        self.username = username
        self.password = password
        self.subject = None
        self.body = None

    def send(self, badge):
        msg = MIMEMultipart()
        msg['Subject'] = Header(self.subject, 'utf-8')
        msg['From'] = Header(self.mail_from, 'utf-8')
        msg['Date'] = formatdate(localtime=True)
        msg['To'] = Header(badge.get_identity(), 'utf-8')

        msg.attach(MIMEText(self.body,'plain','utf-8'))

        if badge.source.image_type is BadgeImgType.SVG:
            mime_type = 'svg+xml'
        elif badge.source.image_type is BadgeImgType.PNG:
            mime_type = 'png'

        image = MIMEImage(badge.source.image,
                          Content_Disposition='attachment; filename=%s' % basename(badge.file_out),
                          Content_Description='Signed OpenBadge',
                          _subtype=mime_type)
        msg.attach(image)

        try:
            if self.use_ssl:
                smtp = SMTP_SSL(self.smtp_server, self.smtp_port)
            else:
                smtp = SMTP(self.smtp_server, self.smtp_port)

            if self.username:
                try:
                    smtp.login(self.username, self.password)
                except SMTPAuthenticationError as err:
                    print('[!] SMTP Auth Error: %s' % err)
                    sys.exit(-1)

            smtp.sendmail(self.mail_from, badge.get_identity(), msg.as_string())
            smtp.quit()
        except SMTPDataError as err:
            print('[!] Error sending mail to: %s. %s' % (mail_to, err))

    def get_mail_content(self, file):
        """ Return the Subject and Body of the Email. The first line of the file
        is used as Subject """

        with open(file, 'r') as f:
            data = f.readlines()

        if data:
            return data[0].strip('\n'), ''.join(data[1:])
        else:
            return None, None

    def set_subject(self, subject):
        self.subject = subject

    def set_body(self, body):
        self.body = body

if __name__ == '__main__':
    pass

