#!/usr/bin/env python3
"""
        OpenBadges Library

        Copyright (c) 2014, Luis González Fernández, luisgf@luisgf.es
        Copyright (c) 2014, Jesús Cea Avión, jcea@jcea.es

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

import smtplib, sys
from os.path import basename
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from email.header import Header

class BadgeMail():
    def __init__(self, smtp_server='localhost', smtp_port=25, use_ssl=False,
                 mail_from=None):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.use_ssl = use_ssl
        self.mail_from = mail_from

    def send(self, mail_to, subject, body, files=[]):
        msg = MIMEMultipart()
        msg['Subject'] = Header(subject, 'utf-8')
        msg['From'] = Header(self.mail_from, 'utf-8')
        msg['Date'] = formatdate(localtime=True)
        msg['To'] = Header(mail_to, 'utf-8')

        msg.attach(MIMEText(body,'plain','utf-8'))

        """ Support for sending more than one file attached """
        for f in files:
            with open(f, "rb") as file:
                msg.attach(MIMEImage(
                    file.read(),
                    Content_Disposition='attachment; filename="%s"' % basename(f)
                ))
        try:
            if self.use_ssl:
                smtp = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            else:
                smtp = smtplib.SMTP(self.smtp_server, self.smtp_port)

            smtp.sendmail(self.mail_from, mail_to, msg.as_string())
            smtp.quit()
        except smtplib.SMTPDataError as err:
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


if __name__ == '__main__':
    pass

