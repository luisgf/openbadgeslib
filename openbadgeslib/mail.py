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

import smtplib
from os.path import basename
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

class BadgeMail():
    def __init__(self, smtp_server='localhost', smtp_port=25, use_ssl=False,
                 mail_from=None):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.use_ssl = use_ssl
        self.mail_from = mail_from

    def send_badge(self, send_to, subject, text, files=None):
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = self.mail_from
        msg['Date'] = formatdate(localtime=True)
        msg['To'] = COMMASPACE.join(send_to)

        msg.attach(MIMEText(text))

        for f in files or []:
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

            smtp.sendmail(self.mail_from, send_to, msg.as_string())
            #smtp.close()
            smtp.quit()
        except smtplib.SMTPDataError as err:
            print('[!] Error sending mail to: %s. %s' % (send_to, err))
            sys.exit(-1)

if __name__ == '__main__':
    pass
