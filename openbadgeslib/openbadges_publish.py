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
import json
import os, os.path, sys, shutil

from urllib.parse import urljoin
from .confparser import ConfParser
from .util import __version__

def main():
    parser = argparse.ArgumentParser(description='Publisher Parameters')
    parser.add_argument('-c', '--config', default='config.ini', help='Specify the config.ini file to use')
    parser.add_argument('-o', '--output', required=True, help='Specify the output directory to save the public files')
    parser.add_argument('-v', '--version', action='version', version=__version__ )
    args = parser.parse_args()

    cf = ConfParser(args.config)
    conf = cf.read_conf()

    if args.output:
        if os.path.lexists(args.output) :
            raise FileExistsError(args.output)

        umask = os.umask(0o077)  # rwx------
        os.mkdir(args.output)

        issuer = create_issuer_json(conf)
        issuer_file = os.path.join(args.output, 'organization.json')
        with open(issuer_file, "w", encoding='ascii') as f:
            f.write(issuer)

        revocation = create_revocation_json(conf)
        revocation_file = os.path.join(args.output, 'revocation.json')
        with open(revocation_file, "w", encoding='ascii') as f:
            f.write(revocation)

        try:
            badgeid = 1

            while conf['badge_%d' % badgeid]:
                badge_name = 'badge_%d' % badgeid
                badge_path = os.path.join(args.output, conf[badge_name].name)
                badge_file = os.path.join(badge_path, 'badge.json')

                os.mkdir(badge_path)
                with open(badge_file, "w", encoding='ascii') as f:
                    f.write(create_badge_json(conf, badge_name))

                """ Copy the verify keys """
                source = conf['keys']['public']
                destination = os.path.join(badge_path, 'verify.pem')
                shutil.copyfile(source, destination)

                badgeid += 1
        except KeyError:
            pass

        os.umask(umask)

        print('Please configure your Web server to publish the folder %s as %s' % (args.output, conf['issuer']['publish_url']))

    else:
        parser.print_help()

def create_issuer_json(conf):
    publish_url = conf['issuer']['publish_url']
    image_url = urljoin(publish_url, conf['issuer']['image'])
    rev_url = urljoin(publish_url, conf['issuer']['revocationList'])

    issuer = dict(url = conf['issuer']['url'],
            email = conf['issuer']['email'],
            name = conf['issuer']['name'],
            revocationList = rev_url,
            image = image_url)

    return json.dumps(issuer, sort_keys=True, ensure_ascii=True)

def create_revocation_json(conf):
    return json.dumps(dict(), sort_keys=True, ensure_ascii=True)

def create_badge_json(conf, badge_name):
    publish_url = conf['issuer']['publish_url']
    image_url = urljoin(publish_url, conf[badge_name]['image'])
    issuer_url = urljoin(publish_url, 'organization.json')

    badge = dict(image = image_url, criteria = conf[badge_name]['criteria'],
                name = conf[badge_name]['name'],
                description = conf[badge_name]['description'],
                issuer = issuer_url)

    return json.dumps(badge, sort_keys=True, ensure_ascii=True)

if __name__ == '__main__':
    main()
