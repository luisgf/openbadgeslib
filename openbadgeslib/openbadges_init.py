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
import os
import os.path
import sys
import shutil

from .cli_common import version_parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Create an OpenBadges working directory (keys/, images/, '
                    'log/, status/ and a config.ini stub)',
        parents=[version_parser])
    parser.add_argument('directory', metavar='DIRECTORY',
                        help='Directory to create and populate; it must not '
                             'already exist.')
    return parser


def main() -> None:
    directory = build_parser().parse_args().directory

    if os.path.lexists(directory):
        sys.exit('[!] %s already exists' % directory)

    umask = os.umask(0o077)  # rwx------
    try:
        os.mkdir(directory)
        for subdir in ['keys', 'images', 'log', 'status']:
            os.mkdir(os.path.join(directory, subdir))
    finally:
        os.umask(umask)

    source = os.path.join(os.path.dirname(__file__), 'config.ini.example')
    destination = os.path.join(directory, 'config.ini')
    shutil.copyfile(source, destination)


if __name__ == '__main__':
    main()
