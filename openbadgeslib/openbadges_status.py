#!/usr/bin/env python3

"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es

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

# `openbadges status` — read-only inspection of the issued OB3 credentials
# (#170).
#
# Asking whether a credential is revoked is a read, so it gets a read verb
# instead of riding on `publish`, whose every other flag writes: an operator
# auditing production should not have to type "publish" to answer "is this
# badge still valid?". The query itself is not duplicated — this command and
# `publish --list/--status` both call query_ob3().
#
# Unlike the other sub-commands this one has no openbadges-status alias script:
# the five openbadges-<command> scripts exist because they predate the unified
# front-end (#234), and a command born after it needs no legacy name.

import argparse

from .cli_common import (config_parser, debug_parser, json_parser,
                         version_parser)
from .logs import enable_debug_logging
from .openbadges_publish import query_ob3
from .util import emit_cli_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Inspect issued OpenBadges 3.0 credentials and their '
                    'revocation state. Read-only: it reads the private status '
                    'registries and never touches the published artefacts, so '
                    'it needs no output directory.',
        parents=[config_parser, debug_parser, json_parser, version_parser])
    parser.add_argument('credential_id', nargs='?', metavar='ID', default=None,
                        help='Credential to show — its jti (urn:uuid:...) or '
                             'recipient email, printed in full including the '
                             'revocation/suspension reason. Omit to tabulate '
                             'every issued credential and its state.')
    parser.add_argument('-b', '--badge',
                        help='Scope the query to one badge registry')
    return parser


def main() -> None:
    args = build_parser().parse_args()
    enable_debug_logging(args.debug)

    if args.json:
        emit_cli_json(
            lambda: query_ob3(args.config, args.badge, args.credential_id))
    else:
        query_ob3(args.config, args.badge, args.credential_id)


if __name__ == '__main__':
    main()
