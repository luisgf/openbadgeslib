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

# Unified ``openbadges <command>`` front-end (#234).
#
# One entry point dispatches to the five console tools, which stay available
# under their own names as aliases. The dispatch is deliberately thin: a
# sub-command owns everything after its name, so this shell only recognises the
# command, then hands the rest to that tool's own main() unchanged — the tool
# re-parses via its build_parser(), so `openbadges sign ...` behaves exactly
# like `openbadges-signer ...` (same flags, output and 0/1/2 exit status).
#
# `status` is the one command with no openbadges-status alias: the five aliases
# exist because they predate this front-end, and a command born after it needs
# no legacy name. Dispatch is unchanged — it too is a module with a main().

import argparse
import importlib
import sys

from typing import Dict, Tuple

from .cli_common import version_parser

#: sub-command -> (module implementing main(), one-line summary for --help).
COMMANDS: Dict[str, Tuple[str, str]] = {
    'init': ('openbadgeslib.openbadges_init',
             'Create an OpenBadges working directory'),
    'keygen': ('openbadgeslib.openbadges_keygenerator',
               'Generate a key pair for a badge section'),
    'sign': ('openbadgeslib.openbadges_signer',
             'Issue (sign) a badge for one or more recipients'),
    'verify': ('openbadgeslib.openbadges_verifier',
               'Verify a badge and report issuer trust'),
    'publish': ('openbadgeslib.openbadges_publish',
                'Publish OB3 artefacts and manage credential status'),
    'status': ('openbadgeslib.openbadges_status',
               'Inspect issued OB3 credentials and their revocation state'),
}


def build_parser() -> argparse.ArgumentParser:
    """The top-level shell parser.

    Each sub-command is registered thin (no flags, add_help=False): it exists so
    the command is a valid choice and shows up in ``openbadges --help``, while
    everything after the command name is left for the target tool to parse.
    """
    parser = argparse.ArgumentParser(
        prog='openbadges',
        description='OpenBadges toolkit — issue, verify and publish Open '
                    'Badges. Every command except "status" is also installed '
                    'as its own openbadges-<command> script.',
        epilog='Run "openbadges COMMAND --help" for a command\'s own options.',
        parents=[version_parser])
    sub = parser.add_subparsers(dest='command', metavar='COMMAND')
    for name, (_module, summary) in COMMANDS.items():
        sub.add_parser(name, help=summary, add_help=False)
    return parser


def main() -> None:
    parser = build_parser()
    # Only the command is parsed here; its arguments ride along in *rest* and go
    # to the target tool untouched (parse_known_args collects them).
    args, rest = parser.parse_known_args()
    if args.command is None:
        parser.print_help(sys.stderr)
        sys.exit(2)

    module = importlib.import_module(COMMANDS[args.command][0])
    # Present the tool with an argv as if invoked directly, so its build_parser
    # prog/usage reads "openbadges <command>" and it parses only its own flags.
    sys.argv = ['openbadges %s' % args.command, *rest]
    module.main()


if __name__ == '__main__':
    main()
