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

# Shared argparse parent parsers for the console tools (#234).
#
# The five entry points each defined the same handful of flags independently,
# with drifting help text and gaps: -c/--config four times, --json four times
# with divergent help, -d/--debug worded two ways and missing from
# openbadges-publish, -v/--version missing from openbadges-init. These
# add_help=False parent parsers centralise them so every build_parser()
# composes one consistent definition via ``parents=[...]``; command-specific
# flags (-b, -r, -o, -V/--ob-version, ...) stay in each tool.
#
# The parsers are module-level singletons: argparse copies a parent's actions
# into each child at construction, so reusing one instance across all five
# build_parser()s is the documented pattern and holds no per-parser state.

import argparse

from .util import __version__

#: -c/--config — the INI file every config-driven tool reads.
config_parser = argparse.ArgumentParser(add_help=False)
config_parser.add_argument('-c', '--config', default='config.ini',
                           help='Specify the config.ini file to use')

#: -d/--debug — turn on debug logging (see logs.enable_debug_logging).
debug_parser = argparse.ArgumentParser(add_help=False)
debug_parser.add_argument('-d', '--debug', action='store_true',
                          help='Show debug messages at runtime.')

#: --json — machine-readable output. The exit-status contract is uniform across
#: the tools (0 success, 2 partial success, 1 any error; see #233); the shape
#: of the emitted JSON object is command-specific and documented per command.
json_parser = argparse.ArgumentParser(add_help=False)
json_parser.add_argument('--json', action='store_true',
                         help='Emit a machine-readable JSON result instead of '
                              'the human output. Exit status: 0 success, 2 '
                              'partial success, 1 any error.')

#: -v/--version — print the single-sourced library version and exit.
version_parser = argparse.ArgumentParser(add_help=False)
version_parser.add_argument('-v', '--version', action='version',
                            version=__version__)
