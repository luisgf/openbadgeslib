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

from configparser import ConfigParser, ExtendedInterpolation
from typing import Optional
import os
import sys
import logging
logger = logging.getLogger(__name__)


def read_config_or_exit(config_file: str) -> ConfigParser:
    """Read a config file for a CLI tool, exiting with a clear message if it is
    missing or empty. Shared by all the console-script entrypoints."""
    conf = ConfParser(config_file).read_conf()
    if not conf:
        print('[!] The config file %s does not exist or is empty' % config_file)
        sys.exit(-1)
    return conf


def resolve_badge_section(conf: ConfigParser, name: str) -> str:
    """Return the ``badge_<name>`` section name, exiting if it is not defined."""
    section = 'badge_' + name
    if section not in conf:
        sys.exit('There is no "%s" badge in the configuration' % name)
    return section


class ConfParser():
    def __init__(self, config_file: str = 'config.ini') -> None:
        self.config_file = config_file

    def read_conf(self) -> Optional[ConfigParser]:
        if not os.path.isfile(self.config_file):
            return None

        self.parser = ConfigParser(interpolation=ExtendedInterpolation())

        try:
            self.parser.read(self.config_file)
        except UnicodeDecodeError:
            # We should raise an UnicodeDecodeError, but the error message is too cryptic.#
            raise ValueError("The encoding of the configuration file and the default encoding of "
                             "the operating system mismatch") from None
        try:
            base = self.parser['paths']['base']
        except KeyError:
            raise ValueError(
                "Configuration file %s is missing the [paths] section or its "
                "'base' key" % self.config_file) from None
        if not base:
            raise ValueError(
                "Configuration file %s has an empty [paths] 'base' value" % self.config_file)

        if base[0] == '.':
            abs_path = os.path.dirname(self.config_file)
            full_path = os.path.abspath(abs_path)
            self.parser['paths']['base'] = full_path
        return self.parser


if __name__ == '__main__':
    pass
