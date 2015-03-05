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

import os
import logging
logger = logging.getLogger(__name__)

from configparser import ConfigParser, ExtendedInterpolation, Error, NoOptionError

class ConfParser():
    def __init__(self, config_file='config.ini'):
        self.config_file = config_file

    def read_conf(self):
        if not os.path.isfile(self.config_file):
            return None

        self.parser = ConfigParser(interpolation=ExtendedInterpolation())
        self.parser.read(self.config_file)
        if self.parser['paths']['base'][0] == '.':
            abs_path = os.path.dirname(self.config_file)
            full_path = os.path.abspath(abs_path)
            self.parser['paths']['base'] = full_path
        return self.parser

if __name__ == '__main__':
    pass
