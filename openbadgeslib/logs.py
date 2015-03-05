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

import logging
import os

class Logger():
    def __init__(self, *args, **kwargs):
        self.main = self.init_log(logger='general', base_log=kwargs['base_log'],
                                  file=kwargs['general'])
        self.signer = self.init_log(logger='signer', base_log=kwargs['base_log'],
                                    file=kwargs['signer'])
        try:
            self.console = self.init_console(show_debug=kwargs['show_debug'])
        except KeyError:
            self.console = self.init_console()

    def init_log(self, logger='', base_log=None, log_level=logging.INFO,
                 file=None):
        logger = logging.getLogger(logger)
        logger.setLevel(logging.DEBUG)
        file_path = os.path.join(base_log, file)

        """ Create a file handler """
        handler = logging.FileHandler(file_path, "w",
                                      encoding='utf-8', delay=False)
        handler.setLevel(log_level)
        formatter = logging.Formatter("%(asctime)s %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger

    def init_console(self, show_debug=False):
        logger = logging.getLogger()
        logger.setLevel(logging.NOTSET)

        """ Console a console handler """
        handler = logging.StreamHandler()
        if not show_debug:
            handler.setLevel(logging.INFO)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger