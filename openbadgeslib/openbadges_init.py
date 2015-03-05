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

import os, os.path, sys, shutil

def main():
    if (len(sys.argv) != 2) or (sys.argv[1] == '-h') :
        sys.exit('%s DIRECTORY' %sys.argv[0])

    directory = sys.argv[1]

    if os.path.lexists(directory) :
        raise FileExistsError(directory)

    umask = os.umask(0o077)  # rwx------
    os.mkdir(directory)
    for subdir in ['keys', 'images', 'log'] :
        os.mkdir(os.path.join(directory, subdir))
    os.umask(umask)

    source = os.path.join(os.path.dirname(__file__), 'config.ini.example')
    destination = os.path.join(directory, 'config.ini')
    shutil.copyfile(source, destination)

if __name__ == '__main__':
    main()

