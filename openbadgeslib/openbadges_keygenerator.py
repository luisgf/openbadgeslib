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
import logging
import os
import sys

from typing import Any

from .logs import enable_debug_logging
from .keys import KeyFactory, KeyType
from .confparser import read_config_or_exit, resolve_badge_section
from .util import __version__, emit_cli_json

logger = logging.getLogger(__name__)

# Entry Point


def _write_pem_file(path: str, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    os.chmod(path, mode)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Key Generation Parameters')
    parser.add_argument('-c', '--config', default='config.ini',
                        help='Specify the config.ini file to use')
    parser.add_argument('-g', '--genkey', metavar='BADGE',
                        help=("Generate a new key pair for the badge section "
                              "[badge_<BADGE>] (the suffix after 'badge_'). "
                              "Key type (RSA/ECC/ED25519) is taken from the "
                              "badge's key_type field; default RSA."))
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Show debug messages at runtime.')
    parser.add_argument('--json', action='store_true',
                        help='Emit a machine-readable JSON result '
                             '{key_type, private_key, public_key} instead of '
                             'the human log lines. Exit status: 0 on success, '
                             '1 on any error.')
    parser.add_argument('-v', '--version', action='version',
                        version=__version__)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    enable_debug_logging(args.debug)

    if args.json:
        emit_cli_json(lambda: _generate(args))
        return

    if not args.genkey:
        parser.print_help()
        return
    _generate(args)


def _generate(args: argparse.Namespace) -> dict[str, Any]:
    """Generate the badge key pair; returns the machine-readable result
    {key_type, private_key, public_key} consumed by the --json path."""
    if not args.genkey:
        sys.exit('nothing to do: pass -g/--genkey BADGE to generate a key pair')

    conf = read_config_or_exit(args.config)
    badge = resolve_badge_section(conf, args.genkey)

    for key in ('private_key', 'public_key'):
        if key not in conf[badge]:
            sys.exit("[!] [%s] is missing the required '%s' config key"
                     % (badge, key))
    private_key = conf[badge]['private_key']
    public_key = conf[badge]['public_key']

    # Key type comes from the badge profile (default RSA).
    key_type_name = conf[badge].get('key_type', 'RSA').strip().upper()
    if key_type_name == 'ECC':
        key_type = KeyType.ECC
    elif key_type_name == 'RSA':
        key_type = KeyType.RSA
    elif key_type_name in ('ED25519', 'EDDSA'):
        key_type = KeyType.ED25519
    else:
        sys.exit("Unknown key_type %r for badge '%s' (use RSA, ECC, or ED25519)"
                 % (key_type_name, args.genkey))

    for i in (private_key, public_key):
        if os.path.exists(i):
            print('[!] Key file is present at %s' % i)
            sys.exit(1)

    # Key generation must not require [paths]/[logs]/[issuer]: the legacy Logger
    # opened general.log/signer.log (KeyError/FileNotFoundError on an incomplete
    # config) just to emit these console lines. The module logger needs none.
    logger.debug("key_type=%s private=%s public=%s",
                 key_type.name, private_key, public_key)
    issuer_name = (conf['issuer'].get('name', '?')
                   if conf.has_section('issuer') else '?')
    logger.info("Generating a %s key pair for issuer '%s'",
                key_type.name, issuer_name)

    kf = KeyFactory(key_type)
    priv_key_pem, pub_key_pem = kf.generate_keypair()

    _write_pem_file(private_key, priv_key_pem, 0o600)
    _write_pem_file(public_key, pub_key_pem, 0o644)

    logger.info('Private key saved at: %s', private_key)
    logger.info('Public key saved at: %s', public_key)
    return {'key_type': key_type.name, 'private_key': private_key,
            'public_key': public_key}


if __name__ == '__main__':
    main()
