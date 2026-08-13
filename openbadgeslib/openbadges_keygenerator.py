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
from .keys import KeyFactory
from .confparser import read_config_or_exit, resolve_badge_section, resolve_key_type
from .errors import ConfigError
from .util import emit_cli_json
from .cli_common import (config_parser, debug_parser, json_parser,
                         version_parser)

logger = logging.getLogger(__name__)

# Entry Point


def _write_pem_file(path: str, data: bytes, mode: int) -> None:
    """Create *path* exclusively and write *data* with the given permission bits.

    Mode is applied on the open file descriptor (``fchmod``), not via a
    path-based ``chmod`` after close: the latter is a TOCTOU window where a
    local attacker with write access to the key directory could replace *path*
    with a symlink and redirect the permission change onto another file the
    invoking user owns (#289). ``O_CREAT|O_EXCL`` already prevents following a
    pre-planted symlink at create time; ``fchmod`` closes the post-close gap.

    Windows has no ``os.fchmod`` and its ``os.chmod`` only toggles the
    read-only bit, so there the mode argument is left to the platform and the
    permission dance is skipped outright: NTFS ACLs, not POSIX bits, are the
    access control, and the calling user's own profile directory is the
    boundary that matters there.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, 'wb') as f:
            fd = -1                         # ownership transferred to the file object
            f.write(data)
            if hasattr(os, 'fchmod'):
                os.fchmod(f.fileno(), mode)
    except Exception:
        if fd >= 0:
            os.close(fd)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Key Generation Parameters',
        parents=[config_parser, debug_parser, json_parser, version_parser])
    parser.add_argument('-g', '--genkey', metavar='BADGE',
                        help=("Generate a new key pair for the badge section "
                              "[badge_<BADGE>] (the suffix after 'badge_'). "
                              "Key type (RSA/ECC/ED25519) is taken from the "
                              "badge's key_type field; default RSA."))
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

    # Key type comes from the badge profile (default RSA); resolve_key_type is
    # the single home for the name->KeyType mapping and the default.
    try:
        key_type = resolve_key_type(conf[badge].get('key_type'))
    except ConfigError as exc:
        sys.exit("%s for badge '%s'" % (exc, args.genkey))

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

    try:
        _write_pem_file(private_key, priv_key_pem, 0o600)
        _write_pem_file(public_key, pub_key_pem, 0o644)
    except OSError as err:
        # Missing parent directory, permission denied, full disk, … — report a
        # clean CLI error instead of a raw traceback (human mode). emit_cli_json
        # turns this SystemExit into {"error": ...} under --json (#289).
        sys.exit('[!] Could not write key file: %s' % err)

    logger.info('Private key saved at: %s', private_key)
    logger.info('Public key saved at: %s', public_key)
    return {'key_type': key_type.name, 'private_key': private_key,
            'public_key': public_key}


if __name__ == '__main__':
    main()
