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

from configparser import ConfigParser, ExtendedInterpolation, Error as ConfigParserError
from dataclasses import dataclass
from typing import Dict, List, Optional
import os
import sys
import logging

from .errors import ConfigError

logger = logging.getLogger(__name__)


def read_config_or_exit(config_file: str) -> ConfigParser:
    """Read a config file for a CLI tool, exiting with a clear message if it is
    missing, empty, or malformed. Shared by all the console-script entrypoints."""
    try:
        conf = ConfParser(config_file).read_conf()
    except ConfigError as exc:
        # read_conf() raises a clean, typed ConfigError for a malformed config
        # (bad INI syntax, an unresolvable ${...} reference, an encoding
        # mismatch, or a missing/empty [paths] base). Present it as a controlled
        # CLI error rather than letting it escape as a raw traceback.
        # ConfigError is a ValueError too, so pre-existing `except ValueError`
        # callers keep working.
        print('[!] %s' % exc)
        sys.exit(-1)
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


def ob3_issuer_id(conf: ConfigParser) -> str:
    """Return the issuer identifier OB3 credentials are issued under.

    Without an [issuer] ``did`` key this is ``publish_url`` (falling back to
    ``url``), the historical behaviour. ``did = auto`` derives the did:web
    identifier from ``publish_url`` — the DID whose document
    ``openbadges-publish -V 3`` generates — and an explicit ``did:...`` value
    is used verbatim. Raises ConfigError for anything else.
    """
    issuer_section = conf['issuer']
    base = issuer_section.get('publish_url', issuer_section.get('url', ''))
    did = (issuer_section.get('did') or '').strip()
    if not did:
        return base
    if did == 'auto':
        from .ob3.did import did_web_from_url
        return did_web_from_url(base)
    if did.startswith('did:'):
        return did
    raise ConfigError(
        "[issuer] did must be 'auto' or a did:... identifier, got %r" % did)


#: Proof formats an OB3 credential can be issued with — the same vocabulary
#: openbadges-verifier reports in its JSON output.
OB3_PROOF_FORMATS = ('vc-jwt', 'ldp')


def ob3_proof_format(conf: ConfigParser, badge_section: str) -> str:
    """Return the proof format OB3 credentials of *badge_section* use:
    ``vc-jwt`` (compact JWT-VC, the default) or ``ldp`` (embedded Data
    Integrity proof, cryptosuite eddsa-rdfc-2022 — needs an Ed25519 key and
    the [ldp] extra). Raises ConfigError for anything else.
    """
    value = (conf[badge_section].get('proof_format') or 'vc-jwt').strip()
    if value in OB3_PROOF_FORMATS:
        return value
    raise ConfigError(
        "[%s] proof_format must be one of %s, got %r"
        % (badge_section, ', '.join(OB3_PROOF_FORMATS), value))


@dataclass
class OB3StatusConfig:
    """Resolved per-badge OB3 credential status configuration."""
    purposes: List[str]           # ordered subset of ('revocation', 'suspension')
    size_bits: int
    registry_path: str            # private index registry JSON
    list_urls: Dict[str, str]     # purpose -> public status list URL
    validity_days: Optional[int] = None   # validUntil horizon; None => no bound


def ob3_status_config(conf: ConfigParser,
                      badge_section: str) -> Optional[OB3StatusConfig]:
    """Parse a badge section's opt-in ``status_lists`` configuration.

    Returns None when the badge does not opt in (no ``status_lists`` key),
    which callers must treat as "issue without credentialStatus" — the
    pre-3.1 behaviour. Raises ConfigError for an invalid purpose or size.
    """
    from urllib.parse import urljoin
    from .ob3.status_list import DEFAULT_SIZE_BITS, STATUS_PURPOSES

    raw = conf[badge_section].get('status_lists', '')
    purposes = []
    for piece in raw.split(','):
        purpose = piece.strip()
        if not purpose:
            continue
        if purpose not in STATUS_PURPOSES:
            raise ConfigError(
                "[%s] status_lists: unknown purpose %r (choose from %s)"
                % (badge_section, purpose, ', '.join(STATUS_PURPOSES)))
        if purpose not in purposes:
            purposes.append(purpose)
    if not purposes:
        return None

    try:
        size_bits = int(conf[badge_section].get('status_size_bits',
                                                str(DEFAULT_SIZE_BITS)))
    except ValueError:
        raise ConfigError("[%s] status_size_bits must be an integer"
                          % badge_section) from None
    # encode_bitstring requires a positive multiple of 8; validate here so a
    # misconfiguration is a clean config error at issuance/publish load rather
    # than a latent raw ValueError from encode_bitstring at publish time.
    if size_bits <= 0 or size_bits % 8:
        raise ConfigError("[%s] status_size_bits must be a positive multiple "
                          "of 8" % badge_section)

    # Optional validUntil horizon: when set, published status lists carry a
    # validUntil = now + N days, and a verifier rejects a stale copy (replay
    # protection). Unset => no bound (offline-friendly default). The issuer
    # must republish within the window (see the wiki).
    validity_raw = (conf[badge_section].get('status_validity_days') or '').strip()
    validity_days: Optional[int] = None
    if validity_raw:
        try:
            validity_days = int(validity_raw)
        except ValueError:
            raise ConfigError("[%s] status_validity_days must be an integer"
                              % badge_section) from None
        if validity_days <= 0:
            raise ConfigError("[%s] status_validity_days must be positive"
                              % badge_section)

    base_status = conf['paths'].get('base_status') or \
        os.path.join(conf['paths']['base'], 'status')
    registry_path = os.path.join(base_status, badge_section + '.json')

    status_base = conf[badge_section].get('status_base') or \
        urljoin(conf['issuer']['publish_url'], badge_section + '/')
    if not status_base.endswith('/'):
        status_base += '/'
    list_urls = {p: urljoin(status_base, p + '.jwt') for p in purposes}

    return OB3StatusConfig(purposes=purposes, size_bits=size_bits,
                           registry_path=registry_path, list_urls=list_urls,
                           validity_days=validity_days)


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
            raise ConfigError("The encoding of the configuration file and the default encoding of "
                              "the operating system mismatch") from None
        except ConfigParserError as exc:
            # Malformed INI syntax (duplicate section/option, a value line
            # with no section header before it, ...) raises directly from
            # read(), before any interpolation is even attempted.
            raise ConfigError(
                "Configuration file %s has invalid INI syntax: %s" % (self.config_file, exc)) from exc
        try:
            base = self.parser['paths']['base']
        except KeyError:
            raise ConfigError(
                "Configuration file %s is missing the [paths] section or its "
                "'base' key" % self.config_file) from None
        if not base:
            raise ConfigError(
                "Configuration file %s has an empty [paths] 'base' value" % self.config_file)

        # A relative base is resolved against the directory that contains the
        # config file (not the process CWD), so ${base}/... paths land where the
        # operator expects no matter where the tool is launched from. The old
        # check only matched a bare '.' and replaced the *whole* value with the
        # config dir — silently dropping the suffix of './data' or '../shared'
        # (and mis-handling a real '.hidden' dir), which could redirect private
        # keys and logs to the wrong tree with no error.
        if not os.path.isabs(base):
            base_dir = os.path.dirname(self.config_file)
            resolved = os.path.abspath(os.path.join(base_dir, base))
            # Writing back through the parser runs the value through
            # ExtendedInterpolation, which treats '$' specially: a config
            # directory whose absolute path contains a literal '$' would raise a
            # raw configparser error (or silently collapse '$$' to '$'). Escape
            # '$' -> '$$' so the path round-trips to its original form on read.
            self.parser['paths']['base'] = resolved.replace('$', '$$')

        # ExtendedInterpolation resolves ${...} references lazily, only when a
        # value is actually read — a bad reference anywhere in the file would
        # otherwise surface as a raw configparser exception deep inside a CLI
        # tool the first time it happens to touch that key. Resolve every
        # value now so a malformed config fails cleanly, here, at load time.
        try:
            for section in self.parser.sections():
                dict(self.parser.items(section))
        except ConfigParserError as exc:
            raise ConfigError(
                "Configuration file %s has an invalid value: %s" % (self.config_file, exc)) from exc

        return self.parser


if __name__ == '__main__':
    pass
