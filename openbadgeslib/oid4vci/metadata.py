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

# The two discovery documents a wallet reads before it will talk to an issuer.
#
# Pure config-to-JSON: no crypto, no key material, no I/O. The issuer serves
# what these return as static documents; nothing here decides anything at
# request time.
#
# SELF-CHECK. Before a document leaves this module it is passed through
# openvc-core's fail-closed parser for the wire contract
# (parse_credential_issuer_metadata / parse_credential_offer), so a document
# no conformant wallet would accept becomes a ConfigError here — at build
# time, while the operator is looking, rather than at scan time. The check is
# cheap (structure only, no network) and openvc fetches nothing, so running
# it on output carries no SSRF surface. A deployment with an http://
# credential_issuer already fails at oid4vci_config(); these parsers are the
# backstop for everything else the wire contract pins.

import configparser
import logging
from typing import Any, Dict, List, Optional, Sequence

from ..confparser import (OID4VCIConfig, oid4vci_config, oid4vci_formats,
                          oid4vci_key_attestations_required, resolve_key_type)
from ..errors import ConfigError
from ..keys import KeyType
from .formats import FORMAT_JWT_VC_JSON, FORMAT_SD_JWT_VC

logger = logging.getLogger(__name__)

#: The grant type that identifies the pre-authorized code flow.
PRE_AUTHORIZED_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'

#: Proof signing algorithms a wallet may use for its key proof. A constant, not
#: a config value and never read from the request: an issuer that echoes back
#: whatever algorithm it is offered has no algorithm policy at all.
PROOF_SIGNING_ALGS = ('ES256', 'ES384', 'EdDSA')

#: Signing algorithms this issuer can produce, by badge key type.
_CREDENTIAL_ALGS = {
    KeyType.RSA: ('RS256',),
    KeyType.ECC: ('ES256',),
    KeyType.ED25519: ('EdDSA',),
}

#: The binding method advertised per format: a did:jwk subject for JWT-VC, a
#: bare `cnf` JWK for SD-JWT VC.
_BINDING_METHODS = {
    FORMAT_JWT_VC_JSON: ('did:jwk',),
    FORMAT_SD_JWT_VC: ('jwk',),
}


def credential_configuration_id(badge_section: str,
                                credential_format: str) -> str:
    """The metadata id of one (badge, format) pair.

    Derived rather than configurable so the offer, the metadata and the
    credential endpoint cannot drift apart — they all call this. The format is
    slugged because a raw ``vc+sd-jwt`` would put a ``+`` into an identifier
    that travels in URLs and JSON keys.
    """
    return '%s_%s' % (badge_section,
                      credential_format.replace('+', '_').replace('-', '_'))


def parse_credential_configuration_id(conf: configparser.ConfigParser,
                                      configuration_id: str
                                      ) -> tuple[str, str]:
    """Resolve a configuration id back to ``(badge_section, format)``.

    Resolved by matching against what this issuer actually offers rather than
    by splitting the string, so an id the config does not produce cannot be
    reverse-engineered into a badge section. Raises :class:`ConfigError` for an
    id this issuer does not publish.
    """
    for badge in offered_badges(conf):
        for fmt in oid4vci_formats(conf, badge):
            if credential_configuration_id(badge, fmt) == configuration_id:
                return badge, fmt
    raise ConfigError('no credential configuration %r is offered'
                      % configuration_id)


def offered_badges(conf: configparser.ConfigParser) -> List[str]:
    """The badge sections that opted into OID4VCI, in config order.

    Sections without ``oid4vci_formats`` are skipped silently — the same
    prefix walk publish_ob3 does, and the same opt-in contract as
    ``ob3_status_config`` returning None.
    """
    return [section for section in conf.sections()
            if section.startswith('badge_') and oid4vci_formats(conf, section)]


def build_issuer_metadata(conf: configparser.ConfigParser, *,
                          badges: Optional[Sequence[str]] = None
                          ) -> Dict[str, Any]:
    """The ``/.well-known/openid-credential-issuer`` document.

    Serve this at exactly ``<credential_issuer>/.well-known/
    openid-credential-issuer``: the identifier inside must equal the one the
    wallet dereferenced, and it is also the value every key proof's ``aud``
    must carry, so a mismatch fails every request rather than degrading.

    Raises :class:`ConfigError` if no badge opts into OID4VCI — an issuer
    metadata document offering nothing is a deployment mistake worth catching
    at build time, not an empty page to debug against a wallet.
    """
    cfg = oid4vci_config(conf)
    sections = list(badges) if badges is not None else offered_badges(conf)
    if not sections:
        raise ConfigError(
            'no badge section opts into OID4VCI — add oid4vci_formats to at '
            'least one [badge_*] section')

    configurations: Dict[str, Any] = {}
    for badge in sections:
        formats = oid4vci_formats(conf, badge)
        if not formats:
            raise ConfigError('[%s] does not opt into OID4VCI '
                              '(no oid4vci_formats)' % badge)
        for fmt in formats:
            configurations[credential_configuration_id(badge, fmt)] = \
                _configuration(conf, cfg, badge, fmt)

    metadata: Dict[str, Any] = {
        'credential_issuer': cfg.credential_issuer,
        'credential_endpoint': cfg.credential_endpoint,
        'nonce_endpoint': cfg.nonce_endpoint,
        # Point wallets at the AS metadata document below. Without this a
        # wallet has to guess, and the pre-authorized flow stops before its
        # first request.
        'authorization_servers': [cfg.credential_issuer],
        'credential_configurations_supported': configurations,
    }
    if cfg.batch_size > 1:
        metadata['batch_credential_issuance'] = {'batch_size': cfg.batch_size}
    display = _issuer_display(conf)
    if display:
        metadata['display'] = [display]
    _validate_issuer_metadata(metadata)
    return metadata


def _validate_issuer_metadata(metadata: Dict[str, Any]) -> None:
    """Refuse to publish a metadata document no wallet would accept.

    Runs openvc-core's fail-closed wire-contract parser over what this module
    just built and maps any violation onto :class:`ConfigError`: the document
    comes from local configuration, so a rejection is a config mistake, not
    attacker input. Without the ``[oid4vci]`` extra the document is returned
    unchecked — issuance itself is unavailable there anyway, and importing
    openvc from this module would break installs that never asked for it.
    """
    try:
        from openvc.openid4vci import parse_credential_issuer_metadata
    except ImportError:
        # An install WITH the extra that lands an openvc-core below the 1.26
        # floor (parsers landed in 1.25) would take this branch too —
        # indistinguishable from a plain minimal install, and silent about
        # the skipped check either way.
        logger.debug('openvc-core OID4VCI discovery parsers unavailable; '
                     'the issuer metadata self-check is skipped (install the '
                     '[oid4vci] extra for it)')
        return
    try:
        parse_credential_issuer_metadata(metadata)
    except Exception as exc:
        raise ConfigError(
            'the issuer metadata this configuration produces is not a valid '
            'OID4VCI 1.0 document: %s' % exc) from exc


def build_authorization_server_metadata(conf: configparser.ConfigParser
                                        ) -> Dict[str, Any]:
    """The ``/.well-known/oauth-authorization-server`` document (RFC 8414).

    For an issuer that is its own authorization server, which is what the
    pre-authorized code flow amounts to: there is nothing to authorize, only a
    code to exchange.

    ``pre-authorized_grant_anonymous_access_supported`` is the flag that tells
    a wallet it may call the token endpoint with no client credentials. Without
    it, a conformant wallet will look for a client authentication method,
    find none, and stop.
    """
    cfg = oid4vci_config(conf)
    return {
        'issuer': cfg.credential_issuer,
        'token_endpoint': cfg.token_endpoint,
        'grant_types_supported': [PRE_AUTHORIZED_GRANT],
        'pre-authorized_grant_anonymous_access_supported': True,
        'response_types_supported': [],
    }


def _configuration(conf: configparser.ConfigParser, cfg: OID4VCIConfig,
                   badge: str, credential_format: str) -> Dict[str, Any]:
    """One entry of ``credential_configurations_supported``."""
    section = conf[badge]
    key_type = resolve_key_type(section.get('key_type'))
    entry: Dict[str, Any] = {
        'format': credential_format,
        'scope': credential_configuration_id(badge, credential_format),
        'cryptographic_binding_methods_supported':
            list(_BINDING_METHODS[credential_format]),
        # Derived from the configured key type, never by reading the private
        # key: this document is public and must not touch key material.
        'credential_signing_alg_values_supported':
            list(_CREDENTIAL_ALGS[key_type]),
        'proof_types_supported': {
            'jwt': {'proof_signing_alg_values_supported':
                    list(PROOF_SIGNING_ALGS)},
        },
    }
    required = oid4vci_key_attestations_required(conf, badge)
    if required is not None:
        # Presence is the requirement. An empty object is the spec's
        # "needed, unconstrained" spelling — not a placeholder.
        entry['proof_types_supported']['jwt'][
            'key_attestations_required'] = required
    if credential_format == FORMAT_SD_JWT_VC:
        from ..ob3.eudi import OB3_SD_JWT_VCT
        entry['vct'] = (conf['issuer'].get('sd_jwt_vct') or '').strip() \
            or OB3_SD_JWT_VCT
    else:
        entry['credential_definition'] = {
            'type': ['VerifiableCredential', 'OpenBadgeCredential'],
        }
    display = _badge_display(conf, badge)
    if display:
        entry['display'] = [display]
    return entry


def _issuer_display(conf: configparser.ConfigParser) -> Dict[str, Any]:
    section = conf['issuer']
    display: Dict[str, Any] = {}
    name = (section.get('name') or '').strip()
    if name:
        display['name'] = name
    if section.get('url'):
        display['url'] = section['url'].strip()
    return display


def _badge_display(conf: configparser.ConfigParser,
                   badge: str) -> Dict[str, Any]:
    section = conf[badge]
    display: Dict[str, Any] = {}
    name = (section.get('name') or '').strip()
    if name:
        display['name'] = name
    description = (section.get('description') or '').strip()
    if description:
        display['description'] = description
    image = (section.get('image') or '').strip()
    if image:
        display['logo'] = {'uri': image}
    return display


__all__ = [
    'PRE_AUTHORIZED_GRANT', 'PROOF_SIGNING_ALGS',
    'build_authorization_server_metadata', 'build_issuer_metadata',
    'credential_configuration_id', 'offered_badges',
    'parse_credential_configuration_id',
]
