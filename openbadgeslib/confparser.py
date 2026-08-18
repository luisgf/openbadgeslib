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
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING
import json
import os
import sys
import logging

from .errors import ConfigError

if TYPE_CHECKING:
    from .keys import KeyType

logger = logging.getLogger(__name__)


def load_config(config_file: str) -> ConfigParser:
    """Load a config file as a library call: return the parsed ConfigParser, or
    raise :class:`ConfigError` if the file is missing, empty, or malformed.

    This is the programmatic entry point — no printing, no ``sys.exit`` — so an
    integrator can trap the error. CLI tools use :func:`read_config_or_exit`,
    which presents the message and exits. ``read_conf`` already raises a typed
    ConfigError for a malformed config (bad INI syntax, an unresolvable
    ``${...}`` reference, an encoding mismatch, or a missing/empty [paths]
    base); a missing/empty file returns None, mapped to ConfigError here.
    """
    conf = ConfParser(config_file).read_conf()
    if conf is None:
        raise ConfigError(
            'The config file %s does not exist or is empty' % config_file)
    return conf


def read_config_or_exit(config_file: str) -> ConfigParser:
    """CLI wrapper over :func:`load_config`: read a config file for a console
    tool, presenting a clear message and exiting if it is missing, empty, or
    malformed. Shared by all the console-script entrypoints."""
    try:
        return load_config(config_file)
    except ConfigError as exc:
        # ConfigError is a ValueError too, so pre-existing `except ValueError`
        # callers keep working.
        print('[!] %s' % exc)
        sys.exit(1)


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


# ── OID4VCI (OpenID for Verifiable Credential Issuance) ──────────────────────
# Issuing to a wallet inverts the library's usual direction: instead of the
# issuer pushing a badge to a known recipient, the wallet claims it against an
# offer and proves possession of its own key. That needs a handful of
# deployment values the rest of the config has no reason to carry — the public
# identifier the wallet's key proofs bind to, and the lifetimes of the
# short-lived secrets the flow mints.
#
# The whole section is optional: without it, nothing else in the library
# changes behaviour.

#: How long a Credential Offer's pre-authorized code stays redeemable. Short by
#: default: it is a bearer secret that travels in a QR code or a link.
DEFAULT_OFFER_TTL_S = 600

#: Lifetime of a c_nonce handed out by the nonce endpoint.
DEFAULT_NONCE_TTL_S = 120

#: Lifetime of an access token minted at the token endpoint. It only has to
#: survive the wallet's immediate follow-up call to the credential endpoint.
DEFAULT_TOKEN_TTL_S = 300

#: How stale a wallet key proof's `iat` may be (openvc's max_age_s).
DEFAULT_PROOF_MAX_AGE_S = 300

#: Digits in a numeric tx_code, and the input modes OID4VCI 1.0 defines.
DEFAULT_TX_CODE_LENGTH = 6
TX_CODE_INPUT_MODES = ('numeric', 'text')


@dataclass
class OID4VCIConfig:
    """Resolved [oid4vci] section: the issuer identifier, the endpoint URLs and
    the lifetimes of the flow's short-lived secrets.

    ``credential_issuer`` is load-bearing beyond being an identifier: it is the
    value every wallet key proof must name in its ``aud``, so it has to match
    byte for byte what is actually served at
    ``<credential_issuer>/.well-known/openid-credential-issuer``."""

    credential_issuer: str
    credential_endpoint: str
    nonce_endpoint: str
    token_endpoint: str
    store_path: str
    offer_ttl_s: int = DEFAULT_OFFER_TTL_S
    nonce_ttl_s: int = DEFAULT_NONCE_TTL_S
    token_ttl_s: int = DEFAULT_TOKEN_TTL_S
    proof_max_age_s: int = DEFAULT_PROOF_MAX_AGE_S
    batch_size: int = 1
    tx_code_length: int = DEFAULT_TX_CODE_LENGTH
    tx_code_input_mode: str = 'numeric'


def _positive_int(conf: ConfigParser, section: str, key: str,
                  default: int) -> int:
    """Read a positive integer config key, or its default when unset."""
    raw = (conf[section].get(key) or '').strip() if section in conf else ''
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError("[%s] %s must be an integer, got %r"
                          % (section, key, raw)) from None
    if value <= 0:
        raise ConfigError("[%s] %s must be positive" % (section, key))
    return value


def oid4vci_config(conf: ConfigParser) -> OID4VCIConfig:
    """Resolve the optional [oid4vci] section.

    Every key has a default, so a typical deployment writes none of them: the
    issuer identifier falls back to ``[issuer] publish_url`` and the three
    endpoints are derived from it. Raises :class:`ConfigError` when there is no
    base to derive an issuer identifier from, when it is not https, or when a
    lifetime is not a positive integer.

    ``https`` is required rather than encouraged. A key proof's ``aud`` binds
    the wallet's signature to this exact string; over plaintext http an attacker
    who can rewrite the metadata response also chooses what the wallet signs
    for, which makes the binding decorative.
    """
    from urllib.parse import urljoin

    section = conf['oid4vci'] if 'oid4vci' in conf else None
    base = (section.get('credential_issuer') if section else None) or \
        conf['issuer'].get('publish_url') or ''
    base = base.strip()
    if not base:
        raise ConfigError(
            "[oid4vci] needs a credential_issuer (or an [issuer] publish_url "
            "to derive it from): it is the identifier wallet key proofs bind "
            "their 'aud' to")
    if not base.startswith('https://'):
        raise ConfigError(
            "[oid4vci] credential_issuer must be an https URL, got %r — a "
            "wallet key proof's audience binding is meaningless over plaintext"
            % base)
    # A trailing slash makes urljoin append rather than replace the last path
    # segment; without it, an issuer at https://host/issuer would derive
    # https://host/credential.
    endpoint_base = base if base.endswith('/') else base + '/'

    def endpoint(key: str, default_path: str) -> str:
        explicit = (section.get(key) or '').strip() if section else ''
        return explicit or urljoin(endpoint_base, default_path)

    store_path = (section.get('store_path') if section else None) or \
        os.path.join(conf['paths']['base'], 'oid4vci.sqlite3')

    input_mode = ((section.get('tx_code_input_mode') if section else None)
                  or 'numeric').strip()
    if input_mode not in TX_CODE_INPUT_MODES:
        raise ConfigError("[oid4vci] tx_code_input_mode must be one of %s, "
                          "got %r" % (', '.join(TX_CODE_INPUT_MODES),
                                      input_mode))

    return OID4VCIConfig(
        credential_issuer=base,
        credential_endpoint=endpoint('credential_endpoint', 'credential'),
        nonce_endpoint=endpoint('nonce_endpoint', 'nonce'),
        token_endpoint=endpoint('token_endpoint', 'token'),
        store_path=store_path,
        offer_ttl_s=_positive_int(conf, 'oid4vci', 'offer_ttl_s',
                                  DEFAULT_OFFER_TTL_S),
        nonce_ttl_s=_positive_int(conf, 'oid4vci', 'nonce_ttl_s',
                                  DEFAULT_NONCE_TTL_S),
        token_ttl_s=_positive_int(conf, 'oid4vci', 'token_ttl_s',
                                  DEFAULT_TOKEN_TTL_S),
        proof_max_age_s=_positive_int(conf, 'oid4vci', 'proof_max_age_s',
                                      DEFAULT_PROOF_MAX_AGE_S),
        batch_size=_positive_int(conf, 'oid4vci', 'batch_size', 1),
        tx_code_length=_positive_int(conf, 'oid4vci', 'tx_code_length',
                                     DEFAULT_TX_CODE_LENGTH),
        tx_code_input_mode=input_mode,
    )


def oid4vci_formats(conf: ConfigParser, badge_section: str) -> Tuple[str, ...]:
    """The OID4VCI credential formats a badge section opts into, in order.

    Returns an empty tuple when the badge does not opt in (no
    ``oid4vci_formats`` key), which callers treat as "this badge is not offered
    over OID4VCI" — the same contract as :func:`ob3_status_config` returning
    None. Opt-in rather than opt-out because listing a badge in the issuer
    metadata publishes its existence and makes it claimable.

    Raises :class:`ConfigError` for an unknown format, or for ``vc+sd-jwt`` on a
    section with ``key_type = RSA``: SD-JWT VC has no RSA algorithm profile, so
    that pairing could never issue and the operator should learn about it when
    the config loads, not when a wallet is waiting.
    """
    from .keys import KeyType
    from .oid4vci.formats import EC_ONLY_FORMATS, OID4VCI_FORMATS

    raw = conf[badge_section].get('oid4vci_formats', '')
    formats: List[str] = []
    for piece in raw.split(','):
        fmt = piece.strip()
        if not fmt:
            continue
        if fmt not in OID4VCI_FORMATS:
            raise ConfigError(
                "[%s] oid4vci_formats: unknown format %r (choose from %s)"
                % (badge_section, fmt, ', '.join(OID4VCI_FORMATS)))
        if fmt not in formats:
            formats.append(fmt)
    if not formats:
        return ()

    key_type = resolve_key_type(conf[badge_section].get('key_type'))
    if key_type is KeyType.RSA:
        rsa_incapable = [f for f in formats if f in EC_ONLY_FORMATS]
        if rsa_incapable:
            raise ConfigError(
                "[%s] oid4vci_formats includes %s, which cannot be signed with "
                "an RSA key — use key_type = ED25519 or ECC, or drop that "
                "format" % (badge_section, ', '.join(rsa_incapable)))
    return tuple(formats)


def oid4vci_key_attestations_required(
        conf: ConfigParser, badge_section: str) -> Optional[Dict[str, Any]]:
    """The key-attestation policy a badge advertises over OID4VCI, or None.

    Absent (the default) means the issuer does **not** require a key
    attestation, and OpenID4VCI 1.0 §12.2.4 says the parameter MUST NOT then
    appear in metadata. Present means it is required:

    * ``true`` / ``yes`` / ``1`` / ``{}`` / empty advertise an unconstrained
      requirement (a key attestation is needed, with no extra constraints);
    * a JSON object is the Appendix D.2 constraint set, validated by the same
      shape check :func:`~openbadgeslib.ob3.eudi.badge_credential_configuration`
      uses.

    The credential endpoint reads this same key, so advertising the
    requirement without enforcing it — the wallet-retry loop openvc-core
    1.26's ``require_key_attestation`` exists to close — cannot happen from
    configuration alone.
    """
    if (badge_section not in conf
            or 'oid4vci_key_attestations_required' not in conf[badge_section]):
        return None
    raw = (conf[badge_section].get('oid4vci_key_attestations_required')
           or '').strip()
    if raw.lower() in ('', 'true', 'yes', '1', '{}'):
        value: Any = {}
    else:
        try:
            parsed = json.loads(raw)
        except ValueError as exc:
            raise ConfigError(
                "[%s] oid4vci_key_attestations_required must be true or a "
                "JSON object, got %r" % (badge_section, raw)) from exc
        if not isinstance(parsed, dict):
            raise ConfigError(
                "[%s] oid4vci_key_attestations_required must be a JSON "
                "object, got %s" % (badge_section, type(parsed).__name__))
        value = parsed
    from .ob3.eudi import EudiError, _key_attestations_required
    try:
        return _key_attestations_required(value)
    except EudiError as exc:
        raise ConfigError("[%s] oid4vci_key_attestations_required: %s"
                          % (badge_section, exc)) from exc


# ── centralized config defaults ──────────────────────────────────────────────
# One inventory for the accepted-key defaults, so each lives in a single place
# rather than being re-spelled at every read site. (The status-list defaults —
# base_status, status_base, validity horizon — are resolved in
# ob3_status_config / OB3StatusConfig above.)
DEFAULT_KEY_TYPE = 'RSA'


def resolve_key_type(name: Optional[str]) -> 'KeyType':
    """Map a config ``key_type`` name to a :class:`~openbadgeslib.keys.KeyType`,
    defaulting to RSA when unset. Accepts RSA / ECC / ED25519 (with EDDSA as an
    alias), case-insensitively. Raises :class:`ConfigError` for an unknown name.

    The single home for the mapping the keygenerator used to inline.
    """
    from .keys import KeyType
    key = (name or DEFAULT_KEY_TYPE).strip().upper()
    mapping = {'RSA': KeyType.RSA, 'ECC': KeyType.ECC,
               'ED25519': KeyType.ED25519, 'EDDSA': KeyType.ED25519}
    try:
        return mapping[key]
    except KeyError:
        raise ConfigError(
            "Unknown key_type %r (use RSA, ECC, or ED25519)" % key) from None


@dataclass
class IssuerConfig:
    """Resolved [issuer] section: the identity fields OB2/OB3 issuance needs,
    with the OB3 issuer id (did / publish_url / url) resolved once — one home
    for the [issuer] reads each CLI used to re-spell."""
    name: str
    id: str
    url: Optional[str] = None
    email: Optional[str] = None
    publish_url: Optional[str] = None
    image: Optional[str] = None


def issuer_config(conf: ConfigParser) -> IssuerConfig:
    """Resolve and validate the [issuer] section into a typed IssuerConfig,
    raising :class:`ConfigError` if the section or its required ``name`` is
    missing."""
    if not conf.has_section('issuer'):
        raise ConfigError("Configuration is missing the [issuer] section")
    section = conf['issuer']
    name = (section.get('name') or '').strip()
    if not name:
        raise ConfigError("[issuer] is missing the required 'name' key")
    return IssuerConfig(
        name=name,
        id=ob3_issuer_id(conf),
        url=section.get('url'),
        email=section.get('email'),
        publish_url=section.get('publish_url'),
        image=section.get('image'),
    )


@dataclass
class BadgeSectionConfig:
    """Resolved optional badge-section fields with the centralized
    defaults/fallbacks applied: the criteria narrative (``criteria_narrative``
    falling back to the OpenBadges 1.0 ``criteria``) and the hosted-assertions
    base URL. Required keys (name, description, badge) stay direct reads so a
    missing one still raises ``KeyError`` — the "missing required config key"
    IssuanceError contract."""
    section: str
    criteria_narrative: str
    hosted_assertions_base: Optional[str] = None


def badge_section_config(conf: ConfigParser,
                         badge_section: str) -> BadgeSectionConfig:
    """Resolve the optional fields of a badge section with centralized
    fallbacks."""
    section = conf[badge_section]
    return BadgeSectionConfig(
        section=badge_section,
        criteria_narrative=section.get('criteria_narrative',
                                       section.get('criteria', '')),
        hosted_assertions_base=section.get('hosted_assertions_base'),
    )


#: Sections whose values are the *public* identifiers of a deployment, checked
#: by :func:`reject_url_userinfo`. [smtp] is deliberately excluded: its
#: username/password are credentials that stay on the issuer's machine.
#: [oid4vci] belongs here because its credential_issuer and endpoint URLs are
#: published in the issuer metadata and handed to every wallet that reads it.
_PUBLIC_URL_SECTIONS = ('issuer', 'oid4vci')
_PUBLIC_URL_SECTION_PREFIX = 'badge_'


def reject_url_userinfo(parser: ConfigParser, config_file: str) -> None:
    """Reject any [issuer]/[badge_*] value that is a URL containing an ``@``.

    Those sections hold the identifiers the tools publish: ``publish_url`` is
    printed by every publish command, joined into the ids written to
    organization.json / badge.json / key.json (``urljoin`` keeps the
    ``user:pass@``), turned into the issuer's did:web, and used to build the
    ``credentialStatus`` list URLs embedded in signed OB3 credentials. A
    ``https://user:password@host/`` value would therefore carry the credential
    into user-visible output, publicly served files and the credentials
    delivered to recipients alike — so it is refused once here, at load time,
    and every consumer (OB1/OB2/OB3, DID derivation, status lists) inherits the
    guarantee instead of re-checking it.

    A published identifier has no legitimate use for an ``@``, so the whole URL
    is searched rather than the userinfo component alone: ``urlsplit`` only
    reports userinfo when the ``@`` sits inside the authority, and a password
    holding a ``/``, ``?`` or ``#`` pushes it into the path, where the parser
    stops seeing it as a credential but every downstream consumer still
    publishes it verbatim. ``%40`` is refused for the same reason. The cost is
    that an innocent ``https://host/@name/`` is refused too — deliberate: after
    parsing, the two are the same shape.

    A value with no authority is left alone: an ``[issuer] email`` or a local
    path may legitimately hold an ``@`` and is not a dereferenceable URL.

    The message names the offending section and key but never echoes the value:
    printing it would leak the very password the check exists to protect.
    """
    from urllib.parse import urlsplit
    for section in parser.sections():
        if (section not in _PUBLIC_URL_SECTIONS
                and not section.startswith(_PUBLIC_URL_SECTION_PREFIX)):
            continue
        for key, value in parser.items(section):
            if '@' not in value and '%40' not in value.lower():
                continue
            try:
                has_authority = bool(urlsplit(value).netloc)
            except ValueError:
                # Too malformed for urlsplit (an unbalanced IPv6 bracket) to
                # report an authority. A '//' still makes it a URL, and it is
                # written out verbatim downstream, so judge it as one.
                has_authority = '//' in value
            if has_authority:
                raise ConfigError(
                    "Configuration file %s: [%s] %s must not contain '@' in "
                    "its URL. That URL is printed by the tools, published in "
                    "badge metadata and embedded in signed credentials, so a "
                    "'user:password@' there would leak; a published identifier "
                    "has no legitimate use for an '@'." % (config_file, section, key))


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

        # Every value is resolved by now, so a ${...} reference cannot smuggle
        # a credential past this check.
        reject_url_userinfo(self.parser, self.config_file)

        return self.parser


if __name__ == '__main__':
    pass
