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

# Building a Credential Offer — the issuer's half of the handshake.
#
# This is where the credential's content is DECIDED: which badge, to whom, in
# what format, against which status-list slot. Everything after this point can
# only match that decision or be refused. That is what makes "no wrong-issue"
# a checkable property rather than a hope: the wallet's request never gets to
# widen what it was offered, because the grant already says what it is.
#
# It is also the only place that writes to the status registry. Reserving the
# revocation slot here rather than when the wallet claims keeps the registry's
# exclusive lock and full-file rewrite out of a concurrent HTTP path — and off
# the platforms where that lock silently does nothing.

import configparser
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union
from urllib.parse import quote

from ..confparser import oid4vci_config, oid4vci_formats
from ..errors import ConfigError, IssuanceError
from .codes import hash_tx_code, new_id, new_secret, new_tx_code, secret_id
from .errors import INVALID_REQUEST, OID4VCIError, as_oid4vci_error
from .formats import REVOCABLE_FORMATS
from .metadata import credential_configuration_id
from .store import PreAuthorizedGrant

logger = logging.getLogger(__name__)

#: The scheme a wallet registers for offers arriving by QR or deep link.
OFFER_SCHEME = 'openid-credential-offer://'

#: Beyond roughly this many characters a QR code needs a high version and
#: stops scanning reliably from a phone camera at arm's length. Not a hard
#: limit — it drives the hint to use the by-reference form instead.
QR_COMFORTABLE_LIMIT = 1200


@dataclass
class CredentialOffer:
    """A Credential Offer, with its grant already persisted.

    ``uri`` is what goes into the QR code or the deep link. ``tx_code`` is the
    PIN IN THE CLEAR and this is the only time it exists: the store keeps only
    a KDF digest of it. Deliver it over a DIFFERENT channel from the offer —
    an email, an SMS, a screen the learner is already looking at — or it
    protects nothing, since an attacker who intercepted the offer would have
    intercepted the PIN alongside it.
    """

    offer: Dict[str, Any]
    uri: str
    pre_authorized_code: str
    grant_id: str
    recipient: str
    expires_at: datetime
    credential_configuration_ids: List[str] = field(default_factory=list)
    tx_code: Optional[str] = None
    status_index: Optional[int] = None
    notices: List[str] = field(default_factory=list)

    @property
    def offer_json(self) -> str:
        """The offer as the bytes to serve for a by-reference fetch."""
        return json.dumps(self.offer, sort_keys=True, separators=(',', ':'))

    @property
    def fits_in_a_qr_code(self) -> bool:
        """Whether :attr:`uri` is short enough to scan comfortably."""
        return len(self.uri) <= QR_COMFORTABLE_LIMIT

    def uri_by_reference(self, offer_uri: str) -> str:
        """The offer as a pointer, for when the inline form is too long.

        Serve :attr:`offer_json` at *offer_uri* and encode this instead. A
        multi-badge offer, or one with long display strings, overflows what a
        phone camera reads reliably.
        """
        return '%s?credential_offer_uri=%s' % (OFFER_SCHEME, quote(offer_uri,
                                                                   safe=''))


def build_credential_offer(conf: configparser.ConfigParser, badge: str,
                           recipient: str, *, store: Any,
                           credential_format: Optional[str] = None,
                           tx_code: bool = False,
                           expires_in_s: Optional[int] = None,
                           now: Optional[datetime] = None) -> CredentialOffer:
    """Offer *badge* to *recipient*, persisting the grant that backs it.

    *credential_format* defaults to the badge's first ``oid4vci_formats``
    entry. Set *tx_code* to require an out-of-band PIN, which is what turns an
    intercepted QR code from a stolen credential into a useless one.

    The grant is written BEFORE the offer is returned, so a crash can only
    leave an unused grant — harmless, and collected on expiry — rather than an
    offer in someone's hands whose code the issuer never recorded.

    Raises :class:`ConfigError` for a badge that does not opt into OID4VCI or a
    format it did not offer, and :class:`IssuanceError` if a revocation slot
    could not be reserved.
    """
    moment = now or datetime.now(tz=timezone.utc)
    cfg = oid4vci_config(conf)
    formats = oid4vci_formats(conf, badge)
    if not formats:
        raise ConfigError(
            "[%s] does not offer OID4VCI issuance — add oid4vci_formats to "
            "that section" % badge)
    chosen = credential_format or formats[0]
    if chosen not in formats:
        raise ConfigError("[%s] does not offer %r (it offers %s)"
                          % (badge, chosen, ', '.join(formats)))

    notices: List[str] = []
    expires_at = moment + timedelta(
        seconds=expires_in_s if expires_in_s is not None else cfg.offer_ttl_s)
    # The credential's id is fixed now, not at signing time: the status
    # registry indexes the reserved slot by it, and a signing-time id would
    # leave the registry naming a credential that never existed.
    credential_id = 'urn:uuid:%s' % uuid.uuid4()
    status_index = _reserve_status_index(conf, badge, chosen, recipient,
                                         credential_id, expires_at, notices)
    if status_index is not None and cfg.batch_size > 1:
        # A grant reserves exactly one status-list slot, so batch issuance
        # would hand out N credentials of which N-1 could never be revoked.
        raise ConfigError(
            "[%s] configures status_lists and [oid4vci] sets batch_size = %d, "
            "but one grant reserves one revocation slot — the extra "
            "credentials would be irrevocable. Set batch_size = 1, or drop "
            "status_lists from that section."
            % (badge, cfg.batch_size))

    code = new_secret()
    configuration_id = credential_configuration_id(badge, chosen)

    grant = PreAuthorizedGrant(
        grant_id=new_id(), code_id=secret_id(code), badge=badge,
        credential_configuration_id=configuration_id,
        credential_format=chosen, recipient=recipient,
        expires_at=expires_at, status_index=status_index,
        credential_id=credential_id,
        max_proofs=cfg.batch_size, created_at=moment)

    plain_tx_code = None
    if tx_code:
        plain_tx_code = new_tx_code(cfg.tx_code_length, cfg.tx_code_input_mode)
        kdf, salt, digest = hash_tx_code(plain_tx_code)
        grant.tx_code_kdf, grant.tx_code_salt, grant.tx_code_digest = \
            kdf, salt, digest
        grant.tx_code_length = cfg.tx_code_length
        grant.tx_code_input_mode = cfg.tx_code_input_mode

    offer = _offer_document(cfg.credential_issuer, [configuration_id], code,
                            cfg if tx_code else None)
    _validate_offer(offer)
    store.save_grant(grant)
    return CredentialOffer(
        offer=offer, uri=_offer_uri(offer), pre_authorized_code=code,
        grant_id=grant.grant_id, recipient=recipient, expires_at=expires_at,
        credential_configuration_ids=[configuration_id],
        tx_code=plain_tx_code, status_index=status_index, notices=notices)


def _offer_document(credential_issuer: str, configuration_ids: Sequence[str],
                    code: str, cfg: Any) -> Dict[str, Any]:
    grant: Dict[str, Any] = {'pre-authorized_code': code}
    if cfg is not None:
        grant['tx_code'] = {'input_mode': cfg.tx_code_input_mode,
                            'length': cfg.tx_code_length,
                            'description':
                                'Enter the code the issuer sent you'}
    return {
        'credential_issuer': credential_issuer,
        'credential_configuration_ids': list(configuration_ids),
        'grants': {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': grant,
        },
    }


def _offer_uri(offer: Dict[str, Any]) -> str:
    return '%s?credential_offer=%s' % (
        OFFER_SCHEME,
        quote(json.dumps(offer, sort_keys=True, separators=(',', ':')),
              safe=''))


def _validate_offer(offer: Dict[str, Any]) -> None:
    """Refuse to hand a wallet an offer document no wallet would accept.

    Same self-check contract as the issuer metadata (see metadata.py): the
    document is built from local configuration, so a rejection from
    openvc-core's fail-closed parser is a ConfigError raised BEFORE the grant
    is persisted — a crash leaves nothing behind, matching the
    grant-before-offer ordering above. Without the ``[oid4vci]`` extra the
    offer is returned unchecked, as issuance is unavailable there anyway.
    """
    try:
        from openvc.openid4vci import parse_credential_offer
    except ImportError:
        # Same caveat as the metadata self-check: an openvc-core older than
        # 1.25 takes this branch too, silently skipping the check.
        logger.debug('openvc-core OID4VCI discovery parsers unavailable; '
                     'the Credential Offer self-check is skipped (install '
                     'the [oid4vci] extra for it)')
        return
    try:
        parse_credential_offer(offer)
    except Exception as exc:
        raise ConfigError(
            'the Credential Offer this configuration produces is not a valid '
            'OID4VCI 1.0 document: %s' % exc) from exc


def parse_received_credential_offer(
        offer: Union[Mapping[str, Any], str]) -> Mapping[str, Any]:
    """Validate a Credential Offer this issuer RECEIVED, fail-closed.

    This is the mirror of :func:`build_credential_offer`: a badge platform
    acting as a relay, or a deployment that cross-checks its own served
    by-reference offer documents, receives third-party JSON and must not act
    on one that violates the wire contract. The validation is openvc-core's
    ``parse_credential_offer`` (OID4VCI 1.0 §4.1.1), which requires an
    absolute https ``credential_issuer`` and a non-empty, duplicate-free
    ``credential_configuration_ids`` array; unknown members are preserved in
    the returned mapping rather than dropped.

    A by-reference ``credential_offer_uri`` is NOT dereferenced here — this
    library fetches nothing it was not explicitly asked to fetch; resolving
    one stays the caller's (guarded) fetch. Raises :class:`OID4VCIError` with
    ``invalid_request`` for a malformed offer; the ``[oid4vci]`` extra is
    required.
    """
    try:
        from openvc.openid4vci import parse_credential_offer
    except ImportError as exc:
        raise OID4VCIError(
            INVALID_REQUEST,
            'validating a received Credential Offer needs the [oid4vci] '
            'extra: pip install openbadgeslib[oid4vci]') from exc
    try:
        parsed = parse_credential_offer(offer)
    except Exception as exc:                       # noqa: BLE001 - mapped
        raise as_oid4vci_error(exc) from exc
    # raw is the offer mapping exactly as received (openvc preserves every
    # extension member in it), which is the honest thing to hand back: the
    # typed view would silently discard what this library chose not to model.
    return dict(parsed.raw)


def _reserve_status_index(conf: configparser.ConfigParser, badge: str,
                          credential_format: str, recipient: str,
                          credential_id: str, offer_expires_at: datetime,
                          notices: List[str]) -> Optional[int]:
    """Reserve this credential's revocation slot, or explain why there is none.

    Registered under the credential's real id and recipient, so the operator
    can revoke it through the ordinary ``openbadges publish`` path without
    knowing it came from a wallet flow.

    Only formats that can actually carry status get a slot. Reserving one for
    SD-JWT VC would burn capacity on a credential that is irrevocable anyway
    (#226), so that combination is refused here — at offer time, while the
    operator is still looking — rather than when a wallet has already scanned
    the code.
    """
    from ..confparser import ob3_status_config

    status_conf = ob3_status_config(conf, badge)
    if status_conf is None:
        return None
    if credential_format not in REVOCABLE_FORMATS:
        raise ConfigError(
            "[%s] configures status_lists, but %s credentials cannot carry "
            "status, so this badge would be irrevocable. Offer it as one of "
            "%s, or drop status_lists from that section."
            % (badge, credential_format, ', '.join(REVOCABLE_FORMATS)))

    from ..errors import StatusError
    from ..ob3.status_registry import StatusRegistry

    try:
        with StatusRegistry.locked(status_conf.registry_path,
                                   status_conf.size_bits) as registry:
            index = registry.allocate(credential_id, recipient,
                                      datetime.now(tz=timezone.utc),
                                      pending=True,
                                      offer_expires_at=offer_expires_at)
            registry.save()
    except (StatusError, OSError) as exc:
        raise IssuanceError(
            'could not reserve a status list index for [%s]: %s'
            % (badge, exc)) from exc
    notices.append(
        'reserved status list index %d; it stays used until the credential is '
        'claimed or the reservation is reclaimed after the offer lapses'
        % index)
    return index


__all__ = ['CredentialOffer', 'OFFER_SCHEME', 'QR_COMFORTABLE_LIMIT',
           'build_credential_offer', 'parse_received_credential_offer']
