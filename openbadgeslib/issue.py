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

# Reusable issuance orchestration, extracted from the CLI.
#
# openbadges-signer used to hold the real business logic — building a
# credential/assertion from a config section, salt generation, the hosted-vs-
# signed decision, the status-registry→sign transaction, the Data Integrity
# verificationMethod policy and the did:key==key validation — interleaved with
# prints and sys.exit. That made "issue badge X to Y per config" impossible to
# call as a library without copying the CLI.
#
# issue_from_conf / issue_badge perform that orchestration and return a
# SignResult (signed bytes + metadata), doing NO user-facing I/O: no prints, no
# sys.exit and no badge-file write. Any config or policy problem raises
# IssuanceError. The one deliberate side effect is the OB3 status registry: for
# a revocable badge the index is allocated and the registry persisted *before*
# signing, so the transactional order the CLI relied on (a delivered badge is
# always in the registry, an unused index is a harmless orphan) is preserved
# here rather than in the caller.
#
# OpenBadges 1.0 issuance stays in the CLI: it is a legacy version (supported,
# but its signer writes the badge itself instead of returning bytes).

import configparser
import json
import logging
import ntpath
import os
import os.path
import uuid

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, List, NamedTuple, Optional, TYPE_CHECKING
from urllib.parse import urljoin

from .errors import (BadgeImgFormatUnsupported, ErrorSigningFile,
                     LibOpenBadgesException, StatusError)
# Re-export explicitly (X as X) so mypy --strict treats the historical
# `from openbadgeslib.issue import IssuanceError` path as a real public export.
from .errors import IssuanceError as IssuanceError
from .keys import KeyType, alg_for_key_type, detect_key_type
from .badge_model import Badge, BadgeImgType
from .util import normalize_recipient_id

if TYPE_CHECKING:
    # Boundary types for SignResult / _Ob3Context. Imported only for typing
    # (zero runtime cost, correct autocompletion and pdoc) — the modules are
    # otherwise resolved lazily inside the issuance functions.
    from .ob2 import Assertion
    from .ob3 import Achievement, Issuer, OpenBadgeCredential
    from .confparser import OB3StatusConfig

logger = logging.getLogger(__name__)

# IssuanceError now lives in openbadgeslib.errors (anchored under
# LibOpenBadgesException, so `except LibOpenBadgesException` catches it).
# Re-exported here so `from openbadgeslib.issue import IssuanceError` — the
# historical import path — keeps working.


@dataclass
class SignResult:
    """The outcome of issuing one badge: everything the caller needs to persist
    and report, with no I/O performed. ``badge_bytes`` is the signed badge
    image ready to write; the CLI writes it, appends the audit line and prints,
    while a library caller uses ``badge_bytes`` / ``credential`` directly."""

    ob_version: str
    badge_bytes: bytes
    badge_filename: str                 # suggested basename: <badge>_<recipient>.<ext>
    jti: Optional[str] = None           # OB3 credential id
    status_index: Optional[int] = None  # OB3 status-list index (revocable badges)
    proof_format: Optional[str] = None  # OB3: 'vc-jwt' | 'ldp'
    credential: Optional['OpenBadgeCredential'] = None    # OB3
    assertion: Optional['Assertion'] = None               # OB2
    assertion_id: Optional[str] = None  # OB2 hosted assertion URL
    hosted_json: Optional[str] = None   # OB2 hosted: assertion JSON to publish
    # Informational hints the CLI prints (without the '[!]'/'[i]' prefix), e.g.
    # the self-asserted did:key warning for a non-DID LDP issuer.
    notices: List[str] = field(default_factory=list)


@dataclass
class BatchResult:
    """One recipient's outcome in a batch issuance: exactly one of ``result``
    (a :class:`SignResult`) or ``error`` (why it failed) is set. A failure is
    captured here, not raised, so one bad recipient does not abort the batch."""

    recipient: str
    result: Optional[SignResult] = None
    error: Optional[str] = None


def _safe_filename_component(value: str, field_name: str) -> str:
    if not value or value in ('.', '..') or '\x00' in value:
        raise ValueError('%s is not safe for use in an output filename' % field_name)
    if os.path.basename(value) != value or ntpath.basename(value) != value:
        raise ValueError('%s must not contain path separators' % field_name)
    return value


def output_basename(badge: str, recipient: str,
                    image_type: Optional[BadgeImgType]) -> str:
    """The badge output file basename ``<badge>_<recipient>.<ext>``.

    Raises ``ValueError`` if either component is unsafe for a filename (path
    separators, NUL, ``.``/``..``) — the CLI turns that into its ``ERROR:``
    message — and ``BadgeImgFormatUnsupported`` for a non-PNG/SVG image."""
    safe_badge = _safe_filename_component(badge, 'badge')
    safe_recipient = _safe_filename_component(recipient, 'receptor')
    if image_type is BadgeImgType.PNG:
        return '%s_%s.png' % (safe_badge, safe_recipient)
    if image_type is BadgeImgType.SVG:
        return '%s_%s.svg' % (safe_badge, safe_recipient)
    raise BadgeImgFormatUnsupported('Unsupported image type: %r' % (image_type,))


def _badge_from_conf(conf: configparser.ConfigParser, badge: str) -> Badge:
    """Build the Badge config model, mapping a missing required config key or an
    unreadable key/image to :class:`IssuanceError` — so the issue_* entry points
    honour their documented contract instead of leaking a raw ``KeyError`` (e.g.
    an OB3 config with no OB1 ``verify_key``) out of ``Badge.create_from_conf``."""
    try:
        return Badge.create_from_conf(conf, badge)
    except KeyError as exc:
        raise IssuanceError('missing required config key %s' % exc) from exc
    except LibOpenBadgesException as exc:
        raise IssuanceError(str(exc)) from exc


def issue_from_conf(conf: configparser.ConfigParser, badge: str, recipient: str,
                    ob_version: str = '3', *, evidence: Optional[str] = None,
                    expires: Optional[int] = None, hosted: bool = False,
                    proof_format: Optional[str] = None) -> SignResult:
    """Issue one badge from config section ``[badge]`` to ``recipient``.

    ``recipient`` is an email (or a DID/URI for OB3); ``expires`` is a number of
    days; ``hosted`` selects OB2 HostedBadge over SignedBadge; ``proof_format``
    overrides the OB3 badge's ``proof_format`` ('vc-jwt' | 'ldp'). Returns a
    :class:`SignResult`; raises :class:`IssuanceError`. Supports OB 2.0 and
    3.0 (OB 1.0 is issued via the CLI only)."""
    badge_obj = _badge_from_conf(conf, badge)
    return issue_badge(conf, badge, recipient, badge_obj, ob_version,
                       evidence=evidence, expires=expires, hosted=hosted,
                       proof_format=proof_format)


def issue_badge(conf: configparser.ConfigParser, badge: str, recipient: str,
                badge_obj: Badge, ob_version: str = '3', *,
                evidence: Optional[str] = None, expires: Optional[int] = None,
                hosted: bool = False,
                proof_format: Optional[str] = None) -> SignResult:
    """Like :func:`issue_from_conf` but for a caller that already built the
    :class:`Badge` config model (the CLI, which needs its ``image_type`` for
    the output-file existence check before issuing) — avoids rebuilding it."""
    if ob_version == '3':
        return _issue_ob3(conf, badge, recipient, badge_obj, evidence, expires,
                          proof_format)
    if ob_version == '2':
        return _issue_ob2(conf, badge, recipient, badge_obj, evidence, expires,
                          hosted)
    raise IssuanceError(
        "issue_from_conf supports OpenBadges 2.0 and 3.0; OpenBadges 1.0 (-V 1) "
        "is a legacy version, issued through the CLI only")


def issue_batch_from_conf(conf: configparser.ConfigParser, badge: str,
                          recipients: List[str], ob_version: str = '3', *,
                          evidence: Optional[str] = None,
                          expires: Optional[int] = None, hosted: bool = False,
                          proof_format: Optional[str] = None
                          ) -> List[BatchResult]:
    """Issue ``badge`` to several ``recipients``, returning one
    :class:`BatchResult` per recipient in order.

    For OB3 revocable badges every status-list index is allocated in a SINGLE
    registry transaction (load once, allocate all, save once) — the piece that
    makes thousands-scale issuance practical — persisted before any badge is
    signed. A per-recipient signing failure is captured as ``BatchResult.error``,
    not raised, so it does not abort the rest. A config-level problem (a bad
    section, or the status list lacking room for the whole batch) raises
    :class:`IssuanceError` — the transaction is atomic, so nothing is issued.
    OpenBadges 1.0 is single-recipient only (CLI)."""
    badge_obj = _badge_from_conf(conf, badge)
    return issue_batch(conf, badge, recipients, badge_obj, ob_version,
                       evidence=evidence, expires=expires, hosted=hosted,
                       proof_format=proof_format)


def issue_batch(conf: configparser.ConfigParser, badge: str,
                recipients: List[str], badge_obj: Badge, ob_version: str = '3',
                *, evidence: Optional[str] = None, expires: Optional[int] = None,
                hosted: bool = False,
                proof_format: Optional[str] = None) -> List[BatchResult]:
    """Like :func:`issue_batch_from_conf` for a caller that already built the
    :class:`Badge` config model."""
    if ob_version == '3':
        return _issue_ob3_batch(conf, badge, list(recipients), badge_obj,
                                evidence, expires, proof_format)
    if ob_version == '2':
        # OB2 has no status registry, so there is no shared transaction: issue
        # each independently and isolate a per-recipient failure.
        results: List[BatchResult] = []
        for recipient in recipients:
            try:
                res = _issue_ob2(conf, badge, recipient, badge_obj, evidence,
                                 expires, hosted)
                results.append(BatchResult(recipient=recipient, result=res))
            except IssuanceError as exc:
                results.append(BatchResult(recipient=recipient, error=str(exc)))
        return results
    raise IssuanceError(
        "batch issuance supports OpenBadges 2.0 and 3.0; OpenBadges 1.0 (-V 1) "
        "is single-recipient only")


def _issue_ob2(conf: configparser.ConfigParser, badge: str, recipient: str,
               badge_obj: Badge, evidence: Optional[str], expires: Optional[int],
               hosted: bool) -> SignResult:
    """Issue a strict OpenBadges 2.0 badge (SignedBadge JWS or HostedBadge)."""
    from .ob2 import OB2Signer, Assertion, IdentityObject, Verification

    badge_section = conf[badge]

    # create_from_conf always populates these for a valid badge section.
    assert (badge_obj.json_url is not None and badge_obj.key_type is not None
            and badge_obj.image is not None and badge_obj.privkey_pem is not None)

    # Recipient: hashed email + a fresh random salt.
    salt = os.urandom(16).hex()
    recipient_obj = IdentityObject.create(recipient, salt=salt)

    if hosted:
        from .confparser import badge_section_config
        hosted_base = badge_section_config(conf, badge).hosted_assertions_base
        if not hosted_base:
            raise IssuanceError(
                "-V 2 -H (hosted) requires 'hosted_assertions_base' in the "
                "badge's config section.")
        base = hosted_base if hosted_base.endswith('/') else hosted_base + '/'
        assertion_id: Optional[str] = urljoin(base, '%s.json' % uuid.uuid4().hex)
        verification = Verification(type='HostedBadge')
    else:
        creator = badge_section.get('crypto_key')
        if not creator:
            raise IssuanceError(
                "-V 2 (signed) requires 'crypto_key' (the CryptographicKey URL) "
                "in the badge's config section.")
        assertion_id = None   # auto-generated as urn:uuid:…
        verification = Verification(type='SignedBadge', creator=creator)

    issued_on = datetime.now(tz=timezone.utc)
    expiration = issued_on + timedelta(days=expires) if expires else None

    assertion = Assertion(
        recipient=recipient_obj,
        badge=badge_obj.json_url,
        verification=verification,
        id=assertion_id,
        issued_on=issued_on,
        expires=expiration,
        image=badge_obj.image_url,
        evidence=evidence,
    )

    algorithm = alg_for_key_type(badge_obj.key_type)
    logger.debug("OB2 sign: key_type=%s algorithm=%s hosted=%s image_type=%s",
                 badge_obj.key_type, algorithm, hosted, badge_obj.image_type)

    signer = OB2Signer(privkey_pem=badge_obj.privkey_pem, algorithm=algorithm)
    # Surface a baking failure (ErrorSigningFile) as an IssuanceError, as the
    # OB3 paths do, so it is caught by the batch loop / CLI, not leaked raw.
    try:
        if badge_obj.image_type is BadgeImgType.SVG:
            signed_bytes = signer.sign_into_svg(assertion, badge_obj.image)
        else:
            signed_bytes = signer.sign_into_png(assertion, badge_obj.image)
    except ErrorSigningFile as exc:
        raise IssuanceError(str(exc)) from exc

    hosted_json = (json.dumps(assertion.to_dict(), sort_keys=True,
                              ensure_ascii=True) if hosted else None)
    return SignResult(
        ob_version='2', badge_bytes=signed_bytes,
        badge_filename=output_basename(badge, recipient, badge_obj.image_type),
        assertion=assertion,
        assertion_id=assertion.id if hosted else None,
        hosted_json=hosted_json)


class _Ob3Context(NamedTuple):
    """The per-badge OB3 config resolved once, shared by every recipient in a
    batch (issuer/achievement are identical; only the subject differs)."""
    issuer: 'Issuer'
    achievement: 'Achievement'
    issuer_id: str
    status_conf: Optional['OB3StatusConfig']
    proof_format: str
    key_type: KeyType


def _ob3_setup(conf: configparser.ConfigParser, badge: str, badge_obj: Badge,
               proof_format: Optional[str]) -> _Ob3Context:
    """Resolve the OB3 issuance config for a badge section once: the issuer and
    achievement (recipient-independent), the issuer id, the optional status
    config, the effective proof format and the signing key type. Raises
    IssuanceError on any config problem."""
    from .ob3 import Issuer, Achievement
    from .confparser import (ob3_proof_format, ob3_status_config,
                             issuer_config, badge_section_config)

    # A missing [issuer]/[badge] key raises KeyError and the confparser helpers
    # raise ConfigError (a ValueError); both are config problems, so surface them
    # as the documented IssuanceError rather than a raw traceback out of the
    # CLI/API. IssuerConfig / BadgeSectionConfig resolve the sections and their
    # defaults once (issuer id, criteria_narrative->criteria fallback).
    try:
        status_conf = ob3_status_config(conf, badge)
        proof_format = proof_format or ob3_proof_format(conf, badge)

        issuer_cfg = issuer_config(conf)
        issuer_id = issuer_cfg.id
        issuer = Issuer(
            id=issuer_cfg.id,
            name=issuer_cfg.name,
            url=issuer_cfg.url,
            email=issuer_cfg.email,
        )

        badge_section = conf[badge]
        bsc = badge_section_config(conf, badge)
        achievement = Achievement(
            id=badge_section['badge'],
            name=badge_section['name'],
            description=badge_section['description'],
            criteria_narrative=bsc.criteria_narrative,
            image_url=badge_section.get('image'),
        )
    except ValueError as exc:
        raise IssuanceError(str(exc)) from exc
    except KeyError as exc:
        raise IssuanceError("missing required config key %s" % exc) from exc

    # create_from_conf always populates these from the badge config section.
    assert badge_obj.privkey_pem is not None and badge_obj.image is not None
    key_type = detect_key_type(badge_obj.privkey_pem)

    return _Ob3Context(issuer, achievement, issuer_id, status_conf,
                       proof_format, key_type)


def _build_ob3_credential(ctx: _Ob3Context, recipient: str,
                          evidence: Optional[str],
                          expires: Optional[int]) -> Any:
    """Build one OpenBadgeCredential from the shared context (no status yet)."""
    from .ob3 import OpenBadgeCredential
    expiration_date = None
    if expires:
        expiration_date = datetime.now(tz=timezone.utc) + timedelta(days=expires)
    return OpenBadgeCredential(
        issuer=ctx.issuer,
        recipient_id=normalize_recipient_id(recipient),
        achievement=ctx.achievement,
        evidence_url=evidence,
        expiration_date=expiration_date,
    )


def _sign_ob3_credential(badge: str, credential: Any, badge_obj: Badge,
                         ctx: _Ob3Context, notices: List[str]) -> bytes:
    """Sign a built OB3 credential into the badge image — the Data Integrity
    (LDP) or the compact JWT-VC path, per ``ctx.proof_format``."""
    from .ob3 import OB3Signer
    # create_from_conf always populates these for a valid badge section.
    assert badge_obj.privkey_pem is not None and badge_obj.image is not None
    recipient_id = credential.recipient_id
    if ctx.proof_format == 'ldp':
        return _issue_ob3_ldp(badge, badge_obj, credential, ctx.issuer_id,
                              ctx.key_type, recipient_id, notices)
    algorithm = alg_for_key_type(ctx.key_type)
    logger.debug("OB3 sign: key_type=%s algorithm=%s recipient=%s",
                 ctx.key_type, algorithm, recipient_id)
    signer = OB3Signer(privkey_pem=badge_obj.privkey_pem, algorithm=algorithm)
    # A baking failure (e.g. a malformed carrier image) raises ErrorSigningFile,
    # which is not an IssuanceError; surface it as one so callers -- the batch
    # loop and the CLI -- handle it like every other issuance error instead of
    # leaking a raw traceback (mirrors the LDP branch).
    try:
        if badge_obj.image_type is BadgeImgType.SVG:
            return signer.sign_into_svg(credential, badge_obj.image)
        return signer.sign_into_png(credential, badge_obj.image)
    except ErrorSigningFile as exc:
        raise IssuanceError(str(exc)) from exc


def _issue_ob3(conf: configparser.ConfigParser, badge: str, recipient: str,
               badge_obj: Badge, evidence: Optional[str], expires: Optional[int],
               proof_format: Optional[str]) -> SignResult:
    """Issue an OpenBadges 3.0 credential (JWT-VC or a Data Integrity proof)."""
    ctx = _ob3_setup(conf, badge, badge_obj, proof_format)
    credential = _build_ob3_credential(ctx, recipient, evidence, expires)
    status_index = _allocate_status_batch(
        [credential], ctx.status_conf)[0]
    notices: List[str] = []
    signed_bytes = _sign_ob3_credential(badge, credential, badge_obj, ctx, notices)
    return SignResult(
        ob_version='3', badge_bytes=signed_bytes,
        badge_filename=output_basename(badge, recipient, badge_obj.image_type),
        jti=credential.id, status_index=status_index,
        proof_format=ctx.proof_format, credential=credential, notices=notices)


def _issue_ob3_batch(conf: configparser.ConfigParser, badge: str,
                     recipients: List[str], badge_obj: Badge,
                     evidence: Optional[str], expires: Optional[int],
                     proof_format: Optional[str]) -> List[BatchResult]:
    """Issue OB3 to N recipients with a single status-registry transaction.

    The issuer/achievement config is resolved once; every credential is built,
    then all indices are allocated and stamped in one load→save cycle; then each
    is signed with a per-recipient failure isolated into its BatchResult."""
    ctx = _ob3_setup(conf, badge, badge_obj, proof_format)
    credentials = [_build_ob3_credential(ctx, r, evidence, expires)
                   for r in recipients]
    indices = _allocate_status_batch(credentials, ctx.status_conf)

    results: List[BatchResult] = []
    for recipient, credential, status_index in zip(recipients, credentials, indices):
        notices: List[str] = []
        try:
            signed_bytes = _sign_ob3_credential(badge, credential, badge_obj,
                                                ctx, notices)
        except IssuanceError as exc:
            results.append(BatchResult(recipient=recipient, error=str(exc)))
            continue
        results.append(BatchResult(recipient=recipient, result=SignResult(
            ob_version='3', badge_bytes=signed_bytes,
            badge_filename=output_basename(badge, recipient,
                                           badge_obj.image_type),
            jti=credential.id, status_index=status_index,
            proof_format=ctx.proof_format, credential=credential,
            notices=notices)))
    return results


def _allocate_status_batch(credentials: List[Any],
                           status_conf: Any) -> List[Optional[int]]:
    """Allocate a status-list index for every credential in ONE registry
    transaction — load once, allocate all, save once — stamping each
    credential's credentialStatus, and return the indices aligned with
    ``credentials`` (all None when the badge is not revocable). The single-badge
    path is this with one credential.

    The registry is persisted BEFORE any badge is signed and written: a signing
    failure leaves harmless orphan indices, while a delivered badge missing from
    the registry could never be revoked. The transaction is atomic (a capacity
    failure allocates nothing) and runs under an exclusive lock, so a concurrent
    signer cannot clobber the allocation (see StatusRegistry.locked)."""
    if status_conf is None:
        return [None] * len(credentials)

    from .ob3.status_list import status_entry
    from .ob3.status_registry import StatusRegistry

    indices: List[Optional[int]] = []
    try:
        with StatusRegistry.locked(status_conf.registry_path,
                                   status_conf.size_bits) as registry:
            for credential in credentials:
                assert credential.id is not None \
                    and credential.issuance_date is not None
                index = registry.allocate(credential.id,
                                          credential.recipient_id,
                                          credential.issuance_date)
                credential.credential_status = [
                    status_entry(status_conf.list_urls[p], p, index)
                    for p in status_conf.purposes]
                indices.append(index)
            registry.save()
    except (StatusError, OSError) as exc:
        raise IssuanceError(
            'Could not allocate a status list index: %s' % exc) from exc
    return indices


def _issue_ob3_ldp(badge: str, badge_obj: Badge, credential: Any, issuer_id: str,
                   key_type: KeyType, recipient_id: str,
                   notices: List[str]) -> bytes:
    """Sign an OB3 credential with a Data Integrity proof, baked into the badge
    image. The proof's verificationMethod follows the issuer config: a did:web
    issuer signs with the method id openbadges-publish publishes
    (did:web:…#badge_section — trusted); anything else falls back to a did:key
    derived from the signing key (self-asserted). Appends the self-asserted
    hint to ``notices`` for the caller to surface."""
    from .ob3 import OB3LdpSigner

    if key_type is not KeyType.ED25519:
        raise IssuanceError(
            "--proof-format ldp (eddsa-rdfc-2022) requires an Ed25519 key; "
            "[%s] uses %s. Set 'key_type = ED25519' in that badge's config "
            "section and regenerate its key with openbadges-keygenerator -g"
            % (badge, key_type.value))

    verification_method = None
    if issuer_id.startswith('did:web:'):
        verification_method = '%s#%s' % (issuer_id, badge)

    assert badge_obj.privkey_pem is not None and badge_obj.image is not None
    try:
        signer = OB3LdpSigner(badge_obj.privkey_pem,
                              verification_method=verification_method)
    except ErrorSigningFile as exc:
        raise IssuanceError(str(exc)) from exc

    if issuer_id.startswith('did:key:'):
        # A did:key issuer IS its key; signing with a different one would
        # produce a credential no verifier accepts.
        derived = signer.verification_method.partition('#')[0]
        if derived != issuer_id:
            raise IssuanceError(
                "[issuer] did %s does not match the signing key's did:key (%s); "
                "a did:key issuer must be the signing key itself"
                % (issuer_id, derived))
    elif not issuer_id.startswith('did:'):
        notices.append(
            "The issuer id is not a DID, so the proof carries a self-asserted "
            "did:key verification method and verifiers must pin the public key "
            "(-k/-l). Set [issuer] did = auto to publish a trusted did:web "
            "instead.")

    logger.debug("OB3 sign: proof_format=ldp vm=%s recipient=%s",
                 signer.verification_method, recipient_id)
    try:
        if badge_obj.image_type is BadgeImgType.SVG:
            return signer.sign_into_svg(credential, badge_obj.image)
        return signer.sign_into_png(credential, badge_obj.image)
    except ErrorSigningFile as exc:
        raise IssuanceError(str(exc)) from exc
