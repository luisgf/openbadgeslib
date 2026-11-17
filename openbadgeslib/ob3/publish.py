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

# Reusable OB3 issuer-artefact publishing and status management, extracted from
# the CLI.
#
# openbadges-publish held the real lifecycle logic — the revoke/suspend/unsuspend
# status-registry transaction (an unlocked best-effort locate, then a locked
# read-modify-write), the regeneration of the did:web document, the signed
# Bitstring Status List credentials and the SD-JWT VC Type Metadata, and the
# optional live-artefact check — interleaved with prints and sys.exit.
#
# publish_ob3 performs that orchestration and returns a PublishResult. It DOES
# write the published artefacts (that is the operation's purpose, unlike the
# no-I/O issue_from_conf / verify_badge), but does no user-facing I/O: no prints
# and no sys.exit. Any config or lifecycle problem raises a PublishError (the
# CLI turns it into its historical message and exit status). The flock
# semantics of the status transaction are preserved exactly: the locate is a
# best-effort unlocked read, the mutation reloads the winning registry under an
# exclusive lock so it is atomic against a concurrent signer or revoke.

import configparser
import os
import posixpath
import tempfile

from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional, Tuple, Union
from urllib.parse import urljoin, urlparse

from ..errors import LibOpenBadgesException


class PublishError(LibOpenBadgesException):
    """Raised when OB3 publication or a status operation cannot proceed (bad
    config, an unresolvable did:web, no readable key, or a status-registry
    failure). ``cli_exit`` carries the historical CLI exit status (1 or 255)
    the presenter preserves until the 0/1/2 contract (#233); messages carry no
    ``[!]`` prefix — the presentation layer adds one."""

    def __init__(self, message: str, cli_exit: int = 255) -> None:
        super().__init__(message)
        self.cli_exit = cli_exit


class PublicKeyRefused(PublishError):
    """A badge's configured ``public_key`` file was read and is not a key that
    may be published: it holds private key material, it is not an RSA, EC or
    Ed25519 public key, or it is not the public half of the badge's
    ``private_key``. The message names the file and the reason, never the
    file's contents."""

    def __init__(self, message: str) -> None:
        super().__init__(message, cli_exit=1)


def load_publishable_public_key(public_key_path: str,
                                private_key_path: Optional[str] = None
                                ) -> bytes:
    """Read a badge's ``public_key`` file and return the PEM to publish.

    Every publish path (OB1, OB2, OB3) used to copy the configured file as
    ``verify.pem``, whatever it held: one crossed path in the config (the
    ``private_key`` path under ``public_key``) served the signing key at a
    public URL (#337). The file is now only ever an input to this function,
    and what gets written is the key it returns, re-serialised:

      * a file with ``PRIVATE KEY`` anywhere in it is refused before it is
        parsed (a public block followed by a private one would parse);
      * it must load as an RSA, EC or Ed25519 public key (any PEM flavour
        ``cryptography`` reads, PKCS#1 ``RSA PUBLIC KEY`` included);
      * when *private_key_path* names a readable private key, the public key
        must be its public half. A missing or unloadable private key (the
        publishing host need not hold it) leaves nothing to compare against,
        and is not an error here.

    Returns the SubjectPublicKeyInfo ``PUBLIC KEY`` PEM. Raises
    :class:`PublicKeyRefused` for a file that was read and rejected, and lets
    the ``OSError`` of an unreadable *public_key_path* through, so a caller can
    tell "not generated yet" from "refused".
    """
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey)
    from ..keys import _load_private_pem, _load_public_pem, _public_pem

    with open(public_key_path, 'rb') as f:
        data = f.read()
    if b'PRIVATE KEY' in data:
        raise PublicKeyRefused(
            'public_key file %s holds a private key and was not published '
            '(if an earlier publish served it as verify.pem, replace the key '
            'pair)' % public_key_path)
    try:
        key = _load_public_pem(data)
    except LibOpenBadgesException as exc:
        raise PublicKeyRefused(
            'public_key file %s is not a public key and was not published '
            '(%s)' % (public_key_path, exc)) from exc
    if not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey,
                            Ed25519PublicKey)):
        raise PublicKeyRefused(
            'public_key file %s is not an RSA, EC or Ed25519 public key and '
            'was not published' % public_key_path)
    pem = _public_pem(key)

    if private_key_path:
        try:
            with open(private_key_path, 'rb') as f:
                private_key = _load_private_pem(f.read())
        except (OSError, LibOpenBadgesException):
            private_key = None
        if private_key is not None \
                and _public_pem(private_key.public_key()) != pem:
            raise PublicKeyRefused(
                'public_key file %s does not match the private_key %s (it is '
                'not its public half) and was not published'
                % (public_key_path, private_key_path))
    return pem


class CredentialNotFound(PublishError):
    """No credential matched the revoke/suspend/unsuspend identifier."""

    def __init__(self, ident: str, searched: List[str]) -> None:
        super().__init__(
            "No credential %r in the status registries (searched: %s)"
            % (ident, ', '.join(searched)), cli_exit=255)
        self.ident = ident
        self.searched = searched


class AmbiguousCredential(PublishError):
    """The identifier matched several credentials — the caller must use the jti.
    ``matches`` is a list of ``(badge, jti, issued_on)`` for presentation."""

    def __init__(self, ident: str, matches: List[Tuple[str, str, str]]) -> None:
        super().__init__(
            "%r matches several credentials; re-run with the jti" % ident,
            cli_exit=255)
        self.ident = ident
        self.matches = matches


@dataclass
class StatusOperation:
    """The applied status change (revoke/suspend/unsuspend) on one credential."""
    operation: str          # 'revoke' | 'suspend' | 'unsuspend'
    verb: str               # 'REVOKED' | 'SUSPENDED' | 'UNSUSPENDED'
    badge: str
    jti: str
    index: int
    reason: Optional[str] = None


@dataclass
class TypeMetadata:
    """Outcome of the opt-in SD-JWT VC Type Metadata publication."""
    vct: str
    rel_path: Optional[str]         # None => vct not under publish_url, not written
    integrity: Optional[str] = None  # the vct#integrity to pin, when written


@dataclass
class LiveArtifact:
    """One artefact's live-server check (only when check_live=True)."""
    rel: str
    url: str
    ok: bool
    detail: str = ''                # error message when missing/unreadable


@dataclass
class PublishResult:
    """Everything that happened, for the caller to report — no printing done.

    ``files_written`` are output-relative paths (did.json, per-badge
    ``<purpose>.jwt`` and ``verify.pem``, optional Type Metadata). ``did_skipped``
    / ``status_skipped`` are ``(badge, reason)`` for badges left out of did.json
    or whose status lists could not be regenerated; a badge whose ``public_key``
    was refused (:class:`PublicKeyRefused`) is in both, whether or not it has
    status lists, and nothing is written for it. ``no_status_config`` lists
    badges without ``status_lists``. ``no_validity_bound`` lists revocable badges
    whose status lists were published with no ``validUntil`` (no anti-replay
    freshness — set ``status_validity_days`` and republish regularly).
    ``status_operation`` is set when a revoke/suspend/unsuspend was applied.
    """
    did: str
    publish_url: str
    output: str
    files_written: List[str]
    status_operation: Optional[StatusOperation] = None
    did_skipped: List[Tuple[str, str]] = field(default_factory=list)
    status_skipped: List[Tuple[str, str]] = field(default_factory=list)
    no_status_config: List[str] = field(default_factory=list)
    no_validity_bound: List[str] = field(default_factory=list)
    type_metadata: Optional[TypeMetadata] = None
    live_check: Optional[List[LiveArtifact]] = None

    @property
    def bare_host_did(self) -> bool:
        """True when the issuer did:web is a bare host (resolves at
        /.well-known/did.json), so the CLI can add the serving hint."""
        return self.did.startswith('did:web:') \
            and ':' not in self.did[len('did:web:'):]

    @property
    def partial(self) -> bool:
        """A badge was skipped or a live artefact is stale/missing — the
        'some work skipped' outcome (exit 2 in --json)."""
        return bool(self.status_skipped) or bool(
            self.live_check and any(not a.ok for a in self.live_check))


def _dump(obj: dict[str, Any]) -> str:
    import json
    return json.dumps(obj, sort_keys=True, ensure_ascii=True)


def _write_atomic(path: str, data: Union[str, bytes]) -> None:
    """Write *path* via a same-directory temp file + rename, so re-publishing
    over a served directory can never expose a truncated artefact.

    ``bytes`` are written as they are: a multi-line PEM written in text mode
    would get CRLF line ends on Windows, and verify.pem must be the same bytes
    on every platform (and under every -V)."""
    directory = os.path.dirname(path) or '.'
    fd, tmp_path = tempfile.mkstemp(dir=directory, suffix='.tmp')
    try:
        if isinstance(data, bytes):
            with os.fdopen(fd, 'wb') as binary:
                binary.write(data)
        else:
            with os.fdopen(fd, 'w', encoding='ascii') as f:
                f.write(data)
        os.replace(tmp_path, path)
    except BaseException:
        os.unlink(tmp_path)
        raise


def _sd_jwt_vct_relpath(vct: str, publish_url: str) -> Optional[str]:
    """The output-relative path to write Type Metadata for *vct* so serving the
    output dir at *publish_url* resolves it there — or None if *vct* is not
    hosted under *publish_url* (same scheme+host, path under it).

    The remainder is POSIX-normalized. A ``..`` that would leave the publish
    prefix is refused (PublishError) rather than joined onto ``-o`` — a vct
    of ``https://host/out/../../../tmp/x`` used to write outside the output
    directory (#318).
    """
    v, p = urlparse(vct), urlparse(publish_url)
    if (v.scheme, v.netloc) != (p.scheme, p.netloc):
        return None
    base = p.path if p.path.endswith('/') else p.path + '/'
    if not v.path.startswith(base):
        return None
    rel = v.path[len(base):]
    if not rel:
        return None
    normalized = posixpath.normpath(rel)
    if posixpath.isabs(normalized) or normalized == '..' \
            or normalized.startswith('../'):
        raise PublishError(
            "[issuer] sd_jwt_vct path escapes the publish_url prefix")
    return normalized


def _publish_type_metadata(vct: str, publish_url: str, output: str,
                           files_written: List[str]) -> TypeMetadata:
    """Write the SD-JWT VC Type Metadata for *vct* under the webroot, when it is
    hosted under *publish_url*. Returns a TypeMetadata describing what happened
    (rel_path None means not written — the caller hosts it itself). The
    pure-Python builder needs no [eudi] extra."""
    from .eudi import (badge_type_metadata, type_metadata_document_bytes,
                       type_metadata_integrity)
    rel = _sd_jwt_vct_relpath(vct, publish_url)
    if rel is None:
        return TypeMetadata(vct=vct, rel_path=None)
    document = badge_type_metadata(vct)
    served = type_metadata_document_bytes(document)
    path = os.path.join(output, rel.replace('/', os.sep))
    root = os.path.abspath(output)
    dest = os.path.abspath(path)
    if os.path.commonpath([root, dest]) != root:
        raise PublishError(
            "[issuer] sd_jwt_vct would write Type Metadata outside %s"
            % output)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    _write_atomic(path, served.decode('ascii'))
    files_written.append(rel)
    return TypeMetadata(vct=vct, rel_path=rel,
                        integrity=type_metadata_integrity(document))


def _check_live(output: str, publish_url: str, files_written: List[str],
                download: Optional[Callable[[str], bytes]]) -> List[LiveArtifact]:
    """Download each freshly-written artefact from its published URL and
    byte-compare it against the local copy. Returns one LiveArtifact per file."""
    from ..util import download_file
    fetch = download if download is not None else download_file
    results: List[LiveArtifact] = []
    for rel in files_written:
        url = urljoin(publish_url, rel.replace(os.sep, '/'))
        with open(os.path.join(output, rel), 'rb') as f:
            local = f.read()
        try:
            live = fetch(url)
        except Exception as exc:
            results.append(LiveArtifact(rel=rel, url=url, ok=False,
                                        detail=str(exc)))
            continue
        results.append(LiveArtifact(rel=rel, url=url, ok=(live == local)))
    return results


def _apply_status_operation(conf: configparser.ConfigParser,
                            status_confs: dict[str, Any],
                            op: str, verb: str, ident: str,
                            badge: Optional[str],
                            reason: Optional[str]) -> StatusOperation:
    """Locate the credential *ident* names and apply *op* to it.

    Locate is a best-effort UNLOCKED read across the relevant registries; the
    mutation reloads the winning registry under an exclusive lock so it is
    atomic against a concurrent signer or revoke (StatusRegistry.locked)."""
    from datetime import datetime, timezone
    from ..confparser import resolve_badge_section
    from ..errors import StatusError
    from .status_registry import StatusRegistry

    if badge:
        scoped = resolve_badge_section(conf, badge)
        if status_confs.get(scoped) is None:
            raise PublishError('[%s] has no status_lists configured' % scoped,
                               cli_exit=1)
        sections = [scoped]
    else:
        sections = [n for n, sc in status_confs.items() if sc is not None]

    matches = []
    for name in sections:
        status_conf = status_confs[name]
        try:
            registry = StatusRegistry.load(status_conf.registry_path,
                                           status_conf.size_bits)
        except StatusError as exc:
            raise PublishError(str(exc), cli_exit=255) from exc
        matches += [(name, registry, entry) for entry in registry.find(ident)]

    if not matches:
        raise CredentialNotFound(ident, sections)
    if len(matches) > 1:
        raise AmbiguousCredential(
            ident, [(name, entry.jti, entry.issued_on)
                    for name, _registry, entry in matches])

    name, registry, entry = matches[0]
    jti = entry.jti
    now = datetime.now(tz=timezone.utc)
    try:
        with StatusRegistry.locked(registry.path,
                                   registry.size_bits) as locked:
            if op == 'revoke':
                locked.revoke(jti, now, reason)
            elif op == 'suspend':
                locked.suspend(jti, now, reason)
            else:
                locked.unsuspend(jti)
            locked.save()
    except (StatusError, OSError) as exc:
        raise PublishError(str(exc), cli_exit=255) from exc
    return StatusOperation(operation=op, verb=verb, badge=name, jti=jti,
                           index=entry.index, reason=reason)


def publish_ob3(conf: configparser.ConfigParser, output: str, *,
                revoke: Optional[str] = None, suspend: Optional[str] = None,
                unsuspend: Optional[str] = None, reason: Optional[str] = None,
                badge: Optional[str] = None, check_live: bool = False,
                download: Optional[Callable[[str], bytes]] = None
                ) -> PublishResult:
    """Publish OB3 issuer artefacts and manage credential status.

    Regenerates, from the per-badge status registries: the issuer's did:web
    document (``did.json``), every configured badge's signed Bitstring Status
    List credentials plus its ``verify.pem`` (the badge's public key,
    validated and re-serialised by :func:`load_publishable_public_key`, never
    a copy of the configured file), and (opt-in) the SD-JWT VC Type
    Metadata. With ``revoke``/``suspend``/``unsuspend`` (a jti or recipient) the
    registry is updated first, so the regenerated lists carry the change;
    ``reason`` annotates a revoke/suspend, ``badge`` scopes the operation to one
    badge section. ``check_live`` byte-compares each written artefact against
    ``publish_url``.

    Writes into ``output`` (created if absent) and returns a
    :class:`PublishResult`; raises :class:`PublishError` (or
    :class:`CredentialNotFound` / :class:`AmbiguousCredential`) on any config or
    lifecycle problem. Does no printing. OpenBadges 1.0/2.0 publication stays in
    the CLI.
    """
    from datetime import datetime, timedelta, timezone
    from ..confparser import ob3_issuer_id, ob3_status_config
    from ..errors import LibOpenBadgesException, StatusError
    from ..keys import alg_for_key_type, detect_key_type, public_jwk_from_pem
    from .did import build_did_document, did_web_from_url
    from .status_list import (build_status_list_credential,
                              sign_status_list_credential)
    from .status_registry import StatusRegistry

    if reason and not (revoke or suspend):
        raise PublishError('--reason needs --revoke or --suspend', cli_exit=1)

    # publish_url anchors the did:web id, the status-list URLs and the served
    # folder; validate it (and [issuer]) up front rather than dying later with a
    # raw KeyError('publish_url').
    if 'issuer' not in conf:
        raise PublishError('config is missing the [issuer] section', cli_exit=255)
    if not conf['issuer'].get('publish_url'):
        raise PublishError("[issuer] is missing the 'publish_url' key", cli_exit=255)
    try:
        issuer_id = ob3_issuer_id(conf)
        status_confs = {
            name: ob3_status_config(conf, name)
            for name in conf.sections() if name.startswith('badge_')
        }
    except ValueError as exc:
        raise PublishError(str(exc), cli_exit=255) from exc
    if not status_confs:
        raise PublishError('No badge_* sections', cli_exit=1)

    # ── status management (before regeneration, so the lists pick it up) ────
    status_operation: Optional[StatusOperation] = None
    op_triple = (('revoke', 'REVOKED', revoke) if revoke else
                 ('suspend', 'SUSPENDED', suspend) if suspend else
                 ('unsuspend', 'UNSUSPENDED', unsuspend) if unsuspend else None)
    if op_triple is not None:
        op, verb, ident = op_triple
        status_operation = _apply_status_operation(
            conf, status_confs, op, verb, ident, badge, reason)

    # ── regenerate every managed artefact from the registries ───────────────
    publish_url = conf['issuer']['publish_url']
    if issuer_id.startswith('did:web:'):
        did = issuer_id
    else:
        try:
            did = did_web_from_url(publish_url)
        except ValueError as exc:
            raise PublishError('Cannot derive a did:web identifier: %s' % exc,
                               cli_exit=255) from exc

    did_skipped: List[Tuple[str, str]] = []
    status_skipped: List[Tuple[str, str]] = []
    no_status_config: List[str] = []
    no_validity_bound: List[str] = []
    files_written: List[str] = []
    type_metadata: Optional[TypeMetadata] = None

    # Every badge's public key is read and validated once, before anything is
    # written: the same validated PEM feeds did.json and verify.pem, and the
    # configured file itself is never copied (#337).
    public_pems: dict[str, bytes] = {}
    key_refused: dict[str, str] = {}
    key_unread: dict[str, str] = {}
    methods = []
    for name in status_confs:
        try:
            public_pem = load_publishable_public_key(
                conf[name]['public_key'], conf[name].get('private_key'))
            methods.append((name, public_jwk_from_pem(public_pem)))
            public_pems[name] = public_pem
        except PublicKeyRefused as exc:
            # The file is there and is not this badge's public key (a private
            # key, something else, another pair's key): refuse the badge as a
            # whole, and make the publish report it (exit 2).
            key_refused[name] = str(exc)
            did_skipped.append((name, str(exc)))
        except (OSError, KeyError, LibOpenBadgesException) as exc:
            # A badge whose keys were never generated must not block the others'
            # publication — skip it in did.json (its own status lists, if any,
            # still fail hard below: they cannot be signed without the key).
            key_unread[name] = str(exc)
            did_skipped.append((name, str(exc)))
    if not methods:
        if key_refused:
            raise PublishError(
                'No badge public key could be published: %s' % '; '.join(
                    '[%s] %s' % item for item in key_refused.items()),
                cli_exit=1)
        raise PublishError('No badge public key could be read; generate key '
                           'pairs with openbadges-keygenerator first',
                           cli_exit=1)

    umask = os.umask(0o077)  # rwx------
    try:
        os.makedirs(output, exist_ok=True)

        _write_atomic(os.path.join(output, 'did.json'),
                      _dump(build_did_document(did, methods)))
        files_written.append('did.json')

        sd_jwt_vct = conf['issuer'].get('sd_jwt_vct')
        if sd_jwt_vct:
            type_metadata = _publish_type_metadata(
                sd_jwt_vct, publish_url, output, files_written)

        for name, status_conf in status_confs.items():
            if name in key_refused:
                status_skipped.append((name, key_refused[name]))
                continue
            if status_conf is None:
                no_status_config.append(name)
                continue
            # Isolate a per-badge failure: don't abort the whole publish — a
            # badge_2 mid-configuration must not make an urgent badge_1
            # revocation appear to fail after its list was written.
            try:
                registry = StatusRegistry.load(status_conf.registry_path,
                                               status_conf.size_bits)
                with open(conf[name]['private_key'], 'rb') as key:
                    priv_pem = key.read()
                algorithm = alg_for_key_type(detect_key_type(priv_pem))

                valid_until = None
                if status_conf.validity_days is not None:
                    valid_until = (datetime.now(tz=timezone.utc)
                                   + timedelta(days=status_conf.validity_days))
                else:
                    # No validUntil => the published list has no anti-replay
                    # freshness: a verifier can't tell a stale/replayed copy
                    # (with fewer revocations) from the current one. Flag it
                    # loudly so the issuer sets status_validity_days.
                    no_validity_bound.append(name)

                badge_dir = os.path.join(output, name)
                os.makedirs(badge_dir, exist_ok=True)
                for purpose in status_conf.purposes:
                    indices = registry.revoked_indices() if purpose == 'revocation' \
                        else registry.suspended_indices()
                    vc = build_status_list_credential(
                        issuer_id, status_conf.list_urls[purpose], purpose,
                        indices, registry.size_bits, valid_until=valid_until)
                    token = sign_status_list_credential(vc, priv_pem, algorithm)
                    _write_atomic(os.path.join(badge_dir, purpose + '.jwt'), token)
                    # files_written entries are output-relative URL paths (they
                    # map onto publish_url via urljoin and back to a file via
                    # rel.replace('/', os.sep) in _check_live) — always '/', never
                    # os.sep, or a Windows backslash would break both.
                    files_written.append('%s/%s.jwt' % (name, purpose))

                if name not in public_pems:
                    # The public key file could not be read (as opposed to
                    # refused): the lists above are regenerated all the same,
                    # so a revocation still gets out, and the badge is
                    # reported as skipped for its missing verify.pem — what
                    # the failed file copy did here before.
                    status_skipped.append((name, key_unread[name]))
                    continue
                _write_atomic(os.path.join(badge_dir, 'verify.pem'),
                              public_pems[name])
                files_written.append('%s/verify.pem' % name)
            except (StatusError, OSError, KeyError, LibOpenBadgesException) as exc:
                status_skipped.append((name, str(exc)))
                continue
    finally:
        os.umask(umask)

    live_check = None
    if check_live:
        live_check = _check_live(output, publish_url, files_written, download)

    return PublishResult(
        did=did, publish_url=publish_url, output=output,
        files_written=files_written, status_operation=status_operation,
        did_skipped=did_skipped, status_skipped=status_skipped,
        no_status_config=no_status_config,
        no_validity_bound=no_validity_bound, type_metadata=type_metadata,
        live_check=live_check)
