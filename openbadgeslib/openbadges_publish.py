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
import configparser
import json
import os
import os.path
import shutil
import sys
import tempfile

from typing import Any, List, Optional, TYPE_CHECKING, Tuple
from urllib.parse import urljoin, urlparse
from .confparser import read_config_or_exit, resolve_badge_section
from .util import __version__, emit_cli_json

if TYPE_CHECKING:
    from .ob3.status_registry import StatusEntry, StatusEvent, StatusRegistry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Publisher Parameters')
    parser.add_argument('-c', '--config', default='config.ini', help='Specify the config.ini file to use')
    parser.add_argument('-o', '--output',
                        help='Output directory for the published files '
                             '(required to publish; not needed for '
                             '--list/--status)')
    parser.add_argument('-V', '--ob-version', choices=['1', '2', '3'], default='3',
                        metavar='VERSION',
                        help='OpenBadges specification version: 1 (legacy hosted), '
                             '2 (strict OB 2.0), or 3 (default: did.json and the '
                             'Bitstring Status Lists of badges with status_lists set).')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--revoke', metavar='ID',
                       help='OB3 only: permanently revoke a credential; ID is its '
                            'jti (urn:uuid:...) or the recipient email')
    group.add_argument('--suspend', metavar='ID',
                       help='OB3 only: suspend a credential (reversible with --unsuspend)')
    group.add_argument('--unsuspend', metavar='ID',
                       help='OB3 only: lift a suspension')
    group.add_argument('--list', action='store_true',
                       help='OB3 only: tabulate issued credentials and their '
                            'state (scope to one badge with -b); read-only')
    group.add_argument('--status', metavar='ID',
                       help='OB3 only: show the full status record of a '
                            'credential by jti (urn:uuid:...) or recipient '
                            'email, including revocation/suspension reason')
    parser.add_argument('--reason',
                        help='Free-text reason recorded with --revoke/--suspend')
    parser.add_argument('-b', '--badge',
                        help='Badge name; scopes the --revoke/--suspend/--unsuspend '
                             'lookup to that badge registry')
    parser.add_argument('--json', action='store_true',
                        help='OB3 only (-V 3): emit a machine-readable JSON '
                             'result instead of the human output — for publish '
                             '{did, files_written, status_operation, skipped} '
                             'and for --list/--status the queried records. Exit '
                             'status: 0 success, 2 partial (some badges '
                             'skipped), 1 any error.')
    parser.add_argument('--check-live', action='store_true',
                        help='OB3 only (-V 3): after publishing, download each '
                             'written artifact (did.json, status lists, '
                             'verify.pem) from publish_url and byte-compare it '
                             'against the local copy — verifying the web server '
                             'serves the freshly-regenerated versions, not a '
                             'stale cache. Exit 2 if any artifact is stale or '
                             'missing on the server.')
    parser.add_argument('-v', '--version', action='version', version=__version__)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # JSON output is defined for the OB3 artefacts/registries only (did.json,
    # status lists, the status registries); OB1/OB2 hosted metadata has no such
    # contract, so reject the combination rather than emit half of one.
    if args.json and args.ob_version != '3':
        sys.exit('[!] --json is supported for OpenBadges 3.0 (-V 3) only')

    # Read-only registry queries need no output directory and never touch the
    # published tree, so they route before the publish paths and the -o check.
    if args.list or args.status is not None:
        if args.ob_version != '3':
            sys.exit('[!] --list/--status query the OpenBadges 3.0 status '
                     'registries and need -V 3')
        if args.json:
            emit_cli_json(lambda: _query_ob3(args, parser))
        else:
            _query_ob3(args, parser)
        return

    if args.ob_version == '3':
        if args.output is None:
            parser.error('-o/--output is required to publish '
                         '(it is not needed for --list/--status)')
        if args.json:
            emit_cli_json(lambda: _publish_ob3(args, parser))
        else:
            result = _publish_ob3(args, parser)
            # A partial failure historically exits 1 in human mode; --json maps
            # it to 2 (see the result's _exit). Preserve the human exit here.
            if result.get('_exit') == 2:
                sys.exit(1)
        return

    if args.revoke or args.suspend or args.unsuspend or args.reason or args.badge:
        sys.exit('[!] --revoke/--suspend/--unsuspend manage OpenBadges 3.0 status '
                 'lists and need -V 3 (OB %s revocation is edited by hand in the '
                 'published revocation list)' % args.ob_version)

    if args.output is None:
        parser.error('-o/--output is required to publish')

    if args.ob_version == '2':
        _publish_ob2(args, parser)
        return

    _publish_ob1(args, parser)


def _dump(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True)


def _write_atomic(path: str, data: str) -> None:
    """Write *path* via a same-directory temp file + rename, so re-publishing
    over a served directory can never expose a truncated artefact."""
    directory = os.path.dirname(path) or '.'
    fd, tmp_path = tempfile.mkstemp(dir=directory, suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='ascii') as f:
            f.write(data)
        os.replace(tmp_path, path)
    except BaseException:
        os.unlink(tmp_path)
        raise


def _sd_jwt_vct_relpath(vct: str, publish_url: str) -> Optional[str]:
    """The output-relative path to write Type Metadata for *vct* so that serving
    the output dir at *publish_url* resolves it there — or ``None`` if *vct* is
    not hosted under *publish_url* (same scheme+host, path under it)."""
    v, p = urlparse(vct), urlparse(publish_url)
    if (v.scheme, v.netloc) != (p.scheme, p.netloc):
        return None
    base = p.path if p.path.endswith('/') else p.path + '/'
    if not v.path.startswith(base):
        return None
    return v.path[len(base):] or None


def _publish_type_metadata(vct: str, publish_url: str, output: str,
                           files_written: List[str]) -> None:
    """Opt-in (#176): write the SD-JWT VC Type Metadata for the ``[issuer]``
    ``sd_jwt_vct`` into the webroot so a wallet can resolve and validate a
    library-issued SD-JWT badge. The vct must be hosted under *publish_url*; the
    printed ``vct#integrity`` is what an issuer pins with
    ``issue_badge_sd_jwt(vct_integrity=…)``. The pure-Python builder needs no
    ``[eudi]`` extra."""
    from .ob3.eudi import (badge_type_metadata, type_metadata_document_bytes,
                           type_metadata_integrity)
    rel = _sd_jwt_vct_relpath(vct, publish_url)
    if rel is None:
        print('[!] [issuer] sd_jwt_vct %r is not under publish_url %r — not '
              'publishing its Type Metadata (host it yourself).'
              % (vct, publish_url))
        return
    document = badge_type_metadata(vct)
    served = type_metadata_document_bytes(document)
    path = os.path.join(output, rel.replace('/', os.sep))
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    _write_atomic(path, served.decode('ascii'))
    files_written.append(rel)
    print('[i] Wrote SD-JWT VC Type Metadata for %s' % vct)
    print('    Pin it on issued badges: vct_integrity=%s'
          % type_metadata_integrity(document))


def _query_ob3(args: argparse.Namespace,
               parser: argparse.ArgumentParser) -> dict[str, Any]:
    """Read-only inspection of the private OB3 status registries.

    ``--list`` tabulates every issued credential (jti, recipient, issue date,
    state) for one badge or all of them; ``--status <jti|email>`` prints the
    full record of the matching credential(s), including the revocation or
    suspension date and reason. Neither reads nor writes the published
    artefacts, so no output directory is needed — this closes the credential
    lifecycle from the CLI: issue -> revoke/suspend -> audit.
    """
    from .confparser import ob3_status_config
    from .errors import StatusError
    from .ob3.status_registry import StatusRegistry

    conf = read_config_or_exit(args.config)

    if args.reason:
        sys.exit('[!] --reason needs --revoke or --suspend')

    try:
        if 'issuer' not in conf:
            raise ValueError('config is missing the [issuer] section')
        if not conf['issuer'].get('publish_url'):
            raise ValueError("[issuer] is missing the 'publish_url' key")
        if args.badge:
            sections = [resolve_badge_section(conf, args.badge)]
        else:
            sections = [n for n in conf.sections() if n.startswith('badge_')]
        status_confs = {name: ob3_status_config(conf, name)
                        for name in sections}
    except ValueError as exc:
        print('[!] %s' % exc)
        sys.exit(-1)

    configured = [(name, sc) for name, sc in status_confs.items()
                  if sc is not None]
    if not configured:
        if args.badge:
            sys.exit('[!] badge_%s has no status_lists configured' % args.badge)
        sys.exit('[!] No badge has status_lists configured in %s' % args.config)

    # Load each badge's registry once; isolate a per-badge failure (corrupt or
    # unreadable registry) so it does not mask the badges that read cleanly.
    registries: List[Tuple[str, 'StatusRegistry']] = []
    for name, status_conf in configured:
        assert status_conf is not None
        try:
            registries.append((name, StatusRegistry.load(
                status_conf.registry_path, status_conf.size_bits)))
        except StatusError as exc:
            print('[!] Skipping [%s] — %s' % (name, exc))

    if not registries:
        sys.exit(-1)

    if args.status is not None:
        return _print_status_detail(registries, args.status)
    return _print_registry_table(registries)


def _state_label(entry: 'StatusEntry') -> str:
    """One-word lifecycle state; revocation (permanent) dominates suspension."""
    if entry.revoked is not None:
        return 'REVOKED'
    if entry.suspended is not None:
        return 'SUSPENDED'
    return 'active'


def _event_detail(event: 'StatusEvent') -> str:
    if event.reason:
        return '%s  (reason: %s)' % (event.date, event.reason)
    return event.date


def _entry_to_dict(name: str, entry: 'StatusEntry') -> dict[str, Any]:
    """The machine-readable record of one credential, for --json output."""
    data: dict[str, Any] = {
        'badge': name, 'jti': entry.jti, 'index': entry.index,
        'recipient': entry.recipient, 'issued_on': entry.issued_on,
        'state': _state_label(entry),
    }
    if entry.revoked is not None:
        data['revoked'] = entry.revoked.to_dict()
    if entry.suspended is not None:
        data['suspended'] = entry.suspended.to_dict()
    return data


def _print_registry_table(
        registries: List[Tuple[str, 'StatusRegistry']]) -> dict[str, Any]:
    header = ('JTI', 'RECIPIENT', 'ISSUED', 'STATE')
    grand_total = 0
    badges = []
    for name, registry in registries:
        entries = sorted(registry.entries.values(),
                         key=lambda e: (e.issued_on, e.jti))
        grand_total += len(entries)
        badges.append({'badge': name,
                       'credentials': [_entry_to_dict(name, e)
                                       for e in entries]})
        print('\n# %s — %d credential%s'
              % (name, len(entries), '' if len(entries) == 1 else 's'))
        if not entries:
            continue
        rows = [(e.jti, e.recipient, e.issued_on, _state_label(e))
                for e in entries]
        widths = [max(len(header[i]), max(len(row[i]) for row in rows))
                  for i in range(len(header))]
        for cells in (header, *rows):
            print('  '.join(cells[i].ljust(widths[i])
                            for i in range(len(header))).rstrip())
    print('\n%d credential%s total across %d badge%s'
          % (grand_total, '' if grand_total == 1 else 's',
             len(registries), '' if len(registries) == 1 else 's'))
    return {'badges': badges, 'total': grand_total}


def _print_status_detail(registries: List[Tuple[str, 'StatusRegistry']],
                         ident: str) -> dict[str, Any]:
    matches = [(name, entry)
               for name, registry in registries
               for entry in registry.find(ident)]
    if not matches:
        print('[!] No credential %r in the status registries (searched: %s)'
              % (ident, ', '.join(name for name, _ in registries)))
        sys.exit(1)
    for position, (name, entry) in enumerate(matches):
        if position:
            print()
        _print_field('badge', name)
        _print_field('jti', entry.jti)
        _print_field('index', str(entry.index))
        _print_field('recipient', entry.recipient)
        _print_field('issued', entry.issued_on)
        _print_field('state', _state_label(entry))
        if entry.revoked is not None:
            _print_field('revoked', _event_detail(entry.revoked))
        if entry.suspended is not None:
            _print_field('suspended', _event_detail(entry.suspended))
    return {'matches': [_entry_to_dict(name, entry)
                        for name, entry in matches]}


def _print_field(label: str, value: str) -> None:
    print('%-11s %s' % (label + ':', value))


def _check_live_artifacts(output: str, publish_url: str,
                          files_written: List[str]) -> List[str]:
    """Download each freshly-written artifact from its published URL and
    byte-compare it against the local copy, so the "re-upload" reminder becomes
    a verifiable guarantee. Returns the artifacts that are missing or stale on
    the live server (an empty list means the server is fully current)."""
    from .util import download_file
    stale: List[str] = []
    for rel in files_written:
        url = urljoin(publish_url, rel.replace(os.sep, '/'))
        with open(os.path.join(output, rel), 'rb') as f:
            local = f.read()
        try:
            live = download_file(url)
        except Exception as exc:
            print('[!] %s: no live copy at %s (%s)' % (rel, url, exc))
            stale.append(rel)
            continue
        if live == local:
            print('[+] %s matches the live copy' % rel)
        else:
            print('[!] %s is STALE at %s — re-upload needed' % (rel, url))
            stale.append(rel)
    return stale


def _publish_ob3(args: argparse.Namespace,
                 parser: argparse.ArgumentParser) -> dict[str, Any]:
    """Publish OpenBadges 3.0 issuer artefacts and manage credential status.

    Always regenerates, from the per-badge status registries: the issuer's
    did:web document (``did.json``) and, for every badge with ``status_lists``
    configured, its signed Bitstring Status List credentials plus the raw
    verification PEM. With --revoke/--suspend/--unsuspend the registry is
    updated first, so the regenerated lists already carry the change.

    Unlike -V 1/2 the output directory may exist: re-running publish after
    every status change is the normal workflow, and the managed files are
    replaced atomically.
    """
    from datetime import datetime, timedelta, timezone
    from .confparser import ob3_issuer_id, ob3_status_config
    from .errors import LibOpenBadgesException, StatusError
    from .keys import alg_for_key_type, detect_key_type, public_jwk_from_pem
    from .ob3.did import build_did_document, did_web_from_url
    from .ob3.status_list import (build_status_list_credential,
                                  sign_status_list_credential)
    from .ob3.status_registry import StatusRegistry

    conf = read_config_or_exit(args.config)

    if args.reason and not (args.revoke or args.suspend):
        sys.exit('[!] --reason needs --revoke or --suspend')

    try:
        # publish_url is required for OB3 publication (it anchors the did:web
        # id, the status-list URLs and the served-folder instruction). Check
        # it here so a config carrying only [issuer] url — which ob3_issuer_id
        # tolerantly falls back to — fails cleanly instead of dying later with
        # a raw KeyError('publish_url') at conf['issuer']['publish_url'].
        if 'issuer' not in conf:
            raise ValueError('config is missing the [issuer] section')
        if not conf['issuer'].get('publish_url'):
            raise ValueError("[issuer] is missing the 'publish_url' key")
        issuer_id = ob3_issuer_id(conf)
        status_confs = {
            name: ob3_status_config(conf, name)
            for name in conf.sections() if name.startswith('badge_')
        }
    except ValueError as exc:
        print('[!] %s' % exc)
        sys.exit(-1)
    if not status_confs:
        sys.exit('[!] No badge_* sections in %s' % args.config)

    # ── status management (before regeneration, so the lists pick it up) ────
    operation = None
    operation_result: Optional[dict[str, Any]] = None
    if args.revoke:
        operation = ('revoke', 'REVOKED', args.revoke)
    elif args.suspend:
        operation = ('suspend', 'SUSPENDED', args.suspend)
    elif args.unsuspend:
        operation = ('unsuspend', 'UNSUSPENDED', args.unsuspend)

    if operation is not None:
        op, verb, ident = operation
        if args.badge:
            scoped = resolve_badge_section(conf, args.badge)
            if status_confs.get(scoped) is None:
                sys.exit('[!] [%s] has no status_lists configured' % scoped)
            sections = [scoped]
        else:
            sections = [n for n, sc in status_confs.items() if sc is not None]

        matches = []
        for name in sections:
            status_conf = status_confs[name]
            assert status_conf is not None
            try:
                registry = StatusRegistry.load(status_conf.registry_path,
                                               status_conf.size_bits)
            except StatusError as exc:
                print('[!] %s' % exc)
                sys.exit(-1)
            matches += [(name, registry, entry)
                        for entry in registry.find(ident)]

        if not matches:
            print('[!] No credential %r in the status registries (searched: %s)'
                  % (ident, ', '.join(sections)))
            sys.exit(-1)
        if len(matches) > 1:
            print('[!] %r matches several credentials; re-run with the jti:'
                  % ident)
            for name, _registry, entry in matches:
                print('    %s  %s  (issued %s)'
                      % (name, entry.jti, entry.issued_on))
            sys.exit(-1)

        name, registry, entry = matches[0]
        jti = entry.jti
        now = datetime.now(tz=timezone.utc)
        # The search above is an unlocked best-effort locator; the mutation
        # reloads the winning registry under an exclusive lock so it is atomic
        # against a concurrent signer or revoke (see StatusRegistry.locked).
        try:
            with StatusRegistry.locked(registry.path,
                                       registry.size_bits) as registry:
                if op == 'revoke':
                    registry.revoke(jti, now, args.reason)
                elif op == 'suspend':
                    registry.suspend(jti, now, args.reason)
                else:
                    registry.unsuspend(jti)
                registry.save()
        except (StatusError, OSError) as exc:
            print('[!] %s' % exc)
            sys.exit(-1)
        print('[+] %s %s %s (index %d)' % (verb, name, jti, entry.index))
        operation_result = {'operation': op, 'badge': name, 'jti': jti,
                            'index': entry.index, 'reason': args.reason}

    # ── regenerate every managed artefact from the registries ───────────────
    publish_url = conf['issuer']['publish_url']
    if issuer_id.startswith('did:web:'):
        did = issuer_id
    else:
        try:
            did = did_web_from_url(publish_url)
        except ValueError as exc:
            print('[!] Cannot derive a did:web identifier: %s' % exc)
            sys.exit(-1)

    failures = []                 # badges skipped (unreadable key / registry)
    files_written: List[str] = []  # output-relative paths, for --json
    umask = os.umask(0o077)  # rwx------
    try:
        os.makedirs(args.output, exist_ok=True)

        methods = []
        for name in status_confs:
            # A badge whose keys were never generated must not block the
            # publication of the others' — skip it in did.json with a notice.
            # (Its own status lists, if configured, still fail hard below:
            # they cannot be signed without the private key.)
            try:
                with open(conf[name]['public_key'], 'rb') as key:
                    methods.append((name, public_jwk_from_pem(key.read())))
            except (OSError, KeyError, LibOpenBadgesException) as exc:
                print('[!] Skipping [%s] in did.json — could not read its '
                      'public key: %s' % (name, exc))
        if not methods:
            sys.exit('[!] No badge public key could be read; generate key '
                     'pairs with openbadges-keygenerator first')
        _write_atomic(os.path.join(args.output, 'did.json'),
                      _dump(build_did_document(did, methods)))
        files_written.append('did.json')

        # Opt-in (#176): publish the SD-JWT VC Type Metadata if the issuer hosts
        # a vct, so library-issued SD-JWT badges are self-describing to wallets.
        sd_jwt_vct = conf['issuer'].get('sd_jwt_vct')
        if sd_jwt_vct:
            _publish_type_metadata(sd_jwt_vct, publish_url, args.output,
                                   files_written)

        for name, status_conf in status_confs.items():
            if status_conf is None:
                print('[i] [%s] has no status_lists configured; publishing no '
                      'status list for it' % name)
                continue
            try:
                registry = StatusRegistry.load(status_conf.registry_path,
                                               status_conf.size_bits)
                with open(conf[name]['private_key'], 'rb') as key:
                    priv_pem = key.read()
            except (StatusError, OSError) as exc:
                # Isolate a per-badge failure (unreadable key, corrupt registry)
                # like the did.json skip above: don't abort the whole publish —
                # a badge_2 mid-configuration must not make an urgent badge_1
                # revocation appear to fail after its list was already written.
                print('[!] Skipping [%s] status lists — %s' % (name, exc))
                failures.append(name)
                continue
            algorithm = alg_for_key_type(detect_key_type(priv_pem))

            valid_until = None
            if status_conf.validity_days is not None:
                valid_until = (datetime.now(tz=timezone.utc)
                               + timedelta(days=status_conf.validity_days))

            badge_dir = os.path.join(args.output, name)
            os.makedirs(badge_dir, exist_ok=True)
            for purpose in status_conf.purposes:
                indices = registry.revoked_indices() if purpose == 'revocation' \
                    else registry.suspended_indices()
                vc = build_status_list_credential(
                    issuer_id, status_conf.list_urls[purpose], purpose,
                    indices, registry.size_bits, valid_until=valid_until)
                token = sign_status_list_credential(vc, priv_pem, algorithm)
                _write_atomic(os.path.join(badge_dir, purpose + '.jwt'), token)
                files_written.append(os.path.join(name, purpose + '.jwt'))

            # Keep the raw PEM alongside for tools that fetch it directly.
            shutil.copyfile(conf[name]['public_key'],
                            os.path.join(badge_dir, 'verify.pem'))
            files_written.append(os.path.join(name, 'verify.pem'))
    finally:
        os.umask(umask)

    if failures:
        print('[!] %d badge(s) skipped (see above): %s — their status lists '
              'were NOT regenerated' % (len(failures), ', '.join(failures)))
    print('Please configure your Web server to publish the folder %s as %s' %
          (args.output, publish_url))
    if not failures:
        print('[i] Issuer DID: %s' % did)
        if ':' not in did[len('did:web:'):]:
            print('[i] A bare-host did:web resolves at '
                  'https://%s/.well-known/did.json — serve did.json there.'
                  % did[len('did:web:'):])
        if operation is not None:
            print('[!] Re-upload %s so the change takes effect' % args.output)

    # --check-live turns that "re-upload" reminder into a verified fact: fetch
    # every written artifact from publish_url and byte-compare it.
    live_check = None
    if args.check_live:
        print('[i] Verifying published artifacts against %s ...' % publish_url)
        stale = _check_live_artifacts(args.output, publish_url, files_written)
        live_check = {'checked': len(files_written), 'stale': stale}
        if stale:
            print('[!] %d of %d artifact(s) stale or missing on the server; '
                  're-upload %s' % (len(stale), len(files_written), args.output))
        else:
            print('[+] All %d published artifact(s) are live and current.'
                  % len(files_written))

    # A partial failure (a skipped badge, or a stale live artifact) reports exit
    # 2 in --json (a documented "some work skipped" outcome); the human path
    # preserves its historical exit 1 (set in main) for skipped badges.
    return {
        'did': did,
        'files_written': sorted(files_written),
        'status_operation': operation_result,
        'skipped': failures,
        'live_check': live_check,
        '_exit': 2 if (failures or (live_check and live_check['stale'])) else 0,
    }


def _require_issuer_publish_keys(conf: configparser.ConfigParser) -> None:
    """Validate the ``[issuer]`` keys the OB1/OB2 hosted-publish paths
    dereference directly (``publish_url`` and ``revocationList``), so a
    misconfigured config exits with a clean CLI error instead of a raw
    ``KeyError`` traceback thrown mid-publish — after the output directory
    was already created. Mirrors the ``publish_url`` check the OB3 path and
    ``_query_ob3`` already perform."""
    if not conf.has_section('issuer'):
        sys.exit('[!] config is missing the [issuer] section')
    for key in ('publish_url', 'revocationList'):
        if not conf['issuer'].get(key):
            sys.exit("[!] [issuer] is missing the '%s' key, required to "
                     "publish hosted OpenBadges metadata" % key)


def _publish_ob2(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Publish strict OpenBadges 2.0 hosted metadata.

    Emits conformant JSON-LD Badge Objects: an issuer Profile (with a
    ``publicKey`` array back-linking every badge's CryptographicKey), a
    BadgeClass and a CryptographicKey (``key.json``) per badge, plus a
    RevocationList document.
    """
    from .ob2 import Profile, BadgeClass, CryptographicKey, RevocationList

    conf = read_config_or_exit(args.config)

    if not args.output:
        parser.print_help()
        return

    if os.path.lexists(args.output):
        sys.exit('[!] %s already exists' % args.output)

    _require_issuer_publish_keys(conf)

    publish_url = conf['issuer']['publish_url']
    issuer_id = urljoin(publish_url, 'organization.json')
    rev_relative = conf['issuer']['revocationList']
    rev_url = urljoin(publish_url, rev_relative)

    badge_names = [s for s in conf.sections() if s.startswith('badge_')]
    key_urls = {name: urljoin(publish_url, '%s/key.json' % name) for name in badge_names}

    umask = os.umask(0o077)  # rwx------
    try:
        os.mkdir(args.output)

        issuer_image = conf['issuer'].get('image')
        profile = Profile(
            id=issuer_id,
            name=conf['issuer']['name'],
            url=conf['issuer'].get('url'),
            email=conf['issuer'].get('email'),
            image_url=urljoin(publish_url, issuer_image) if issuer_image else None,
            public_key=[key_urls[name] for name in badge_names],
            revocation_list=rev_url,
        )
        with open(os.path.join(args.output, 'organization.json'), 'w', encoding='ascii') as f:
            f.write(_dump(profile.to_dict()))

        revocation = RevocationList(id=rev_url, issuer=issuer_id, revoked_assertions=[])
        with open(os.path.join(args.output, os.path.basename(rev_relative)),
                  'w', encoding='ascii') as f:
            f.write(_dump(revocation.to_dict()))

        for name in badge_names:
            badge_path = os.path.join(args.output, name)
            os.mkdir(badge_path)

            badge_class = BadgeClass(
                id=urljoin(publish_url, '%s/badge.json' % name),
                name=conf[name]['name'],
                description=conf[name]['description'],
                image=urljoin(publish_url, conf[name]['image']),
                criteria=conf[name]['criteria'],
                issuer=issuer_id,
            )
            with open(os.path.join(badge_path, 'badge.json'), 'w', encoding='ascii') as f:
                f.write(_dump(badge_class.to_dict()))

            with open(conf[name]['public_key'], 'rb') as key:
                pubkey_pem = key.read().decode('ascii')
            crypto_key = CryptographicKey(
                id=key_urls[name], owner=issuer_id, public_key_pem=pubkey_pem)
            with open(os.path.join(badge_path, 'key.json'), 'w', encoding='ascii') as f:
                f.write(_dump(crypto_key.to_dict()))

            # Keep the raw PEM alongside for tools that fetch it directly.
            shutil.copyfile(conf[name]['public_key'], os.path.join(badge_path, 'verify.pem'))
    finally:
        os.umask(umask)

    print('Please configure your Web server to publish the folder %s as %s' %
          (args.output, publish_url))


def _publish_ob1(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Publish OpenBadges 1.0 (legacy) hosted issuer/badge/revocation metadata."""
    print('[!] OpenBadges 1.0 (-V 1) is a legacy version, still supported; '
          'prefer publishing OB 2.0 (-V 2) or OB 3.0 (-V 3).')
    conf = read_config_or_exit(args.config)

    if args.output:
        if os.path.lexists(args.output):
            sys.exit('[!] %s already exists' % args.output)

        _require_issuer_publish_keys(conf)

        umask = os.umask(0o077)  # rwx------
        try:
            os.mkdir(args.output)

            issuer = create_issuer_json(conf)
            issuer_file = os.path.join(args.output, 'organization.json')
            with open(issuer_file, "w", encoding='ascii') as f:
                f.write(issuer)

            revocation = create_revocation_json(conf)
            # Derive the on-disk name from the configured revocationList (as
            # _publish_ob2 does), so it matches the URL create_issuer_json
            # publishes in organization.json. A hardcoded 'revoked.json' left a
            # dangling reference whenever the operator set another name.
            rev_name = os.path.basename(conf['issuer']['revocationList'])
            revocation_file = os.path.join(args.output, rev_name)
            with open(revocation_file, "w", encoding='ascii') as f:
                f.write(revocation)

            for badge_name in conf.sections():
                if not badge_name.startswith('badge_'):
                    continue

                badge_path = os.path.join(args.output, badge_name)
                badge_file = os.path.join(badge_path, 'badge.json')

                os.mkdir(badge_path)
                with open(badge_file, "w", encoding='ascii') as f:
                    f.write(create_badge_json(conf, badge_name))

                """ Copy the verify key for this badge """
                source = conf[badge_name]['public_key']
                destination = os.path.join(badge_path, 'verify.pem')
                shutil.copyfile(source, destination)
        finally:
            os.umask(umask)

        print('Please configure your Web server to publish the folder %s as %s' %
              (args.output, conf['issuer']['publish_url']))

    else:
        parser.print_help()


def create_issuer_json(conf: configparser.ConfigParser) -> str:
    publish_url = conf['issuer']['publish_url']
    image_url = urljoin(publish_url, conf['issuer']['image'])
    rev_url = urljoin(publish_url, conf['issuer']['revocationList'])

    issuer = dict(url=conf['issuer']['url'],
                  email=conf['issuer']['email'],
                  name=conf['issuer']['name'],
                  revocationList=rev_url,
                  image=image_url)

    return json.dumps(issuer, sort_keys=True, ensure_ascii=True)


def create_revocation_json(conf: configparser.ConfigParser) -> str:
    return json.dumps(dict(), sort_keys=True, ensure_ascii=True)


def create_badge_json(conf: configparser.ConfigParser, badge_name: str) -> str:
    publish_url = conf['issuer']['publish_url']
    image_url = urljoin(publish_url, conf[badge_name]['image'])
    issuer_url = urljoin(publish_url, 'organization.json')

    badge = dict(image=image_url, criteria=conf[badge_name]['criteria'],
                 name=conf[badge_name]['name'],
                 description=conf[badge_name]['description'],
                 issuer=issuer_url)

    return json.dumps(badge, sort_keys=True, ensure_ascii=True)


if __name__ == '__main__':
    main()
