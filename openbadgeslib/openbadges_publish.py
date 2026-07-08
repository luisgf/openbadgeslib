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

from typing import Any, List, TYPE_CHECKING, Tuple
from urllib.parse import urljoin
from .confparser import read_config_or_exit, resolve_badge_section
from .util import __version__

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
    parser.add_argument('-v', '--version', action='version', version=__version__)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Read-only registry queries need no output directory and never touch the
    # published tree, so they route before the publish paths and the -o check.
    if args.list or args.status is not None:
        if args.ob_version != '3':
            sys.exit('[!] --list/--status query the OpenBadges 3.0 status '
                     'registries and need -V 3')
        _query_ob3(args, parser)
        return

    if args.ob_version == '3':
        if args.output is None:
            parser.error('-o/--output is required to publish '
                         '(it is not needed for --list/--status)')
        _publish_ob3(args, parser)
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


def _query_ob3(args: argparse.Namespace,
               parser: argparse.ArgumentParser) -> None:
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
        _print_status_detail(registries, args.status)
    else:
        _print_registry_table(registries)


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


def _print_registry_table(
        registries: List[Tuple[str, 'StatusRegistry']]) -> None:
    header = ('JTI', 'RECIPIENT', 'ISSUED', 'STATE')
    grand_total = 0
    for name, registry in registries:
        entries = sorted(registry.entries.values(),
                         key=lambda e: (e.issued_on, e.jti))
        grand_total += len(entries)
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


def _print_status_detail(registries: List[Tuple[str, 'StatusRegistry']],
                         ident: str) -> None:
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


def _print_field(label: str, value: str) -> None:
    print('%-11s %s' % (label + ':', value))


def _publish_ob3(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
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
    from datetime import datetime, timezone
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

            badge_dir = os.path.join(args.output, name)
            os.makedirs(badge_dir, exist_ok=True)
            for purpose in status_conf.purposes:
                indices = registry.revoked_indices() if purpose == 'revocation' \
                    else registry.suspended_indices()
                vc = build_status_list_credential(
                    issuer_id, status_conf.list_urls[purpose], purpose,
                    indices, registry.size_bits)
                token = sign_status_list_credential(vc, priv_pem, algorithm)
                _write_atomic(os.path.join(badge_dir, purpose + '.jwt'), token)

            # Keep the raw PEM alongside for tools that fetch it directly.
            shutil.copyfile(conf[name]['public_key'],
                            os.path.join(badge_dir, 'verify.pem'))
    finally:
        os.umask(umask)

    if failures:
        print('[!] %d badge(s) skipped (see above): %s — their status lists '
              'were NOT regenerated' % (len(failures), ', '.join(failures)))
    print('Please configure your Web server to publish the folder %s as %s' %
          (args.output, publish_url))
    if failures:
        sys.exit(1)
    print('[i] Issuer DID: %s' % did)
    if ':' not in did[len('did:web:'):]:
        print('[i] A bare-host did:web resolves at '
              'https://%s/.well-known/did.json — serve did.json there.'
              % did[len('did:web:'):])
    if operation is not None:
        print('[!] Re-upload %s so the change takes effect' % args.output)


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
    conf = read_config_or_exit(args.config)

    if args.output:
        if os.path.lexists(args.output):
            sys.exit('[!] %s already exists' % args.output)

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
