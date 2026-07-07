#!/usr/bin/env python3
"""Fail if any *versioned* JSON-LD context we pin has drifted from upstream.

openbadgeslib ships the exact @context documents its Data Integrity verifier
canonicalizes against (openbadgeslib/ob3/contexts/), behind a fail-closed
allowlist. Those versioned URLs are supposed to be immutable — but 1EdTech has
mutated one in place before (context-3.0.3.json gained endorsementJwt after its
first publication). If it happens again, credentials signed against our pinned
copy would stop verifying against a peer that fetches the mutated document, with
no signal until that failure. This scheduled check turns that silent hazard into
a red build: it fetches each pinned versioned context and compares it,
semantically (parsed JSON, so whitespace/key-order reformatting is ignored),
against the bundled copy.

The unversioned OB3 alias (…/context.json) is deliberately NOT checked: it is an
internal pointer to our latest bundled revision, not a mirror of the moving
upstream alias (which currently serves an older revision matching none we ship).
Its internal consistency is covered by the unit tests instead.

Exit 0 if everything matches, 1 (with a report) on any drift.
"""
import json
import sys
import urllib.request
from importlib import resources

from openbadgeslib.ob3.contexts import _URL_TO_RESOURCE

# Intentional aliases that point at our latest bundled revision rather than a
# fixed upstream document — excluded from the upstream-drift comparison.
_ALIAS_URLS = {'https://purl.imsglobal.org/spec/ob/v3p0/context.json'}

_UA = {'User-Agent': 'openbadgeslib-context-drift-check'}


def _fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (https)
        return json.loads(resp.read().decode('utf-8'))


def _bundled(resource: str) -> dict:
    text = resources.files('openbadgeslib.ob3.contexts').joinpath(
        resource).read_text('utf-8')
    return json.loads(text)


def main() -> int:
    drift = []
    for url, resource in sorted(_URL_TO_RESOURCE.items()):
        if url in _ALIAS_URLS:
            print('[skip] %s (internal latest alias)' % url)
            continue
        try:
            matches = _fetch(url) == _bundled(resource)
        except Exception as exc:                       # network / parse failure
            print('[error] %s: %s' % (url, exc))
            drift.append((url, resource))
            continue
        print('[%s] %s -> %s' % ('ok' if matches else 'DRIFT', url, resource))
        if not matches:
            drift.append((url, resource))

    if drift:
        print('\n%d pinned context(s) drifted from upstream:' % len(drift))
        for url, resource in drift:
            print('  %s (pinned as %s)' % (url, resource))
        print('\n1EdTech/W3C changed a versioned context in place, or it could '
              'not be fetched. Review the change; if legitimate, re-capture the '
              'bundled file and update its SHA-256 provenance in '
              'openbadgeslib/ob3/contexts/__init__.py.')
        return 1
    print('\nAll pinned versioned contexts match upstream.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
