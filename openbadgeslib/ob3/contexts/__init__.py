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

# Bundled, allowlisted JSON-LD contexts for Data Integrity verification.
#
# RDF canonicalization resolves every @context a credential names. Fetching
# them from the network at verification time would be both an SSRF vector and
# a correctness hazard (a context host could serve different definitions over
# time, silently changing what a signature covers). So the exact context
# documents are pinned here, shipped inside the wheel, and served by a static
# document loader that refuses anything outside the allowlist — fail closed.
#
# Provenance (captured 2026-07-03; SHA-256 of the bundled file):
#   https://www.w3.org/ns/credentials/v2
#     credentials-v2.json
#     59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734
#   https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.1.json
#     ob-v3p0-context-3.0.1.json
#     5f3d9dd6288ef437ff8286cf95ffbff609c748a66f24a1e9450c45ca64be1571
#   https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.2.json
#     ob-v3p0-context-3.0.2.json
#     00666ad080ba407687ed1846b7f5e7495f5019042b202a727de47c48a1755c53
#   https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json
#     ob-v3p0-context-3.0.3.json  (also served for the unversioned context.json)
#     3d34f4d4ef1bce691106e63798beb5e7b862ba841423f5ee1e53ab7ddf3bca84
#   https://w3id.org/security/data-integrity/v2
#     security-data-integrity-v2.json
#     67f21e6e33a6c14e5ccfd2fc7865f7474fb71a04af7e94136cb399dfac8ae8f4
#   https://w3id.org/security/multikey/v1
#     security-multikey-v1.json
#     ba2c182de2d92f7e47184bcca8fcf0beaee6d3986c527bf664c195bbc7c58597
#
# This module deliberately does NOT import pyld: it only hands out plain dicts
# in the shape pyld's documentLoader expects, so it works (and is tested)
# without the optional [ldp] extra installed.

import functools
import json

from importlib import resources
from typing import Any, Callable, Dict, Mapping, Optional

from ...errors import LibOpenBadgesException


class UnknownContextError(LibOpenBadgesException):
    """A credential names an @context URL outside the bundled allowlist.

    Remote contexts are never fetched during verification; verify fails
    closed instead.
    """


#: Exact-match allowlist: @context URL -> bundled resource filename.
_URL_TO_RESOURCE: Dict[str, str] = {
    'https://www.w3.org/ns/credentials/v2': 'credentials-v2.json',
    'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.1.json':
        'ob-v3p0-context-3.0.1.json',
    'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.2.json':
        'ob-v3p0-context-3.0.2.json',
    'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json':
        'ob-v3p0-context-3.0.3.json',
    # The unversioned OB3 context URL is an internal alias to our latest
    # bundled revision (3.0.3). We deliberately pin it here rather than mirror
    # 1EdTech's moving unversioned endpoint (which currently serves an older
    # revision matching none we ship); the context-drift check skips it for
    # that reason.
    'https://purl.imsglobal.org/spec/ob/v3p0/context.json':
        'ob-v3p0-context-3.0.3.json',
    'https://w3id.org/security/data-integrity/v2':
        'security-data-integrity-v2.json',
    'https://w3id.org/security/multikey/v1': 'security-multikey-v1.json',
}


@functools.lru_cache(maxsize=None)
def load_context(url: str) -> dict[str, Any]:
    """Return the bundled JSON-LD context document for an allowlisted URL.

    Raises UnknownContextError for any URL outside the allowlist — the match
    is an exact string comparison, with no scheme/case/slash normalisation
    (fail closed).
    """
    resource = _URL_TO_RESOURCE.get(url)
    if resource is None:
        raise UnknownContextError(
            'JSON-LD context %r is not in the bundled allowlist; remote '
            'contexts are never fetched during verification' % (url,))
    payload = resources.files(__name__).joinpath(resource).read_text('utf-8')
    document = json.loads(payload)
    if not isinstance(document, dict):
        raise UnknownContextError('bundled context %r is not an object' % (url,))
    return document


def bundled_contexts() -> Dict[str, dict[str, Any]]:
    """The whole pinned allowlist as a ``{url: context document}`` map.

    For handing openbadgeslib's fail-closed context set to another Data
    Integrity engine that takes its own ``extra_contexts`` (e.g. openvc-core's
    verifier for the delegated ecdsa-sd-2023 path), so it canonicalizes against
    exactly these pinned documents and never the network.
    """
    return {url: load_context(url) for url in _URL_TO_RESOURCE}


def document_loader(
        extra_contexts: Optional[Mapping[str, dict[str, Any]]] = None,
) -> Callable[[str, Any], dict[str, Any]]:
    """Build a static documentLoader in the shape pyld expects.

    *extra_contexts* extends the allowlist for one loader instance (e.g. a
    test suite injecting the W3C examples context) without widening the
    global allowlist. Every other URL raises UnknownContextError, which the
    Data Integrity verifier surfaces as a clean verification failure.
    """
    extras: Dict[str, dict[str, Any]] = dict(extra_contexts) if extra_contexts else {}

    def _loader(url: str, options: Any = None) -> dict[str, Any]:
        if url in extras:
            # extra_contexts vary per loader instance (a test's examples
            # context, openvc's delegated set). pyld caches resolved contexts
            # in a *process-global* map keyed by URL, so tagging one 'static'
            # would let a later call with different content for the same URL
            # be served this call's stale term definitions. Leave extras
            # untagged — pyld re-resolves them on every normalize.
            return {'contextUrl': None, 'documentUrl': url,
                    'document': extras[url]}
        # A bundled allowlist entry is immutable for the life of the process
        # (pinned in the wheel), so tag it 'static': this primes pyld's global
        # resolved-context cache and skips re-creating ~101 term definitions on
        # every normalize (~1.6x faster LDP sign/verify).
        return {'contextUrl': None, 'documentUrl': url,
                'document': load_context(url), 'tag': 'static'}

    return _loader
