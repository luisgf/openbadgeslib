"""Tests for the bundled JSON-LD context allowlist — ob3.contexts.

Deliberately runs WITHOUT the [ldp] extra: this module never imports pyld.
"""
import hashlib
import re

import pytest

from openbadgeslib.ob3.contexts import (
    UnknownContextError,
    _URL_TO_RESOURCE,
    document_loader,
    load_context,
)

CREDS_V2 = 'https://www.w3.org/ns/credentials/v2'


class TestLoadContext:
    def test_every_allowlisted_url_loads_as_object(self):
        for url in _URL_TO_RESOURCE:
            doc = load_context(url)
            assert isinstance(doc, dict) and '@context' in doc, url

    def test_unversioned_ob3_url_serves_latest(self):
        latest = load_context(
            'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json')
        assert load_context(
            'https://purl.imsglobal.org/spec/ob/v3p0/context.json') == latest

    def test_unknown_url_fails_closed(self):
        with pytest.raises(UnknownContextError, match='allowlist'):
            load_context('https://evil.example/context.json')

    def test_no_url_normalisation(self):
        # Exact string match only: scheme/case/slash variants of an
        # allowlisted URL are NOT accepted (fail closed).
        for variant in (CREDS_V2 + '/', CREDS_V2.upper(),
                        CREDS_V2.replace('https', 'http')):
            with pytest.raises(UnknownContextError):
                load_context(variant)

    def test_cached_instances(self):
        assert load_context(CREDS_V2) is load_context(CREDS_V2)


class TestDocumentLoader:
    def test_pyld_shape(self):
        loader = document_loader()
        result = loader(CREDS_V2, {})
        assert result['documentUrl'] == CREDS_V2
        assert result['contextUrl'] is None
        assert isinstance(result['document'], dict)

    def test_extra_contexts_extend_one_instance_only(self):
        extra_url = 'https://www.w3.org/ns/credentials/examples/v2'
        extra_doc = {'@context': {'@vocab': 'https://example.org/#'}}
        loader = document_loader({extra_url: extra_doc})
        assert loader(extra_url, {})['document'] == extra_doc
        # The global allowlist is not widened...
        with pytest.raises(UnknownContextError):
            load_context(extra_url)
        # ...nor is a fresh loader.
        with pytest.raises(UnknownContextError):
            document_loader()(extra_url, {})

    def test_unknown_url_raises_through_loader(self):
        with pytest.raises(UnknownContextError):
            document_loader()('https://evil.example/ctx', {})

    def test_bundled_tagged_static_extra_untagged(self):
        # A bundled allowlist URL is immutable per process, so the loader tags
        # it 'static' to prime pyld's process-global resolved-context cache.
        extra_url = 'https://www.w3.org/ns/credentials/examples/v2'
        extra_doc = {'@context': {'@vocab': 'https://example.org/#'}}
        loader = document_loader({extra_url: extra_doc})
        assert loader(CREDS_V2, {})['tag'] == 'static'
        # An extra context varies per loader instance; tagging it 'static'
        # would poison that global cache, so it must be served untagged.
        assert 'tag' not in loader(extra_url, {})


def test_contexts_ship_as_package_data():
    # The JSON files must be reachable via importlib.resources (i.e. packaged
    # as package-data), not via filesystem-relative paths.
    from importlib import resources
    files = {p.name for p in resources.files('openbadgeslib.ob3.contexts').iterdir()}
    for resource in set(_URL_TO_RESOURCE.values()):
        assert resource in files, resource


# ── provenance ───────────────────────────────────────────────────────────────
# The module header of ob3/contexts/__init__.py records the SHA-256 of every
# bundled context. That record is the control that makes the fail-closed
# allowlist meaningful: RDF canonicalization resolves each @context, so the
# bundled document decides what a Data Integrity signature actually covers, and
# an edit to one silently changes the meaning of every proof the library makes
# and checks. Nothing enforced it — the scheduled context-drift job compares
# against UPSTREAM over the network, which is a different property and cannot
# run on a PR — so a reformat or a tampered file passed every gate while the
# comment quietly became a lie (#266). These gates are offline and stdlib-only.

def _package_dir():
    from importlib import resources
    return resources.files('openbadgeslib.ob3.contexts')


def _recorded_digests():
    """{filename: sha256} parsed from the provenance block in the module header."""
    source = _package_dir().joinpath('__init__.py').read_text('utf-8')
    header = source.split('import functools', 1)[0]
    return dict(re.findall(r'#\s+([\w.-]+\.json)[^\n]*\n#\s+([0-9a-f]{64})',
                           header))


def test_bundled_contexts_match_their_recorded_provenance():
    recorded = _recorded_digests()
    assert recorded, 'no SHA-256 provenance found in ob3/contexts/__init__.py'
    mismatched = []
    for name, expected in sorted(recorded.items()):
        actual = hashlib.sha256(
            _package_dir().joinpath(name).read_bytes()).hexdigest()
        if actual != expected:
            mismatched.append('%s: recorded %s, actual %s'
                              % (name, expected, actual))
    assert not mismatched, (
        'bundled JSON-LD context(s) no longer match their recorded SHA-256 '
        'provenance:\n  %s\nIf the change is legitimate, re-capture the file '
        'AND update its digest in openbadgeslib/ob3/contexts/__init__.py.'
        % '\n  '.join(mismatched))


def test_every_bundled_context_has_recorded_provenance():
    shipped = {p.name for p in _package_dir().iterdir()
               if p.name.endswith('.json')}
    recorded = set(_recorded_digests())
    assert shipped == recorded, (
        'context files without a recorded SHA-256: %s; digests recorded for '
        'files that are not shipped: %s'
        % (sorted(shipped - recorded), sorted(recorded - shipped)))


def test_gitattributes_pins_the_contexts_against_eol_conversion():
    """The digests above are only checkable if git leaves the bytes alone.

    Without a `-text` attribute git rewrites these files to CRLF on a Windows
    checkout, so every recorded digest mismatches and the provenance control
    cannot be evaluated on that platform at all — which is how the Windows CI
    leg went red for three days (#274). Pin the attribute, not just the digests.
    """
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    attributes = (root / '.gitattributes')
    assert attributes.is_file(), '.gitattributes is missing (#274)'
    rules = [line.split('#', 1)[0].split()
             for line in attributes.read_text(encoding='utf-8').splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    assert any(rule and rule[0].endswith('ob3/contexts/*.json')
               and '-text' in rule[1:] for rule in rules), (
        '.gitattributes must mark openbadgeslib/ob3/contexts/*.json as -text so '
        'git never rewrites the line endings the recorded SHA-256 digests cover')
