"""Tests for the bundled JSON-LD context allowlist — ob3.contexts.

Deliberately runs WITHOUT the [ldp] extra: this module never imports pyld.
"""
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
