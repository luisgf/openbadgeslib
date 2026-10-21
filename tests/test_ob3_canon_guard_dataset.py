"""canonize_dataset: the bounded URDNA2015 of ob3/_canon_guard.py for a caller
that builds the RDF dataset itself (ob3.ldp does, for the ecdsa-sd-2023 view
openvc-core canonicalizes: an N-Quads round trip of the dataset).

It must give what stock pyld gives, spend the budget it is given, refuse the
shapes canonize() refuses, and never fall back to an unmetered run.

Needs the [ldp] extra (pyld); skipped otherwise.
"""
import time

import pytest

pytest.importorskip('pyld')

from pyld import jsonld  # noqa: E402
from pyld.jsonld import JsonLdProcessor  # noqa: E402

from openbadgeslib.ob3 import _canon_guard as guard  # noqa: E402

_CONTEXT = {'@vocab': 'https://example.org/c#'}


def _document(blank_nodes=3):
    return {'@context': _CONTEXT, '@id': 'https://example.org/c/root',
            'p': [{'name': 'n%d' % i, 'q': {'name': 'm%d' % i}}
                  for i in range(blank_nodes)]}


def _clique(size):
    return {'@context': _CONTEXT, '@id': 'https://example.org/c/root',
            'p': [{'@id': '_:b%d' % i,
                   'q': [{'@id': '_:b%d' % j} for j in range(size) if j != i]}
                  for i in range(size)]}


def _dataset(document):
    return jsonld.to_rdf(document, {'produceGeneralizedRdf': False})


def test_it_gives_what_canonize_and_stock_pyld_give():
    document = _document()
    stock = jsonld.normalize(document, {'algorithm': 'URDNA2015',
                                        'format': 'application/n-quads'})
    assert guard.canonize_dataset(_dataset(document)) == stock
    assert guard.canonize(jsonld, document, None) == stock


def test_a_dataset_parsed_from_nquads_is_canonicalized_as_pyld_does():
    # the shape ob3.ldp feeds it: to_rdf as N-Quads text, parsed back
    document = _document(5)
    text = jsonld.to_rdf(document, {'produceGeneralizedRdf': False,
                                    'format': 'application/n-quads'})
    stock = jsonld.normalize(text, {'algorithm': 'URDNA2015',
                                    'inputFormat': 'application/n-quads',
                                    'format': 'application/n-quads'})
    assert guard.canonize_dataset(JsonLdProcessor.parse_nquads(text)) == stock


def test_it_spends_the_budget_it_is_given():
    # blank nodes nothing tells apart: Hash N-Degree Quads runs and is charged
    budget = guard.WorkBudget()
    guard.canonize_dataset(_dataset(_clique(3)), budget)
    first = budget.spent
    assert first > 0
    guard.canonize_dataset(_dataset(_clique(3)), budget)
    assert budget.spent > first            # one budget over several runs


def test_a_budget_too_small_for_the_graph_refuses_it():
    with pytest.raises(guard.CanonicalizationWorkExceeded):
        guard.canonize_dataset(_dataset(_clique(4)),
                               guard.WorkBudget(limit=10))


def test_a_poison_dataset_is_refused_in_a_fraction_of_a_second():
    # eight labelled blank nodes that all link to each other: factorial for
    # an unmetered pyld (24 s of CPU on 3.14)
    dataset = _dataset(_clique(8))
    started = time.process_time()
    with pytest.raises(guard.CanonicalizationWorkExceeded):
        guard.canonize_dataset(dataset)
    assert time.process_time() - started < 5.0


def test_an_unavailable_guard_never_falls_back_to_stock_pyld(monkeypatch):
    def down():
        raise guard.CanonicalizationGuardUnavailable('no meter')

    monkeypatch.setattr(guard, '_bounded_class', down)
    with pytest.raises(guard.CanonicalizationGuardUnavailable):
        guard.canonize_dataset(_dataset(_document()))
