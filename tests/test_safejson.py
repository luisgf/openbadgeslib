"""openbadgeslib._safejson: the one bound every parser of untrusted JSON shares
(nesting depth, lone surrogates, non-finite numbers)."""
import json

import pytest

from openbadgeslib._safejson import (MAX_JSON_DEPTH, JSONTooDeepError,
                                     UntrustedJSONError, check, loads,
                                     nested_deeper_than)


def _nested(depth, leaf=1):
    return '{"a":' * depth + str(leaf) + '}' * depth


class TestDepth:
    def test_the_bound_itself_is_accepted(self):
        assert loads(_nested(MAX_JSON_DEPTH)) is not None
        assert loads('[' * MAX_JSON_DEPTH + ']' * MAX_JSON_DEPTH) is not None

    def test_one_level_past_the_bound_is_refused(self):
        with pytest.raises(JSONTooDeepError, match='nested more than'):
            loads(_nested(MAX_JSON_DEPTH + 1))
        with pytest.raises(JSONTooDeepError):
            loads('[' * (MAX_JSON_DEPTH + 1) + ']' * (MAX_JSON_DEPTH + 1))

    @pytest.mark.parametrize('depth', [1000, 20000, 200000])
    def test_nesting_past_the_parser_is_the_same_failure(self, depth):
        # Whether json.loads recurses to its limit (RecursionError) or, on
        # Python 3.14+, takes 100 000 levels, the caller sees one ValueError.
        with pytest.raises(UntrustedJSONError):
            loads('[' * depth + ']' * depth)

    def test_it_is_a_value_error(self):
        # So every caller that already maps ValueError (JSONDecodeError and
        # UnicodeDecodeError are ones) types it without change.
        assert issubclass(UntrustedJSONError, ValueError)
        with pytest.raises(ValueError):
            loads('{"a": ')
        with pytest.raises(ValueError):
            loads(b'\xff')

    def test_a_self_referencing_dict_ends_at_the_bound(self):
        loop = {}
        loop['x'] = loop
        with pytest.raises(JSONTooDeepError):
            check(loop)
        ring = []
        ring.append(ring)
        with pytest.raises(JSONTooDeepError):
            check(ring)

    def test_tuples_count_as_arrays(self):
        node = ()
        for _ in range(MAX_JSON_DEPTH - 1):
            node = (node,)
        check(node)
        with pytest.raises(JSONTooDeepError):
            check((node,))

    def test_nested_deeper_than(self):
        doc = {'a': [{'b': [1]}]}
        assert not nested_deeper_than(doc, 4)
        assert nested_deeper_than(doc, 3)
        assert not nested_deeper_than([], 1) and not nested_deeper_than('x', 0)
        # Depth alone: a lone surrogate is not what it answers for.
        assert not nested_deeper_than({'a': '\ud800'}, 1)

    def test_the_message_never_quotes_the_value(self):
        # repr() of the offending value is what raised in the first place.
        with pytest.raises(UntrustedJSONError) as caught:
            loads('{"secret-marker": ' + '[' * (MAX_JSON_DEPTH + 1)
                  + ']' * (MAX_JSON_DEPTH + 1) + '}')
        assert 'secret-marker' not in str(caught.value)


class TestScalars:
    @pytest.mark.parametrize('text', [
        '"\\ud800"', '"x\\udfffy"', '["\\ud83d"]', '{"\\ud800": 1}',
        '{"a": {"b": ["\\udc00"]}}'])
    def test_a_lone_surrogate_is_refused(self, text):
        with pytest.raises(UntrustedJSONError, match='surrogate'):
            loads(text)

    def test_a_surrogate_pair_is_one_character_and_accepted(self):
        assert loads('"\\ud83d\\ude00"') == '\U0001f600'

    def test_ordinary_non_ascii_is_accepted(self):
        assert loads('{"nombre": "Luis González — 日本語 \U0001f600"}')

    @pytest.mark.parametrize('text', [
        'Infinity', '-Infinity', 'NaN', '1e999', '-1e999', '[1, 1e999]',
        '{"a": {"b": NaN}}'])
    def test_a_number_that_is_not_finite_is_refused(self, text):
        with pytest.raises(UntrustedJSONError, match='not finite'):
            loads(text)

    def test_finite_numbers_pass(self):
        assert loads('[1, -2.5, 1e308, 0, 123456789012345678901234567890]')

    def test_a_dict_a_caller_hands_in_is_checked_alike(self):
        check({'a': [1, {'b': 'ok'}]})
        with pytest.raises(UntrustedJSONError):
            check({'a': [float('nan')]})
        with pytest.raises(UntrustedJSONError):
            check({'a': '\ud800'})
        with pytest.raises(UntrustedJSONError):
            check({'\ud800': 1})
        # Non-JSON values are not this module's concern: others handle them.
        check({1: object(), 'b': b'\xff', 'c': None, 'd': True})


class TestLoads:
    def test_bytes_and_str(self):
        assert loads(b'{"a": 1}') == {'a': 1} == loads('{"a": 1}')
        assert loads(bytearray(b'[1]')) == [1]

    def test_it_is_json_loads_for_everything_else(self):
        text = json.dumps({'a': [1, 2.5, None, True, 'é'], 'b': {'c': 'd'}})
        assert loads(text) == json.loads(text)
