"""Shared OB2/OB3 JSON helpers (#225).

The four helpers `_iso` / `_parse_iso` / `_as_dict` / `_require` used to be
duplicated in ob2.models and ob3.credential and had drifted — the OB2 `_iso`
serialised a naive datetime as *local* time. They are now a single
implementation in openbadgeslib._jsonmodel with the OB3 (naive => UTC) rule.
"""
from datetime import datetime, timezone

import pytest

from openbadgeslib import _jsonmodel as jm
from openbadgeslib.ob2 import models as ob2_models
from openbadgeslib.ob3 import credential as ob3_credential


class TestHelpersAreDeduplicated:
    def test_ob2_and_ob3_share_one_implementation(self):
        assert ob2_models._iso is jm._iso is ob3_credential._iso
        assert ob2_models._parse_iso is jm._parse_iso is ob3_credential._parse_iso
        assert ob2_models._as_dict is jm._as_dict is ob3_credential._as_dict
        assert ob2_models._require is jm._require is ob3_credential._require


class TestIsoNaiveIsUTCNotLocal:
    """The bug this dedup fixes: a naive datetime must serialise as UTC, so OB2
    and OB3 emit the same instant regardless of the host's timezone."""

    def test_naive_datetime_treated_as_utc(self):
        assert jm._iso(datetime(2026, 1, 1, 12, 0, 0)) == '2026-01-01T12:00:00Z'

    def test_aware_datetime_converted_to_utc(self):
        from datetime import timedelta
        plus2 = timezone(timedelta(hours=2))
        assert jm._iso(datetime(2026, 1, 1, 12, 0, 0, tzinfo=plus2)) \
            == '2026-01-01T10:00:00Z'


class TestParseIso:
    def test_default_where_matches_ob3_message(self):
        # ob3 called _parse_iso(s) with no `where`; the default keeps its message.
        with pytest.raises(ValueError, match='date is missing a UTC offset'):
            jm._parse_iso('2026-01-01T00:00:00')

    def test_named_where_for_ob2_callers(self):
        with pytest.raises(ValueError, match='assertion.issuedOn'):
            jm._parse_iso('not-a-date', 'assertion.issuedOn')

    def test_rejects_non_string(self):
        with pytest.raises(ValueError, match='must be an ISO 8601 string'):
            jm._parse_iso(1767225600, 'x')

    def test_roundtrip(self):
        dt = jm._parse_iso('2026-01-01T00:00:00Z')
        assert dt == datetime(2026, 1, 1, tzinfo=timezone.utc)


class TestAsDictAndRequire:
    def test_as_dict_rejects_non_dict(self):
        with pytest.raises(ValueError, match='must be a JSON object'):
            jm._as_dict([], 'x')

    def test_require_rejects_missing(self):
        with pytest.raises(ValueError, match='missing required field'):
            jm._require({}, 'id', 'obj')

    def test_require_rejects_non_string(self):
        with pytest.raises(ValueError, match='must be a string'):
            jm._require({'id': 5}, 'id', 'obj')
