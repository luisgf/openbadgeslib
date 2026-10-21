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


class TestIsoRange:
    """_iso converts to UTC; a timestamp whose UTC instant ``datetime`` cannot
    hold keeps its own offset instead of raising OverflowError."""

    def test_the_edges_of_the_representable_range_are_padded_z_forms(self):
        # strftime("%Y") leaves a year below 1000 unpadded on some platforms.
        assert jm._iso(datetime(1, 1, 1, tzinfo=timezone.utc)) == '0001-01-01T00:00:00Z'
        assert jm._iso(datetime(999, 12, 31, 1, 2, 3)) == '0999-12-31T01:02:03Z'
        assert jm._iso(datetime(9999, 12, 31, 23, 59, 59, 999999,
                                tzinfo=timezone.utc)) == '9999-12-31T23:59:59Z'

    @pytest.mark.parametrize('value', [
        '9999-12-31T23:59:59-05:00', '9999-12-31T23:59:59-00:01',
        '9999-12-31T23:59:59-23:59', '0001-01-01T00:00:00+05:00',
        '0001-01-01T00:00:00+23:59'])
    def test_an_instant_with_no_utc_datetime_keeps_its_offset(self, value):
        parsed = jm._parse_iso(value)
        with pytest.raises(OverflowError):
            parsed.astimezone(timezone.utc)          # what _iso used to do
        assert jm._iso(parsed) == value
        assert jm._parse_iso(jm._iso(parsed)) == parsed

    def test_the_fallback_drops_microseconds_like_the_z_form(self):
        parsed = jm._parse_iso('9999-12-31T23:59:59.999999-05:00')
        assert jm._iso(parsed) == '9999-12-31T23:59:59-05:00'

    def test_a_representable_offset_still_writes_the_z_form(self):
        # The last instant an offset can reach without leaving the range.
        parsed = jm._parse_iso('9999-12-31T18:59:59-05:00')
        assert jm._iso(parsed) == '9999-12-31T23:59:59Z'
        assert jm._iso(jm._parse_iso('0001-01-01T05:00:00+05:00')) \
            == '0001-01-01T00:00:00Z'


class TestParseIso:
    def test_accepts_an_offset_whose_utc_instant_is_out_of_range(self):
        # Comparisons and timestamp() do not convert to UTC; 4.6.2 accepted it.
        late = jm._parse_iso('9999-12-31T23:59:59-05:00')
        early = jm._parse_iso('0001-01-01T00:00:00+05:00')
        assert late > datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert early < datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert late.timestamp() == 253402318799
        assert early.timestamp() == -62135614800

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
