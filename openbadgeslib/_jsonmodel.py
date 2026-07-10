#!/usr/bin/env python3
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

# Shared JSON <-> dataclass helpers for the OB2 and OB3 models. These lived in
# duplicate in openbadgeslib.ob2.models and openbadgeslib.ob3.credential and had
# drifted: the OB2 copy of ``_iso`` ran ``astimezone`` on a *naive* datetime,
# which Python interprets as **local** time — so the same value serialised to a
# different instant in OB2 than in OB3 (which anchors naive datetimes to UTC).
# This module keeps the OB3 semantics (naive => UTC) as the single source of
# truth, matching ob3.status_registry._iso_z and the JWT nbf/exp claims.

from datetime import datetime, timezone
from typing import Any


def _iso(dt: datetime) -> str:
    """Return a datetime as an ISO 8601 string with a ``Z`` (UTC) suffix.

    A naive datetime is assumed to be UTC (not local time), so validFrom/
    validUntil and OB2 issuedOn/expires never silently shift by the host's
    offset and stay consistent with the JWT nbf/exp claims.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: Any, where: str = 'date') -> datetime:
    """Parse an ISO 8601 timestamp (with a UTC offset or trailing ``Z``).

    A non-string (e.g. a bare Unix timestamp, the legacy OB 1.0 shape) is
    rejected, as is a naive timestamp with no offset — verify() always compares
    against an aware ``datetime.now(timezone.utc)``, so only unambiguously
    anchored timestamps are accepted. Raises ValueError otherwise, naming
    *where* the bad value came from.
    """
    if not isinstance(value, str):
        raise ValueError("%s must be an ISO 8601 string, got %r" % (where, value))
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid ISO 8601 date in %s: %r" % (where, value)) from exc
    if dt.tzinfo is None:
        raise ValueError("%s is missing a UTC offset: %r" % (where, value))
    return dt


def _as_dict(value: Any, where: str) -> dict[str, Any]:
    """Return *value* if it is a dict, else raise a clear ValueError."""
    if not isinstance(value, dict):
        raise ValueError("%s must be a JSON object" % where)
    return value


def _require(data: dict[str, Any], key: str, where: str) -> str:
    """Return ``data[key]`` as a non-empty string, raising a clear ValueError if
    it is missing, empty, or not a string. All fields validated here are
    identifiers consumed as strings downstream (e.g. recipient binding calls
    ``.lower()``), so a non-string value must be rejected rather than crash
    later."""
    value = data.get(key)
    if value is None or value == "":
        raise ValueError("missing required field %s.%s" % (where, key))
    if not isinstance(value, str):
        raise ValueError("field %s.%s must be a string" % (where, key))
    return value
