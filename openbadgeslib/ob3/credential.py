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

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, List, Optional

OB3_CONTEXT = [
    "https://www.w3.org/ns/credentials/v2",
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
]

_SUPPORTED_ALGORITHMS = {'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'}


def _iso(dt: datetime) -> str:
    """Return a datetime as an ISO 8601 string with Z suffix."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Issuer:
    """Profile of the badge issuer."""

    id: str
    name: str
    url: Optional[str] = None
    email: Optional[str] = None
    image_url: Optional[str] = None

    def to_dict(self) -> dict:
        d: dict = {"id": self.id, "type": ["Profile"], "name": self.name}
        if self.url:
            d["url"] = self.url
        if self.email:
            d["email"] = self.email
        if self.image_url:
            d["image"] = {"id": self.image_url, "type": "Image"}
        return d


@dataclass
class Achievement:
    """A badge class / achievement definition."""

    id: str
    name: str
    description: str
    criteria_narrative: str
    image_url: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d: dict = {
            "id": self.id,
            "type": ["Achievement"],
            "name": self.name,
            "description": self.description,
            "criteria": {"narrative": self.criteria_narrative},
        }
        if self.image_url:
            d["image"] = {"id": self.image_url, "type": "Image"}
        if self.tags:
            d["tag"] = self.tags
        return d


@dataclass
class OpenBadgeCredential:
    """An OpenBadges 3.0 credential (W3C Verifiable Credential)."""

    issuer: Issuer
    recipient_id: str          # 'mailto:email@example.com' or a DID
    achievement: Achievement
    id: Optional[str] = None   # auto-generated as 'urn:uuid:…' if absent
    name: Optional[str] = None  # defaults to achievement.name
    issuance_date: Optional[datetime] = None   # defaults to now (UTC)
    expiration_date: Optional[datetime] = None
    evidence_url: Optional[str] = None

    def __post_init__(self) -> None:
        if self.id is None:
            self.id = f"urn:uuid:{uuid.uuid4()}"
        if self.issuance_date is None:
            self.issuance_date = datetime.now(timezone.utc)
        if self.name is None:
            self.name = self.achievement.name

    # ── serialisation ──────────────────────────────────────────────────────────

    def to_vc(self) -> dict:
        """Return the Verifiable Credential JSON object (no JWT wrapper)."""
        # __post_init__ guarantees issuance_date is set.
        assert self.issuance_date is not None
        vc: dict = {
            "@context": OB3_CONTEXT,
            "id": self.id,
            "type": ["VerifiableCredential", "OpenBadgeCredential"],
            "name": self.name,
            "issuer": self.issuer.to_dict(),
            "validFrom": _iso(self.issuance_date),
            "credentialSubject": {
                "id": self.recipient_id,
                "type": ["AchievementSubject"],
                "achievement": self.achievement.to_dict(),
            },
        }
        if self.expiration_date:
            vc["validUntil"] = _iso(self.expiration_date)
        if self.evidence_url:
            vc["evidence"] = [{"id": self.evidence_url, "type": ["Evidence"]}]
        return vc

    def to_jwt_payload(self) -> dict:
        """Return the JWT payload for a JWT-VC signed credential."""
        # __post_init__ guarantees issuance_date is set.
        assert self.issuance_date is not None
        payload: dict = {
            "iss": self.issuer.id,
            "sub": self.recipient_id,
            "jti": self.id,
            "iat": int(self.issuance_date.timestamp()),
            "vc":  self.to_vc(),
        }
        if self.expiration_date:
            payload["exp"] = int(self.expiration_date.timestamp())
        return payload

    # ── deserialisation ────────────────────────────────────────────────────────

    @classmethod
    def from_jwt_payload(cls, payload: dict) -> "OpenBadgeCredential":
        """Reconstruct an OpenBadgeCredential from a decoded JWT payload.

        The ``vc`` claim is untrusted input, so its structure is validated
        explicitly: every required object/field is checked and a clear
        ``ValueError`` is raised on anything missing or malformed (the OB3
        verifier wraps these as ``OB3VerificationError``).
        """
        vc = _as_dict(payload.get("vc"), "vc")

        issuer_data = _as_dict(vc.get("issuer"), "vc.issuer")
        issuer = Issuer(
            id=_require(issuer_data, "id", "vc.issuer"),
            name=issuer_data.get("name", ""),
            url=issuer_data.get("url"),
            email=issuer_data.get("email"),
            image_url=_as_dict_or_empty(issuer_data.get("image")).get("id"),
        )

        # credentialSubject may be a single object or a (non-empty) array.
        subj_raw = vc.get("credentialSubject")
        if isinstance(subj_raw, list):
            if not subj_raw:
                raise ValueError("vc.credentialSubject must not be empty")
            subj_raw = subj_raw[0]
        subj = _as_dict(subj_raw, "vc.credentialSubject")

        ach_data = _as_dict(subj.get("achievement"),
                            "vc.credentialSubject.achievement")
        criteria = _as_dict_or_empty(ach_data.get("criteria"))
        image = _as_dict_or_empty(ach_data.get("image"))
        achievement = Achievement(
            id=_require(ach_data, "id", "vc.credentialSubject.achievement"),
            name=_require(ach_data, "name", "vc.credentialSubject.achievement"),
            description=ach_data.get("description", ""),
            criteria_narrative=criteria.get("narrative", ""),
            image_url=image.get("id"),
            tags=ach_data.get("tag", []),
        )

        # Accept both VC 2.0 (validFrom/validUntil) and VC 1.1
        # (issuanceDate/expirationDate) field names for backward compatibility.
        issued = vc.get("validFrom") or vc.get("issuanceDate")
        issuance_date = _parse_date(issued, "vc.validFrom") if issued else None
        expires = vc.get("validUntil") or vc.get("expirationDate")
        expiration_date = _parse_date(expires, "vc.validUntil") if expires else None

        evidence_url = None
        evidence = vc.get("evidence")
        if isinstance(evidence, list) and evidence and isinstance(evidence[0], dict):
            evidence_url = evidence[0].get("id")

        return cls(
            id=_require(vc, "id", "vc"),
            issuer=issuer,
            recipient_id=_require(subj, "id", "vc.credentialSubject"),
            achievement=achievement,
            name=vc.get("name"),
            issuance_date=issuance_date,
            expiration_date=expiration_date,
            evidence_url=evidence_url,
        )


def _as_dict(value: Any, where: str) -> dict:
    """Return value if it is a dict, else raise a clear ValueError."""
    if not isinstance(value, dict):
        raise ValueError("%s must be a JSON object" % where)
    return value


def _as_dict_or_empty(value: Any) -> dict:
    """Return value if it is a dict, else an empty dict (optional sub-objects)."""
    return value if isinstance(value, dict) else {}


def _require(data: dict, key: str, where: str) -> str:
    """Return data[key] as a string, raising a clear ValueError if missing,
    empty, or not a string. All fields validated here (id/name) are identifiers
    consumed as strings downstream (e.g. recipient binding calls .lower()), so a
    non-string value must be rejected rather than crash later."""
    value = data.get(key)
    if value is None or value == "":
        raise ValueError("missing required field %s.%s" % (where, key))
    if not isinstance(value, str):
        raise ValueError("field %s.%s must be a string" % (where, key))
    return value


def _parse_date(value: Any, where: str) -> datetime:
    """Parse an ISO 8601 date, raising a clear ValueError naming the field."""
    try:
        return _parse_iso(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(
            "invalid ISO 8601 date in %s: %r" % (where, value)) from exc


def _parse_iso(s: str) -> datetime:
    """Parse an ISO 8601 date string, handling trailing Z."""
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        # A date-time with no UTC/offset suffix is valid ISO 8601, but verify()
        # always compares against an aware datetime.now(timezone.utc) — accept
        # only unambiguously-anchored timestamps.
        raise ValueError("date is missing a UTC offset: %r" % s)
    return dt
