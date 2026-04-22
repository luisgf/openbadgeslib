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
from typing import List, Optional

OB3_CONTEXT = [
    "https://www.w3.org/2018/credentials/v1",
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
        vc: dict = {
            "@context": OB3_CONTEXT,
            "id": self.id,
            "type": ["VerifiableCredential", "OpenBadgeCredential"],
            "name": self.name,
            "issuer": self.issuer.to_dict(),
            "issuanceDate": _iso(self.issuance_date),
            "credentialSubject": {
                "id": self.recipient_id,
                "type": ["AchievementSubject"],
                "achievement": self.achievement.to_dict(),
            },
        }
        if self.expiration_date:
            vc["expirationDate"] = _iso(self.expiration_date)
        if self.evidence_url:
            vc["evidence"] = [{"id": self.evidence_url, "type": ["Evidence"]}]
        return vc

    def to_jwt_payload(self) -> dict:
        """Return the JWT payload for a JWT-VC signed credential."""
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
        """Reconstruct an OpenBadgeCredential from a decoded JWT payload."""
        vc = payload["vc"]

        issuer_data = vc["issuer"]
        issuer = Issuer(
            id=issuer_data["id"],
            name=issuer_data.get("name", ""),
            url=issuer_data.get("url"),
            email=issuer_data.get("email"),
            image_url=(issuer_data.get("image") or {}).get("id"),
        )

        subj = vc["credentialSubject"]
        ach_data = subj["achievement"]
        criteria = ach_data.get("criteria") or {}
        image = ach_data.get("image") or {}
        achievement = Achievement(
            id=ach_data["id"],
            name=ach_data["name"],
            description=ach_data.get("description", ""),
            criteria_narrative=criteria.get("narrative", ""),
            image_url=image.get("id"),
            tags=ach_data.get("tag", []),
        )

        issuance_date = _parse_iso(vc["issuanceDate"])
        expiration_date = (
            _parse_iso(vc["expirationDate"]) if "expirationDate" in vc else None
        )
        evidence_url = None
        if vc.get("evidence"):
            evidence_url = vc["evidence"][0].get("id")

        return cls(
            id=vc["id"],
            issuer=issuer,
            recipient_id=subj["id"],
            achievement=achievement,
            name=vc.get("name"),
            issuance_date=issuance_date,
            expiration_date=expiration_date,
            evidence_url=evidence_url,
        )


def _parse_iso(s: str) -> datetime:
    """Parse an ISO 8601 date string, handling trailing Z."""
    return datetime.fromisoformat(s.replace("Z", "+00:00"))
