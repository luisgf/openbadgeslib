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

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, List, Optional

_VC2_CONTEXT = "https://www.w3.org/ns/credentials/v2"

OB3_CONTEXT = [
    _VC2_CONTEXT,
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
]

# The OB v3p0 context URI, optionally version-pinned (…/context-3.0.3.json),
# mirroring the JSON Schema's @context[1] pattern.
_OB_CONTEXT_RE = re.compile(
    r'^https://purl\.imsglobal\.org/spec/ob/v3p0/context(-\d+\.\d+\.\d+)?\.json$')

_SUPPORTED_ALGORITHMS = {'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'EdDSA'}

# 1EdTech's published JSON Schema for an AchievementCredential. Issued badges
# carry a credentialSchema pointing at it (§8, 1EdTechJsonSchemaValidator2019),
# so validators and wallets can self-check them; the offline conformance gate
# proves our credentials satisfy this exact schema.
_OB3_CREDENTIAL_SCHEMA = {
    "id": "https://purl.imsglobal.org/spec/ob/v3p0/schema/json/"
          "ob_v3p0_achievementcredential_schema.json",
    "type": "1EdTechJsonSchemaValidator2019",
}


def _validate_context(ctx: Any) -> None:
    """Validate an OpenBadgeCredential ``@context`` per the schema: an array
    whose first item is the VC 2.0 context and whose second is the OB v3p0
    context; extra items may follow. Raises ValueError otherwise."""
    if not isinstance(ctx, list) or len(ctx) < 2:
        raise ValueError(
            "@context must be an array with the VC 2.0 and OB v3p0 contexts")
    if ctx[0] != _VC2_CONTEXT:
        raise ValueError("@context[0] must be %r" % (_VC2_CONTEXT,))
    if not (isinstance(ctx[1], str) and _OB_CONTEXT_RE.match(ctx[1])):
        raise ValueError(
            "@context[1] must be the OB v3p0 context URI, got %r" % (ctx[1],))


def _iso(dt: datetime) -> str:
    """Return a datetime as an ISO 8601 string with Z suffix.

    A naive datetime is assumed to be UTC (matching status_registry._iso_z),
    not local time — so validFrom/validUntil never silently shift by the host's
    offset and stay consistent with the nbf/exp JWT claims.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Issuer:
    """Profile of the badge issuer."""

    id: str
    name: str
    url: Optional[str] = None
    email: Optional[str] = None
    image_url: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id, "type": ["Profile"], "name": self.name}
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

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
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
    # 'mailto:email@example.com' or a DID; Optional because OB3 makes
    # credentialSubject.id optional (identity may travel via 'identifier').
    recipient_id: Optional[str]
    achievement: Achievement
    id: Optional[str] = None   # auto-generated as 'urn:uuid:…' if absent
    name: Optional[str] = None  # defaults to achievement.name
    issuance_date: Optional[datetime] = None   # defaults to now (UTC)
    expiration_date: Optional[datetime] = None
    evidence_url: Optional[str] = None
    # Raw credentialStatus entries (Bitstring Status List / StatusList2021),
    # normalised to a list of objects. Consumed by ob3.status to check
    # revocation; empty when the credential carries no status.
    credential_status: List[dict[str, Any]] = field(default_factory=list)
    # The raw, already-validated VC document this credential was parsed from
    # (set by the verifiers, via _from_vc); None when built in-memory to issue.
    # Lets a caller read spec fields the model does not map — alignment,
    # results, multiple evidence, endorsements, … — without re-parsing the
    # token. Excluded from equality/repr so it never affects comparisons.
    raw: Optional[dict[str, Any]] = field(default=None, compare=False,
                                          repr=False)

    def __post_init__(self) -> None:
        if self.id is None:
            self.id = f"urn:uuid:{uuid.uuid4()}"
        if self.issuance_date is None:
            self.issuance_date = datetime.now(timezone.utc)
        elif self.issuance_date.tzinfo is None:
            # A naive datetime is assumed UTC, so validFrom (string) and nbf
            # (epoch int) agree instead of diverging by the host's offset.
            self.issuance_date = self.issuance_date.replace(tzinfo=timezone.utc)
        if self.expiration_date is not None \
                and self.expiration_date.tzinfo is None:
            self.expiration_date = self.expiration_date.replace(
                tzinfo=timezone.utc)
        if self.name is None:
            self.name = self.achievement.name

    # ── serialisation ──────────────────────────────────────────────────────────

    def to_vc(self) -> dict[str, Any]:
        """Return the Verifiable Credential JSON object (no JWT wrapper)."""
        # __post_init__ guarantees issuance_date is set.
        assert self.issuance_date is not None
        vc: dict[str, Any] = {
            "@context": OB3_CONTEXT,
            "id": self.id,
            "type": ["VerifiableCredential", "OpenBadgeCredential"],
            "name": self.name,
            "issuer": self.issuer.to_dict(),
            "validFrom": _iso(self.issuance_date),
            "credentialSubject": {
                "type": ["AchievementSubject"],
                "achievement": self.achievement.to_dict(),
            },
            "credentialSchema": [dict(_OB3_CREDENTIAL_SCHEMA)],
        }
        # credentialSubject.id is optional; emit it only when present.
        if self.recipient_id is not None:
            vc["credentialSubject"]["id"] = self.recipient_id
        if self.expiration_date:
            vc["validUntil"] = _iso(self.expiration_date)
        if self.evidence_url:
            vc["evidence"] = [{"id": self.evidence_url, "type": ["Evidence"]}]
        if self.credential_status:
            vc["credentialStatus"] = (
                self.credential_status[0] if len(self.credential_status) == 1
                else self.credential_status)
        return vc

    def to_jwt_payload(self) -> dict[str, Any]:
        """Return the JWT payload for a JWT-VC signed credential.

        OB 3.0 §8.2.4.1 (native VC-JWT): the JWT payload **is** the
        OpenBadgeCredential — its members sit at the top level of the payload,
        not nested under a ``vc`` claim — with the registered claims alongside:
        ``iss`` (issuer id), ``sub`` (credentialSubject id), ``jti`` (credential
        id) and ``nbf`` (validFrom). ``exp`` mirrors validUntil when present.
        There is deliberately no ``iat`` claim (the spec maps issuance to nbf).
        """
        # __post_init__ guarantees issuance_date is set.
        assert self.issuance_date is not None
        payload: dict[str, Any] = dict(self.to_vc())   # credential at the payload top level
        payload["iss"] = self.issuer.id
        if self.recipient_id is not None:
            payload["sub"] = self.recipient_id
        payload["jti"] = self.id
        payload["nbf"] = int(self.issuance_date.timestamp())
        if self.expiration_date:
            payload["exp"] = int(self.expiration_date.timestamp())
        return payload

    # ── deserialisation ────────────────────────────────────────────────────────

    @classmethod
    def from_jwt_payload(cls, payload: dict[str, Any]) -> "OpenBadgeCredential":
        """Reconstruct an OpenBadgeCredential from a decoded JWT payload.

        OB 3.0 native VC-JWT: the payload IS the credential (its members at the
        top level), so ``payload`` is read directly as the credential body. The
        registered claims (iss/sub/jti/nbf/exp) coexist at the top level and
        are simply ignored by the field reads.
        """
        return cls._from_vc(payload)

    @classmethod
    def from_vc_document(cls, document: dict[str, Any]) -> "OpenBadgeCredential":
        """Reconstruct an OpenBadgeCredential from a JSON-LD VC document.

        The shape a credential secured with an embedded Data Integrity proof
        has (OB 3.0 Linked Data Proof format): the document is the credential
        itself, with a ``proof`` member — ignored here, verified separately by
        ob3.ldp — and no JWT registered claims.
        """
        return cls._from_vc(document)

    @classmethod
    def _from_vc(cls, payload: dict[str, Any]) -> "OpenBadgeCredential":
        """Shared constructor from an untrusted credential body.

        Every required object/field is checked and a clear ``ValueError`` is
        raised on anything missing or malformed (the OB3 verifiers wrap these
        as ``OB3VerificationError``). Unknown members (JWT claims, ``proof``)
        are simply ignored by the field reads.
        """
        vc = _as_dict(payload, "credential")

        _validate_context(vc.get("@context"))

        # issuer may be a Profile object or a bare string IRI (both schema-valid).
        issuer_raw = vc.get("issuer")
        if isinstance(issuer_raw, str):
            if not issuer_raw:
                raise ValueError("field vc.issuer must not be empty")
            issuer = Issuer(id=issuer_raw, name="")
        else:
            issuer_data = _as_dict(issuer_raw, "vc.issuer")
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

        # credentialStatus may be a single object or an array; keep only object
        # entries so the status checker can rely on .get() without crashing.
        status_raw = vc.get("credentialStatus")
        if isinstance(status_raw, dict):
            credential_status = [status_raw]
        elif isinstance(status_raw, list):
            credential_status = [s for s in status_raw if isinstance(s, dict)]
        else:
            credential_status = []

        # credentialSubject.id is optional (schema); identity may instead be
        # conveyed via one or more 'identifier' objects. Reject only when BOTH
        # are absent — a subject with no identity at all is non-conformant.
        recipient_id = subj.get("id")
        if recipient_id is not None and not isinstance(recipient_id, str):
            raise ValueError("field vc.credentialSubject.id must be a string")
        if not recipient_id:                        # None or empty string
            identifiers = subj.get("identifier")
            if not (isinstance(identifiers, list) and identifiers):
                raise ValueError(
                    "vc.credentialSubject must have an 'id' or an 'identifier'")
            recipient_id = None

        credential = cls(
            id=_require(vc, "id", "vc"),
            issuer=issuer,
            recipient_id=recipient_id,
            achievement=achievement,
            name=vc.get("name"),
            issuance_date=issuance_date,
            expiration_date=expiration_date,
            evidence_url=evidence_url,
            credential_status=credential_status,
        )
        # Keep the validated document so the caller can read fields the model
        # does not map (see the ``raw`` field). This is the JWT-VC payload or
        # the Data Integrity document, exactly as verified.
        credential.raw = vc
        return credential


def _as_dict(value: Any, where: str) -> dict[str, Any]:
    """Return value if it is a dict, else raise a clear ValueError."""
    if not isinstance(value, dict):
        raise ValueError("%s must be a JSON object" % where)
    return value


def _as_dict_or_empty(value: Any) -> dict[str, Any]:
    """Return value if it is a dict, else an empty dict (optional sub-objects)."""
    return value if isinstance(value, dict) else {}


def _require(data: dict[str, Any], key: str, where: str) -> str:
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
