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

# Shared JSON helpers live in openbadgeslib._jsonmodel now (deduplicated with
# ob2.models). Re-exported (X as X) so the ob3 modules and tests that do
# `from .credential import _iso, _parse_iso` keep working.
from .._jsonmodel import (
    _iso as _iso, _parse_iso as _parse_iso,
    _as_dict as _as_dict, _require as _require,
)

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


@dataclass
class Issuer:
    """Profile of the badge issuer."""

    id: str
    name: str
    url: Optional[str] = None
    email: Optional[str] = None
    image_url: Optional[str] = None
    # Compact EndorsementCredential JWTs vouching for this profile (OB 3.0
    # `endorsementJwt`, added to context 3.0.3 by errata v1.6). Verifiable with
    # verify_endorsement_jwt; the endorser is a third party, not this issuer.
    endorsement_jwts: List[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id, "type": ["Profile"], "name": self.name}
        if self.url:
            d["url"] = self.url
        if self.email:
            d["email"] = self.email
        if self.image_url:
            d["image"] = {"id": self.image_url, "type": "Image"}
        if self.endorsement_jwts:
            d["endorsementJwt"] = list(self.endorsement_jwts)
        return d


@dataclass
class Alignment:
    """Alignment of an achievement to a node in an educational framework
    (OB 3.0 `alignment`) — what an LMS reads to map a badge to a competency."""

    target_name: str
    target_url: str
    target_framework: Optional[str] = None
    target_code: Optional[str] = None
    target_description: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": ["Alignment"],
            "targetName": self.target_name,
            "targetUrl": self.target_url,
        }
        if self.target_framework:
            d["targetFramework"] = self.target_framework
        if self.target_code:
            d["targetCode"] = self.target_code
        if self.target_description:
            d["targetDescription"] = self.target_description
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alignment":
        return cls(
            target_name=_require(data, "targetName", "alignment"),
            target_url=_require(data, "targetUrl", "alignment"),
            target_framework=data.get("targetFramework"),
            target_code=data.get("targetCode"),
            target_description=data.get("targetDescription"),
        )


@dataclass
class Evidence:
    """A piece of evidence supporting a credential (OB 3.0 `evidence`), richer
    than a bare URL: an optional narrative and descriptive metadata."""

    id: Optional[str] = None          # dereferenceable URL of the evidence
    narrative: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    genre: Optional[str] = None
    audience: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": ["Evidence"]}
        if self.id:
            d["id"] = self.id
        for key, value in (("narrative", self.narrative), ("name", self.name),
                           ("description", self.description),
                           ("genre", self.genre), ("audience", self.audience)):
            if value:
                d[key] = value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        return cls(
            id=data.get("id"),
            narrative=data.get("narrative"),
            name=data.get("name"),
            description=data.get("description"),
            genre=data.get("genre"),
            audience=data.get("audience"),
        )


@dataclass
class IdentityObject:
    """A subject identity (OB 3.0 ``credentialSubject.identifier``): a hashed or
    plaintext identifier such as a salted SHA-256 of the recipient's email. An
    alternative or supplement to ``credentialSubject.id`` — a credential may
    convey identity through either or both."""

    identity_hash: str
    identity_type: str   # IdentifierTypeEnum, e.g. 'emailAddress', or 'ext:…'
    hashed: bool
    salt: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        # This schema type sets additionalProperties:false — emit these keys only.
        d: dict[str, Any] = {
            "type": "IdentityObject",
            "hashed": self.hashed,
            "identityHash": self.identity_hash,
            "identityType": self.identity_type,
        }
        if self.salt:
            d["salt"] = self.salt
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IdentityObject":
        hashed = data.get("hashed")
        if not isinstance(hashed, bool):
            raise ValueError("field identifier.hashed must be a boolean")
        return cls(
            identity_hash=_require(data, "identityHash", "identifier"),
            identity_type=_require(data, "identityType", "identifier"),
            hashed=hashed,
            salt=data.get("salt"),
        )


@dataclass
class Result:
    """A result achieved for an achievement (OB 3.0 ``credentialSubject.result``).
    ``result_description`` is the ``id`` of the ResultDescription on the
    achievement that this result instantiates."""

    value: Optional[str] = None
    status: Optional[str] = None            # ResultStatusEnum
    achieved_level: Optional[str] = None    # id of a RubricCriterionLevel
    result_description: Optional[str] = None  # id of the linked ResultDescription
    alignments: List[Alignment] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": ["Result"]}
        for key, value in (("status", self.status), ("value", self.value),
                           ("achievedLevel", self.achieved_level),
                           ("resultDescription", self.result_description)):
            if value:
                d[key] = value
        if self.alignments:
            d["alignment"] = [a.to_dict() for a in self.alignments]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Result":
        return cls(
            value=data.get("value"),
            status=data.get("status"),
            achieved_level=data.get("achievedLevel"),
            result_description=data.get("resultDescription"),
            alignments=_alignment_list(data.get("alignment")),
        )


@dataclass
class ResultDescription:
    """A possible result an achievement can convey (OB 3.0
    ``achievement.resultDescription``); a Result links back to it by ``id``."""

    id: str
    name: str
    result_type: str     # ResultType enum, e.g. 'LetterGrade'/'Status', or 'ext:…'
    allowed_values: List[str] = field(default_factory=list)
    required_value: Optional[str] = None
    required_level: Optional[str] = None
    value_min: Optional[str] = None
    value_max: Optional[str] = None
    alignments: List[Alignment] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "type": ["ResultDescription"],
            "name": self.name,
            "resultType": self.result_type,
        }
        if self.allowed_values:
            d["allowedValue"] = list(self.allowed_values)
        for key, value in (("requiredValue", self.required_value),
                           ("requiredLevel", self.required_level),
                           ("valueMin", self.value_min),
                           ("valueMax", self.value_max)):
            if value:
                d[key] = value
        if self.alignments:
            d["alignment"] = [a.to_dict() for a in self.alignments]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResultDescription":
        allowed = data.get("allowedValue")
        if isinstance(allowed, str):
            allowed_values = [allowed]
        elif isinstance(allowed, list):
            allowed_values = [v for v in allowed if isinstance(v, str)]
        else:
            allowed_values = []
        return cls(
            id=_require(data, "id", "resultDescription"),
            name=_require(data, "name", "resultDescription"),
            result_type=_require(data, "resultType", "resultDescription"),
            allowed_values=allowed_values,
            required_value=data.get("requiredValue"),
            required_level=data.get("requiredLevel"),
            value_min=data.get("valueMin"),
            value_max=data.get("valueMax"),
            alignments=_alignment_list(data.get("alignment")),
        )


@dataclass
class Achievement:
    """A badge class / achievement definition."""

    id: str
    name: str
    description: str
    criteria_narrative: str
    image_url: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    # Compact EndorsementCredential JWTs vouching for this achievement
    # (OB 3.0 `endorsementJwt`). See Issuer.endorsement_jwts.
    endorsement_jwts: List[str] = field(default_factory=list)
    # Kind of achievement (OB 3.0 `achievementType`, e.g. 'Badge',
    # 'Certificate', 'Competency', …) and any academic credit it carries.
    achievement_type: Optional[str] = None
    credits_available: Optional[float] = None
    # Framework alignments (OB 3.0 `alignment`): the competency mappings LMSes
    # consume. Empty when the achievement declares none.
    alignments: List[Alignment] = field(default_factory=list)
    # Possible results this achievement can convey (OB 3.0 `resultDescription`);
    # a Result on the subject links to one of these by id. Empty when none.
    result_descriptions: List["ResultDescription"] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "type": ["Achievement"],
            "name": self.name,
            "description": self.description,
            "criteria": {"narrative": self.criteria_narrative},
        }
        if self.achievement_type:
            d["achievementType"] = self.achievement_type
        if self.credits_available is not None:
            d["creditsAvailable"] = self.credits_available
        if self.image_url:
            d["image"] = {"id": self.image_url, "type": "Image"}
        if self.tags:
            d["tag"] = self.tags
        if self.alignments:
            d["alignment"] = [a.to_dict() for a in self.alignments]
        if self.result_descriptions:
            d["resultDescription"] = [r.to_dict()
                                      for r in self.result_descriptions]
        if self.endorsement_jwts:
            d["endorsementJwt"] = list(self.endorsement_jwts)
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
    # Backward-compatible single-URL evidence convenience. For the full OB 3.0
    # evidence list (narrative, name, …) use `evidence`; when both are set the
    # list wins. Parsing populates both (evidence_url = evidence[0].id).
    evidence_url: Optional[str] = None
    evidence: List["Evidence"] = field(default_factory=list)
    # Raw credentialStatus entries (Bitstring Status List / StatusList2021),
    # normalised to a list of objects. Consumed by ob3.status to check
    # revocation; empty when the credential carries no status.
    credential_status: List[dict[str, Any]] = field(default_factory=list)
    # Compact EndorsementCredential JWTs vouching for the credential itself
    # (top-level OB 3.0 `endorsementJwt`). Endorsements attached to the issuer
    # or the achievement live on those objects; all_endorsement_jwts() gathers
    # the three. Empty when the credential carries none.
    endorsement_jwts: List[str] = field(default_factory=list)
    # AchievementSubject-level fields (OB 3.0 credentialSubject.*): creditsEarned
    # pairs with achievement.creditsAvailable; identifier carries hashed/plaintext
    # subject identities (an alternative or supplement to credentialSubject.id);
    # result records measured outcomes, each linking to an achievement
    # resultDescription. None/empty when the credential conveys none.
    credits_earned: Optional[float] = None
    identifiers: List["IdentityObject"] = field(default_factory=list)
    results: List["Result"] = field(default_factory=list)
    # A read-only view of the already-validated document this credential was
    # parsed from (set by the verifiers via _from_vc); None when built in-memory
    # to issue. Lets a caller read spec fields the model does not map —
    # alignment, results, multiple evidence, endorsements, … — without
    # re-parsing the token. Do NOT mutate it: on the from_*() classmethods it
    # may alias the caller-supplied dict. Its shape is the document as parsed,
    # so it reflects parse time (not later edits to the model fields) and is
    # path-dependent — the JWT-VC payload (with the registered iss/sub/jti/nbf/
    # exp claims alongside) or the Data Integrity document (with its proof).
    # Excluded from equality/repr so it never affects comparisons.
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
        subject: dict[str, Any] = {
            "type": ["AchievementSubject"],
            "achievement": self.achievement.to_dict(),
        }
        # credentialSubject.id is optional; emit it only when present.
        if self.recipient_id is not None:
            subject["id"] = self.recipient_id
        if self.credits_earned is not None:
            subject["creditsEarned"] = self.credits_earned
        if self.identifiers:
            subject["identifier"] = [i.to_dict() for i in self.identifiers]
        if self.results:
            subject["result"] = [r.to_dict() for r in self.results]
        vc: dict[str, Any] = {
            "@context": OB3_CONTEXT,
            "id": self.id,
            "type": ["VerifiableCredential", "OpenBadgeCredential"],
            "name": self.name,
            "issuer": self.issuer.to_dict(),
            "validFrom": _iso(self.issuance_date),
            "credentialSubject": subject,
            "credentialSchema": [dict(_OB3_CREDENTIAL_SCHEMA)],
        }
        if self.expiration_date:
            vc["validUntil"] = _iso(self.expiration_date)
        evidence_items = self.evidence or (
            [Evidence(id=self.evidence_url)] if self.evidence_url else [])
        if evidence_items:
            vc["evidence"] = [e.to_dict() for e in evidence_items]
        if self.credential_status:
            vc["credentialStatus"] = (
                self.credential_status[0] if len(self.credential_status) == 1
                else self.credential_status)
        if self.endorsement_jwts:
            vc["endorsementJwt"] = list(self.endorsement_jwts)
        return vc

    def all_endorsement_jwts(self) -> List[str]:
        """Every compact EndorsementCredential JWT attached to this credential,
        gathered from the credential itself and from its issuer and achievement
        (OB 3.0 allows `endorsementJwt` at all three levels). Verify each with
        :func:`openbadgeslib.ob3.verify_endorsement_jwt`."""
        return [*self.endorsement_jwts,
                *self.issuer.endorsement_jwts,
                *self.achievement.endorsement_jwts]

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
                endorsement_jwts=_string_list(issuer_data.get("endorsementJwt")),
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
        rd_raw = ach_data.get("resultDescription")
        result_descriptions = [ResultDescription.from_dict(r) for r in rd_raw
                               if isinstance(r, dict)] \
            if isinstance(rd_raw, list) else []
        achievement = Achievement(
            id=_require(ach_data, "id", "vc.credentialSubject.achievement"),
            name=_require(ach_data, "name", "vc.credentialSubject.achievement"),
            description=ach_data.get("description", ""),
            criteria_narrative=criteria.get("narrative", ""),
            image_url=image.get("id"),
            tags=ach_data.get("tag", []),
            endorsement_jwts=_string_list(ach_data.get("endorsementJwt")),
            achievement_type=ach_data.get("achievementType"),
            credits_available=_float_or_none(ach_data.get("creditsAvailable")),
            alignments=_alignment_list(ach_data.get("alignment")),
            result_descriptions=result_descriptions,
        )

        # Accept both VC 2.0 (validFrom/validUntil) and VC 1.1
        # (issuanceDate/expirationDate) field names for backward compatibility.
        issued = vc.get("validFrom") or vc.get("issuanceDate")
        issuance_date = _parse_date(issued, "vc.validFrom") if issued else None
        expires = vc.get("validUntil") or vc.get("expirationDate")
        expiration_date = _parse_date(expires, "vc.validUntil") if expires else None

        evidence_raw = vc.get("evidence")
        if isinstance(evidence_raw, list):
            evidence_list = [Evidence.from_dict(e) for e in evidence_raw
                             if isinstance(e, dict)]
        elif isinstance(evidence_raw, dict):
            evidence_list = [Evidence.from_dict(evidence_raw)]
        else:
            evidence_list = []
        # Backward-compatible convenience: the first evidence's URL.
        evidence_url = evidence_list[0].id if evidence_list else None

        # credentialStatus may be a single object or an array; keep only object
        # entries so the status checker can rely on .get() without crashing.
        status_raw = vc.get("credentialStatus")
        if isinstance(status_raw, dict):
            credential_status = [status_raw]
        elif isinstance(status_raw, list):
            credential_status = [s for s in status_raw if isinstance(s, dict)]
        else:
            credential_status = []

        # credentialSubject.identifier: zero or more hashed/plaintext identities.
        identifier_raw = subj.get("identifier")
        identifiers = [IdentityObject.from_dict(i) for i in identifier_raw
                       if isinstance(i, dict)] \
            if isinstance(identifier_raw, list) else []

        # credentialSubject.id is optional (schema); identity may instead be
        # conveyed via one or more 'identifier' objects. Reject only when BOTH
        # are absent — a subject with no identity at all is non-conformant.
        recipient_id = subj.get("id")
        if recipient_id is not None and not isinstance(recipient_id, str):
            raise ValueError("field vc.credentialSubject.id must be a string")
        if not recipient_id:                        # None or empty string
            if not identifiers:
                raise ValueError(
                    "vc.credentialSubject must have an 'id' or an 'identifier'")
            recipient_id = None

        # credentialSubject.result: measured outcomes (each may link to an
        # achievement resultDescription); creditsEarned pairs with creditsAvailable.
        result_raw = subj.get("result")
        results = [Result.from_dict(r) for r in result_raw
                   if isinstance(r, dict)] if isinstance(result_raw, list) else []
        credits_earned = _float_or_none(subj.get("creditsEarned"))

        credential = cls(
            id=_require(vc, "id", "vc"),
            issuer=issuer,
            recipient_id=recipient_id,
            achievement=achievement,
            name=vc.get("name"),
            issuance_date=issuance_date,
            expiration_date=expiration_date,
            evidence_url=evidence_url,
            evidence=evidence_list,
            credential_status=credential_status,
            endorsement_jwts=_string_list(vc.get("endorsementJwt")),
            credits_earned=credits_earned,
            identifiers=identifiers,
            results=results,
        )
        # Keep the validated document so the caller can read fields the model
        # does not map (see the ``raw`` field). This is the JWT-VC payload or
        # the Data Integrity document, exactly as verified.
        credential.raw = vc
        return credential


def _as_dict_or_empty(value: Any) -> dict[str, Any]:
    """Return value if it is a dict, else an empty dict (optional sub-objects)."""
    return value if isinstance(value, dict) else {}


def _float_or_none(value: Any) -> Optional[float]:
    """Coerce a JSON number to float, else None (for optional numeric fields
    like creditsAvailable). A bool is not a number here."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _string_list(value: Any) -> List[str]:
    """Return the string members of *value* when it is a list, else an empty
    list. `endorsementJwt` is an array of compact JWT strings; a single string
    is also accepted (tolerant read of a producer that omitted the array)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _alignment_list(value: Any) -> List["Alignment"]:
    """Parse OB 3.0 ``alignment`` — the schema allows a single Alignment object
    or an array of them — into a list; non-object members are skipped."""
    if isinstance(value, dict):
        return [Alignment.from_dict(value)]
    if isinstance(value, list):
        return [Alignment.from_dict(a) for a in value if isinstance(a, dict)]
    return []


def _parse_date(value: Any, where: str) -> datetime:
    """Parse an ISO 8601 date, raising a clear ValueError naming the field."""
    try:
        return _parse_iso(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(
            "invalid ISO 8601 date in %s: %r" % (where, value)) from exc
