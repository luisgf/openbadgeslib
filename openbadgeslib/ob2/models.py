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

# Strict OpenBadges 2.0 data model. Unlike the legacy (OB 1.0) package in
# openbadgeslib.ob1, these objects are conformant JSON-LD Badge Objects: every
# object carries an ``@context`` and a ``type``, the Assertion uses an IRI
# ``id`` (never the deprecated ``uid``), a ``verification`` object (not the
# 1.x ``verify``), a real boolean ``hashed`` flag and ISO 8601 timestamps.
# The dataclasses mirror the openbadgeslib.ob3 style (``@dataclass`` +
# ``to_dict()``), and untrusted input is parsed with explicit checks rather
# than a validation framework.

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, List, Optional

from ..util import hash_email

OB2_CONTEXT = "https://w3id.org/openbadges/v2"

# JWS signature algorithms this package can emit/accept, matching the key types
# openbadges-keygenerator produces (RSA → RS*, ECC P-256 → ES*, Ed25519 → EdDSA).
_SUPPORTED_ALGORITHMS = {'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'EdDSA'}


# ── date helpers ─────────────────────────────────────────────────────────────

def _iso(dt: datetime) -> str:
    """Return a datetime as an ISO 8601 string with a ``Z`` UTC suffix."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: Any, where: str) -> datetime:
    """Parse an ISO 8601 timestamp (with a UTC offset or trailing ``Z``).

    OB 2.0 requires string ISO 8601 timestamps with a time-zone indicator;
    a bare Unix timestamp (the legacy OB 1.0 shape) is deliberately rejected
    here so the strict verifier does not silently accept legacy assertions.
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


# ── JSON-LD validation helpers ───────────────────────────────────────────────

def _validate_context(ctx: Any) -> None:
    """Validate an OB 2.0 ``@context``: either the context IRI itself, or an
    array whose first entry is that IRI (extra extension contexts may follow)."""
    if isinstance(ctx, str):
        if ctx != OB2_CONTEXT:
            raise ValueError("@context must be %r, got %r" % (OB2_CONTEXT, ctx))
    elif isinstance(ctx, list):
        if not ctx or ctx[0] != OB2_CONTEXT:
            raise ValueError("@context[0] must be %r" % (OB2_CONTEXT,))
    else:
        raise ValueError("@context must be a string or array, got %r" % (ctx,))


def _validate_type(value: Any, expected: str, where: str) -> None:
    """Validate a JSON-LD ``type`` that may be a string or an array of strings."""
    if isinstance(value, str):
        types = [value]
    elif isinstance(value, list):
        types = [t for t in value if isinstance(t, str)]
    else:
        raise ValueError("%s.type must be a string or array" % where)
    if expected not in types:
        raise ValueError("%s.type must include %r, got %r" % (where, expected, value))


def _as_dict(value: Any, where: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError("%s must be a JSON object" % where)
    return value


def _require(data: dict, key: str, where: str) -> str:
    """Return ``data[key]`` as a non-empty string, else raise a clear error."""
    value = data.get(key)
    if value is None or value == "":
        raise ValueError("missing required field %s.%s" % (where, key))
    if not isinstance(value, str):
        raise ValueError("field %s.%s must be a string" % (where, key))
    return value


def _iri_or_none(value: Any) -> Optional[str]:
    """Return an IRI from a value that may be a bare string or an object with
    an ``id`` (OB 2.0 lets image/evidence be either); None for anything else."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        got = value.get("id")
        return got if isinstance(got, str) else None
    return None


def hash_identity(email: str, salt: Optional[str]) -> str:
    """Return the ``sha256$<hex>`` IdentityHash for an email plus optional salt."""
    return "sha256$" + hash_email(email, salt if salt is not None else "").decode("ascii")


# ── data model ───────────────────────────────────────────────────────────────

@dataclass
class IdentityObject:
    """The Assertion ``recipient`` — a (typically hashed) recipient identity."""

    identity: str            # 'sha256$<hex>' when hashed, else the plaintext value
    hashed: bool = True
    salt: Optional[str] = None
    type: str = "email"

    @classmethod
    def create(cls, email: str, salt: Optional[str]) -> "IdentityObject":
        """Build a hashed email IdentityObject from a plaintext email + salt."""
        return cls(identity=hash_identity(email, salt), hashed=True, salt=salt, type="email")

    def to_dict(self) -> dict:
        d: dict = {"type": self.type, "hashed": self.hashed, "identity": self.identity}
        if self.salt is not None:
            d["salt"] = self.salt
        return d

    @classmethod
    def from_dict(cls, data: Any) -> "IdentityObject":
        d = _as_dict(data, "recipient")
        identity = _require(d, "identity", "recipient")
        hashed = d.get("hashed")
        if not isinstance(hashed, bool):
            # Strict: OB 2.0 requires a JSON boolean. The legacy OB 1.0 string
            # "true" is intentionally rejected (that format is verified via -V 1).
            raise ValueError("recipient.hashed must be a JSON boolean, got %r" % (hashed,))
        salt = d.get("salt")
        if salt is not None and not isinstance(salt, str):
            raise ValueError("recipient.salt must be a string")
        type_ = d.get("type", "email")
        if not isinstance(type_, str):
            raise ValueError("recipient.type must be a string")
        return cls(identity=identity, hashed=hashed, salt=salt, type=type_)


@dataclass
class Verification:
    """The Assertion ``verification`` object (SignedBadge or HostedBadge)."""

    type: str                       # "SignedBadge" or "HostedBadge"
    creator: Optional[str] = None   # IRI of the issuer's CryptographicKey (signed)

    def to_dict(self) -> dict:
        d: dict = {"type": self.type}
        if self.creator:
            d["creator"] = self.creator
        return d

    @classmethod
    def from_dict(cls, data: Any) -> "Verification":
        d = _as_dict(data, "verification")
        raw = _require(d, "type", "verification")
        lowered = raw.lower()
        if lowered in ("signedbadge", "signed"):
            canonical = "SignedBadge"
        elif lowered in ("hostedbadge", "hosted"):
            canonical = "HostedBadge"
        else:
            raise ValueError(
                "verification.type must be SignedBadge or HostedBadge, got %r" % (raw,))
        creator = d.get("creator")
        if creator is not None and not isinstance(creator, str):
            raise ValueError("verification.creator must be a string IRI")
        return cls(type=canonical, creator=creator)


@dataclass
class Assertion:
    """An OpenBadges 2.0 Assertion (the signed/hosted claim about a recipient)."""

    recipient: IdentityObject
    badge: str                      # BadgeClass IRI
    verification: Verification
    id: Optional[str] = None        # 'urn:uuid:…' (signed) or the hosted URL; auto for signed
    issued_on: Optional[datetime] = None   # defaults to now (UTC)
    expires: Optional[datetime] = None
    image: Optional[str] = None
    evidence: Optional[str] = None
    narrative: Optional[str] = None

    def __post_init__(self) -> None:
        if self.id is None:
            self.id = "urn:uuid:%s" % uuid.uuid4()
        if self.issued_on is None:
            self.issued_on = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        assert self.issued_on is not None   # set by __post_init__
        d: dict = {
            "@context": OB2_CONTEXT,
            "type": "Assertion",
            "id": self.id,
            "recipient": self.recipient.to_dict(),
            "badge": self.badge,
            "verification": self.verification.to_dict(),
            "issuedOn": _iso(self.issued_on),
        }
        if self.expires:
            d["expires"] = _iso(self.expires)
        if self.image:
            d["image"] = self.image
        if self.evidence:
            d["evidence"] = self.evidence
        if self.narrative:
            d["narrative"] = self.narrative
        return d

    @classmethod
    def from_dict(cls, data: Any) -> "Assertion":
        """Parse and validate an Assertion JSON object (strict OB 2.0)."""
        d = _as_dict(data, "assertion")
        _validate_context(d.get("@context"))
        _validate_type(d.get("type"), "Assertion", "assertion")

        recipient = IdentityObject.from_dict(d.get("recipient"))
        verification = Verification.from_dict(d.get("verification"))

        issued_raw = d.get("issuedOn")
        if not issued_raw:
            raise ValueError("missing required field assertion.issuedOn")
        issued_on = _parse_iso(issued_raw, "assertion.issuedOn")

        expires_raw = d.get("expires")
        expires = _parse_iso(expires_raw, "assertion.expires") if expires_raw else None

        return cls(
            id=_require(d, "id", "assertion"),
            recipient=recipient,
            badge=_require(d, "badge", "assertion"),
            verification=verification,
            issued_on=issued_on,
            expires=expires,
            image=_iri_or_none(d.get("image")),
            evidence=_iri_or_none(d.get("evidence")),
            narrative=d.get("narrative") if isinstance(d.get("narrative"), str) else None,
        )


@dataclass
class CryptographicKey:
    """A published CryptographicKey document (resolves verification.creator)."""

    id: str
    owner: str                # IRI of the owning issuer Profile (bidirectional)
    public_key_pem: str

    def to_dict(self) -> dict:
        return {
            "@context": OB2_CONTEXT,
            "type": "CryptographicKey",
            "id": self.id,
            "owner": self.owner,
            "publicKeyPem": self.public_key_pem,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "CryptographicKey":
        d = _as_dict(data, "cryptographicKey")
        _validate_type(d.get("type"), "CryptographicKey", "cryptographicKey")
        return cls(
            id=_require(d, "id", "cryptographicKey"),
            owner=_require(d, "owner", "cryptographicKey"),
            public_key_pem=_require(d, "publicKeyPem", "cryptographicKey"),
        )


@dataclass
class Profile:
    """An issuer Profile document."""

    id: str
    name: str
    url: Optional[str] = None
    email: Optional[str] = None
    image_url: Optional[str] = None
    public_key: List[str] = field(default_factory=list)   # CryptographicKey IRIs
    revocation_list: Optional[str] = None

    def to_dict(self) -> dict:
        d: dict = {
            "@context": OB2_CONTEXT,
            "type": "Issuer",
            "id": self.id,
            "name": self.name,
        }
        if self.url:
            d["url"] = self.url
        if self.email:
            d["email"] = self.email
        if self.image_url:
            d["image"] = self.image_url
        if self.public_key:
            d["publicKey"] = self.public_key if len(self.public_key) > 1 else self.public_key[0]
        if self.revocation_list:
            d["revocationList"] = self.revocation_list
        return d


@dataclass
class BadgeClass:
    """A BadgeClass document (the achievement definition)."""

    id: str
    name: str
    description: str
    image: str
    criteria: str            # a criteria URL (or narrative text)
    issuer: str              # issuer Profile IRI
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d: dict = {
            "@context": OB2_CONTEXT,
            "type": "BadgeClass",
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "image": self.image,
            "criteria": self.criteria,
            "issuer": self.issuer,
        }
        if self.tags:
            d["tags"] = self.tags
        return d


@dataclass
class RevocationList:
    """A RevocationList document (revokedAssertions is a list of IRIs or objects)."""

    id: str
    issuer: str
    revoked_assertions: List[Any] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "@context": OB2_CONTEXT,
            "type": "RevocationList",
            "id": self.id,
            "issuer": self.issuer,
            "revokedAssertions": self.revoked_assertions,
        }
