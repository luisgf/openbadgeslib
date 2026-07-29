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

# OB 3.0 badges in the EUDI **SD-JWT VC** format, delegated to the generic
# openvc-core library (https://pypi.org/project/openvc-core/).
#
# This is an *additive* track: it does not touch the native OB 3.0 VC-JWT or
# Data Integrity issuance (those stay in signer.py / ldp.py). It maps an
# OpenBadgeCredential into an IETF SD-JWT VC — the format the EU Digital Identity
# Wallet / ARF converges on — and back, using openvc-core's SdJwtVcProofSuite for
# the crypto. Selective disclosure lets a holder prove the achievement while
# withholding their identity.
#
# Requires the optional ``[eudi]`` extra (``pip install openbadgeslib[eudi]``),
# which pulls ``openvc-core``. SD-JWT allows only Ed25519 (EdDSA) and the NIST
# curves P-256 (ES256) / P-384 (ES384) — RSA is not in its algorithm set.
#
# Revocation on this track is the **IETF OAuth Token Status List** (the JOSE
# status format SD-JWT VC uses), not the W3C Bitstring Status List the OB 3.0
# JWT-VC / Data Integrity tracks use — see ``issue_badge_sd_jwt(status=…)``.

import base64
import hashlib
import json

from typing import Any, Callable, Iterable, Mapping, Optional, Union, cast

from .credential import OpenBadgeCredential
from ..errors import LibOpenBadgesException
from ..keys import (
    KeyType, detect_key_type, ec_curve_from_pem, public_jwk_from_pem)
from ..util import download_file

# A vct (Verifiable Credential Type) for Open Badges expressed as SD-JWT VC.
OB3_SD_JWT_VCT = "https://purl.imsglobal.org/spec/ob/v3p0#OpenBadgeCredential"

# The OpenID4VCI / DCQL format identifier for an IETF SD-JWT VC credential.
OB3_SD_JWT_FORMAT = "dc+sd-jwt"

# Claims made selectively disclosable by default: the recipient's identity, so a
# holder can present the achievement while withholding who they are.
DEFAULT_DISCLOSABLE = ("credentialSubject",)

_INSTALL_HINT = (
    "SD-JWT VC support needs the [eudi] extra: pip install openbadgeslib[eudi]")


class EudiError(LibOpenBadgesException):
    """Raised on SD-JWT VC issuance/verification problems (the EUDI track)."""


def _require_openvc() -> Any:
    """Import the openvc-core pieces, or raise with an actionable hint."""
    try:
        from openvc.keys import (
            Ed25519SigningKey, P256SigningKey, P384SigningKey)
        from openvc.proof.sd_jwt import SdJwtVcProofSuite
    except ImportError as exc:
        raise EudiError(_INSTALL_HINT) from exc
    return Ed25519SigningKey, P256SigningKey, P384SigningKey, SdJwtVcProofSuite


def _require_openvc_status() -> Any:
    """Import openvc-core's IETF Token Status List pieces, or raise with a hint.

    Needs openvc-core >=1.22, where the status-list codec grew the IETF token
    flavour alongside the W3C Bitstring one.
    """
    try:
        from openvc.status.token_status_list import (
            check_token_status, parse_token_status_ref)
    except ImportError as exc:
        raise EudiError(
            "%s (>=1.22 for IETF Token Status List support)" % _INSTALL_HINT
        ) from exc
    return check_token_status, parse_token_status_ref


def _signing_key(privkey_pem: Any, kid: str) -> Any:
    """Build the openvc SigningKey matching the PEM's key type / curve.

    Ed25519 -> EdDSA; NIST P-256 -> ES256; NIST P-384 -> ES384. The ECDSA
    curve is read from the key itself, since it fixes the JOSE algorithm.
    """
    Ed25519SigningKey, P256SigningKey, P384SigningKey, _ = _require_openvc()
    key_type = detect_key_type(privkey_pem)
    if key_type is KeyType.ED25519:
        return Ed25519SigningKey.from_pem(privkey_pem, kid=kid)
    if key_type is KeyType.ECC:                       # NIST curve -> ES256/ES384
        curve = ec_curve_from_pem(privkey_pem)
        if curve == "secp256r1":                      # P-256 -> ES256
            return P256SigningKey.from_pem(privkey_pem, kid=kid)
        if curve == "secp384r1":                      # P-384 -> ES384
            return P384SigningKey.from_pem(privkey_pem, kid=kid)
        raise EudiError(
            "SD-JWT VC over ECDSA needs a NIST P-256 (ES256) or P-384 (ES384) "
            "key; got curve %r." % curve)
    raise EudiError(
        "SD-JWT VC allows only Ed25519 (EdDSA) or NIST P-256/P-384 (ES256/"
        "ES384) keys; got %s (RSA is not in the SD-JWT algorithm set)."
        % key_type.value)


def badge_to_sd_jwt_claims(credential: OpenBadgeCredential) -> dict[str, Any]:
    """Map an OpenBadgeCredential to a flat SD-JWT VC claim set.

    The ``achievement`` (the badge itself) is always disclosed; the recipient's
    identity is kept under ``credentialSubject`` — both ``id`` and the hashed
    ``identifier`` entries — so it can be made selectively disclosable
    (``DEFAULT_DISCLOSABLE`` covers the whole ``credentialSubject``).
    ``iss``/``vct``/``iat`` are set by the suite at issuance.

    The credential's W3C ``credentialStatus`` is NOT mapped: this track revokes
    through the **IETF Token Status List**, a different wire format pointing at a
    different list (see :func:`issue_badge_sd_jwt`, which takes that reference as
    ``status=`` and emits it as an always-disclosed ``status`` claim). A
    credential carrying a W3C entry is still rejected at issuance rather than
    silently dropped here.
    """
    vc = credential.to_vc()
    subject = vc.get("credentialSubject", {})
    claims: dict[str, Any] = {
        "iss": credential.issuer.id,
        "name": vc.get("name"),
        "achievement": subject.get("achievement"),
        "validFrom": vc.get("validFrom"),
    }
    # Keep the recipient's identity: credentialSubject.id AND the hashed
    # identifier entries — a badge whose subject travelled via identifier (no id)
    # would otherwise end up with no checkable recipient.
    subject_claims: dict[str, Any] = {}
    recipient = subject.get("id")
    if recipient is not None:
        subject_claims["id"] = recipient
    identifier = subject.get("identifier")
    if identifier:
        subject_claims["identifier"] = identifier
    if subject_claims:
        claims["credentialSubject"] = subject_claims
    if "validUntil" in vc:
        claims["validUntil"] = vc["validUntil"]
    return claims


# ── SD-JWT VC Type Metadata (draft-ietf-oauth-sd-jwt-vc §4) ──────────────────
# A wallet/verifier resolves the Type Metadata a badge's ``vct`` points to and
# validates the badge against it — fail-closed (openvc-core >=1.2 does this).
# These build that document for the OB 3.0 badge claim set plus its
# ``vct#integrity`` SRI pin: the issuer serves ``type_metadata_document_bytes``
# at the ``vct`` URL and pins it via ``issue_badge_sd_jwt(vct_integrity=…)``.
# Pure-Python — no ``[eudi]`` extra needed to build or hash the document.


def badge_type_metadata(vct: str = OB3_SD_JWT_VCT, *, name: str = "Open Badge 3.0",
                        description: Optional[str] = None) -> dict[str, Any]:
    """Build the SD-JWT VC Type Metadata document for the OB 3.0 badge type.

    Its ``claims`` describe the payload :func:`badge_to_sd_jwt_claims` emits:
    ``name`` / ``achievement`` / ``validFrom`` are always disclosed (``mandatory``),
    the recipient ``credentialSubject`` and ``validUntil`` are optional (selective
    disclosure). ``vct`` is the type identifier a wallet resolves this from — it
    must equal the issued badge's ``vct`` (openvc-core enforces that identity
    check). Serve :func:`type_metadata_document_bytes` of this document at *vct*
    and pin it with :func:`type_metadata_integrity`.
    """
    document: dict[str, Any] = {
        "vct": vct,
        "name": name,
        "claims": [
            {"path": ["name"], "mandatory": True},
            {"path": ["achievement"], "mandatory": True},
            {"path": ["achievement", "name"], "mandatory": True},
            {"path": ["validFrom"], "mandatory": True},
            {"path": ["credentialSubject"], "sd": "allowed"},
            {"path": ["validUntil"], "sd": "allowed"},
        ],
    }
    if description is not None:
        document["description"] = description
    return document


def type_metadata_document_bytes(document: Mapping[str, Any]) -> bytes:
    """The exact UTF-8 bytes to serve for a Type Metadata *document*.

    SRI integrity is checked over the literal transferred bytes (the spec does
    no canonicalization), so the issuer MUST serve these bytes verbatim — the
    same ones :func:`type_metadata_integrity` hashes. Serialized deterministically
    (sorted keys, compact, ASCII) so the served document and its integrity pin
    cannot drift apart, and the bytes are ASCII like the other published
    artifacts.
    """
    return json.dumps(dict(document), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def type_metadata_integrity(document: Mapping[str, Any]) -> str:
    """The ``vct#integrity`` value (W3C SRI, SHA-256) for a Type Metadata
    *document*, hashed over :func:`type_metadata_document_bytes`. Pass it to
    :func:`issue_badge_sd_jwt` (``vct_integrity=``) and serve those same bytes at
    the ``vct`` URL."""
    digest = hashlib.sha256(type_metadata_document_bytes(document)).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def _status_claim(status: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize and validate an IETF Token Status List reference.

    Accepts either the wrapper ``openvc.status.issue.build_token_status_reference``
    returns (``{"status": {"status_list": {"uri": …, "idx": …}}}``) or the inner
    ``{"status_list": …}`` object, and returns the wrapper form. The reference is
    parsed by openvc-core's ``parse_token_status_ref``, so a malformed one
    (missing ``uri``/``idx``, a negative or non-integer index) is rejected **here**
    rather than producing a badge whose status can never be read.
    """
    if not isinstance(status, Mapping):
        raise EudiError(
            "status must be the mapping build_token_status_reference() returns, "
            "got %s" % type(status).__name__)
    inner = status["status"] if "status" in status else status
    if not isinstance(inner, Mapping):
        raise EudiError(
            "status.status must be a mapping, got %s" % type(inner).__name__)
    claim: dict[str, Any] = dict(inner)
    _, parse_token_status_ref = _require_openvc_status()
    try:
        ref = parse_token_status_ref({"status": claim})
    except Exception as exc:
        raise EudiError("invalid status reference: %s" % exc) from exc
    if ref is None:
        raise EudiError(
            "status carries no status_list reference; build it with "
            "openvc.status.issue.build_token_status_reference(uri=…, index=…)")
    return claim


# ── OpenID4VCI credential configuration (Credential Issuer Metadata) ─────────
# An OpenID4VCI issuer advertises what it can issue in
# ``credential_configurations_supported``, and a wallet picks one by
# ``credential_configuration_id``. The *content* of the Open Badge entry is Open
# Badges knowledge — the vct, the claim set, which claims are disclosable — so it
# is built here, from the same constants issuance uses, instead of hand-written
# once per deployment. The *document* that embeds it
# (``/.well-known/openid-credential-issuer``: credential_issuer, endpoints,
# authorization servers, per-tenant display) is deployment policy and stays the
# application's; so are the Credential Offer, the Credential Response and the
# nonce store. Pure-Python — no ``[eudi]`` extra needed.

# Human labels for the badge claim paths, so a wallet has something to show.
_CLAIM_DISPLAY_NAMES: dict[tuple[str, ...], str] = {
    ("name",): "Credential name",
    ("achievement",): "Achievement",
    ("achievement", "name"): "Achievement name",
    ("validFrom",): "Valid from",
    ("validUntil",): "Valid until",
    ("credentialSubject",): "Recipient",
}

# The only two constraints OpenID4VCI 1.0 Appendix D.2 defines inside
# ``key_attestations_required``. The *values* are deliberately extensible there
# ("ecosystems may define their own values"), so only the shape is checked here,
# never the level strings themselves.
_KEY_ATTESTATION_CONSTRAINTS = ("key_storage", "user_authentication")


def _key_attestations_required(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and copy a ``key_attestations_required`` object.

    Empty is legal and meaningful — OpenID4VCI 1.0 §12.2.4: with both
    ``key_storage`` and ``user_authentication`` absent the object indicates "a key
    attestation is needed without additional constraints". What is rejected is the
    shape a wallet cannot act on: an unknown key, an empty array where the spec
    says non-empty, or a bare string where an array belongs — that last one is
    silent otherwise, since ``list("iso_18045_moderate")`` is a list of letters.
    """
    if not isinstance(value, Mapping):
        raise EudiError(
            "key_attestations_required must be a mapping (use {} for 'required, "
            "no additional constraints'), got %s" % type(value).__name__)
    unknown = sorted(k for k in value if k not in _KEY_ATTESTATION_CONSTRAINTS)
    if unknown:
        raise EudiError(
            "unknown key_attestations_required key(s) %s; OpenID4VCI 1.0 D.2 "
            "defines only %s" % (", ".join(unknown),
                                 ", ".join(_KEY_ATTESTATION_CONSTRAINTS)))
    required: dict[str, Any] = {}
    for name in _KEY_ATTESTATION_CONSTRAINTS:
        if name not in value:
            continue
        levels = value[name]
        if isinstance(levels, (str, bytes)) or not isinstance(levels, (list, tuple)):
            raise EudiError(
                "key_attestations_required.%s must be a list of attack potential "
                "resistance values, got %s" % (name, type(levels).__name__))
        if not levels:
            raise EudiError(
                "key_attestations_required.%s must be a non-empty array; omit the "
                "key entirely to leave it unconstrained" % name)
        for level in levels:
            if not isinstance(level, str):
                raise EudiError(
                    "key_attestations_required.%s values must be strings, got %s"
                    % (name, type(level).__name__))
        required[name] = list(levels)
    return required


def badge_credential_configuration(
    *,
    vct: str = OB3_SD_JWT_VCT,
    signing_alg_values: Iterable[str] = ("ES256",),
    proof_signing_alg_values: Optional[Iterable[str]] = None,
    key_attestations_required: Optional[Mapping[str, Any]] = None,
    cryptographic_binding_methods: Iterable[str] = ("jwk",),
    display: Optional[Iterable[Mapping[str, Any]]] = None,
    scope: Optional[str] = None,
    locale: str = "en",
) -> dict[str, Any]:
    """Build the ``credential_configurations_supported`` **entry** for an Open
    Badge issued as SD-JWT VC (OpenID4VCI 1.0, Appendix A.3 — ``dc+sd-jwt``).

    Returns one configuration object: ``format``, ``vct``,
    ``credential_signing_alg_values_supported``,
    ``cryptographic_binding_methods_supported``, ``proof_types_supported``
    (``jwt``, whose ``proof_signing_alg_values_supported`` defaults to
    *signing_alg_values*), ``claims`` and ``display``, plus ``scope`` and the
    proof type's ``key_attestations_required`` when given.
    Put it in your metadata document under the ``credential_configuration_id`` you
    want wallets to request::

        {"credential_configurations_supported": {
            "openbadge_sd_jwt_vc": badge_credential_configuration()}}

    The two facts this exists to keep straight are the ones a hand-written copy
    gets wrong: the ``vct`` is the one :func:`issue_badge_sd_jwt` actually stamps,
    and the ``claims`` are exactly what :func:`badge_to_sd_jwt_claims` emits —
    both derived here from :func:`badge_type_metadata`, so the Type Metadata
    document an issuer serves and the configuration it advertises cannot drift
    apart. ``mandatory`` mirrors that document: the achievement is always
    disclosed, the recipient (``credentialSubject``) is the selectively
    disclosable one (``DEFAULT_DISCLOSABLE``).

    *display* defaults to a generic English label; an issuer with a badge in hand
    passes its own name, logo and locales. *signing_alg_values* defaults to
    ``ES256``, the algorithm HAIP pins for EUDI wallets.

    *key_attestations_required* is omitted by default, and that default is
    normative rather than conservative: OpenID4VCI 1.0 §12.2.4 says the parameter
    "MUST NOT be present in the metadata" unless the issuer requires a key
    attestation, and an **empty** object is not a neutral placeholder — it is the
    positive claim "a key attestation is needed without additional constraints".
    Emitting it unasked would have every badge issuer demand a hardware-backed
    attestation from every holder and lock out software wallets. An issuer that
    does require one passes ``{}``, or ``{"key_storage": [...],
    "user_authentication": [...]}`` with the Appendix D.2 resistance values it
    accepts; the shape is validated (:class:`EudiError`), the values are not —
    D.2 lets each ecosystem define its own.

    Two things this deliberately does NOT do. It does not build the enclosing
    ``/.well-known/openid-credential-issuer`` document — ``credential_issuer``,
    the endpoints, the authorization servers and per-tenant display are
    deployment policy, and a multi-tenant issuer has one document per tenant. And
    it does not declare the revocation ``status`` claim
    (:func:`issue_badge_sd_jwt`'s ``status=``): it is machine-read, never
    displayed, and declaring it would also change the Type Metadata document's
    bytes and therefore every already-published ``vct#integrity`` pin.

    Note on layout: OpenID4VCI 1.0 Final carries ``claims`` and ``display`` at
    the top level of the configuration, which is what this emits. The EU
    reference issuer has moved them under a ``credential_metadata`` object; if
    you must match that deployment, nest them yourself — it is a pure dict.
    """
    algs = list(signing_alg_values)
    proof_algs = list(proof_signing_alg_values) if proof_signing_alg_values is not None else algs
    proof_jwt: dict[str, Any] = {"proof_signing_alg_values_supported": proof_algs}
    if key_attestations_required is not None:
        proof_jwt["key_attestations_required"] = _key_attestations_required(
            key_attestations_required)
    claims: list[dict[str, Any]] = []
    for claim in badge_type_metadata(vct)["claims"]:
        path = list(claim["path"])
        entry: dict[str, Any] = {
            "path": path,
            "mandatory": bool(claim.get("mandatory", False)),
        }
        label = _CLAIM_DISPLAY_NAMES.get(tuple(path))
        if label is not None:
            entry["display"] = [{"name": label, "locale": locale}]
        claims.append(entry)
    configuration: dict[str, Any] = {
        "format": OB3_SD_JWT_FORMAT,
        "vct": vct,
        "credential_signing_alg_values_supported": algs,
        "cryptographic_binding_methods_supported": list(cryptographic_binding_methods),
        "proof_types_supported": {"jwt": proof_jwt},
        "claims": claims,
        "display": ([dict(d) for d in display] if display is not None
                    else [{"name": "Open Badge 3.0", "locale": locale}]),
    }
    if scope is not None:
        configuration["scope"] = scope
    return configuration


def issue_badge_sd_jwt(
    credential: OpenBadgeCredential,
    *,
    privkey_pem: Any,
    kid: Optional[str] = None,
    disclosable: Iterable[str] = DEFAULT_DISCLOSABLE,
    holder_jwk: Optional[dict[str, Any]] = None,
    expires_in_s: Optional[int] = None,
    vct: str = OB3_SD_JWT_VCT,
    vct_integrity: Optional[str] = None,
    x5c: Optional[Iterable[str]] = None,
    status: Optional[Mapping[str, Any]] = None,
) -> str:
    """Issue *credential* as an SD-JWT VC.

    Returns the compact SD-JWT (``<issuer-jwt>~<disclosure>~…``). Only claims in
    *disclosable* that are actually present are made selectively disclosable.
    Pass *holder_jwk* to bind the credential to a holder key (``cnf``) for a later
    Key-Binding presentation. Ed25519, P-256 or P-384 keys only.

    Pass *vct_integrity* (from :func:`type_metadata_integrity`) to embed a
    ``vct#integrity`` claim that pins the Type Metadata served at *vct*, so a
    wallet resolving it fails closed on any tampering — always disclosed,
    alongside ``vct``.

    Pass *x5c* — an X.509 certificate chain (base64 DER, leaf first) — to anchor
    the issuer in the issuer JWT header, so a verifier validates the badge in one
    call via ``verify_badge_sd_jwt(token, x5c_trust_anchors=[…])`` (eIDAS / EU
    Trusted List trust). The leaf's key must be *privkey_pem* and the issuer id
    must be in the leaf SAN, or verification fails closed. Needs openvc-core
    >=1.18. This closes the loop with the verify-side x5c support (#178).

    REVOCATION: pass *status* — the reference
    ``openvc.status.issue.build_token_status_reference(uri=…, index=…)`` builds —
    to make the badge revocable through an **IETF Token Status List** (the JOSE
    status format of the SD-JWT VC track). It is emitted as a ``status`` claim
    that is **always disclosed**, never selectively disclosable: a holder able to
    withhold the pointer could present a revoked badge as an unrevokable one,
    which is worse than no status at all. Publish the list as a status-list token
    (``openvc.status.issue.build_status_list_token``) at that ``uri`` and flip the
    badge's bit to revoke it; the verifier side is
    ``verify_badge_sd_jwt(..., resolve_status_list_token=…)``.

    Two status formats, two lists — the boundary an issuer must know before
    allocating indices: the W3C **Bitstring** Status List (the JWT-VC / Data
    Integrity tracks) and the IETF **Token** Status List (this one) differ in bit
    order and compression, so a badge issued on both tracks needs *two* status
    entries pointing at *two* lists, not one list read two ways. Accordingly a
    credential carrying a W3C ``credentialStatus`` is still refused here (#226's
    reasoning does not expire): its Bitstring entry cannot be honoured by an
    SD-JWT verifier, and silently dropping it would issue a badge the issuer
    believes is revocable. Issue the wallet copy from a credential without one
    (``dataclasses.replace(cred, credential_status=[])``) and give it its own
    index in the status-list token.
    """
    if credential.credential_status:
        raise EudiError(
            "this credential carries a W3C credentialStatus (Bitstring Status "
            "List), which an SD-JWT VC verifier cannot honour: the SD-JWT VC "
            "track revokes through the IETF Token Status List, a different wire "
            "format pointing at a different list. Refusing to silently drop it — "
            "issue this copy from a credential without credentialStatus and pass "
            "status=build_token_status_reference(uri=…, index=…) with its own "
            "index in the status-list token.")
    status_claim = _status_claim(status) if status is not None else None
    _, _, _, SdJwtVcProofSuite = _require_openvc()
    signing_key = _signing_key(privkey_pem, kid or ("%s#key-1" % credential.issuer.id))
    claims = badge_to_sd_jwt_claims(credential)
    if vct_integrity is not None:
        claims["vct#integrity"] = vct_integrity
    if status_claim is not None:
        claims["status"] = status_claim
    # "status" is never made selectively disclosable, whatever the caller passed
    # in *disclosable* — see the docstring.
    present = [name for name in disclosable if name in claims and name != "status"]
    try:
        return cast(str, SdJwtVcProofSuite().issue(
            claims, signing_key=signing_key, disclosable=present, vct=vct,
            holder_jwk=holder_jwk, expires_in_s=expires_in_s, x5c=x5c))
    except EudiError:
        raise
    except Exception as exc:
        raise EudiError("could not issue SD-JWT VC badge: %s" % exc) from exc


def status_list_token_resolver(
    *,
    pubkey_pem: Union[str, bytes],
    download: Optional[Callable[[str], bytes]] = None,
    leeway_s: int = 60,
) -> Callable[[str], dict[str, Any]]:
    """Build the ``resolve_status_list_token`` callable :func:`verify_badge_sd_jwt`
    takes: fetch the status-list token at a URI and **verify** it with
    *pubkey_pem* before its bits are read.

    The verification is openvc-core's ``verify_status_list_token`` — algorithm
    allow-list, ``typ: statuslist+jwt``, signature, ``exp`` — plus the IETF
    anti-swap check that the token's ``sub`` equals the URI it was fetched from,
    which this passes for you: without it a status list served at one URL could
    be replayed at another to un-revoke a badge. *download* defaults to
    :func:`openbadgeslib.util.download_file` (HTTPS-only, SSRF-guarded,
    size-capped) and is injectable for testing or for a private deployment.

    A resolver is deliberately caller-supplied rather than implicit: the key that
    signs the status list is a trust decision (typically the badge issuer's own
    key, as ``openbadges-publish`` does for the Bitstring track). Writing your
    own is fine — it must return the verified token's claims dict.
    """
    fetch = download if download is not None else download_file

    def resolve(uri: str) -> dict[str, Any]:
        try:
            from openvc.status.issue import verify_status_list_token
        except ImportError as exc:
            raise EudiError(_INSTALL_HINT) from exc
        raw = fetch(uri)
        token = (raw.decode("ascii").strip() if isinstance(raw, bytes)
                 else str(raw).strip())
        claims: dict[str, Any] = verify_status_list_token(
            token, public_key_jwk=public_jwk_from_pem(pubkey_pem),
            expected_uri=uri, leeway_s=leeway_s)
        return claims

    return resolve


def _check_sd_jwt_status(claims: Mapping[str, Any], *, require_status: bool,
                         resolve_status_list_token: Any) -> Any:
    """Check the IETF ``status`` reference on a verified badge's claims.

    Mirrors what openvc-core's ``verify_credential`` does for the x5c path, for
    the pinned-key path (whose suite-level verify has no status stage): resolve
    the status-list token and raise :class:`EudiError` if this badge's bit says
    revoked or suspended. Returns openvc-core's ``TokenStatusResult`` (or None
    when the badge declares no status).

    Fail-closed: a declared status with no resolver raises when *require_status*
    is set, and any resolve/decode failure raises whenever a resolver is given —
    an unreadable list is never read as "not revoked".
    """
    check_token_status, parse_token_status_ref = _require_openvc_status()
    try:
        ref = parse_token_status_ref(dict(claims))
    except Exception as exc:                          # malformed reference
        raise EudiError("badge carries a malformed status reference: %s" % exc) from exc
    if ref is None:
        # A `status` claim of an unrecognised shape is not "no status": treat it
        # like the delegate does and fail closed when status is required.
        if require_status and claims.get("status") is not None:
            raise EudiError(
                "badge declares a status of an unrecognised shape and it cannot "
                "be checked (pass require_status=False to skip)")
        if require_status and claims.get("credentialStatus") is not None:
            raise EudiError(
                "badge declares a W3C credentialStatus, which this track does "
                "not check: SD-JWT VC status is the IETF Token Status List "
                "(pass require_status=False to skip)")
        return None
    if resolve_status_list_token is None:
        if require_status:
            raise EudiError(
                "badge declares a revocation status (%s) but no "
                "resolve_status_list_token was supplied to check it" % ref.uri)
        return None
    try:
        result = check_token_status(
            dict(claims), resolve_status_list_token=resolve_status_list_token)
    except EudiError:
        raise
    except Exception as exc:
        raise EudiError(
            "could not check the badge's revocation status at %s: %s"
            % (ref.uri, exc)) from exc
    if result is not None and result.revoked:
        raise EudiError("badge is revoked (status list %s, index %d)"
                        % (result.ref.uri, result.ref.index))
    if result is not None and result.suspended:
        raise EudiError("badge is suspended (status list %s, index %d)"
                        % (result.ref.uri, result.ref.index))
    return result


def verify_badge_sd_jwt(
    token: str,
    *,
    pubkey_pem: Any = None,
    audience: Optional[str] = None,
    nonce: Optional[str] = None,
    require_key_binding: bool = False,
    expected_vct: Optional[str] = OB3_SD_JWT_VCT,
    x5c_trust_anchors: Any = None,
    require_status: bool = False,
    resolve_status_list_token: Any = None,
) -> Any:
    """Verify a badge SD-JWT VC (issuer form or a holder presentation).

    Returns openvc-core's ``VerifiedSdJwt`` (``.claims``, ``.issuer``, ``.vct``,
    ``.key_bound``, ``.confirmation``). Raises :class:`EudiError` on any failure.
    Pass *audience*/*nonce* (and ``require_key_binding=True``) to check a Key
    Binding JWT from a holder presentation.

    Revocation (IETF Token Status List) is checked when you supply
    *resolve_status_list_token* — the callable
    :func:`status_list_token_resolver` builds, or your own ``uri -> claims``
    fetch-and-verify. A badge whose bit says revoked or suspended raises
    :class:`EudiError`, on both trust paths. Without a resolver the status is not
    checked and a badge that declares one still verifies, unless you also pass
    ``require_status=True``, which turns an uncheckable status into a failure
    (fail-closed, and the same knob name and meaning as the delegate's
    ``VerificationPolicy.require_status``). A badge that declares no status is
    unaffected by either flag: it verifies, and it is simply not revocable
    (:func:`issue_badge_sd_jwt` without ``status=``).

    Trust comes from exactly one of two sources:

    * *pubkey_pem* — pin the issuer's public key (the default; right for a known
      issuer whose key you already hold).
    * *x5c_trust_anchors* — a sequence of trusted X.509 root ``Certificate``
      objects (e.g. an EU Trusted List's ``TrustAnchorSet.certificates`` from
      ``openvc.trustlist``). Opts into eIDAS **X.509 issuer trust**: a received
      third-party badge whose issuer JWT carries an ``x5c`` chain is
      path-validated to those anchors and bound to ``iss`` before its leaf key
      is used — routed through openvc-core's ``verify_credential`` pipeline (the
      JWK-pin suite path cannot do X.509 trust). A token that carries no ``x5c``
      chain is rejected in this mode: the anchors are never bypassed by falling
      back to DID / issuer-URL key resolution. Credential status is checked the
      same way as on the pinned path — here by the delegate itself, which is
      handed the same *require_status* / *resolve_status_list_token*.

    X.509 / eIDAS trust boundary — division of responsibility
    ---------------------------------------------------------
    In the *x5c_trust_anchors* mode the X.509 trust decision is **delegated to
    openvc-core** (which builds on ``cryptography``'s ``PolicyBuilder``). This
    library only guarantees the *envelope*; the chain verdict is not re-asserted
    here. Concretely:

    * **openbadgeslib guarantees**: the issuer JWT actually carries an ``x5c``
      header before delegating (:func:`_issuer_jwt_has_x5c`), so the anchors can
      never be silently bypassed by a DID / issuer-URL fallback (fail-closed);
      and it surfaces any openvc-core failure as :class:`EudiError`.
    * **openvc-core guarantees** (asserted by the boundary tests in
      ``tests/test_ob3_eudi_x5c.py`` against both the pinned and latest release):
      chain path-validation — signatures, the leaf/intermediate **temporal
      validity windows** (an expired or not-yet-valid leaf is rejected), name
      chaining, ``basicConstraints`` — the leaf ``SAN`` ↔ ``iss`` binding, and a
      P-256 leaf key.
    * **NOT checked by either** — certificate **revocation (CRL / OCSP)**.
      ``cryptography``'s path validation does not consult CRL Distribution Points
      or OCSP, so a leaf that is revoked but still inside its validity window,
      with an otherwise-valid chain, **will verify**. A deployment that must
      honour revocation has to obtain it out of band (e.g. the EU Trusted List's
      own revocation signalling) — do not assume this call applies it. This gap
      is pinned by a regression test so a future openvc-core that adds revocation
      is caught by the floor/latest drift job (#236).
    """
    if x5c_trust_anchors is not None:
        return _verify_sd_jwt_x5c(
            token, x5c_trust_anchors, expected_vct=expected_vct,
            audience=audience, nonce=nonce,
            require_key_binding=require_key_binding,
            require_status=require_status,
            resolve_status_list_token=resolve_status_list_token)
    if pubkey_pem is None:
        raise EudiError(
            "verify_badge_sd_jwt needs either pubkey_pem (pin the issuer's key) "
            "or x5c_trust_anchors (eIDAS X.509 / EU Trusted List trust)")
    _, _, _, SdJwtVcProofSuite = _require_openvc()
    try:
        public_key_jwk = public_jwk_from_pem(pubkey_pem)
        verified = SdJwtVcProofSuite().verify(
            token, public_key_jwk=public_key_jwk, audience=audience, nonce=nonce,
            require_key_binding=require_key_binding, expected_vct=expected_vct)
    except EudiError:
        raise
    except Exception as exc:
        raise EudiError("SD-JWT VC badge verification failed: %s" % exc) from exc
    # The suite verifies the signature and the disclosures but has no status
    # stage (the delegate does status one layer up, in verify_credential — which
    # is the x5c path). Check it here so both paths honour the same seam.
    _check_sd_jwt_status(verified.claims, require_status=require_status,
                         resolve_status_list_token=resolve_status_list_token)
    return verified


def _issuer_jwt_has_x5c(token: str) -> bool:
    """True if the SD-JWT's issuer JWT carries a non-empty ``x5c`` header.

    The issuer JWT is the segment before the first ``~``; its JOSE header is the
    first ``.``-separated part, base64url-encoded JSON. A parse failure fails
    closed (raises :class:`EudiError`), since we then cannot confirm an ``x5c``.
    """
    header_b64 = token.split("~", 1)[0].split(".", 1)[0]
    try:
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError) as exc:
        raise EudiError(
            "could not parse the SD-JWT issuer JWT header: %s" % exc) from exc
    return bool(isinstance(header, dict) and header.get("x5c"))


def _verify_sd_jwt_x5c(token: str, x5c_trust_anchors: Any, *,
                       expected_vct: Optional[str], audience: Optional[str],
                       nonce: Optional[str], require_key_binding: bool,
                       require_status: bool = False,
                       resolve_status_list_token: Any = None) -> Any:
    """Verify a badge SD-JWT whose issuer JWT carries an ``x5c`` chain against
    *x5c_trust_anchors* (X.509 roots), via openvc-core's ``verify_credential``
    pipeline — which path-validates the chain and binds it to ``iss`` before
    using the leaf key. Returns the underlying ``VerifiedSdJwt``.

    See :func:`verify_badge_sd_jwt` for the trust-boundary contract: openvc-core
    owns the chain verdict (temporal validity, name chaining, SAN↔iss binding);
    certificate revocation (CRL/OCSP) is NOT checked by either layer (#236).

    *Credential* status (the badge's own IETF Token Status List reference, which
    is a different thing from certificate revocation) is checked by the delegate
    on this path: the policy carries *require_status* and the resolver is passed
    straight through, so a revoked badge raises ``CredentialRevoked`` inside
    openvc-core and surfaces here as :class:`EudiError`."""
    try:
        from openvc import VerificationPolicy, verify_credential
    except ImportError as exc:
        raise EudiError(_INSTALL_HINT) from exc
    # X.509 trust MUST anchor to the chain in the issuer JWT's x5c header.
    # openvc-core silently falls back to DID / issuer-URL key resolution when the
    # token carries no x5c, which would bypass x5c_trust_anchors entirely (a
    # did:jwk / did:key issuer is self-certifying: it merely asserts its own
    # key). Refuse that fallback here — fail closed.
    if not _issuer_jwt_has_x5c(token):
        raise EudiError(
            "x5c_trust_anchors was supplied but the badge's issuer JWT carries "
            "no x5c certificate chain; refusing to fall back to DID/issuer-URL "
            "key resolution, which would bypass the X.509 trust anchors")
    policy = VerificationPolicy(
        expected_vct=expected_vct, audience=audience, nonce=nonce,
        require_key_binding=require_key_binding, require_status=require_status)
    try:
        result = verify_credential(
            token, policy=policy, x5c_trust_anchors=x5c_trust_anchors,
            resolve_status_list_token=resolve_status_list_token)
    except EudiError:
        raise
    except Exception as exc:
        raise EudiError(
            "SD-JWT VC badge verification against the X.509 trust anchors "
            "failed: %s" % exc) from exc
    return result.raw
