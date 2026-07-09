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

import base64
import hashlib
import json

from typing import Any, Iterable, Mapping, Optional, cast

from .credential import OpenBadgeCredential
from ..errors import LibOpenBadgesException
from ..keys import (
    KeyType, detect_key_type, ec_curve_from_pem, public_jwk_from_pem)

# A vct (Verifiable Credential Type) for Open Badges expressed as SD-JWT VC.
OB3_SD_JWT_VCT = "https://purl.imsglobal.org/spec/ob/v3p0#OpenBadgeCredential"

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
    identity is kept under ``credentialSubject`` so it can be made selectively
    disclosable (``DEFAULT_DISCLOSABLE``). ``iss``/``vct``/``iat`` are set by the
    suite at issuance.
    """
    vc = credential.to_vc()
    subject = vc.get("credentialSubject", {})
    claims: dict[str, Any] = {
        "iss": credential.issuer.id,
        "name": vc.get("name"),
        "achievement": subject.get("achievement"),
        "validFrom": vc.get("validFrom"),
    }
    recipient = subject.get("id")
    if recipient is not None:
        claims["credentialSubject"] = {"id": recipient}
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
    """
    _, _, _, SdJwtVcProofSuite = _require_openvc()
    signing_key = _signing_key(privkey_pem, kid or ("%s#key-1" % credential.issuer.id))
    claims = badge_to_sd_jwt_claims(credential)
    if vct_integrity is not None:
        claims["vct#integrity"] = vct_integrity
    present = [name for name in disclosable if name in claims]
    try:
        return cast(str, SdJwtVcProofSuite().issue(
            claims, signing_key=signing_key, disclosable=present, vct=vct,
            holder_jwk=holder_jwk, expires_in_s=expires_in_s))
    except EudiError:
        raise
    except Exception as exc:
        raise EudiError("could not issue SD-JWT VC badge: %s" % exc) from exc


def verify_badge_sd_jwt(
    token: str,
    *,
    pubkey_pem: Any = None,
    audience: Optional[str] = None,
    nonce: Optional[str] = None,
    require_key_binding: bool = False,
    expected_vct: Optional[str] = OB3_SD_JWT_VCT,
    x5c_trust_anchors: Any = None,
) -> Any:
    """Verify a badge SD-JWT VC (issuer form or a holder presentation).

    Returns openvc-core's ``VerifiedSdJwt`` (``.claims``, ``.issuer``, ``.vct``,
    ``.key_bound``, ``.confirmation``). Raises :class:`EudiError` on any failure.
    Pass *audience*/*nonce* (and ``require_key_binding=True``) to check a Key
    Binding JWT from a holder presentation.

    Trust comes from exactly one of two sources:

    * *pubkey_pem* — pin the issuer's public key (the default; right for a known
      issuer whose key you already hold).
    * *x5c_trust_anchors* — a sequence of trusted X.509 root ``Certificate``
      objects (e.g. an EU Trusted List's ``TrustAnchorSet.certificates`` from
      ``openvc.trustlist``). Opts into eIDAS **X.509 issuer trust**: a received
      third-party badge whose issuer JWT carries an ``x5c`` chain is
      path-validated to those anchors and bound to ``iss`` before its leaf key
      is used — routed through openvc-core's ``verify_credential`` pipeline (the
      JWK-pin suite path cannot do X.509 trust). Status is not checked here, as
      with the pinned path.
    """
    if x5c_trust_anchors is not None:
        return _verify_sd_jwt_x5c(
            token, x5c_trust_anchors, expected_vct=expected_vct,
            audience=audience, nonce=nonce,
            require_key_binding=require_key_binding)
    if pubkey_pem is None:
        raise EudiError(
            "verify_badge_sd_jwt needs either pubkey_pem (pin the issuer's key) "
            "or x5c_trust_anchors (eIDAS X.509 / EU Trusted List trust)")
    _, _, _, SdJwtVcProofSuite = _require_openvc()
    try:
        public_key_jwk = public_jwk_from_pem(pubkey_pem)
        return SdJwtVcProofSuite().verify(
            token, public_key_jwk=public_key_jwk, audience=audience, nonce=nonce,
            require_key_binding=require_key_binding, expected_vct=expected_vct)
    except EudiError:
        raise
    except Exception as exc:
        raise EudiError("SD-JWT VC badge verification failed: %s" % exc) from exc


def _verify_sd_jwt_x5c(token: str, x5c_trust_anchors: Any, *,
                       expected_vct: Optional[str], audience: Optional[str],
                       nonce: Optional[str], require_key_binding: bool) -> Any:
    """Verify a badge SD-JWT whose issuer JWT carries an ``x5c`` chain against
    *x5c_trust_anchors* (X.509 roots), via openvc-core's ``verify_credential``
    pipeline — which path-validates the chain and binds it to ``iss`` before
    using the leaf key. Returns the underlying ``VerifiedSdJwt``."""
    try:
        from openvc import VerificationPolicy, verify_credential
    except ImportError as exc:
        raise EudiError(_INSTALL_HINT) from exc
    policy = VerificationPolicy(
        expected_vct=expected_vct, audience=audience, nonce=nonce,
        require_key_binding=require_key_binding, require_status=False)
    try:
        result = verify_credential(
            token, policy=policy, x5c_trust_anchors=x5c_trust_anchors)
    except EudiError:
        raise
    except Exception as exc:
        raise EudiError(
            "SD-JWT VC badge verification against the X.509 trust anchors "
            "failed: %s" % exc) from exc
    return result.raw
