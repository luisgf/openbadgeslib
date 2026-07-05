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
# which pulls ``openvc-core``. SD-JWT allows only Ed25519 (EdDSA) and NIST P-256
# (ES256) keys — RSA is not in its algorithm set.

from typing import Any, Iterable, Optional

from .credential import OpenBadgeCredential
from ..errors import LibOpenBadgesException
from ..keys import KeyType, detect_key_type, public_jwk_from_pem

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
        from openvc.keys import Ed25519SigningKey, P256SigningKey
        from openvc.proof.sd_jwt import SdJwtVcProofSuite
    except ImportError as exc:
        raise EudiError(_INSTALL_HINT) from exc
    return Ed25519SigningKey, P256SigningKey, SdJwtVcProofSuite


def _signing_key(privkey_pem: Any, kid: str) -> Any:
    """Build the openvc SigningKey matching the PEM's key type (Ed25519 / P-256)."""
    Ed25519SigningKey, P256SigningKey, _ = _require_openvc()
    key_type = detect_key_type(privkey_pem)
    if key_type is KeyType.ED25519:
        return Ed25519SigningKey.from_pem(privkey_pem, kid=kid)
    if key_type is KeyType.ECC:                       # NIST P-256 -> ES256
        return P256SigningKey.from_pem(privkey_pem, kid=kid)
    raise EudiError(
        "SD-JWT VC allows only Ed25519 (EdDSA) or NIST P-256 (ES256) keys; got "
        "%s (RSA is not in the SD-JWT algorithm set)." % key_type.value)


def badge_to_sd_jwt_claims(credential: OpenBadgeCredential) -> dict:
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


def issue_badge_sd_jwt(
    credential: OpenBadgeCredential,
    *,
    privkey_pem: Any,
    kid: Optional[str] = None,
    disclosable: Iterable[str] = DEFAULT_DISCLOSABLE,
    holder_jwk: Optional[dict] = None,
    expires_in_s: Optional[int] = None,
    vct: str = OB3_SD_JWT_VCT,
) -> str:
    """Issue *credential* as an SD-JWT VC.

    Returns the compact SD-JWT (``<issuer-jwt>~<disclosure>~…``). Only claims in
    *disclosable* that are actually present are made selectively disclosable.
    Pass *holder_jwk* to bind the credential to a holder key (``cnf``) for a later
    Key-Binding presentation. Ed25519 / P-256 keys only.
    """
    _, _, SdJwtVcProofSuite = _require_openvc()
    signing_key = _signing_key(privkey_pem, kid or ("%s#key-1" % credential.issuer.id))
    claims = badge_to_sd_jwt_claims(credential)
    present = [name for name in disclosable if name in claims]
    try:
        return SdJwtVcProofSuite().issue(
            claims, signing_key=signing_key, disclosable=present, vct=vct,
            holder_jwk=holder_jwk, expires_in_s=expires_in_s)
    except EudiError:
        raise
    except Exception as exc:
        raise EudiError("could not issue SD-JWT VC badge: %s" % exc) from exc


def verify_badge_sd_jwt(
    token: str,
    *,
    pubkey_pem: Any,
    audience: Optional[str] = None,
    nonce: Optional[str] = None,
    require_key_binding: bool = False,
    expected_vct: Optional[str] = OB3_SD_JWT_VCT,
) -> Any:
    """Verify a badge SD-JWT VC (issuer form or a holder presentation).

    Returns openvc-core's ``VerifiedSdJwt`` (``.claims``, ``.issuer``, ``.vct``,
    ``.key_bound``, ``.confirmation``). Raises :class:`EudiError` on any failure.
    Pass *audience*/*nonce* (and ``require_key_binding=True``) to check a Key
    Binding JWT from a holder presentation.
    """
    _, _, SdJwtVcProofSuite = _require_openvc()
    try:
        public_key_jwk = public_jwk_from_pem(pubkey_pem)
        return SdJwtVcProofSuite().verify(
            token, public_key_jwk=public_key_jwk, audience=audience, nonce=nonce,
            require_key_binding=require_key_binding, expected_vct=expected_vct)
    except EudiError:
        raise
    except Exception as exc:
        raise EudiError("SD-JWT VC badge verification failed: %s" % exc) from exc
