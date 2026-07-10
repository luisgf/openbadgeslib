"""
        OpenBadges Library

        Copyright (c) 2014-2026, Luis González Fernández, luisgf@luisgf.es

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

# Reusable verification orchestration, extracted from the CLI.
#
# openbadges-verifier used to hold the real verification logic — extracting the
# baked token, auto-detecting the JWT-VC vs Data Integrity format, reading the
# issuer DID from the untrusted credential, classifying trust (a did:web is
# anchored on DNS+TLS; a did:key / badge-embedded key is only self-asserted),
# selecting and constructing the verifier — interleaved with prints and
# sys.exit. That made "verify this badge for this recipient" impossible to call
# as a library without copying the CLI.
#
# verify_badge performs that orchestration and returns a VerifyResult (the
# verdict, the trust classification and the decoded object), doing NO
# user-facing I/O: no prints and no sys.exit. A badge that fails to verify is a
# VerifyResult with valid=False and a reason, NOT an exception — an invalid
# signature is a normal, expected outcome a caller inspects. Only genuine
# misuse (an unsupported ob_version) raises.
#
# OpenBadges 1.0 verification stays in the CLI: it is a legacy version whose
# reader takes a file path, mirroring OB 1.0 issuance staying on the CLI.

from dataclasses import dataclass, field
from typing import Any, List, Optional, Union

_PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'


@dataclass
class VerifyResult:
    """The outcome of verifying one badge, with no I/O performed.

    ``valid`` is signature/structure validity; ``trusted`` additionally says
    the issuer was anchored to an operator-supplied key or a did:web (DNS+TLS),
    as opposed to a self-asserted did:key or badge-embedded key that only proves
    internal consistency. A caller gating on issuer identity must require both
    ``valid`` and ``trusted`` — this is the split the CLI turns into exit codes
    0 (valid+trusted) / 2 (valid+untrusted) / 1 (invalid).

    ``credential`` (OB3 :class:`~openbadgeslib.ob3.OpenBadgeCredential`) or
    ``assertion`` (OB2 Assertion) carries the decoded object on success, so a
    caller reads issuer/achievement/dates/… from it without re-parsing.
    ``notices`` holds non-fatal hints (e.g. the self-asserted-key caveat).
    """

    ob_version: str
    valid: bool
    trusted: bool
    reason: Optional[str] = None
    recipient: Optional[str] = None
    proof_format: Optional[str] = None      # OB3: 'vc-jwt' | 'ldp'
    issuer_did: Optional[str] = None        # OB3: DID resolved from the credential
    credential: Optional[Any] = None        # OB3 OpenBadgeCredential
    assertion: Optional[Any] = None         # OB2 Assertion
    notices: List[str] = field(default_factory=list)


def verify_badge(data: bytes, ob_version: str = '3', *,
                 pubkey_pem: Optional[Union[str, bytes]] = None,
                 resolve_did: bool = False,
                 expected_recipient: Optional[str] = None,
                 check_status: bool = False,
                 verify_status_list: bool = True,
                 download: Any = None,
                 image_format: Optional[str] = None) -> VerifyResult:
    """Verify a baked badge image and return a :class:`VerifyResult`.

    ``data`` is the raw SVG/PNG bytes (the format is auto-detected from the
    content; override with ``image_format='svg'|'png'``). ``ob_version`` is
    ``'2'`` or ``'3'`` — OpenBadges 1.0 is verified through the CLI only.

    Trust anchoring (OB3): pass ``pubkey_pem`` to verify against an
    operator-trusted key (``trusted=True``), or ``resolve_did=True`` to resolve
    the issuer DID read from the credential — a did:web stays trusted, a did:key
    is self-asserted (``trusted=False``). With neither, the result is
    ``valid=False`` with a reason. ``expected_recipient`` binds the credential
    to a recipient; ``check_status`` / ``verify_status_list`` / ``download``
    behave as on :meth:`~openbadgeslib.ob3.OB3Verifier.verify` (OB3 only).

    For OB2, ``pubkey_pem`` verifies a SignedBadge against a trusted key; a
    HostedBadge is anchored by its scope-checked HTTPS retrieval. Returns a
    :class:`VerifyResult`; raises ``ValueError`` only for an unsupported
    ``ob_version``.
    """
    if ob_version == '3':
        return _verify_ob3(data, pubkey_pem, resolve_did, expected_recipient,
                           check_status, verify_status_list, download,
                           image_format)
    if ob_version == '2':
        return _verify_ob2(data, pubkey_pem, expected_recipient, image_format)
    raise ValueError(
        "verify_badge supports OpenBadges 2.0 and 3.0; OpenBadges 1.0 (-V 1) "
        "is a legacy version, verified through the CLI only")


def _detect_image_format(data: bytes, image_format: Optional[str]) -> Optional[str]:
    """Return 'png', 'svg' or None, from an explicit hint or the byte content."""
    if image_format is not None:
        fmt = image_format.lower().lstrip('.')
        return fmt if fmt in ('png', 'svg') else None
    if data[:8] == _PNG_SIGNATURE:
        return 'png'
    if data[:512].lstrip()[:1] == b'<':      # XML/SVG document
        return 'svg'
    return None


def issuer_did_from_token(token: str) -> str:
    """Read the issuer DID from an unverified JWT-VC (``iss``, or ``vc.issuer.id``).

    Only for anchoring trust with ``resolve_did``: the DID is read from the
    UNTRUSTED token, resolved to a key, and the signature is then checked
    against that key (did:key is self-certifying; did:web trusts DNS+TLS).
    Raises :class:`~openbadgeslib.ob3.OB3VerificationError` if there is no DID."""
    import jwt
    from .ob3 import OB3VerificationError
    try:
        payload = jwt.decode(token, options={'verify_signature': False})
    except jwt.exceptions.PyJWTError as exc:
        raise OB3VerificationError('could not read token issuer: %s' % exc) from exc
    iss = payload.get('iss')
    if not iss:
        vc = payload.get('vc')
        if not isinstance(vc, dict):
            vc = {}
        issuer = vc.get('issuer')
        iss = issuer.get('id') if isinstance(issuer, dict) else issuer
    if not isinstance(iss, str) or not iss.startswith('did:'):
        raise OB3VerificationError('token issuer is not a DID: %r' % (iss,))
    return iss


def issuer_did_from_document(document: str) -> str:
    """Read the issuer DID from an unverified Data Integrity credential — the
    LDP counterpart of :func:`issuer_did_from_token`, same trust caveat."""
    import json
    from .ob3 import OB3VerificationError
    try:
        doc = json.loads(document)
    except ValueError as exc:
        raise OB3VerificationError(
            'could not read credential issuer: %s' % exc) from exc
    issuer = doc.get('issuer') if isinstance(doc, dict) else None
    iss = issuer.get('id') if isinstance(issuer, dict) else issuer
    if not isinstance(iss, str) or not iss.startswith('did:'):
        raise OB3VerificationError('credential issuer is not a DID: %r' % (iss,))
    return iss


def _verify_ob2(data: bytes, pubkey_pem: Optional[Union[str, bytes]],
                expected_recipient: Optional[str],
                image_format: Optional[str]) -> VerifyResult:
    """Verify strict OpenBadges 2.0 (SignedBadge JWS or HostedBadge)."""
    from .ob2 import OB2Verifier, OB2VerificationError
    from .errors import ErrorParsingFile

    fmt = _detect_image_format(data, image_format)
    try:
        if fmt == 'svg':
            token = OB2Verifier.extract_token_from_svg(data)
        elif fmt == 'png':
            token = OB2Verifier.extract_token_from_png(data)
        else:
            return VerifyResult(
                ob_version='2', valid=False, trusted=False,
                recipient=expected_recipient,
                reason='Unsupported file format for OB2 verification '
                       '(use .svg or .png)')
    except (OB2VerificationError, ErrorParsingFile) as exc:
        return VerifyResult(
            ob_version='2', valid=False, trusted=False,
            recipient=expected_recipient,
            reason='Could not extract OB2 token: %s' % exc)

    # check_revocation=True mirrors the CLI pipeline; a HostedBadge additionally
    # fetches its id and issuer to anchor trust.
    verifier = OB2Verifier(pubkey_pem=pubkey_pem)
    try:
        assertion = verifier.verify(token, expected_recipient=expected_recipient,
                                    check_revocation=True)
    except OB2VerificationError as exc:
        return VerifyResult(
            ob_version='2', valid=False, trusted=False,
            recipient=expected_recipient,
            reason='OB2 verification failed: %s' % exc)

    verification_type = assertion.verification.type
    # A HostedBadge is anchored by the (scope-checked) HTTPS retrieval of its id;
    # a SignedBadge is trusted only when the operator supplied the key.
    trusted = True if verification_type == 'HostedBadge' else (pubkey_pem is not None)
    reason = None if trusted else (
        'signature is internally consistent but verified against the '
        'badge-declared key, not a trusted issuer key')
    return VerifyResult(
        ob_version='2', valid=True, trusted=trusted,
        recipient=expected_recipient, reason=reason, assertion=assertion)


def _verify_ob3(data: bytes, pubkey_pem: Optional[Union[str, bytes]],
                resolve_did: bool, expected_recipient: Optional[str],
                check_status: bool, verify_status_list: bool, download: Any,
                image_format: Optional[str]) -> VerifyResult:
    """Verify OpenBadges 3.0 (JWT-VC or Data Integrity)."""
    from .ob3 import OB3LdpVerifier, OB3VerificationError, OB3Verifier
    from .errors import ErrorParsingFile

    if pubkey_pem is None and not resolve_did:
        return VerifyResult(
            ob_version='3', valid=False, trusted=False,
            recipient=expected_recipient,
            reason='OB3 verification requires a trusted key (pubkey_pem) or '
                   'resolve_did=True')

    fmt = _detect_image_format(data, image_format)
    try:
        if fmt == 'svg':
            token = OB3Verifier.extract_token_from_svg(data)
        elif fmt == 'png':
            token = OB3Verifier.extract_token_from_png(data)
        else:
            return VerifyResult(
                ob_version='3', valid=False, trusted=False,
                recipient=expected_recipient,
                reason='Unsupported file format for OB3 verification '
                       '(use .svg or .png)')
    except (OB3VerificationError, ErrorParsingFile) as exc:
        return VerifyResult(
            ob_version='3', valid=False, trusted=False,
            recipient=expected_recipient,
            reason='Could not extract OB3 token: %s' % exc)

    # A Data Integrity credential is baked as its JSON document; a JWT-VC is the
    # compact token. Both verifiers share the verify() signature.
    is_ldp = token.lstrip().startswith('{')
    proof_format = 'ldp' if is_ldp else 'vc-jwt'
    issuer_did: Optional[str] = None
    trusted = True

    try:
        verifier: Any
        if pubkey_pem is not None:
            verifier = (OB3LdpVerifier(pubkey_pem=pubkey_pem) if is_ldp
                        else OB3Verifier(pubkey_pem=pubkey_pem))
        else:
            issuer_did = (issuer_did_from_document(token) if is_ldp
                          else issuer_did_from_token(token))
            # The DID comes from the untrusted credential. A did:key IS the
            # presenter's chosen key, so resolving it proves only internal
            # consistency; a did:web is anchored on the issuer's DNS+TLS.
            trusted = issuer_did.startswith('did:web:')
            verifier = (OB3LdpVerifier.for_issuer_did(issuer_did, download=download)
                        if is_ldp
                        else OB3Verifier.for_issuer_did(issuer_did, download=download))
        credential = verifier.verify(
            token, expected_recipient=expected_recipient,
            check_status=check_status, verify_status_list=verify_status_list,
            download=download)
    except OB3VerificationError as exc:
        return VerifyResult(
            ob_version='3', valid=False, trusted=False,
            recipient=expected_recipient, proof_format=proof_format,
            issuer_did=issuer_did,
            reason='OB3 verification failed: %s' % exc)

    notices: List[str] = []
    reason = None
    if not trusted:
        reason = ("signature is valid but verified against a key resolved from "
                  "the credential's own did:key (self-asserted), not a trusted "
                  "issuer key")
        notices.append(reason)
    return VerifyResult(
        ob_version='3', valid=True, trusted=trusted,
        recipient=expected_recipient, proof_format=proof_format,
        issuer_did=issuer_did, reason=reason, credential=credential,
        notices=notices)
