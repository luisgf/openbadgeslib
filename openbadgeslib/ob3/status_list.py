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

# OpenBadges 3.0 credential status (revocation) publishing.
#
# Issuer-side counterpart of ob3.status: builds the W3C Bitstring Status List
# v1.0 artefacts that check_credential_status consumes — the encodedList
# bitstring, the BitstringStatusListCredential document, and the
# credentialStatus entry embedded in each issued credential.
#
# A list carries exactly ONE statusPurpose ('revocation' or 'suspension'):
# with single-bit entries a multi-purpose list could not tell a revoked
# credential from a suspended one, so an issuer publishes one list per
# purpose and reuses the same index for a credential across both.

import base64
import gzip

from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from .credential import _VC2_CONTEXT, _iso

#: Default bitstring capacity: the W3C spec minimum (131072 entries, 16 KiB),
#: sized so the population of a list hides in a large anonymity set.
DEFAULT_SIZE_BITS = 131072

STATUS_PURPOSES = ('revocation', 'suspension')


def encode_bitstring(set_indices: Iterable[int],
                     size_bits: int = DEFAULT_SIZE_BITS) -> str:
    """Build an ``encodedList`` value: the multibase base64url ('u' prefix,
    unpadded) encoding of a GZIP-compressed, MSB-first bitstring of
    *size_bits* bits with *set_indices* flipped on.

    The bit layout inverts the decoding in ob3.status. Note the reader caps
    the *decompressed* bitstring at ``MAX_STATUS_LIST_BYTES`` (5 MiB), so keep
    ``size_bits`` at or below ~41.9M bits — a larger list encodes fine here
    but the library's own reader would refuse it. Raises ValueError for an
    index outside [0, size_bits) or a size that is not a positive multiple
    of 8.
    """
    if size_bits <= 0 or size_bits % 8:
        raise ValueError("size_bits must be a positive multiple of 8, got %r"
                         % (size_bits,))
    bitstring = bytearray(size_bits // 8)
    for index in set_indices:
        if not 0 <= index < size_bits:
            raise ValueError("status list index %r is outside [0, %d)"
                             % (index, size_bits))
        bitstring[index // 8] |= 0x80 >> (index % 8)
    compressed = gzip.compress(bytes(bitstring))
    encoded = base64.urlsafe_b64encode(compressed).decode('ascii').rstrip('=')
    return 'u' + encoded


def build_status_list_credential(issuer_id: str, url: str, purpose: str,
                                 set_indices: Iterable[int],
                                 size_bits: int = DEFAULT_SIZE_BITS,
                                 issued: Optional[datetime] = None) -> dict[str, Any]:
    """Build an (unsigned) BitstringStatusListCredential document.

    *url* is the public HTTPS URL the list will be served from — it becomes
    the credential ``id`` and must match the ``statusListCredential`` of the
    entries that point at it (see :func:`status_entry`). ``statusSize`` is
    omitted: entries are single-bit, the only size the verifier accepts.
    """
    if purpose not in STATUS_PURPOSES:
        raise ValueError("statusPurpose must be one of %r, got %r"
                         % (STATUS_PURPOSES, purpose))
    return {
        "@context": [_VC2_CONTEXT],
        "id": url,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": issuer_id,
        "validFrom": _iso(issued if issued is not None
                          else datetime.now(tz=timezone.utc)),
        "credentialSubject": {
            "id": url + "#list",
            "type": "BitstringStatusList",
            "statusPurpose": purpose,
            "encodedList": encode_bitstring(set_indices, size_bits),
        },
    }


def sign_status_list_credential(vc: dict[str, Any], privkey_pem: Any,
                                algorithm: str) -> str:
    """Sign a status list credential as a compact JWT-VC string.

    The VC claims stay at the top level of the payload (the same native
    VC-JWT shape OpenBadgeCredential uses), plus the registered claims
    ``iss``/``jti``/``nbf``. ob3.status reads either shape back.
    """
    from .signer import OB3Signer
    payload = dict(vc)
    payload['iss'] = vc['issuer']
    payload['jti'] = vc['id']
    payload['nbf'] = int(datetime.now(tz=timezone.utc).timestamp())
    return OB3Signer(privkey_pem=privkey_pem,
                     algorithm=algorithm).sign_payload(payload)


def status_entry(list_url: str, purpose: str, index: int) -> dict[str, Any]:
    """Build the ``credentialStatus`` entry that binds an issued credential
    to bit *index* of the status list served at *list_url*."""
    if purpose not in STATUS_PURPOSES:
        raise ValueError("statusPurpose must be one of %r, got %r"
                         % (STATUS_PURPOSES, purpose))
    if index < 0:
        raise ValueError("statusListIndex must be >= 0, got %d" % index)
    return {
        "id": "%s#%d" % (list_url, index),
        "type": "BitstringStatusListEntry",
        "statusPurpose": purpose,
        "statusListIndex": str(index),
        "statusListCredential": list_url,
    }
