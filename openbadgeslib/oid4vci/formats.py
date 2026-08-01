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

# The OID4VCI credential-format vocabulary, in one module on purpose.
#
# These identifiers appear in four places that MUST agree — the issuer
# metadata, the Credential Offer, the Credential Request the wallet sends back,
# and the badge section's `oid4vci_formats` opt-in — and a mismatch between any
# two of them is an interoperability failure that only shows up against a real
# wallet. Keeping them here means confparser (which validates the opt-in) and
# the protocol modules read the same constants rather than re-spelling string
# literals, the same reason ob3.status_list owns STATUS_PURPOSES.
#
# It also isolates a rename that is coming: OID4VCI 1.0 Final and the current
# SD-JWT VC draft moved the SD-JWT format identifier from `vc+sd-jwt` to
# `dc+sd-jwt`. When the wallets this library targets follow, that is an edit to
# one constant here plus a compatibility alias, not a grep across the package.

#: OB 3.0 as a compact JWT-VC. Revocable: the credential carries a
#: `credentialStatus` pointing at a Bitstring Status List.
FORMAT_JWT_VC_JSON = 'jwt_vc_json'

#: OB 3.0 as an SD-JWT VC (the EUDI track). Selectively disclosable and
#: key-bound via `cnf`, but IRREVOCABLE — see ob3.eudi.issue_badge_sd_jwt,
#: which refuses a credential carrying a credentialStatus (#226).
FORMAT_SD_JWT_VC = 'vc+sd-jwt'

#: Every format this library can issue over OID4VCI, in metadata order.
#: `ldp_vc` is deliberately absent: a document with an embedded proof is not a
#: token, so it does not fit the Credential Response shape without a separate
#: encoding decision.
OID4VCI_FORMATS = (FORMAT_JWT_VC_JSON, FORMAT_SD_JWT_VC)

#: Formats that cannot be signed with an RSA key. SD-JWT VC has no RSA
#: algorithm profile, so a badge section pairing `key_type = RSA` with
#: `vc+sd-jwt` is a configuration that can never issue — rejected at config
#: load rather than mid-request.
EC_ONLY_FORMATS = (FORMAT_SD_JWT_VC,)

#: Formats that can carry revocation/suspension status. A badge that opts into
#: a format outside this set gets an irrevocable credential, which the offer
#: path refuses to combine with a configured status list.
REVOCABLE_FORMATS = (FORMAT_JWT_VC_JSON,)
