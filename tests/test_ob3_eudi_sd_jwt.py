"""Tests for the EUDI SD-JWT VC track (openbadgeslib.ob3.eudi), which issues and
verifies Open Badges as SD-JWT VC by consuming the openvc-core library.

The crypto tests need the [eudi] extra (openvc-core) and skip without it; the
"extra absent" test runs always (it simulates the missing dependency).
"""
import sys

import pytest

from openbadgeslib.ob3.eudi import (
    DEFAULT_DISCLOSABLE,
    OB3_SD_JWT_VCT,
    EudiError,
    badge_to_sd_jwt_claims,
    issue_badge_sd_jwt,
    verify_badge_sd_jwt,
)


class TestSdJwtBadge:
    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        pytest.importorskip("openvc")

    # ── issue + verify round-trip ────────────────────────────────────────────

    def test_roundtrip_ed25519(self, ob3_credential, ed25519_priv_pem, ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
        result = verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem)
        assert result.issuer == ob3_credential.issuer.id
        assert result.vct == OB3_SD_JWT_VCT
        assert result.claims["achievement"]["name"] == ob3_credential.achievement.name
        assert result.claims["credentialSubject"]["id"] == ob3_credential.recipient_id

    def test_roundtrip_es256(self, ob3_credential, ecc_priv_pem, ecc_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ecc_priv_pem)
        result = verify_badge_sd_jwt(token, pubkey_pem=ecc_pub_pem)
        assert result.issuer == ob3_credential.issuer.id
        assert result.claims["achievement"]["name"] == ob3_credential.achievement.name

    def test_roundtrip_es384(self, ob3_credential, p384_priv_pem, p384_pub_pem):
        import base64
        import json
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=p384_priv_pem)
        # A P-384 key must pin the ES384 algorithm in the issuer JWT header.
        header_b64 = token.split(".", 1)[0]
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
        assert header["alg"] == "ES384"
        result = verify_badge_sd_jwt(token, pubkey_pem=p384_pub_pem)
        assert result.issuer == ob3_credential.issuer.id
        assert result.claims["achievement"]["name"] == ob3_credential.achievement.name
        assert result.claims["credentialSubject"]["id"] == ob3_credential.recipient_id

    def test_claims_shape(self, ob3_credential):
        claims = badge_to_sd_jwt_claims(ob3_credential)
        assert claims["iss"] == ob3_credential.issuer.id
        assert claims["achievement"]["name"] == ob3_credential.achievement.name
        assert claims["credentialSubject"]["id"] == ob3_credential.recipient_id
        assert "credentialSubject" in DEFAULT_DISCLOSABLE   # recipient is disclosable

    # ── selective disclosure ─────────────────────────────────────────────────

    def test_holder_can_withhold_recipient(self, ob3_credential,
                                           ed25519_priv_pem, ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
        # A holder presentation that drops the disclosures keeps the achievement
        # but withholds the (selectively-disclosable) recipient identity.
        issuer_jwt = token.split("~", 1)[0] + "~"
        result = verify_badge_sd_jwt(issuer_jwt, pubkey_pem=ed25519_pub_pem)
        assert result.claims["achievement"]["name"] == ob3_credential.achievement.name
        assert "credentialSubject" not in result.claims

    # ── key binding (the EUDI wallet flow) ───────────────────────────────────

    def test_key_binding_presentation(self, ob3_credential,
                                      ed25519_priv_pem, ed25519_pub_pem):
        from openvc.keys import P256SigningKey
        from openvc.proof.sd_jwt import SdJwtVcProofSuite

        holder = P256SigningKey.generate(kid="did:example:holder#0")
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   holder_jwk=holder.public_jwk())
        presentation = SdJwtVcProofSuite().create_presentation(
            token, holder_key=holder, audience="https://verifier.example",
            nonce="n-123")
        result = verify_badge_sd_jwt(
            presentation, pubkey_pem=ed25519_pub_pem,
            audience="https://verifier.example", nonce="n-123",
            require_key_binding=True)
        assert result.key_bound is True

    # ── failure modes ────────────────────────────────────────────────────────

    def test_wrong_key_fails(self, ob3_credential, ed25519_priv_pem, rsa_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
        with pytest.raises(EudiError):
            verify_badge_sd_jwt(token, pubkey_pem=rsa_pub_pem)

    def test_tampered_token_fails(self, ob3_credential, ed25519_priv_pem,
                                  ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
        head, sep, rest = token.partition("~")
        tampered = head[:-3] + ("aaa" if head[-3:] != "aaa" else "bbb") + sep + rest
        with pytest.raises(EudiError):
            verify_badge_sd_jwt(tampered, pubkey_pem=ed25519_pub_pem)

    def test_expected_vct_mismatch_fails(self, ob3_credential, ed25519_priv_pem,
                                         ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
        with pytest.raises(EudiError):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem,
                                expected_vct="https://example.com/other-type")

    def test_rsa_key_rejected(self, ob3_credential, rsa_priv_pem):
        # SD-JWT's algorithm set is {ES256, ES384, EdDSA}; RSA is not allowed.
        with pytest.raises(EudiError, match="Ed25519|P-256|RSA"):
            issue_badge_sd_jwt(ob3_credential, privkey_pem=rsa_priv_pem)

    def test_unparseable_key_raises_eudi_error(self, ob3_credential):
        # #287: a malformed PEM used to surface as UnknownKeyType; the module
        # contract is EudiError for every issuance failure.
        from openbadgeslib.errors import UnknownKeyType
        garbage = b'-----BEGIN PRIVATE KEY-----\ngarbage\n-----END PRIVATE KEY-----\n'
        with pytest.raises(EudiError, match='unparseable'):
            issue_badge_sd_jwt(ob3_credential, privkey_pem=garbage)
        # And it must not be the bare key-type exception.
        with pytest.raises(EudiError):
            try:
                issue_badge_sd_jwt(ob3_credential, privkey_pem=garbage)
            except UnknownKeyType:
                pytest.fail('UnknownKeyType escaped; expected EudiError')

    def test_unsupported_curve_rejected(self, ob3_credential):
        # SD-JWT's ECDSA set is P-256/P-384; a P-521 key must be refused with a
        # clear message rather than mis-signed under the wrong algorithm.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        p521 = ec.generate_private_key(ec.SECP521R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        with pytest.raises(EudiError, match="P-256|P-384|curve"):
            issue_badge_sd_jwt(ob3_credential, privkey_pem=p521)


# ── behaviour without the [eudi] extra (runs with or without openvc) ─────────

class TestExtraAbsent:
    def test_missing_openvc_yields_actionable_error(self, monkeypatch,
                                                    ob3_credential, ed25519_priv_pem):
        # Null the submodules too — nulling only the top package is ignored when
        # the submodules are already cached in sys.modules.
        for name in ("openvc", "openvc.keys", "openvc.proof.sd_jwt"):
            monkeypatch.setitem(sys.modules, name, None)
        with pytest.raises(EudiError, match=r"openbadgeslib\[eudi\]"):
            issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)


# ── #226/#270: status carriage + identifier carriage (pure-Python, no [eudi]) ─

class TestSdJwtStatusAndIdentifier:
    """A W3C credentialStatus is rejected at issuance (not silently dropped) —
    the SD-JWT VC track revokes through the IETF Token Status List instead
    (#270) — and the recipient's hashed identifier is carried under
    credentialSubject. These paths need no openvc.

    ``ob3_credential`` is a session fixture — never mutate it; derive a variant
    with ``dataclasses.replace`` so other tests keep the pristine credential.
    """

    _STATUS = [{
        "id": "https://issuer.example/status/badge_1#5",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "5",
        "statusListCredential": "https://issuer.example/status/badge_1.jwt",
    }]

    def _identifier(self, ihash="sha256$abc"):
        from openbadgeslib.ob3.credential import IdentityObject
        return IdentityObject(identity_hash=ihash, identity_type="emailAddress",
                              hashed=True)

    def test_issue_rejects_credential_with_w3c_status(self, ob3_credential,
                                                      ed25519_priv_pem):
        # Not because the badge cannot be revoked (it can, via status=), but
        # because a Bitstring entry points at a list an SD-JWT verifier cannot
        # read: two formats, two lists.
        from dataclasses import replace
        cred = replace(ob3_credential, credential_status=list(self._STATUS))
        with pytest.raises(EudiError, match="IETF Token Status List"):
            issue_badge_sd_jwt(cred, privkey_pem=ed25519_priv_pem)

    def test_rejection_precedes_the_openvc_requirement(self, ob3_credential):
        # The clear error fires even with a bogus key (before _require_openvc),
        # so an issuer without the [eudi] extra still gets it, not ImportError.
        from dataclasses import replace
        cred = replace(ob3_credential, credential_status=list(self._STATUS))
        with pytest.raises(EudiError, match="credentialStatus"):
            issue_badge_sd_jwt(cred, privkey_pem=b"not-a-key")

    def test_identifier_carried_alongside_id(self, ob3_credential):
        from dataclasses import replace
        cred = replace(ob3_credential, identifiers=[self._identifier()])
        subject = badge_to_sd_jwt_claims(cred)["credentialSubject"]
        assert subject["id"] == cred.recipient_id
        assert subject["identifier"] == [{
            "type": "IdentityObject", "hashed": True,
            "identityHash": "sha256$abc", "identityType": "emailAddress"}]

    def test_identifier_only_subject_has_no_id(self, ob3_credential):
        from dataclasses import replace
        cred = replace(ob3_credential, recipient_id=None,
                       identifiers=[self._identifier("sha256$xyz")])
        subject = badge_to_sd_jwt_claims(cred)["credentialSubject"]
        assert "id" not in subject
        assert subject["identifier"][0]["identityHash"] == "sha256$xyz"

    def test_no_status_credential_still_issues_claims(self, ob3_credential):
        # The common case (no status) is unaffected: claims build fine.
        claims = badge_to_sd_jwt_claims(ob3_credential)
        assert "credentialStatus" not in claims
        assert claims["credentialSubject"]["id"] == ob3_credential.recipient_id


# ── #270: revocation via the IETF Token Status List ──────────────────────────

class TestTokenStatusList:
    """Issue a badge carrying an IETF status reference, verify it, flip the bit,
    re-sign the list and watch the same badge come back revoked.

    Everything about the status list itself — the LSB-first packing, DEFLATE,
    the token's typ/signature — is openvc-core's; these tests pin the seam this
    library owns: that the reference is carried always-disclosed, that both
    verify paths reach the check, and that every way of not knowing the status
    fails closed.
    """

    STATUS_URI = "https://issuer.example/status/list-1.jwt"
    INDEX = 7

    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        pytest.importorskip("openvc")

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _signing_key(priv_pem):
        from openvc.keys import Ed25519SigningKey
        return Ed25519SigningKey.from_pem(priv_pem, kid="status-key")

    def _reference(self, index=None):
        from openvc.status.issue import build_token_status_reference
        return build_token_status_reference(
            uri=self.STATUS_URI, index=self.INDEX if index is None else index)

    def _list_token(self, priv_pem, *, revoked=(), suspended=(), bits=1,
                    uri=None, size=64, **kwargs):
        """Sign a status-list token with the given indices flipped."""
        from openvc.status.issue import build_status_list_token
        from openvc.status.token_status_list import new_status_list, set_status
        data = new_status_list(size, bits=bits)
        for idx in revoked:
            set_status(data, idx, 1, bits=bits)
        for idx in suspended:
            set_status(data, idx, 2, bits=bits)
        return build_status_list_token(
            signing_key=self._signing_key(priv_pem),
            uri=uri or self.STATUS_URI, status_list=data, bits=bits, **kwargs)

    def _resolver(self, list_token, pub_pem, *, uri=None):
        """A resolve_status_list_token that serves *list_token* over a fake
        download, verified by the real status_list_token_resolver."""
        from openbadgeslib.ob3.eudi import status_list_token_resolver
        served = {}
        served[uri or self.STATUS_URI] = list_token.encode("ascii")

        def download(url):
            try:
                return served[url]
            except KeyError:                      # a URL nobody published
                raise OSError("404 %s" % url)

        return status_list_token_resolver(pubkey_pem=pub_pem, download=download)

    @staticmethod
    def _payload(token):
        """The issuer JWT's payload — what is disclosed unconditionally."""
        import base64
        import json
        body = token.split("~", 1)[0].split(".")[1]
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))

    # ── issuance ─────────────────────────────────────────────────────────────

    def test_status_reference_is_carried(self, ob3_credential, ed25519_priv_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   status=self._reference())
        status = self._payload(token)["status"]
        assert status["status_list"] == {"uri": self.STATUS_URI, "idx": self.INDEX}

    def test_status_is_never_selectively_disclosable(self, ob3_credential,
                                                     ed25519_priv_pem,
                                                     ed25519_pub_pem):
        # Even asked for explicitly: a holder able to withhold the pointer could
        # present a revoked badge as an unrevokable one.
        token = issue_badge_sd_jwt(
            ob3_credential, privkey_pem=ed25519_priv_pem,
            status=self._reference(), disclosable=("credentialSubject", "status"))
        assert "status" in self._payload(token)          # in the JWT, not a digest
        # And it survives a presentation that drops every disclosure.
        bare = token.split("~", 1)[0] + "~"
        result = verify_badge_sd_jwt(bare, pubkey_pem=ed25519_pub_pem)
        assert result.claims["status"]["status_list"]["idx"] == self.INDEX
        assert "credentialSubject" not in result.claims   # that one IS withheld

    def test_inner_reference_shape_is_accepted(self, ob3_credential,
                                               ed25519_priv_pem):
        # build_token_status_reference returns the {"status": …} wrapper; the
        # inner object is accepted too, so neither shape is a footgun.
        inner = self._reference()["status"]
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   status=inner)
        assert self._payload(token)["status"] == inner

    @pytest.mark.parametrize("bad", [
        {"status": {}},                                   # no status_list
        {"status": {"status_list": {"uri": "https://x/l"}}},          # no idx
        {"status": {"status_list": {"uri": "https://x/l", "idx": -1}}},
        {"status": {"status_list": {"uri": "https://x/l", "idx": "3"}}},
        "not-a-mapping",
    ])
    def test_malformed_reference_is_rejected_at_issuance(self, bad,
                                                         ob3_credential,
                                                         ed25519_priv_pem):
        # Rejected here rather than producing a badge whose status can never be
        # read — an unreadable status is indistinguishable from no status.
        with pytest.raises(EudiError):
            issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                               status=bad)

    # ── the round trip ───────────────────────────────────────────────────────

    def test_roundtrip_valid_then_revoked(self, ob3_credential, ed25519_priv_pem,
                                          ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   status=self._reference())
        # 1. nothing flipped: verifies, and reports the status it checked
        live = self._resolver(self._list_token(ed25519_priv_pem), ed25519_pub_pem)
        result = verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem,
                                     require_status=True,
                                     resolve_status_list_token=live)
        assert result.claims["achievement"]["name"] == ob3_credential.achievement.name

        # 2. flip this badge's bit and re-sign the list: the same badge is revoked
        revoked = self._resolver(
            self._list_token(ed25519_priv_pem, revoked=[self.INDEX]),
            ed25519_pub_pem)
        with pytest.raises(EudiError, match="revoked"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem,
                                require_status=True,
                                resolve_status_list_token=revoked)

    def test_a_neighbours_revocation_does_not_revoke_this_badge(
            self, ob3_credential, ed25519_priv_pem, ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   status=self._reference())
        others = self._resolver(
            self._list_token(ed25519_priv_pem, revoked=[self.INDEX - 1,
                                                        self.INDEX + 1]),
            ed25519_pub_pem)
        result = verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem,
                                     require_status=True,
                                     resolve_status_list_token=others)
        assert result.issuer == ob3_credential.issuer.id

    def test_suspended_is_rejected_too(self, ob3_credential, ed25519_priv_pem,
                                       ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   status=self._reference())
        suspended = self._resolver(
            self._list_token(ed25519_priv_pem, suspended=[self.INDEX], bits=2),
            ed25519_pub_pem)
        with pytest.raises(EudiError, match="suspended"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem,
                                require_status=True,
                                resolve_status_list_token=suspended)

    # ── fail-closed ──────────────────────────────────────────────────────────

    def test_declared_status_without_resolver_fails_when_required(
            self, ob3_credential, ed25519_priv_pem, ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   status=self._reference())
        with pytest.raises(EudiError, match="no resolve_status_list_token"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem,
                                require_status=True)

    def test_declared_status_without_resolver_is_skipped_by_default(
            self, ob3_credential, ed25519_priv_pem, ed25519_pub_pem):
        # The pre-#270 behaviour for callers that never opted in.
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   status=self._reference())
        result = verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem)
        assert result.issuer == ob3_credential.issuer.id

    def test_unresolvable_list_is_not_read_as_valid(self, ob3_credential,
                                                    ed25519_priv_pem,
                                                    ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   status=self._reference())
        # The list is published somewhere else entirely: the fetch fails.
        missing = self._resolver(self._list_token(ed25519_priv_pem),
                                 ed25519_pub_pem, uri="https://elsewhere/l.jwt")
        with pytest.raises(EudiError, match="could not check"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem,
                                resolve_status_list_token=missing)

    def test_status_list_signed_by_another_key_is_rejected(
            self, ob3_credential, ed25519_priv_pem, ed25519_pub_pem,
            ecc_priv_pem, ecc_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   status=self._reference())
        # The list is signed by a key the verifier does not trust: a compromised
        # status host must not be able to un-revoke (or revoke) a badge.
        from openvc.keys import P256SigningKey
        from openvc.status.issue import build_status_list_token
        from openvc.status.token_status_list import new_status_list
        foreign = build_status_list_token(
            signing_key=P256SigningKey.from_pem(ecc_priv_pem, kid="other"),
            uri=self.STATUS_URI, status_list=new_status_list(64))
        resolver = self._resolver(foreign, ed25519_pub_pem)
        with pytest.raises(EudiError, match="could not check"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem,
                                resolve_status_list_token=resolver)

    def test_list_replayed_from_another_url_is_rejected(self, ob3_credential,
                                                        ed25519_priv_pem,
                                                        ed25519_pub_pem):
        # The IETF anti-swap check: a valid list token published at one URL,
        # served at the URL this badge points to, must not be accepted — it
        # would un-revoke every badge in the real list.
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   status=self._reference())
        elsewhere = self._list_token(ed25519_priv_pem,
                                     uri="https://issuer.example/status/other.jwt")
        resolver = self._resolver(elsewhere, ed25519_pub_pem)   # served at OUR uri
        with pytest.raises(EudiError, match="could not check"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem,
                                resolve_status_list_token=resolver)

    def test_expired_status_list_is_rejected(self, ob3_credential,
                                             ed25519_priv_pem, ed25519_pub_pem):
        # A lapsed list must not keep answering "not revoked" forever.
        import time
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   status=self._reference())
        stale = self._list_token(ed25519_priv_pem,
                                 expires=int(time.time()) - 3600)
        with pytest.raises(EudiError, match="could not check"):
            verify_badge_sd_jwt(
                token, pubkey_pem=ed25519_pub_pem,
                resolve_status_list_token=self._resolver(stale, ed25519_pub_pem))

    # ── badges without a status ──────────────────────────────────────────────

    def test_badge_without_status_verifies_and_says_so(self, ob3_credential,
                                                       ed25519_priv_pem,
                                                       ed25519_pub_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
        assert "status" not in self._payload(token)
        # require_status is about a status that cannot be CHECKED, not about
        # demanding every badge carry one — same meaning as the delegate's.
        result = verify_badge_sd_jwt(
            token, pubkey_pem=ed25519_pub_pem, require_status=True,
            resolve_status_list_token=self._resolver(
                self._list_token(ed25519_priv_pem), ed25519_pub_pem))
        assert result.issuer == ob3_credential.issuer.id


# ── validity window, never-disclosable claims, leeway, issuer-JWT aud ─────────

def _payload_of(token):
    """The issuer JWT's payload — what is disclosed unconditionally."""
    import base64
    import json
    body = token.split("~", 1)[0].split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def _third_party_token(priv_pem, **claims):
    """A badge SD-JWT as another implementation could issue it: a flat payload
    built straight on openvc-core, with exactly the claims given (no ``exp``
    unless one is passed), so what this library checks is what it must check on
    a token it did not make."""
    from openvc.keys import Ed25519SigningKey
    from openvc.proof.sd_jwt import SdJwtVcProofSuite
    payload = {
        "iss": "https://issuer.example",
        "name": "Python 101",
        "achievement": {"id": "https://ex/b/1", "name": "Python 101"},
    }
    payload.update(claims)
    return SdJwtVcProofSuite().issue(
        payload, signing_key=Ed25519SigningKey.from_pem(priv_pem, kid="k"),
        vct=OB3_SD_JWT_VCT)


class TestSdJwtValidityWindow:
    """validFrom/validUntil are a flat IETF payload's only expiry on this track,
    and the delegate does not read them as a bound there: the badge's own
    window is this library's to enforce, on issue (exp) and on verify."""

    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        pytest.importorskip("openvc")

    @staticmethod
    def _credential(base, *, issued, expires=None):
        import dataclasses
        return dataclasses.replace(base, issuance_date=issued, expiration_date=expires)

    def test_exp_is_derived_from_the_credential_expiry(self, ob3_credential,
                                                       ed25519_priv_pem,
                                                       ed25519_pub_pem):
        from datetime import datetime, timezone
        expires = datetime(2099, 1, 1, tzinfo=timezone.utc)
        cred = self._credential(ob3_credential, issued=ob3_credential.issuance_date,
                                expires=expires)
        token = issue_badge_sd_jwt(cred, privkey_pem=ed25519_priv_pem)
        assert _payload_of(token)["exp"] == int(expires.timestamp())
        assert verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem).issuer \
            == cred.issuer.id

    def test_a_badge_that_does_not_expire_has_no_exp(self, ob3_credential,
                                                     ed25519_priv_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
        assert "exp" not in _payload_of(token)

    def test_an_expired_badge_is_refused(self, ob3_credential, ed25519_priv_pem,
                                         ed25519_pub_pem):
        # The wrong-accept this guards: a 2021 expiry used to verify, because
        # nothing turned the flat `validUntil` into an `exp`.
        from datetime import datetime, timezone
        cred = self._credential(
            ob3_credential, issued=datetime(2020, 1, 1, tzinfo=timezone.utc),
            expires=datetime(2021, 1, 1, tzinfo=timezone.utc))
        token = issue_badge_sd_jwt(cred, privkey_pem=ed25519_priv_pem)
        with pytest.raises(EudiError, match="expired"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem)

    def test_the_earlier_of_validuntil_and_expires_in_s_wins(self, ob3_credential,
                                                             ed25519_priv_pem):
        import time
        from datetime import datetime, timezone
        far = datetime(2099, 1, 1, tzinfo=timezone.utc)
        issued = ob3_credential.issuance_date
        # a short explicit expiry shortens a long validUntil ...
        short = issue_badge_sd_jwt(
            self._credential(ob3_credential, issued=issued, expires=far),
            privkey_pem=ed25519_priv_pem, expires_in_s=3600)
        assert abs(_payload_of(short)["exp"] - (int(time.time()) + 3600)) <= 5
        # ... but a long explicit one cannot outlive validUntil.
        soon = datetime.fromtimestamp(int(time.time()) + 600, timezone.utc)
        capped = issue_badge_sd_jwt(
            self._credential(ob3_credential, issued=issued, expires=soon),
            privkey_pem=ed25519_priv_pem, expires_in_s=10 ** 7)
        assert _payload_of(capped)["exp"] == int(soon.timestamp())
        # with no validUntil, expires_in_s alone still works as before
        alone = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   expires_in_s=3600)
        assert abs(_payload_of(alone)["exp"] - (int(time.time()) + 3600)) <= 5

    def test_a_not_yet_valid_badge_is_refused(self, ob3_credential,
                                              ed25519_priv_pem, ed25519_pub_pem):
        from datetime import datetime, timezone
        cred = self._credential(
            ob3_credential, issued=datetime(2099, 1, 1, tzinfo=timezone.utc))
        token = issue_badge_sd_jwt(cred, privkey_pem=ed25519_priv_pem)
        # refused by the delegate on the nbf this library now sets ...
        with pytest.raises(EudiError, match="nbf|not yet valid"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem)

    def test_nbf_is_set_only_for_a_validfrom_still_ahead(self, ob3_credential,
                                                         ed25519_priv_pem):
        # A verifier that does not know validFrom still refuses a badge that
        # has not started; but not when it starts now or earlier, where nbf
        # would only turn a verifier's clock skew into a refusal.
        from datetime import datetime, timedelta, timezone
        future = datetime(2099, 1, 1, tzinfo=timezone.utc)
        ahead = issue_badge_sd_jwt(self._credential(ob3_credential, issued=future),
                                   privkey_pem=ed25519_priv_pem)
        assert _payload_of(ahead)["nbf"] == int(future.timestamp())
        for issued in (datetime.now(timezone.utc),
                       datetime.now(timezone.utc) - timedelta(days=30)):
            current = issue_badge_sd_jwt(self._credential(ob3_credential, issued=issued),
                                         privkey_pem=ed25519_priv_pem)
            assert "nbf" not in _payload_of(current)

    def test_validfrom_inside_the_leeway_verifies_and_outside_is_refused(
            self, ed25519_priv_pem, ed25519_pub_pem):
        from datetime import datetime, timedelta, timezone
        from openbadgeslib.util import CLOCK_SKEW_LEEWAY

        def at(delta):
            return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")

        verify_badge_sd_jwt(
            _third_party_token(ed25519_priv_pem,
                               validFrom=at(CLOCK_SKEW_LEEWAY - timedelta(seconds=20))),
            pubkey_pem=ed25519_pub_pem)
        with pytest.raises(EudiError, match="not yet valid"):
            verify_badge_sd_jwt(
                _third_party_token(ed25519_priv_pem,
                                   validFrom=at(CLOCK_SKEW_LEEWAY + timedelta(seconds=20))),
                pubkey_pem=ed25519_pub_pem)

    @pytest.mark.parametrize("bad", [True, "10", [], float("inf"),
                                     float("nan"), 10 ** 11, -10 ** 11, 10 ** 309])
    def test_expires_in_s_is_a_bounded_number(self, bad, ob3_credential,
                                              ed25519_priv_pem):
        with pytest.raises(EudiError, match="expires_in_s"):
            issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                               expires_in_s=bad)

    @pytest.mark.parametrize("ok", [0, 1, -60, 3600, 3600.0, 3600.5, 10 ** 10])
    def test_expires_in_s_accepts_the_numbers_it_always_did(self, ok, ob3_credential,
                                                            ed25519_priv_pem):
        import time
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   expires_in_s=ok)
        assert abs(_payload_of(token)["exp"] - (time.time() + ok)) <= 5

    def test_an_oversized_or_mistyped_window_value_is_not_echoed(
            self, ed25519_priv_pem, ed25519_pub_pem):
        token = _third_party_token(ed25519_priv_pem, validUntil="9" * 100000)
        with pytest.raises(EudiError, match="malformed") as caught:
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem)
        assert len(str(caught.value)) < 300
        token = _third_party_token(ed25519_priv_pem, validUntil=[[["x"]]])
        with pytest.raises(EudiError, match="got a list"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem)

    # ── a token this library did not make ────────────────────────────────────

    def test_third_party_validuntil_without_exp_is_refused(self, ed25519_priv_pem,
                                                           ed25519_pub_pem):
        token = _third_party_token(ed25519_priv_pem, validUntil="2021-01-01T00:00:00Z")
        assert "exp" not in _payload_of(token)
        with pytest.raises(EudiError, match="expired"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem)

    def test_third_party_validfrom_in_the_future_is_refused(self, ed25519_priv_pem,
                                                            ed25519_pub_pem):
        token = _third_party_token(ed25519_priv_pem, validFrom="2099-01-01T00:00:00Z")
        with pytest.raises(EudiError, match="not yet valid"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem)

    def test_a_window_that_is_current_verifies(self, ed25519_priv_pem, ed25519_pub_pem):
        token = _third_party_token(ed25519_priv_pem,
                                   validFrom="2020-01-01T00:00:00Z",
                                   validUntil="2099-01-01T00:00:00Z")
        assert verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem).claims[
            "validUntil"] == "2099-01-01T00:00:00Z"

    @pytest.mark.parametrize("name", ["validFrom", "validUntil"])
    @pytest.mark.parametrize("value", [None, 4102444800, "tomorrow", "2099-01-01",
                                       "2099-01-01T00:00:00", ["2099-01-01T00:00:00Z"],
                                       {"a": 1}])
    def test_a_malformed_validity_value_fails_closed(self, name, value,
                                                     ed25519_priv_pem,
                                                     ed25519_pub_pem):
        token = _third_party_token(ed25519_priv_pem, **{name: value})
        with pytest.raises(EudiError, match="malformed"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem)

    def test_the_leeway_matches_the_other_verifiers(self, ed25519_priv_pem,
                                                    ed25519_pub_pem):
        from datetime import datetime, timedelta, timezone
        from openbadgeslib.util import CLOCK_SKEW_LEEWAY

        def at(delta):
            return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")

        inside = _third_party_token(
            ed25519_priv_pem, validUntil=at(-CLOCK_SKEW_LEEWAY + timedelta(seconds=20)))
        verify_badge_sd_jwt(inside, pubkey_pem=ed25519_pub_pem)
        outside = _third_party_token(
            ed25519_priv_pem, validUntil=at(-CLOCK_SKEW_LEEWAY - timedelta(seconds=20)))
        with pytest.raises(EudiError, match="expired"):
            verify_badge_sd_jwt(outside, pubkey_pem=ed25519_pub_pem)


class TestNeverDisclosableClaims:
    """A holder may withhold any disclosure undetected, so the claims a verifier
    judges the badge by cannot be made disclosable."""

    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        pytest.importorskip("openvc")

    @pytest.mark.parametrize("claim", ["name", "achievement", "validFrom", "validUntil"])
    def test_issuance_refuses_a_disclosable_judging_claim(self, claim, ob3_credential,
                                                          ed25519_priv_pem):
        with pytest.raises(EudiError, match="cannot be selectively disclosable"):
            issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                               disclosable=("credentialSubject", claim))

    def test_it_is_refused_even_when_the_claim_is_absent(self, ob3_credential,
                                                         ed25519_priv_pem):
        # The badge has no validUntil, but asking for one to be disclosable is a
        # misconfiguration that would bite the first badge that has one.
        assert "validUntil" not in badge_to_sd_jwt_claims(ob3_credential)
        with pytest.raises(EudiError, match="validUntil"):
            issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                               disclosable=("validUntil",))

    @pytest.mark.parametrize("bare", ["credentialSubject", b"credentialSubject", "validUntil"])
    def test_a_bare_string_is_not_read_one_character_at_a_time(
            self, bare, ob3_credential, ed25519_priv_pem):
        with pytest.raises(EudiError, match="iterable of claim names"):
            issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                               disclosable=bare)

    def test_the_recipient_stays_disclosable(self, ob3_credential, ed25519_priv_pem):
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   disclosable=("credentialSubject",))
        assert "credentialSubject" not in _payload_of(token)       # moved to a disclosure

    def test_a_stripped_presentation_still_carries_the_validity_window(
            self, ob3_credential, ed25519_priv_pem, ed25519_pub_pem):
        import dataclasses
        from datetime import datetime, timezone
        cred = dataclasses.replace(
            ob3_credential, expiration_date=datetime(2099, 1, 1, tzinfo=timezone.utc))
        token = issue_badge_sd_jwt(cred, privkey_pem=ed25519_priv_pem)
        stripped = token.split("~", 1)[0] + "~"          # holder drops every disclosure
        claims = verify_badge_sd_jwt(stripped, pubkey_pem=ed25519_pub_pem).claims
        assert claims["validUntil"] == "2099-01-01T00:00:00Z"
        assert claims["validFrom"] and claims["achievement"] and claims["name"]


class TestStatusListLeeway:
    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        pytest.importorskip("openvc")

    @pytest.mark.parametrize("bad", [float("inf"), float("nan"), -1, 86401, 10 ** 12,
                                     1.5, True, None, "60"])
    def test_a_leeway_the_delegate_rejects_fails_when_the_resolver_is_built(self, bad):
        # Before openvc-core 1.35.0 an infinite leeway made an EXPIRED status
        # list verify as current; now neither layer takes it.
        from openbadgeslib.ob3.eudi import status_list_token_resolver
        with pytest.raises(EudiError, match="leeway_s"):
            status_list_token_resolver(pubkey_pem="unused", leeway_s=bad)

    @pytest.mark.parametrize("ok", [0, 60, 86400])
    def test_the_accepted_range_builds(self, ok, ed25519_pub_pem):
        from openbadgeslib.ob3.eudi import status_list_token_resolver
        assert callable(status_list_token_resolver(pubkey_pem=ed25519_pub_pem,
                                                   leeway_s=ok))


class TestIssuerJwtAudience:
    """openvc-core 1.35.0 enforces the issuer JWT's own ``aud`` (RFC 7519 §4.1.3).
    Below it, a badge its issuer restricted to one relying party verified for
    all of them; this pins the behaviour the floor (>=1.35.0) buys, so the
    floor/latest drift job (#236) notices if the delegate moves it."""

    RP = "https://rp.example"

    @pytest.fixture(autouse=True)
    def _needs_openvc(self):
        pytest.importorskip("openvc")

    def test_a_badge_restricted_to_another_party_is_refused(self, ed25519_priv_pem,
                                                            ed25519_pub_pem):
        token = _third_party_token(ed25519_priv_pem, aud="https://someone-else.example")
        with pytest.raises(EudiError, match="aud"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem)
        with pytest.raises(EudiError, match="aud"):
            verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem, audience=self.RP)

    def test_a_badge_restricted_to_this_party_verifies(self, ed25519_priv_pem,
                                                       ed25519_pub_pem):
        token = _third_party_token(ed25519_priv_pem, aud=self.RP)
        result = verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem,
                                     audience=self.RP)
        assert result.claims["aud"] == self.RP

    def test_a_badge_without_aud_is_unaffected(self, ed25519_priv_pem, ed25519_pub_pem):
        token = _third_party_token(ed25519_priv_pem)
        verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem)
        verify_badge_sd_jwt(token, pubkey_pem=ed25519_pub_pem, audience=self.RP)
