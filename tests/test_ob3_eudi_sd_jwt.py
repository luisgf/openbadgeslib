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
