"""Tests for the OpenID4VCI credential configuration entry (#271).

`badge_credential_configuration` is the Open Badges half of an OpenID4VCI
issuer's Credential Issuer Metadata: what a wallet reads to decide it can ask
for this badge, and how to display it. It is pure dict building — no openvc, no
[eudi] extra — so what these tests pin is that it cannot drift away from what
the issuance path actually stamps.
"""
import pytest

from openbadgeslib.ob3.eudi import (
    DEFAULT_DISCLOSABLE,
    OB3_SD_JWT_FORMAT,
    OB3_SD_JWT_VCT,
    badge_credential_configuration,
    badge_to_sd_jwt_claims,
    badge_type_metadata,
)


class TestCredentialConfigurationShape:
    def test_defaults(self):
        cfg = badge_credential_configuration()
        assert cfg["format"] == OB3_SD_JWT_FORMAT == "dc+sd-jwt"
        assert cfg["vct"] == OB3_SD_JWT_VCT
        assert cfg["credential_signing_alg_values_supported"] == ["ES256"]
        assert cfg["cryptographic_binding_methods_supported"] == ["jwk"]
        assert cfg["proof_types_supported"]["jwt"][
            "proof_signing_alg_values_supported"] == ["ES256"]
        assert cfg["display"] == [{"name": "Open Badge 3.0", "locale": "en"}]
        assert "scope" not in cfg                    # only when asked for

    def test_caller_overrides(self):
        cfg = badge_credential_configuration(
            vct="https://issuer.example/vct/badge",
            signing_alg_values=("ES256", "ES384"),
            proof_signing_alg_values=("ES256",),
            cryptographic_binding_methods=("jwk", "did:web"),
            display=[{"name": "Python 101", "locale": "es"}],
            scope="openbadge")
        assert cfg["vct"] == "https://issuer.example/vct/badge"
        assert cfg["credential_signing_alg_values_supported"] == ["ES256", "ES384"]
        assert cfg["proof_types_supported"]["jwt"][
            "proof_signing_alg_values_supported"] == ["ES256"]
        assert cfg["cryptographic_binding_methods_supported"] == ["jwk", "did:web"]
        assert cfg["display"] == [{"name": "Python 101", "locale": "es"}]
        assert cfg["scope"] == "openbadge"

    def test_display_is_copied_not_aliased(self):
        mine = [{"name": "Mine", "locale": "en"}]
        cfg = badge_credential_configuration(display=mine)
        cfg["display"][0]["name"] = "Changed"
        assert mine[0]["name"] == "Mine"

    def test_is_json_serializable(self):
        import json
        json.loads(json.dumps(badge_credential_configuration()))


class TestNoDrift:
    """The reason this function exists: a hand-written copy gets the vct and the
    claim set wrong, and a wallet then either rejects the credential or displays
    nothing."""

    def test_vct_matches_the_issued_badge(self, ob3_credential, ed25519_priv_pem):
        pytest.importorskip("openvc")
        import base64
        import json
        from openbadgeslib.ob3.eudi import issue_badge_sd_jwt
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem)
        body = token.split("~", 1)[0].split(".")[1]
        stamped = json.loads(
            base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))["vct"]
        assert badge_credential_configuration()["vct"] == stamped

    def test_custom_vct_flows_through_both(self, ob3_credential, ed25519_priv_pem):
        pytest.importorskip("openvc")
        import base64
        import json
        from openbadgeslib.ob3.eudi import issue_badge_sd_jwt
        vct = "https://issuer.example/vct/ob3"
        token = issue_badge_sd_jwt(ob3_credential, privkey_pem=ed25519_priv_pem,
                                   vct=vct)
        body = token.split("~", 1)[0].split(".")[1]
        stamped = json.loads(
            base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))["vct"]
        assert badge_credential_configuration(vct=vct)["vct"] == stamped == vct

    def test_claim_paths_match_the_type_metadata_document(self):
        # Both artifacts are served by the same issuer and validated against
        # each other by a wallet, so they are derived from one source here.
        cfg = badge_credential_configuration()
        metadata = badge_type_metadata()
        assert [c["path"] for c in cfg["claims"]] == [
            c["path"] for c in metadata["claims"]]
        assert [c["mandatory"] for c in cfg["claims"]] == [
            bool(c.get("mandatory", False)) for c in metadata["claims"]]

    def test_claim_paths_resolve_in_an_issued_claim_set(self, ob3_credential):
        # Every advertised top-level path exists in what badge_to_sd_jwt_claims
        # emits (validUntil is optional and absent from this fixture).
        claims = badge_to_sd_jwt_claims(ob3_credential)
        advertised = {tuple(c["path"]) for c in
                      badge_credential_configuration()["claims"]}
        assert ("achievement",) in advertised
        assert ("credentialSubject",) in advertised
        for path in advertised:
            if path[0] in claims:
                node = claims
                for component in path:
                    assert component in node, path
                    node = node[component]

    def test_disclosable_claim_is_not_mandatory(self):
        # credentialSubject is what a holder may withhold, so a wallet must not
        # be told the credential always carries it.
        mandatory = {tuple(c["path"]): c["mandatory"]
                     for c in badge_credential_configuration()["claims"]}
        for name in DEFAULT_DISCLOSABLE:
            assert mandatory[(name,)] is False
        assert mandatory[("achievement",)] is True

    def test_claims_carry_display_labels(self):
        for claim in badge_credential_configuration(locale="es")["claims"]:
            assert claim["display"][0]["locale"] == "es"
            assert claim["display"][0]["name"]


def test_works_without_the_eudi_extra(monkeypatch):
    import sys
    for name in ("openvc", "openvc.keys", "openvc.proof.sd_jwt"):
        monkeypatch.setitem(sys.modules, name, None)
    assert badge_credential_configuration()["format"] == "dc+sd-jwt"
