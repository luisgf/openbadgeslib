"""The stable public surface (#232).

The top-level package declares an explicit __all__ (the "public contract"),
re-exports KeyEd25519 and the eudi track, and types the SignResult boundary
fields instead of leaving them Any. These tests lock that contract.
"""
import warnings

import pytest


class TestTopLevelAll:
    def test_all_is_declared(self):
        import openbadgeslib
        assert isinstance(openbadgeslib.__all__, list)

    @pytest.mark.parametrize('name', [
        '__version__', 'ob2', 'ob3', 'errors',
        'OB2Signer', 'OB2Verifier', 'OB2VerificationError',
        'OB3Signer', 'OB3Verifier', 'OB3VerificationError',
        'OpenBadgeCredential', 'Achievement', 'Issuer',
        'KeyFactory', 'KeyRSA', 'KeyECC', 'KeyEd25519',
        'issue_from_conf', 'verify_badge', 'IssuanceError', 'SignResult',
    ])
    def test_contract_name_present_and_resolvable(self, name):
        import openbadgeslib
        assert name in openbadgeslib.__all__
        assert getattr(openbadgeslib, name) is not None

    def test_key_ed25519_is_the_recommended_ob3_key(self):
        from openbadgeslib import KeyEd25519
        from openbadgeslib.keys import KeyEd25519 as Direct
        assert KeyEd25519 is Direct

    def test_import_star_binds_the_contract(self):
        ns = {}
        exec('from openbadgeslib import *', ns)
        for name in ('OB3Signer', 'KeyEd25519', 'verify_badge',
                     'issue_from_conf', 'ob3'):
            assert name in ns


class TestBareImportIsClean:
    def test_bare_import_does_not_warn(self):
        # A plain `import openbadgeslib` must not drag in (or warn about) the
        # legacy OB1 shims; the modern facades resolve lazily and warning-free.
        import importlib
        import openbadgeslib
        with warnings.catch_warnings():
            warnings.simplefilter('error', DeprecationWarning)
            importlib.reload(openbadgeslib)
            assert openbadgeslib.issue_from_conf is not None
            assert openbadgeslib.verify_badge is not None

    def test_legacy_ob1_names_still_work_but_warn(self):
        import openbadgeslib
        with pytest.warns(DeprecationWarning):
            _ = openbadgeslib.Signer          # legacy OB1 compat shim


class TestEudiReExport:
    def test_eudi_reachable_from_ob3(self):
        from openbadgeslib import ob3
        assert 'eudi' in ob3.__all__
        assert hasattr(ob3.eudi, 'issue_badge_sd_jwt')


class TestSignResultBoundaryTypesAreNotAny:
    def test_credential_and_assertion_are_typed(self):
        # The boundary fields carry real forward refs (resolved under
        # TYPE_CHECKING, so they don't exist at runtime — get_type_hints would
        # NameError, which is the whole point: zero runtime cost). Assert on the
        # stored annotation instead.
        from openbadgeslib.issue import SignResult
        cred = str(SignResult.__annotations__['credential'])
        assert 'OpenBadgeCredential' in cred and 'Any' not in cred
        assn = str(SignResult.__annotations__['assertion'])
        assert 'Assertion' in assn and 'Any' not in assn
