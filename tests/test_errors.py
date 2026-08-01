"""Exception-hierarchy contract (#224).

`except LibOpenBadgesException` must catch every error the library raises, and
the config/algorithm errors must stay `ValueError` for backward compatibility.
"""
import configparser

import pytest

from openbadgeslib import errors
from openbadgeslib.errors import (
    LibOpenBadgesException, ConfigError, IssuanceError,
    DecompressionLimitExceeded, UnsupportedAlgorithm,
    KeyGenException, SignerException, VerifierException,
    KeyGenExceptions, SignerExceptions, VerifierExceptions,
)


class TestHierarchyIsUnderTheRoot:
    """Every library exception derives from LibOpenBadgesException so a single
    ``except`` traps them all — the OB2VerificationError docstring's promise."""

    @pytest.mark.parametrize('exc', [
        ConfigError, IssuanceError, DecompressionLimitExceeded,
        UnsupportedAlgorithm, KeyGenExceptions, SignerExceptions,
        VerifierExceptions, errors.BadgeImgFormatUnsupported,
        errors.StatusError, errors.ErrorSigningFile, errors.UnknownKeyType,
    ])
    def test_is_lib_exception(self, exc):
        assert issubclass(exc, LibOpenBadgesException)

    def test_reanchored_errors_are_reachable_from_old_modules(self):
        # The moved classes keep their historical import paths.
        from openbadgeslib.issue import IssuanceError as IssueSideError
        from openbadgeslib.baking import (
            DecompressionLimitExceeded as BakingSideError)
        assert IssueSideError is IssuanceError
        assert BakingSideError is DecompressionLimitExceeded

    def test_ob2_ob3_verification_errors_are_lib_exceptions(self):
        from openbadgeslib.ob2.verifier import OB2VerificationError
        from openbadgeslib.ob3.verifier import OB3VerificationError
        assert issubclass(OB2VerificationError, LibOpenBadgesException)
        assert issubclass(OB3VerificationError, LibOpenBadgesException)

    def test_publish_error_family_is_under_the_root_not_statuserror(self):
        # #280: PublishError and its subclasses live in ob3.publish and are
        # LibOpenBadgesException — but NOT StatusError. The documented tree used
        # to misfile AmbiguousCredential under StatusError, so a caller following
        # it with `except StatusError` around publish/revoke would miss it.
        from openbadgeslib.ob3.publish import (
            AmbiguousCredential, CredentialNotFound, PublishError)
        for exc in (PublishError, CredentialNotFound, AmbiguousCredential):
            assert issubclass(exc, LibOpenBadgesException)
        assert issubclass(AmbiguousCredential, PublishError)
        assert issubclass(CredentialNotFound, PublishError)
        assert not issubclass(AmbiguousCredential, errors.StatusError)

    def test_no_stray_ambiguous_credential_in_errors_module(self):
        # The dead errors.AmbiguousCredential(StatusError) shadow was removed, so
        # `from openbadgeslib.errors import AmbiguousCredential` cannot import a
        # class that is never raised (the live one is ob3.publish's).
        assert not hasattr(errors, 'AmbiguousCredential')


class TestValueErrorCompatibility:
    """ConfigError and UnsupportedAlgorithm stay ValueError so historical
    ``except ValueError`` callers (and the tests) keep working."""

    def test_config_error_is_value_error(self):
        assert issubclass(ConfigError, ValueError)

    def test_unsupported_algorithm_is_value_error(self):
        assert issubclass(UnsupportedAlgorithm, ValueError)

    def test_config_error_caught_both_ways(self):
        with pytest.raises(ValueError):
            raise ConfigError('boom')
        with pytest.raises(LibOpenBadgesException):
            raise ConfigError('boom')


class TestSingularAliases:
    """Singular aliases for the plural base families."""

    def test_aliases(self):
        assert KeyGenException is KeyGenExceptions
        assert SignerException is SignerExceptions
        assert VerifierException is VerifierExceptions


class TestWriteBadgeAndLogSurvivesMissingLogsSection:
    """`_write_badge_and_log` reads the log path inside its try, so a missing
    [logs]/[paths] key is reported — not a traceback that loses the already
    written badge (#224)."""

    def _conf_without_logs(self):
        conf = configparser.ConfigParser()
        conf.read_dict({'paths': {'base': '/tmp'}})  # no base_log, no [logs]
        return conf

    def test_badge_written_and_no_exception(self, tmp_path, capsys):
        from openbadgeslib.openbadges_signer import _write_badge_and_log
        out = tmp_path / 'badge.svg'
        # Must not raise even though conf has neither base_log nor [logs].
        _write_badge_and_log(self._conf_without_logs(), str(out),
                             b'<svg/>', 'X SIGNED for y')
        assert out.read_bytes() == b'<svg/>'  # badge is on disk
        printed = capsys.readouterr().out
        assert 'Could not write sign log' in printed
        assert 'X SIGNED for y at:' in printed
