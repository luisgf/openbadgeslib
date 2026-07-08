"""#159 — OpenBadges 1.0 deprecation.

OB1 is a dead format (Mozilla Backpack shut down in 2019). Step 1 (this
issue) marks the legacy import surface with a DeprecationWarning and prints a
[!] notice on the -V 1 CLI paths; OB1 stays fully functional. Removal lands in
the grouped 4.0.0 release (#170).

The warning must fire on the *deprecated* surface only — the ob1 package, the
three top-level compat shims, and the unprefixed re-exports — while a bare
`import openbadgeslib` and the internal leaf imports (openbadgeslib.ob1.badge,
which OB2/OB3 signing still uses for the shared badge model) stay silent.
"""
import argparse
import importlib
import subprocess
import sys
import warnings
from pathlib import Path
from unittest.mock import patch

import pytest

TESTS_DIR = Path(__file__).parent


# ── the modern surface stays silent ──────────────────────────────────────────

class TestImportSilence:
    def test_modern_and_leaf_imports_are_silent(self):
        """A bare package import (what every OB2/OB3 user does) must neither
        warn nor drag in the ob1 subpackage; the modern APIs and the internal
        leaf import stay warning-free too. Run in a child under
        -W error::DeprecationWarning so any stray warning fails the test."""
        code = (
            'import sys\n'
            'import openbadgeslib\n'
            'assert "openbadgeslib.ob1" not in sys.modules, '
            '"bare import must not load ob1"\n'
            'from openbadgeslib.ob2 import OB2Signer, OB2Verifier\n'
            'from openbadgeslib.ob3 import OB3Signer, OB3Verifier\n'
            'from openbadgeslib.ob1.badge import Badge, BadgeImgType\n'
        )
        result = subprocess.run(
            [sys.executable, '-W', 'error::DeprecationWarning', '-c', code],
            capture_output=True, text=True)
        assert result.returncode == 0, result.stderr


# ── the deprecated surface warns ─────────────────────────────────────────────

class TestImportWarnings:
    @pytest.mark.parametrize('name', ['Signer', 'Verifier', 'VerifyInfo',
                                      'Badge', 'BadgeImgType', 'BadgeType',
                                      'extract_svg_assertion'])
    def test_unprefixed_reexport_warns(self, name):
        import openbadgeslib
        with pytest.warns(DeprecationWarning, match='deprecated'):
            obj = getattr(openbadgeslib, name)
        assert obj is not None

    def test_unknown_top_level_attribute_raises(self):
        import openbadgeslib
        with pytest.raises(AttributeError):
            openbadgeslib.DefinitelyNotAThing  # noqa: B018

    @pytest.mark.parametrize('name', ['Signer', 'Verifier', 'VerifyInfo',
                                      'Badge', 'BadgeSigned', 'BadgeStatus',
                                      'extract_png_assertion'])
    def test_ob1_package_attribute_warns(self, name):
        import openbadgeslib.ob1 as ob1
        with pytest.warns(DeprecationWarning, match='OpenBadges 1.0'):
            obj = getattr(ob1, name)
        assert obj is not None

    def test_ob1_package_unknown_attribute_raises(self):
        import openbadgeslib.ob1 as ob1
        with pytest.raises(AttributeError):
            ob1.Nope  # noqa: B018

    @pytest.mark.parametrize('module', ['openbadgeslib.badge',
                                        'openbadgeslib.signer',
                                        'openbadgeslib.verifier'])
    def test_top_level_shim_warns_on_import(self, module):
        # The shim warns at module level (once per process), so force a fresh
        # execution of the module body to observe it.
        mod = importlib.import_module(module)
        with pytest.warns(DeprecationWarning, match='compatibility shim'):
            importlib.reload(mod)

    def test_warning_does_not_change_the_symbol(self):
        """The deprecation is cosmetic: the unprefixed re-export still resolves
        to the genuine ob1 class."""
        import openbadgeslib
        from openbadgeslib.ob1.signer import Signer as LeafSigner
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            assert openbadgeslib.Signer is LeafSigner


# ── the -V 1 CLI paths print a [!] notice ────────────────────────────────────

_NOTICE = 'OpenBadges 1.0 (-V 1) is deprecated'


class TestCliNotices:
    def test_publish_v1_prints_notice(self, tmp_path, capsys):
        from openbadgeslib import openbadges_publish
        # The notice prints at the top of _publish_ob1, before the config read,
        # so even a missing config surfaces it (then the CLI exits cleanly).
        argv = ['openbadges-publish', '-o', str(tmp_path / 'pub'),
                '-c', str(tmp_path / 'missing.ini'), '-V', '1']
        with patch.object(sys, 'argv', argv), pytest.raises(SystemExit):
            openbadges_publish.main()
        assert _NOTICE in capsys.readouterr().out

    def test_verifier_v1_prints_notice(self, tmp_path, capsys):
        from openbadgeslib import openbadges_verifier
        badge = tmp_path / 'badge.svg'
        badge.write_bytes(b'not a real signed badge')
        argv = ['openbadges-verifier', '-i', str(badge),
                '-r', 'user@example.com', '-V', '1']
        with patch.object(sys, 'argv', argv):
            try:
                openbadges_verifier.main()
            except SystemExit:
                pass
        assert _NOTICE in capsys.readouterr().out

    def test_verifier_v1_json_suppresses_notice(self, tmp_path, capsys):
        # --json output must stay machine-clean: the human notice is silenced.
        from openbadgeslib import openbadges_verifier
        badge = tmp_path / 'badge.svg'
        badge.write_bytes(b'not a real signed badge')
        argv = ['openbadges-verifier', '-i', str(badge),
                '-r', 'user@example.com', '-V', '1', '--json']
        with patch.object(sys, 'argv', argv):
            try:
                openbadges_verifier.main()
            except SystemExit:
                pass
        assert _NOTICE not in capsys.readouterr().out

    def test_signer_v1_prints_notice(self, tmp_path, svg_rsa_badge, capsys):
        from openbadgeslib import openbadges_signer
        (tmp_path / 'log').mkdir()
        conf = {
            'paths': {'base_log': str(tmp_path / 'log')},
            'logs': {'signer': 'signer.log'},
        }
        args = argparse.Namespace(receptor='user@example.com', expires=None,
                                  mail_badge=False)
        # Bypass the URL reachability precheck (the fixture's URLs are
        # unreachable in tests); we only care that the notice is printed.
        with patch.object(openbadges_signer.Badge, 'urls_has_problems',
                          return_value=False):
            openbadges_signer._sign_ob1(args, conf, 'badge_1', svg_rsa_badge,
                                        str(tmp_path / 'out.svg'),
                                        'user@example.com', evidence=None)
        assert _NOTICE in capsys.readouterr().out
