#!/usr/bin/env python3
"""Issue badges straight from a config section with the high-level library API
(openbadgeslib.issue) — how an application integrates issuance without copying
the CLI. Shows a single badge and a batch, and verifies one of the results.

Self-contained: it writes a throwaway config, key pair and image into a temp
directory. Run it with:

    python examples/issue_from_config.py

See the "Library Integration Tutorial" wiki page for the narrative and the
"Configuration" page for the full config reference.
"""
import tempfile
from pathlib import Path

from openbadgeslib.confparser import load_config
from openbadgeslib.issue import issue_batch_from_conf, issue_from_conf
from openbadgeslib.keys import KeyFactory, KeyType
from openbadgeslib.ob3 import OB3Verifier

_MINIMAL_SVG = b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>'


def _write_project(root: Path) -> Path:
    """Write a minimal but complete issuer project (config + key + image)."""
    priv_pem, pub_pem = KeyFactory(KeyType.RSA).generate_keypair()
    (root / 'sign.pem').write_bytes(priv_pem)
    (root / 'verify.pem').write_bytes(pub_pem)
    (root / 'badge.svg').write_bytes(_MINIMAL_SVG)
    (root / 'log').mkdir()
    config = '\n'.join([
        '[paths]',
        'base = %s' % root,
        'base_log = %s/log' % root,
        'base_image = %s' % root,
        '',
        '[logs]', 'general = general.log', 'signer = signer.log',
        '',
        '[issuer]',
        'name = Example University',
        'url = https://issuer.example',
        'publish_url = https://issuer.example/',
        '',
        '[badge_python_101]',
        'name = Python 101',
        'description = Completed the introductory Python course.',
        'local_image = badge.svg',
        'image = https://issuer.example/badge.svg',
        'criteria = https://issuer.example/criteria.html',
        'verify_key = https://issuer.example/verify.pem',
        'badge = https://issuer.example/badges/python_101.json',
        'private_key = %s/sign.pem' % root,
        'public_key = %s/verify.pem' % root,
        'key_type = RSA',
    ]) + '\n'
    config_path = root / 'config.ini'
    config_path.write_text(config)
    return config_path


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        # load_config is the library entry point: it raises ConfigError (which a
        # real app would catch) instead of printing and exiting like the CLI
        # helper read_config_or_exit.
        conf = load_config(str(_write_project(root)))

        # The badge is named by its config *section*: '[badge_python_101]' →
        # 'badge_python_101' (the CLI's -b takes the short 'python_101' and
        # prepends 'badge_' for you).
        badge = 'badge_python_101'

        # 1. Issue one badge. The API returns a SignResult; YOU decide where the
        #    bytes go (a file, an object store, an email attachment, …).
        result = issue_from_conf(conf, badge, 'learner@example.com',
                                 ob_version='3')
        (root / 'learner.svg').write_bytes(result.badge_bytes)
        print('Issued jti=%s proof=%s' % (result.jti, result.proof_format))

        # 2. Issue to a whole cohort in one call (one status-registry
        #    transaction when the badge is revocable). Failures are isolated.
        cohort = ['alice@example.com', 'bob@example.com', 'carol@example.com']
        batch = issue_batch_from_conf(conf, badge, cohort, ob_version='3')
        signed = [r for r in batch if r.result is not None]
        print('Batch: %d/%d signed' % (len(signed), len(cohort)))

        # 3. Verify one of them with the issuer's public key. The SignResult
        #    carries the baked image; extract the token from it (the same thing
        #    openbadges-verifier does) and check the signature + recipient.
        pub_pem = (root / 'verify.pem').read_bytes()
        token = OB3Verifier.extract_token_from_svg(result.badge_bytes)
        verified = OB3Verifier(pubkey_pem=pub_pem).verify(
            token, expected_recipient='learner@example.com')
        print('Verified:', verified.achievement.name)

        assert verified.achievement.name == 'Python 101'


if __name__ == '__main__':
    main()
