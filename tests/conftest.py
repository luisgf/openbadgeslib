"""Shared pytest fixtures and session-level configuration."""
import os
import pytest
from pathlib import Path

TESTS_DIR = Path(__file__).parent
VERIFY_IDENTITY = 'verifytest@example.com'
VERIFY_SALT = b's4lt3d'


@pytest.fixture(autouse=True, scope='session')
def tests_dir_cwd():
    """Change cwd to tests/ so legacy relative-path fixtures keep working."""
    original = os.getcwd()
    os.chdir(TESTS_DIR)
    yield
    os.chdir(original)


# ── raw PEM bytes ──────────────────────────────────────────────────────────────

@pytest.fixture(scope='session')
def rsa_priv_pem():
    return (TESTS_DIR / 'test_sign_rsa.pem').read_bytes()

@pytest.fixture(scope='session')
def rsa_pub_pem():
    return (TESTS_DIR / 'test_verify_rsa.pem').read_bytes()

@pytest.fixture(scope='session')
def ecc_priv_pem():
    return (TESTS_DIR / 'test_sign_ecc.pem').read_bytes()

@pytest.fixture(scope='session')
def ecc_pub_pem():
    return (TESTS_DIR / 'test_verify_ecc.pem').read_bytes()


# ── raw image bytes ────────────────────────────────────────────────────────────

@pytest.fixture(scope='session')
def svg_image():
    return (TESTS_DIR / 'images' / 'sample1.svg').read_bytes()

@pytest.fixture(scope='session')
def png_image():
    return (TESTS_DIR / 'images' / 'sample1.png').read_bytes()


# ── Badge objects ──────────────────────────────────────────────────────────────

def _make_badge(key_type, priv_pem, pub_pem, image_type, image, img_ext):
    from openbadgeslib.badge import Badge
    scheme = 'https://example.com'
    return Badge(
        ini_name=f'test_{key_type.name.lower()}_{img_ext}',
        name=f'Test {img_ext.upper()} {key_type.name} Badge',
        description='Test badge',
        image_type=image_type,
        image=image,
        image_url=f'{scheme}/badge.{img_ext}',
        criteria_url=f'{scheme}/criteria.html',
        json_url=f'{scheme}/badge.json',
        verify_key_url=f'{scheme}/verify_key.pem',
        key_type=key_type,
        privkey_pem=priv_pem,
        pubkey_pem=pub_pem,
    )

@pytest.fixture(scope='session')
def svg_rsa_badge(rsa_priv_pem, rsa_pub_pem, svg_image):
    from openbadgeslib.badge import BadgeImgType
    from openbadgeslib.keys import KeyType
    return _make_badge(KeyType.RSA, rsa_priv_pem, rsa_pub_pem, BadgeImgType.SVG, svg_image, 'svg')

@pytest.fixture(scope='session')
def svg_ecc_badge(ecc_priv_pem, ecc_pub_pem, svg_image):
    from openbadgeslib.badge import BadgeImgType
    from openbadgeslib.keys import KeyType
    return _make_badge(KeyType.ECC, ecc_priv_pem, ecc_pub_pem, BadgeImgType.SVG, svg_image, 'svg')

@pytest.fixture(scope='session')
def png_rsa_badge(rsa_priv_pem, rsa_pub_pem, png_image):
    from openbadgeslib.badge import BadgeImgType
    from openbadgeslib.keys import KeyType
    return _make_badge(KeyType.RSA, rsa_priv_pem, rsa_pub_pem, BadgeImgType.PNG, png_image, 'png')

@pytest.fixture(scope='session')
def png_ecc_badge(ecc_priv_pem, ecc_pub_pem, png_image):
    from openbadgeslib.badge import BadgeImgType
    from openbadgeslib.keys import KeyType
    return _make_badge(KeyType.ECC, ecc_priv_pem, ecc_pub_pem, BadgeImgType.PNG, png_image, 'png')


# ── Signed badges ──────────────────────────────────────────────────────────────

def _sign(badge, identity='test@example.com'):
    from openbadgeslib.signer import Signer
    from openbadgeslib.badge import BadgeType
    return Signer(identity=identity, badge_type=BadgeType.SIGNED, deterministic=True).sign_badge(badge)

@pytest.fixture(scope='session')
def signed_svg_rsa(svg_rsa_badge):
    return _sign(svg_rsa_badge)

@pytest.fixture(scope='session')
def signed_svg_ecc(svg_ecc_badge):
    return _sign(svg_ecc_badge)

@pytest.fixture(scope='session')
def signed_png_rsa(png_rsa_badge):
    return _sign(png_rsa_badge)

@pytest.fixture(scope='session')
def signed_png_ecc(png_ecc_badge):
    return _sign(png_ecc_badge)


# ── BadgeSigned in "loaded from file" format (for Verifier tests) ──────────────

def _make_badge_for_verify(badge):
    """Return (BadgeSigned, identity_str) in the format Verifier.check_identity expects."""
    from openbadgeslib.badge import BadgeSigned, BadgeType
    from openbadgeslib.signer import Signer
    from openbadgeslib.util import hash_email

    signer = Signer(identity=VERIFY_IDENTITY, badge_type=BadgeType.SIGNED, deterministic=True)
    raw = signer.sign_badge(badge)

    # Simulate what BadgeSigned.read_from_file does:
    # recipient.identity in the assertion is the hashed email, not the raw email.
    hashed_identity = b'sha256$' + hash_email(VERIFY_IDENTITY, VERIFY_SALT)

    badge_verify = BadgeSigned(
        source=badge,
        serial_num=raw.serial_num,
        identity=hashed_identity,
        salt=VERIFY_SALT,
        issue_date=raw.issue_date,
        assertion=raw.assertion,
    )
    return badge_verify, VERIFY_IDENTITY

@pytest.fixture  # function-scoped: tests mutate the badge (tampered sig, expiration)
def badge_for_verify_rsa(svg_rsa_badge):
    return _make_badge_for_verify(svg_rsa_badge)

@pytest.fixture  # function-scoped: same reason
def badge_for_verify_ecc(svg_ecc_badge):
    return _make_badge_for_verify(svg_ecc_badge)


# ── OB 3.0 fixtures ────────────────────────────────────────────────────────────

@pytest.fixture(scope='session')
def ob3_credential():
    from datetime import datetime, timezone
    from openbadgeslib.ob3 import Achievement, Issuer, OpenBadgeCredential
    issuer = Issuer(
        id='https://example.com/issuer',
        name='Test Issuer',
        url='https://example.com',
    )
    achievement = Achievement(
        id='https://example.com/achievements/1',
        name='Test Achievement',
        description='Awarded for testing',
        criteria_narrative='Must pass all tests',
        image_url='https://example.com/badge.svg',
        tags=['test', 'automation'],
    )
    return OpenBadgeCredential(
        id='urn:uuid:00000000-0000-0000-0000-000000000001',
        issuer=issuer,
        recipient_id='mailto:recipient@example.com',
        achievement=achievement,
        issuance_date=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
    )

@pytest.fixture(scope='session')
def ob3_rsa_signer(rsa_priv_pem):
    from openbadgeslib.ob3 import OB3Signer
    return OB3Signer(privkey_pem=rsa_priv_pem, algorithm='RS256')

@pytest.fixture(scope='session')
def ob3_ecc_signer(ecc_priv_pem):
    from openbadgeslib.ob3 import OB3Signer
    return OB3Signer(privkey_pem=ecc_priv_pem, algorithm='ES256')

@pytest.fixture(scope='session')
def ob3_rsa_verifier(rsa_pub_pem):
    from openbadgeslib.ob3 import OB3Verifier
    return OB3Verifier(pubkey_pem=rsa_pub_pem)

@pytest.fixture(scope='session')
def ob3_ecc_verifier(ecc_pub_pem):
    from openbadgeslib.ob3 import OB3Verifier
    return OB3Verifier(pubkey_pem=ecc_pub_pem)
