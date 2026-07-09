"""#169 — dedicated tests for openbadgeslib.mail.BadgeMail, with SMTP mocked so
nothing touches the network. Covers the SSL/plain send paths, AUTH, the
graceful error path (library code must never raise/exit on a mail failure), and
the config-driven subject/body split.
"""
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from openbadgeslib.mail import BadgeMail
from openbadgeslib.ob1.badge import BadgeImgType
from openbadgeslib.errors import BadgeImgFormatUnsupported


def _badge(image_type=BadgeImgType.SVG, identity='r@example.com'):
    """A minimal stand-in for a signed Badge: send() reads get_identity(),
    source.image_type, source.image and file_out."""
    source = SimpleNamespace(image_type=image_type, image=b'<svg/>')
    return SimpleNamespace(source=source, file_out='badge_1_r.svg',
                           get_identity=lambda: identity)


def _ready_mail(**kw):
    mail = BadgeMail(mail_from='issuer@example.com', **kw)
    mail.set_subject('Your badge')
    mail.set_body('Congratulations')
    return mail


class TestInit:
    def test_username_without_ssl_is_rejected(self):
        with pytest.raises(ValueError, match='use_ssl'):
            BadgeMail(username='u', password='p', use_ssl=False)


class TestSend:
    def test_plain_smtp_sends_and_quits(self):
        mail = _ready_mail()
        with patch('openbadgeslib.mail.SMTP') as smtp_cls:
            smtp = smtp_cls.return_value
            mail.send(_badge())
        smtp.login.assert_not_called()
        smtp.sendmail.assert_called_once()
        smtp.quit.assert_called_once()
        frm, to, _body = smtp.sendmail.call_args.args
        assert frm == 'issuer@example.com' and to == 'r@example.com'

    def test_ssl_with_auth_logs_in(self):
        mail = _ready_mail(use_ssl=True, username='u', password='p')
        with patch('openbadgeslib.mail.SMTP_SSL') as ssl_cls, \
                patch('openbadgeslib.mail.SMTP') as plain_cls:
            ssl = ssl_cls.return_value
            mail.send(_badge(BadgeImgType.PNG))
        plain_cls.assert_not_called()             # SSL path only
        ssl.login.assert_called_once_with('u', 'p')
        ssl.sendmail.assert_called_once()

    def test_ssl_uses_a_validating_tls_context(self):
        # SMTP_SSL must be given a context that validates the server cert and
        # hostname; its default context does neither, which would expose the
        # AUTH credentials to an on-path attacker (#203).
        import ssl as ssl_mod
        mail = _ready_mail(use_ssl=True, username='u', password='p')
        with patch('openbadgeslib.mail.SMTP_SSL') as ssl_cls:
            mail.send(_badge())
        ctx = ssl_cls.call_args.kwargs.get('context')
        assert ctx is not None
        assert ctx.check_hostname is True
        assert ctx.verify_mode == ssl_mod.CERT_REQUIRED

    def test_smtp_error_is_reported_not_raised(self, capsys):
        from smtplib import SMTPException
        mail = _ready_mail()
        with patch('openbadgeslib.mail.SMTP') as smtp_cls:
            smtp_cls.return_value.sendmail.side_effect = SMTPException('550 no')
            mail.send(_badge())                   # must NOT raise (library code)
        assert 'Error sending mail to: r@example.com' in capsys.readouterr().out

    def test_unsupported_image_type_raises(self):
        mail = _ready_mail()
        with patch('openbadgeslib.mail.SMTP'):
            with pytest.raises(BadgeImgFormatUnsupported):
                mail.send(_badge(image_type=None))


class TestMailContent:
    def test_first_line_is_subject_rest_is_body(self, tmp_path):
        f = tmp_path / 'mail.txt'
        f.write_text('Subject line\nbody line 1\nbody line 2\n')
        subject, body = BadgeMail().get_mail_content(str(f))
        assert subject == 'Subject line'
        assert body == 'body line 1\nbody line 2\n'

    def test_empty_file_returns_none_none(self, tmp_path):
        f = tmp_path / 'empty.txt'
        f.write_text('')
        assert BadgeMail().get_mail_content(str(f)) == (None, None)
