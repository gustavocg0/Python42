"""Outbound email behind a small interface (dev: mailpit SMTP or console log).

SMTP delivery runs in a worker thread (smtplib is blocking; handlers stay
async-clean). The console fallback logs the recipient and subject only — the
body carries single-use tokens and is never logged (SEC-49); dev reads bodies
from mailpit instead.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
from email.message import EmailMessage
from typing import Protocol

from controlplane.config import Settings

logger = logging.getLogger(__name__)


class Mailer(Protocol):
    async def send(self, *, to: str, subject: str, body: str) -> None: ...


class ConsoleMailer:
    """Log-only fallback. Bodies (which contain tokens) are NOT logged."""

    async def send(self, *, to: str, subject: str, body: str) -> None:
        logger.info(
            "email suppressed (console mailer)",
            extra={"mail_to": to, "mail_subject": subject, "mail_bytes": len(body)},
        )


class SmtpMailer:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def send(self, *, to: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = self._settings.smtp_from
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)
        await asyncio.to_thread(self._deliver, message)

    def _deliver(self, message: EmailMessage) -> None:
        with smtplib.SMTP(self._settings.smtp_host, self._settings.smtp_port, timeout=10) as smtp:
            if self._settings.smtp_starttls:
                smtp.starttls()
            if self._settings.smtp_username:
                smtp.login(self._settings.smtp_username, self._settings.smtp_password)
            smtp.send_message(message)


def build_mailer(settings: Settings) -> Mailer:
    if settings.mailer == "smtp":
        return SmtpMailer(settings)
    return ConsoleMailer()
