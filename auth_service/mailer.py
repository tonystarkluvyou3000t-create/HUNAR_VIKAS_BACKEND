"""E-mail delivery.

Development: messages are written to an ignored outbox directory
(AUTH_MAIL_OUTBOX_DIR) as .eml files. Nothing is printed to logs, so one-time
codes never reach log output. Production uses authenticated SMTP or the Resend HTTP API (enforced in config).
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from .config import AuthConfig

log = logging.getLogger("hv_auth.mail")
TEMPLATE_DIR = Path(__file__).parent / "templates"

SUBJECTS = {
    "verify": "Verify your email \u2014 Hunar Vikas India",
    "reset": "Reset your password \u2014 Hunar Vikas India",
}
HTML_TEMPLATES = {"verify": "email-verification.html", "reset": "password-reset.html"}


class Mailer:
    def __init__(self, cfg: AuthConfig):
        self.cfg = cfg
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
            undefined=StrictUndefined,
        )

    # -- building ---------------------------------------------------------
    def _text(self, kind: str, ctx: dict) -> str:
        minutes = ctx.get("expiryMinutes")
        if kind == "verify":
            return (
                f"Your Hunar Vikas India verification code is {ctx['otp']}.\n"
                f"It expires in {minutes} minutes and works once.\n\n"
                f"Or open this link: {ctx['verificationUrl']}\n\n"
                "If you did not create an account, ignore this email."
            )
        if kind == "reset":
            return (
                f"Reset your Hunar Vikas India password: {ctx['resetUrl']}\n"
                f"The link expires in {minutes} minutes and works once.\n\n"
                "If you did not request this, ignore this email; your password is unchanged."
            )
        return (
            "Someone tried to create a Hunar Vikas India account with this email "
            "address, but an account already exists.\n"
            f"Sign in: {ctx['loginUrl']}\n"
            "If you forgot your password, use 'Forgot password?' on the sign-in page.\n"
            "If this was not you, no action is needed."
        )

    def build(self, kind: str, to: str, ctx: dict) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = SUBJECTS[kind]
        msg["From"] = self.cfg.mail_from
        msg["To"] = to
        msg.set_content(self._text(kind, ctx))
        if kind in HTML_TEMPLATES:
            html = self.env.get_template(HTML_TEMPLATES[kind]).render(**ctx)
            msg.add_alternative(html, subtype="html")
        return msg

    # -- sending ----------------------------------------------------------
    def _deliver(self, msg: EmailMessage, kind: str) -> None:
        if self.cfg.mail_backend == "file":
            outbox = Path(self.cfg.mail_outbox_dir)
            outbox.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = outbox / f"{time.time_ns()}-{kind}.eml"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(bytes(msg))
            return
        if self.cfg.mail_backend == "resend":
            html_part = msg.get_body(preferencelist=("html",))
            payload = {
                "from": msg["From"],
                "to": [msg["To"]],
                "subject": msg["Subject"],
                "text": msg.get_body(preferencelist=("plain",)).get_content(),
            }
            if html_part is not None:
                payload["html"] = html_part.get_content()
            request = urllib.request.Request(
                self.cfg.resend_api_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {self.cfg.resend_api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "HunarVikas/1.0",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    if not 200 <= response.status < 300:
                        raise RuntimeError(f"Resend returned HTTP {response.status}")
            except urllib.error.HTTPError as exc:
                err_body = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"Resend returned HTTP {exc.code}: {err_body}") from exc
            return
        with smtplib.SMTP(self.cfg.smtp_host, self.cfg.smtp_port, timeout=10) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if self.cfg.smtp_user:
                smtp.login(self.cfg.smtp_user, self.cfg.smtp_password)
            smtp.send_message(msg)

    def _send_quietly(self, kind: str, to: str, ctx: dict) -> None:
        try:
            self._deliver(self.build(kind, to, ctx), kind)
        except Exception as exc:
            log.error("mail delivery failed kind=%s error=%s", kind, type(exc).__name__)
            print(f"[MAILER ERROR] kind={kind} {type(exc).__name__}: {exc}", flush=True)

    def send(self, kind: str, to: str, ctx: dict) -> None:
        """Fire-and-forget so response time does not depend on mail delivery
        (keeps signup / forgot-password timing uniform)."""
        if self.cfg.mail_async:
            threading.Thread(
                target=self._send_quietly, args=(kind, to, ctx), daemon=True
            ).start()
        else:
            self._send_quietly(kind, to, ctx)