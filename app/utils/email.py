import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import settings

logger = logging.getLogger(__name__)


async def send_password_reset_email(to_email: str, reset_link: str) -> None:
    """
    Send a password-reset email. Uses SMTP_USER/SMTP_PASSWORD from config.
    If creds are empty we just log the link (dev convenience).
    """
    subject = "Password Reset Request"
    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; background:#f4f4f4; padding:40px;">
        <div style="max-width:480px;margin:auto;background:#fff;border-radius:12px;padding:36px;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
          <h2 style="color:#1a1a2e;margin-bottom:8px;">Password Reset</h2>
          <p style="color:#555;">We received a request to reset the password for your account.</p>
          <p style="color:#555;">Click the button below. This link expires in
            <strong>{settings.PASSWORD_RESET_EXPIRE_MINUTES} minutes</strong>.
          </p>
          <a href="{reset_link}"
             style="display:inline-block;margin:20px 0;padding:14px 28px;background:#4f46e5;
                    color:#fff;border-radius:8px;text-decoration:none;font-weight:bold;">
            Reset Password
          </a>
          <p style="color:#aaa;font-size:12px;">
            If you didn't request this, ignore this email — your password won't change.
          </p>
        </div>
      </body>
    </html>
    """

    if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
        # Dev mode: just log it
        logger.warning(
            "SMTP not configured. Password reset link for %s: %s",
            to_email,
            reset_link,
        )
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USER
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(msg["From"], [to_email], msg.as_string())
        logger.info("Password reset email sent to %s", to_email)
    except Exception as exc:
        logger.error("Failed to send reset email to %s: %s", to_email, exc)
        raise
