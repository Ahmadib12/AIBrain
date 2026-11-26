"""Strict-TLS SMTP transport for minimal security notifications."""
import json
import smtplib
import ssl
from email.message import EmailMessage

from backend.app.config import Settings


class SmtpSecurityNotificationTransport:
    """Send plain-text recovery notices over authenticated, verified STARTTLS."""

    def __init__(self, settings: Settings) -> None:
        if not settings.security_notification_delivery_enabled:
            raise ValueError("Security notification SMTP is not configured")
        self.host = settings.security_notification_smtp_host
        self.port = settings.security_notification_smtp_port
        self.username = settings.security_notification_smtp_username
        self.password = (
            settings.security_notification_smtp_password.get_secret_value()
            if settings.security_notification_smtp_password is not None else None
        )
        self.sender = settings.security_notification_sender
        self.timeout = settings.security_notification_smtp_timeout_seconds

    def send(self, notification: dict) -> None:
        if notification.get("notification_type") != "device.recovery.completed":
            raise ValueError("Unsupported security notification type")
        payload = json.loads(notification["payload_json"])
        device_id = payload.get("device_id")
        occurred_at = payload.get("occurred_at")
        if not isinstance(device_id, str) or not isinstance(occurred_at, str):
            raise ValueError("Security notification payload is invalid")

        message = EmailMessage()
        message["From"] = self.sender
        message["To"] = notification["recipient_email"]
        message["Subject"] = "AIBrain security alert: device recovery completed"
        message.set_content(
            "A device recovery was completed for your AIBrain account.\n\n"
            f"Device reference: {device_id}\n"
            f"Time (UTC): {occurred_at}\n\n"
            "If you did not authorize this recovery, secure your account immediately and review your active sessions.\n"
        )

        context = ssl.create_default_context()
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as client:
            client.ehlo()
            client.starttls(context=context)
            client.ehlo()
            if self.username is not None:
                client.login(self.username, self.password)
            client.send_message(message)
