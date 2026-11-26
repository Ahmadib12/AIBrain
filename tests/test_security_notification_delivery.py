import asyncio
from email.message import EmailMessage

import pytest

from backend.app.config import Settings
from backend.app.persistence.security_notification_transport import SmtpSecurityNotificationTransport
from backend.app.persistence.security_notification_worker import SecurityNotificationDeliveryWorker


def test_smtp_delivery_is_disabled_without_explicit_configuration():
    settings = Settings()
    assert settings.security_notification_delivery_enabled is False
    with pytest.raises(ValueError, match="not configured"):
        SmtpSecurityNotificationTransport(settings)


@pytest.mark.parametrize("values", [
    {"security_notification_smtp_host": "smtp.example.com"},
    {"security_notification_sender": "security@example.com"},
    {"security_notification_smtp_username": "user"},
    {"security_notification_smtp_password": "secret"},
])
def test_smtp_configuration_rejects_partial_configuration(values):
    with pytest.raises(ValueError):
        Settings(**values)


def test_smtp_transport_uses_verified_starttls_and_plain_text(monkeypatch):
    calls = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            calls["connect"] = (host, port, timeout)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def ehlo(self):
            calls["ehlo"] = calls.get("ehlo", 0) + 1
        def starttls(self, *, context):
            calls["tls_context"] = context
        def login(self, username, password):
            calls["login"] = (username, password)
        def send_message(self, message):
            calls["message"] = message

    monkeypatch.setattr("backend.app.persistence.security_notification_transport.smtplib.SMTP", FakeSMTP)
    settings = Settings(
        security_notification_smtp_host="smtp.example.com",
        security_notification_smtp_port=587,
        security_notification_smtp_username="mailer",
        security_notification_smtp_password="smtp-secret",
        security_notification_sender="security@example.com",
    )
    transport = SmtpSecurityNotificationTransport(settings)
    transport.send({
        "notification_type": "device.recovery.completed",
        "recipient_email": "owner@example.com",
        "payload_json": '{"device_id":"device-123","occurred_at":"2026-11-26T10:00:00+00:00"}',
    })

    assert calls["connect"] == ("smtp.example.com", 587, 10.0)
    assert calls["ehlo"] == 2
    assert calls["tls_context"].check_hostname is True
    assert calls["tls_context"].verify_mode == 2
    assert calls["login"] == ("mailer", "smtp-secret")
    message = calls["message"]
    assert isinstance(message, EmailMessage)
    assert message["To"] == "owner@example.com"
    assert "device-123" in message.get_content()
    assert "smtp-secret" not in message.get_content()
    assert message.get_content_type() == "text/plain"


class FakeRepository:
    def __init__(self, batch):
        self.batch = batch
        self.delivered = []
        self.retries = []
    def claim_batch(self, *, limit, lease_seconds=300):
        assert limit == 10
        assert lease_seconds >= 300
        return tuple(self.batch)
    def renew_claim(self, notification_id, *, lease_seconds=600):
        assert lease_seconds == 600
        return True
    def mark_delivered(self, notification_id):
        self.delivered.append(notification_id)
        return True
    def release_for_retry(self, notification_id, *, delay_seconds):
        self.retries.append((notification_id, delay_seconds))
        return True


class FakeTransport:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.sent = []
    def send(self, notification):
        self.sent.append(notification["id"])
        if self.fail:
            raise RuntimeError("private transport failure detail")


@pytest.mark.asyncio
async def test_delivery_worker_marks_successful_notifications_delivered():
    repo = FakeRepository([{"id": "n1", "attempts": 1}])
    transport = FakeTransport()
    worker = SecurityNotificationDeliveryWorker(repo, transport)
    assert await worker.run_once() == 1
    assert transport.sent == ["n1"]
    assert repo.delivered == ["n1"]
    assert repo.retries == []


@pytest.mark.asyncio
async def test_delivery_worker_releases_failed_delivery_with_bounded_backoff():
    repo = FakeRepository([{"id": "n2", "attempts": 4}])
    transport = FakeTransport(fail=True)
    worker = SecurityNotificationDeliveryWorker(repo, transport)
    assert await worker.run_once() == 0
    assert repo.delivered == []
    assert repo.retries == [("n2", 240)]


@pytest.mark.asyncio
async def test_delivery_worker_starts_and_stops_cleanly():
    repo = FakeRepository([])
    worker = SecurityNotificationDeliveryWorker(repo, FakeTransport(), interval_seconds=3600)
    await worker.start()
    task = worker._task
    await worker.start()
    assert worker._task is task
    await worker.stop()
    assert worker._task is None
