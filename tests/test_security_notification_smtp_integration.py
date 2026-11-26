"""Opt-in real SMTP smoke test.

Run only against a dedicated test mailbox/SMTP sandbox:
AIBRAIN_SMTP_INTEGRATION=1 plus the SMTP settings and
AIBRAIN_SECURITY_NOTIFICATION_SMTP_TEST_RECIPIENT.
"""
import os

import pytest

from backend.app.config import Settings
from backend.app.persistence.security_notification_transport import SmtpSecurityNotificationTransport


@pytest.mark.skipif(
    os.getenv("AIBRAIN_SMTP_INTEGRATION") != "1",
    reason="real SMTP smoke test is opt-in and must target a controlled test mailbox",
)
def test_real_smtp_provider_accepts_controlled_security_notice():
    recipient = os.getenv("AIBRAIN_SECURITY_NOTIFICATION_SMTP_TEST_RECIPIENT")
    if not recipient or len(recipient) > 320 or chr(13) in recipient or chr(10) in recipient:
        pytest.fail("A dedicated SMTP test recipient must be configured")
    settings = Settings()
    transport = SmtpSecurityNotificationTransport(settings)
    transport.send({
        "notification_type": "device.recovery.completed",
        "recipient_email": recipient,
        "payload_json": '{"device_id":"smtp-integration-test","occurred_at":"controlled-test"}',
    })
