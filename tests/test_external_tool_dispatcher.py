import json

import pytest

from backend.app.tools import (
    ExternalToolExecutionOutcome,
    ExternalToolOutcomeStatus,
    FakeExternalToolProvider,
    ToolContract,
    ToolRisk,
    execution_action_digest,
)
from backend.app.tools.dispatcher import ExternalToolDispatcher


def contract():
    return ToolContract(
        tool_id="send-message",
        name="Send message",
        description="Send a message",
        risk=ToolRisk.STATE_CHANGE,
        input_schema={
            "type": "object",
            "properties": {
                "recipient": {"type": "string"},
                "text": {"type": "string"},
            },
            "required": ["recipient", "text"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
    )


class RepositoryStub:
    def __init__(self, *, outcome=None):
        self.outcome = outcome
        self.calls = []
        self.request_id = "request-1"
        self.user_id = "user-1"
        self.payload = {"recipient": "person@example.com", "text": "Hello"}
        self.binding = None
        self.status = "claimed"

    def claim_passkey_authorized_for_execution(
        self, user_id, request_id, *, expected_contract_fingerprint
    ):
        self.calls.append("claim")
        assert user_id == self.user_id
        assert request_id == self.request_id
        return {"tool_id": "send-message", "arguments": self.payload}

    def create_execution_binding(self, user_id, request_id, **values):
        self.calls.append("binding")
        self.binding = {
            **values,
            "request_id": request_id,
            "payload_json": json.dumps(
                values["payload"], ensure_ascii=False,
                sort_keys=True, separators=(",", ":")
            ),
        }
        return self.binding

    def begin_external_dispatch(self, user_id, request_id, **values):
        self.calls.append("begin")
        return {
            "action_digest": self.binding["action_digest"],
            "idempotency_key": request_id,
        }

    def record_external_dispatch_outcome(self, user_id, request_id, **values):
        self.calls.append(("outcome", values["outcome"]))
        self.status = values["outcome"]

    def get_execution_attempt(self, user_id, request_id):
        return {"status": self.status}

    def get_execution_binding(self, user_id, request_id):
        return {
            **self.binding,
            "idempotency_key": self.request_id,
            "action_digest": self.binding["action_digest"],
            "capabilities": {
                "idempotency_mode": "provider_enforced",
                "key_scope": "provider-account-and-operation",
                "idempotency_retention_seconds": 86400,
                "rejects_payload_mismatch": True,
                "concurrent_deduplication": True,
                "supports_outcome_lookup": True,
            },
        }

    def record_external_outcome_lookup(self, user_id, request_id, **values):
        self.calls.append(("lookup", values["outcome"]))


def test_dispatch_uses_claim_binding_final_check_then_provider():
    repository = RepositoryStub()
    provider = FakeExternalToolProvider()
    dispatcher = ExternalToolDispatcher(repository)

    result = dispatcher.dispatch(
        "user-1", "request-1", contract=contract(), adapter=provider
    )

    assert result["status"] == "completed"
    assert repository.calls[:3] == ["claim", "binding", "begin"]
    assert provider.dispatch_count == 1
    assert provider.effect_count == 1
    assert repository.calls[-1] == ("outcome", "succeeded")


def test_transport_timeout_becomes_unknown_without_retry():
    repository = RepositoryStub()
    provider = FakeExternalToolProvider()
    provider.timeout_after_accept_once = True
    dispatcher = ExternalToolDispatcher(repository)

    result = dispatcher.dispatch(
        "user-1", "request-1", contract=contract(), adapter=provider
    )

    assert result == {
        "status": "outcome_unknown",
        "request_id": "request-1",
        "automatic_retry": False,
    }
    assert provider.dispatch_count == 1
    assert provider.effect_count == 1
    assert repository.calls[-1] == ("outcome", "unknown")


def test_definitive_provider_failure_is_recorded_as_failed():
    repository = RepositoryStub(
        outcome=ExternalToolExecutionOutcome(
            status=ExternalToolOutcomeStatus.FAILED,
            error_code="provider_rejected",
        )
    )
    class FailedProvider(FakeExternalToolProvider):
        def execute(self, action):
            self.dispatch_count += 1
            return repository.outcome

    provider = FailedProvider()
    result = ExternalToolDispatcher(repository).dispatch(
        "user-1", "request-1", contract=contract(), adapter=provider
    )

    assert result["status"] == "failed"
    assert repository.calls[-1] == ("outcome", "failed")


def test_read_only_contract_cannot_use_external_dispatch():
    repository = RepositoryStub()
    read_only = ToolContract(
        tool_id="send-message",
        name="Send message",
        description="Send a message",
        risk=ToolRisk.READ_ONLY,
        input_schema={"type": "object"},
        output_schema={"type": "object"},
    )
    with pytest.raises(PermissionError, match="state-change"):
        ExternalToolDispatcher(repository).dispatch(
            "user-1", "request-1",
            contract=read_only,
            adapter=FakeExternalToolProvider(),
        )
    assert repository.calls == []


def test_lookup_is_read_only_and_requires_unknown_outcome():
    repository = RepositoryStub()
    provider = FakeExternalToolProvider()
    dispatcher = ExternalToolDispatcher(repository)
    dispatcher.dispatch(
        "user-1", "request-1", contract=contract(), adapter=provider
    )
    repository.status = "outcome_unknown"
    outcome = dispatcher.lookup("user-1", "request-1", adapter=provider)

    assert outcome.status is ExternalToolOutcomeStatus.SUCCEEDED
    assert provider.dispatch_count == 1
    assert provider.lookup_count == 1
    assert repository.calls[-1] == ("lookup", "succeeded")
