import pytest

from backend.app.tools import (
    ExecutionIdempotencyMode,
    ExternalToolExecutionCapabilities,
    ExternalToolExecutionOutcome,
    ExternalToolOutcomeStatus,
    execution_action_digest,
)


def capabilities(**overrides):
    values = {
        "provider_id": "mail-provider",
        "adapter_id": "mail-send",
        "adapter_version": "1",
        "provider_scope": "account-123",
        "idempotency_mode": ExecutionIdempotencyMode.NONE,
    }
    values.update(overrides)
    return ExternalToolExecutionCapabilities(**values)


def action_digest(**overrides):
    values = {
        "user_id": "user-1",
        "tool_id": "send-message",
        "arguments": {"recipient": "person@example.com", "text": "Hello"},
        "contract_fingerprint": "a" * 64,
        "adapter_id": "mail-send",
        "adapter_version": "1",
        "provider_scope": "account-123",
    }
    values.update(overrides)
    return execution_action_digest(**values)


def test_non_idempotent_adapter_is_valid_without_provider_guarantees():
    declared = capabilities(supports_outcome_lookup=True)

    assert declared.idempotency_mode is ExecutionIdempotencyMode.NONE
    assert declared.supports_outcome_lookup is True
    assert declared.key_scope is None


@pytest.mark.parametrize(
    "change",
    [
        {"key_scope": "account"},
        {"idempotency_retention_seconds": 600},
        {"rejects_payload_mismatch": True},
        {"concurrent_deduplication": True},
    ],
)
def test_non_idempotent_adapter_cannot_claim_partial_key_guarantees(change):
    with pytest.raises(ValueError, match="Non-idempotent"):
        capabilities(**change)


def test_provider_enforced_idempotency_requires_complete_guarantees():
    declared = capabilities(
        idempotency_mode=ExecutionIdempotencyMode.PROVIDER_ENFORCED,
        key_scope="account-and-operation",
        idempotency_retention_seconds=86_400,
        rejects_payload_mismatch=True,
        concurrent_deduplication=True,
        supports_outcome_lookup=True,
    )

    assert declared.idempotency_mode is ExecutionIdempotencyMode.PROVIDER_ENFORCED
    assert declared.idempotency_retention_seconds == 86_400


@pytest.mark.parametrize(
    "change, message",
    [
        ({"key_scope": None}, "key scope"),
        ({"idempotency_retention_seconds": None}, "positive retention"),
        ({"idempotency_retention_seconds": 0}, "positive retention"),
        ({"idempotency_retention_seconds": True}, "positive retention"),
        ({"rejects_payload_mismatch": False}, "different payloads"),
        ({"concurrent_deduplication": False}, "concurrent same-key"),
    ],
)
def test_provider_enforced_idempotency_rejects_incomplete_guarantees(
    change, message
):
    values = {
        "idempotency_mode": ExecutionIdempotencyMode.PROVIDER_ENFORCED,
        "key_scope": "account-and-operation",
        "idempotency_retention_seconds": 3600,
        "rejects_payload_mismatch": True,
        "concurrent_deduplication": True,
    }
    values.update(change)

    with pytest.raises(ValueError, match=message):
        capabilities(**values)


@pytest.mark.parametrize(
    "field",
    ["provider_id", "adapter_id", "adapter_version", "provider_scope"],
)
def test_adapter_identity_fields_must_be_non_empty(field):
    with pytest.raises(ValueError, match=field):
        capabilities(**{field: "  "})


def test_capabilities_reject_unknown_idempotency_mode():
    with pytest.raises(ValueError, match="Unsupported idempotency mode"):
        capabilities(idempotency_mode="provider_enforced")


def test_succeeded_outcome_requires_operation_reference_and_result():
    outcome = ExternalToolExecutionOutcome(
        status=ExternalToolOutcomeStatus.SUCCEEDED,
        operation_reference="provider-operation-1",
        result={"accepted": True},
        evidence_reference="provider-receipt-1",
    )

    assert outcome.status is ExternalToolOutcomeStatus.SUCCEEDED
    assert outcome.operation_reference == "provider-operation-1"


@pytest.mark.parametrize(
    "values, message",
    [
        ({}, "operation reference"),
        ({"operation_reference": "op-1"}, "result object"),
        (
            {
                "operation_reference": "op-1",
                "result": {},
                "error_code": "failed",
            },
            "cannot include an error code",
        ),
    ],
)
def test_succeeded_outcome_rejects_incomplete_or_conflicting_evidence(
    values, message
):
    with pytest.raises(ValueError, match=message):
        ExternalToolExecutionOutcome(
            status=ExternalToolOutcomeStatus.SUCCEEDED,
            **values,
        )


def test_failed_outcome_requires_bounded_error_code_and_no_result():
    outcome = ExternalToolExecutionOutcome(
        status=ExternalToolOutcomeStatus.FAILED,
        error_code="provider_rejected",
    )

    assert outcome.status is ExternalToolOutcomeStatus.FAILED


@pytest.mark.parametrize(
    "values, message",
    [
        ({}, "requires an error code"),
        ({"error_code": "rejected", "result": {}}, "cannot include a result"),
        ({"error_code": "x" * 65}, "1 to 64"),
    ],
)
def test_failed_outcome_rejects_ambiguous_or_invalid_fields(values, message):
    with pytest.raises(ValueError, match=message):
        ExternalToolExecutionOutcome(
            status=ExternalToolOutcomeStatus.FAILED,
            **values,
        )


def test_unknown_outcome_cannot_claim_success_or_definitive_failure():
    outcome = ExternalToolExecutionOutcome(
        status=ExternalToolOutcomeStatus.UNKNOWN,
        evidence_reference="timeout-after-submit",
    )
    assert outcome.status is ExternalToolOutcomeStatus.UNKNOWN

    with pytest.raises(ValueError, match="cannot claim a result"):
        ExternalToolExecutionOutcome(
            status=ExternalToolOutcomeStatus.UNKNOWN,
            result={"completed": True},
        )

    with pytest.raises(ValueError, match="cannot claim a result"):
        ExternalToolExecutionOutcome(
            status=ExternalToolOutcomeStatus.UNKNOWN,
            error_code="not_found",
        )


def test_action_digest_is_stable_for_equivalent_mapping_order():
    first = action_digest(
        arguments={"recipient": "person@example.com", "text": "Hello"}
    )
    second = action_digest(
        arguments={"text": "Hello", "recipient": "person@example.com"}
    )

    assert first == second
    assert len(first) == 64


@pytest.mark.parametrize(
    "change",
    [
        {"user_id": "another-user"},
        {"tool_id": "another-tool"},
        {"contract_fingerprint": "b" * 64},
        {"adapter_id": "another-adapter"},
        {"adapter_version": "2"},
        {"provider_scope": "another-account"},
        {"arguments": {"recipient": "person@example.com", "text": "Changed"}},
    ],
)
def test_action_digest_changes_when_any_dispatch_binding_changes(change):
    original = action_digest()
    changed = action_digest(**change)

    assert changed != original


@pytest.mark.parametrize(
    "change",
    [
        {"user_id": ""},
        {"tool_id": " "},
        {"contract_fingerprint": None},
        {"adapter_id": ""},
        {"adapter_version": " "},
        {"provider_scope": ""},
        {"arguments": []},
    ],
)
def test_action_digest_rejects_invalid_binding_values(change):
    with pytest.raises(ValueError):
        action_digest(**change)


def test_action_digest_rejects_non_finite_json_values():
    with pytest.raises(ValueError):
        action_digest(arguments={"amount": float("nan")})
