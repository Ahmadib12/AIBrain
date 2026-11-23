from concurrent.futures import ThreadPoolExecutor

import pytest

from backend.app.tools import (
    ExecutionIdempotencyMode,
    ExternalToolOutcomeStatus,
    execution_action_digest,
)
from backend.app.tools.external import ExternalToolAction, ExternalToolAdapter
from backend.app.tools.fake_provider import (
    FakeExternalToolProvider,
    FakeProviderTimeout,
)


def make_action(*, key="request-1", payload=None):
    payload = payload or {"recipient": "person@example.com", "text": "Hello"}
    digest = execution_action_digest(
        user_id="user-1",
        tool_id="send-message",
        arguments=payload,
        contract_fingerprint="a" * 64,
        adapter_id="fake-adapter",
        adapter_version="1",
        provider_scope="fake-account",
    )
    return ExternalToolAction.from_payload(
        idempotency_key=key,
        action_digest=digest,
        payload=payload,
    )


def test_fake_provider_implements_provider_neutral_adapter_protocol():
    provider = FakeExternalToolProvider()

    assert isinstance(provider, ExternalToolAdapter)
    assert provider.capabilities.idempotency_mode is (
        ExecutionIdempotencyMode.PROVIDER_ENFORCED
    )


def test_action_payload_is_canonical_and_defensively_copied():
    source = {"z": 1, "a": {"value": 2}}
    action = make_action(payload=source)
    source["z"] = 99
    returned = action.payload()
    returned["a"]["value"] = 100

    assert action.payload() == {"a": {"value": 2}, "z": 1}
    assert action.payload_json == '{"a":{"value":2},"z":1}'


@pytest.mark.parametrize(
    "values",
    [
        {"idempotency_key": "", "action_digest": "a" * 64, "payload_json": "{}"},
        {"idempotency_key": "key", "action_digest": "A" * 64, "payload_json": "{}"},
        {"idempotency_key": "key", "action_digest": "a" * 64, "payload_json": "{ }"},
        {"idempotency_key": "key", "action_digest": "a" * 64, "payload_json": "[]"},
    ],
)
def test_action_rejects_invalid_or_noncanonical_envelopes(values):
    with pytest.raises(ValueError):
        ExternalToolAction(**values)


def test_same_key_same_action_is_deduplicated():
    provider = FakeExternalToolProvider()
    action = make_action()

    first = provider.execute(action)
    second = provider.execute(action)

    assert first.status is ExternalToolOutcomeStatus.SUCCEEDED
    assert second.operation_reference == first.operation_reference
    assert provider.dispatch_count == 2
    assert provider.effect_count == 1


def test_same_key_different_action_is_rejected_without_second_effect():
    provider = FakeExternalToolProvider()

    provider.execute(make_action())
    with pytest.raises(ValueError, match="different action"):
        provider.execute(
            make_action(payload={"recipient": "other@example.com", "text": "Hello"})
        )

    assert provider.effect_count == 1


def test_timeout_after_acceptance_is_resolved_by_lookup_without_resubmit():
    provider = FakeExternalToolProvider()
    provider.timeout_after_accept_once = True
    action = make_action()

    with pytest.raises(FakeProviderTimeout):
        provider.execute(action)

    outcome = provider.lookup(action.idempotency_key)

    assert outcome.status is ExternalToolOutcomeStatus.SUCCEEDED
    assert outcome.evidence_reference == "fake-provider-lookup"
    assert provider.effect_count == 1
    assert provider.dispatch_count == 1
    assert provider.lookup_count == 1


def test_failure_before_acceptance_leaves_no_provider_effect():
    def reject_before_acceptance(action):
        raise ConnectionError("simulated connection failure before acceptance")

    provider = FakeExternalToolProvider(before_accept=reject_before_acceptance)
    action = make_action()

    with pytest.raises(ConnectionError, match="before acceptance"):
        provider.execute(action)

    outcome = provider.lookup(action.idempotency_key)
    assert outcome.status is ExternalToolOutcomeStatus.UNKNOWN
    assert provider.dispatch_count == 0
    assert provider.effect_count == 0


def test_lookup_for_unseen_key_is_unknown_and_never_dispatches():
    provider = FakeExternalToolProvider()

    outcome = provider.lookup("not-submitted")

    assert outcome.status is ExternalToolOutcomeStatus.UNKNOWN
    assert provider.dispatch_count == 0
    assert provider.effect_count == 0


def test_concurrent_same_key_submissions_create_one_effect():
    provider = FakeExternalToolProvider()
    action = make_action()

    with ThreadPoolExecutor(max_workers=12) as pool:
        outcomes = list(pool.map(lambda _: provider.execute(action), range(12)))

    assert all(
        outcome.status is ExternalToolOutcomeStatus.SUCCEEDED
        for outcome in outcomes
    )
    assert len({outcome.operation_reference for outcome in outcomes}) == 1
    assert provider.dispatch_count == 12
    assert provider.effect_count == 1


def test_non_idempotent_provider_can_create_duplicate_effects():
    provider = FakeExternalToolProvider(
        idempotency_mode=ExecutionIdempotencyMode.NONE
    )
    action = make_action()

    first = provider.execute(action)
    second = provider.execute(action)

    assert first.operation_reference != second.operation_reference
    assert provider.effect_count == 2
