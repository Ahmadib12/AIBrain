import pytest

from backend.app.tools.integration_network import (
    PinnedProviderTarget,
    ProviderEgressPolicy,
    ProviderEgressRejected,
)


def _record(address: str):
    return (2, 1, 6, "", (address, 443))


def test_provider_egress_resolves_and_returns_validated_pinned_target():
    policy = ProviderEgressPolicy({"api.example.com"})
    target = policy.resolve_target(
        "https://api.example.com/v1/profile",
        resolver=lambda host, port, type: [
            _record("93.184.216.34"),
            _record("2606:2800:220:1:248:1893:25c8:1946"),
        ],
    )
    assert target == PinnedProviderTarget(
        host="api.example.com",
        port=443,
        addresses=(
            "2606:2800:220:1:248:1893:25c8:1946",
            "93.184.216.34",
        ),
    )


def test_provider_egress_rejects_mixed_public_and_private_dns_answers():
    policy = ProviderEgressPolicy({"api.example.com"})
    with pytest.raises(ProviderEgressRejected, match="prohibited address"):
        policy.resolve_target(
            "https://api.example.com/",
            resolver=lambda host, port, type: [
                _record("93.184.216.34"),
                _record("127.0.0.1"),
            ],
        )


def test_provider_egress_rejects_dns_failure_and_malformed_answers():
    policy = ProviderEgressPolicy({"api.example.com"})

    def failed(host, port, type):
        raise OSError("private resolver detail")

    with pytest.raises(ProviderEgressRejected, match="DNS resolution failed"):
        policy.resolve_target("https://api.example.com/", resolver=failed)

    with pytest.raises(ProviderEgressRejected, match="malformed"):
        policy.resolve_target(
            "https://api.example.com/",
            resolver=lambda host, port, type: [(2, 1, 6, "", ())],
        )


def test_provider_egress_does_not_resolve_hosts_outside_allowlist():
    policy = ProviderEgressPolicy({"api.example.com"})
    called = False

    def resolver(host, port, type):
        nonlocal called
        called = True
        return [_record("93.184.216.34")]

    with pytest.raises(ProviderEgressRejected, match="allowlist"):
        policy.resolve_target("https://attacker.example/", resolver=resolver)
    assert called is False
