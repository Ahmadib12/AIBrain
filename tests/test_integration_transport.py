import pytest

from backend.app.tools.integration_network import ProviderEgressPolicy
from backend.app.tools.integration_transport import (
    PinnedProviderHTTPTransport,
    ProviderTransportRejected,
    _PinnedHTTPSConnection,
)


def _record(address):
    return (2, 1, 6, "", (address, 443))


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b'{"ok":true}'):
        self.status = status
        self._headers = headers or [("Content-Type", "application/json")]
        self._body = body

    def getheaders(self):
        return self._headers

    def read(self, size):
        return self._body[:size]


class FakeConnection:
    instances = []
    default_response = FakeResponse()

    def __init__(self, target, address, *, timeout_seconds, context):
        self.target = target
        self.address = address
        self.timeout_seconds = timeout_seconds
        self.context = context
        self.response = type(self).default_response
        self.request_args = None
        self.closed = False
        self.instances.append(self)

    def request(self, method, path, *, body, headers):
        self.request_args = (method, path, body, headers)

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def _transport(monkeypatch, *, response=None, **kwargs):
    FakeConnection.instances.clear()
    FakeConnection.default_response = FakeResponse()
    monkeypatch.setattr(
        "backend.app.tools.integration_transport._PinnedHTTPSConnection",
        FakeConnection,
    )
    transport = PinnedProviderHTTPTransport(
        egress_policy=ProviderEgressPolicy({"api.example.com"}),
        resolver=lambda host, port, type: [_record("93.184.216.34")],
        **kwargs,
    )
    if response is not None:
        FakeConnection.default_response = response
    return transport


def test_transport_sends_only_to_validated_target_and_returns_bounded_safe_headers(monkeypatch):
    transport = _transport(monkeypatch)
    result = transport.request(
        "https://api.example.com/v1/items?q=one",
        headers={"Accept": "application/json"},
    )
    connection = FakeConnection.instances[-1]
    assert connection.address == "93.184.216.34"
    assert connection.request_args == (
        "GET", "/v1/items?q=one", None, {"Accept": "application/json"}
    )
    assert result.status == 200
    assert result.body == b'{"ok":true}'
    assert result.headers == (("content-type", "application/json"),)
    assert connection.closed is True


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "TRACE"])
def test_transport_rejects_non_read_methods_before_dns_or_network(monkeypatch, method):
    transport = _transport(monkeypatch)
    with pytest.raises(ProviderTransportRejected, match="Only GET and HEAD"):
        transport.request("https://api.example.com/", method=method)
    assert not FakeConnection.instances


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "attacker.example"},
        {"Connection": "close"},
        {"Proxy-Authorization": "secret"},
        {"X-Test": "safe\r\nInjected: yes"},
    ],
)
def test_transport_rejects_forbidden_or_injected_request_headers(monkeypatch, headers):
    transport = _transport(monkeypatch)
    with pytest.raises(ProviderTransportRejected, match="header"):
        transport.request("https://api.example.com/", headers=headers)
    assert not FakeConnection.instances


def test_transport_rejects_request_body_and_redirects(monkeypatch):
    transport = _transport(monkeypatch)
    with pytest.raises(ProviderTransportRejected, match="bodies"):
        transport.request("https://api.example.com/", body=b"payload")

    transport = _transport(monkeypatch)
    FakeConnection.default_response = FakeResponse(status=302, headers=[("Location", "https://evil.example/")])
    with pytest.raises(ProviderTransportRejected, match="redirects"):
        transport.request("https://api.example.com/")


def test_transport_rejects_oversized_response_body_and_headers(monkeypatch):
    transport = _transport(monkeypatch, max_response_bytes=8)
    FakeConnection.default_response = FakeResponse(body=b"0123456789")
    with pytest.raises(ProviderTransportRejected, match="body exceeds"):
        transport.request("https://api.example.com/")

    transport = _transport(monkeypatch, max_response_headers=1)
    FakeConnection.default_response = FakeResponse(headers=[("A", "1"), ("B", "2")])
    with pytest.raises(ProviderTransportRejected, match="too many headers"):
        transport.request("https://api.example.com/")


def test_transport_rejects_oversized_header_bytes(monkeypatch):
    transport = _transport(monkeypatch, max_response_header_bytes=256)
    FakeConnection.default_response = FakeResponse(headers=[("X-Long", "v" * 300)])
    with pytest.raises(ProviderTransportRejected, match="headers exceed"):
        transport.request("https://api.example.com/")


def test_transport_rejects_invalid_url_and_host_allowlist(monkeypatch):
    transport = _transport(monkeypatch)
    for url in (
        "http://api.example.com/",
        "https://attacker.example/",
        "https://api.example.com:444/",
        "https://user@api.example.com/",
        "https://api.example.com/#fragment",
        "https://api.example.com/\r\nInjected",
    ):
        with pytest.raises((ProviderTransportRejected, PermissionError)):
            transport.request(url)
    assert not FakeConnection.instances


def test_pinned_connection_dials_ip_but_uses_hostname_for_tls(monkeypatch):
    from backend.app.tools.integration_network import PinnedProviderTarget

    calls = {}

    class RawSocket:
        def getpeername(self):
            return ("93.184.216.34", 443)

        def close(self):
            calls["raw_closed"] = True

    class Context:
        def wrap_socket(self, raw, *, server_hostname):
            calls["server_hostname"] = server_hostname
            return "tls-socket"

    def create_connection(address, timeout):
        calls["address"] = address
        calls["timeout"] = timeout
        return RawSocket()

    monkeypatch.setattr(
        "backend.app.tools.integration_transport.socket.create_connection",
        create_connection,
    )
    target = PinnedProviderTarget(
        host="api.example.com", port=443, addresses=("93.184.216.34",)
    )
    connection = _PinnedHTTPSConnection(
        target, "93.184.216.34", timeout_seconds=3, context=Context()
    )
    connection.connect()
    assert calls["address"] == ("93.184.216.34", 443)
    assert calls["server_hostname"] == "api.example.com"
    assert connection.sock == "tls-socket"


def test_pinned_connection_closes_socket_if_peer_does_not_match(monkeypatch):
    from backend.app.tools.integration_network import PinnedProviderTarget

    class RawSocket:
        closed = False

        def getpeername(self):
            return ("127.0.0.1", 443)

        def close(self):
            self.closed = True

    raw = RawSocket()
    monkeypatch.setattr(
        "backend.app.tools.integration_transport.socket.create_connection",
        lambda address, timeout: raw,
    )
    target = PinnedProviderTarget(
        host="api.example.com", port=443, addresses=("93.184.216.34",)
    )
    connection = _PinnedHTTPSConnection(
        target, "93.184.216.34", timeout_seconds=3, context=object()
    )
    with pytest.raises(ProviderTransportRejected, match="pinned provider IP"):
        connection.connect()
    assert raw.closed



@pytest.mark.parametrize(
    "headers",
    [
        [("Content-Length", "1"), ("Content-Length", "1")],
        [("Content-Length", "999"),],
        [("Transfer-Encoding", "gzip"),],
        [("Content-Length", "1"), ("Transfer-Encoding", "chunked")],
    ],
)
def test_transport_rejects_ambiguous_or_oversized_response_framing(monkeypatch, headers):
    transport = _transport(monkeypatch, max_response_bytes=32)
    FakeConnection.default_response = FakeResponse(headers=headers)
    with pytest.raises(ProviderTransportRejected):
        transport.request("https://api.example.com/")
