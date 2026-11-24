"""Pinned, bounded HTTPS transport for trusted integration adapters.

This transport never follows redirects, consults proxy environment variables, or
performs a second DNS lookup. It connects to one validated IP while retaining
the allowlisted DNS hostname for TLS SNI and certificate verification.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass
from typing import Callable, Mapping
from urllib.parse import urlsplit

from backend.app.tools.integration_network import (
    PinnedProviderTarget,
    ProviderEgressPolicy,
    ProviderEgressRejected,
)


class ProviderTransportRejected(PermissionError):
    """A provider request was rejected by the transport security boundary."""


@dataclass(frozen=True)
class ProviderHTTPResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_FORBIDDEN_HEADERS = {
    "host", "connection", "proxy-authorization", "proxy-connection",
    "transfer-encoding", "content-length", "upgrade", "te", "trailer",
}
_SAFE_RESPONSE_HEADERS = {"content-type", "content-length", "date", "etag"}


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials a pinned IP, not the DNS hostname."""

    def __init__(
        self,
        target: PinnedProviderTarget,
        address: str,
        *,
        timeout_seconds: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(
            target.host,
            port=target.port,
            timeout=timeout_seconds,
            context=context,
        )
        self._pinned_address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._pinned_address, self.port), self.timeout
        )
        try:
            peer = raw_socket.getpeername()[0]
            if ipaddress.ip_address(peer) != ipaddress.ip_address(self._pinned_address):
                raise ProviderTransportRejected("Connected peer differs from pinned provider IP")
            self.sock = self._context.wrap_socket(
                raw_socket, server_hostname=self.host
            )
        except Exception:
            raw_socket.close()
            raise


class PinnedProviderHTTPTransport:
    """Small GET/HEAD-only HTTPS client for trusted provider adapters.

    timeout_seconds is a socket connect/read inactivity timeout. Callers must
    also enforce an enclosing operation deadline (the integration runtime
    already applies an async adapter timeout).
    """

    def __init__(
        self,
        *,
        egress_policy: ProviderEgressPolicy,
        timeout_seconds: float = 5.0,
        max_response_bytes: int = 65_536,
        max_response_headers: int = 32,
        max_response_header_bytes: int = 16_384,
        ssl_context: ssl.SSLContext | None = None,
        resolver: Callable[..., list] | None = None,
    ) -> None:
        if not 0.1 <= timeout_seconds <= 30:
            raise ValueError("Provider transport timeout must be between 0.1 and 30 seconds")
        if not 1 <= max_response_bytes <= 1_048_576:
            raise ValueError("Provider response body bound is invalid")
        if not 1 <= max_response_headers <= 100:
            raise ValueError("Provider response header count bound is invalid")
        if not 256 <= max_response_header_bytes <= 65_536:
            raise ValueError("Provider response header byte bound is invalid")
        self.egress_policy = egress_policy
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.max_response_headers = max_response_headers
        self.max_response_header_bytes = max_response_header_bytes
        self.ssl_context = ssl_context or ssl.create_default_context()
        self.resolver = resolver

    @staticmethod
    def _request_path(url: str) -> str:
        if any(ord(char) < 33 or ord(char) > 126 or char == "\\\\" for char in url):
            raise ProviderTransportRejected("Provider URL contains prohibited characters")
        try:
            parsed = urlsplit(url)
        except ValueError:
            raise ProviderTransportRejected("Provider URL is invalid") from None
        path = parsed.path or "/"
        if not path.startswith("/") or path.startswith("//"):
            raise ProviderTransportRejected("Provider request path is invalid")
        return path + (("?" + parsed.query) if parsed.query else "")

    @staticmethod
    def _validate_request(method: str, headers: Mapping[str, str] | None, body: bytes | None) -> dict[str, str]:
        if not isinstance(method, str) or method not in {"GET", "HEAD"}:
            raise ProviderTransportRejected("Only GET and HEAD provider requests are permitted")
        if body not in (None, b""):
            raise ProviderTransportRejected("Provider request bodies are not permitted")
        if headers is None:
            return {}
        if not isinstance(headers, Mapping) or len(headers) > 24:
            raise ProviderTransportRejected("Provider request headers are invalid")
        checked: dict[str, str] = {}
        total_header_bytes = 0
        for name, value in headers.items():
            if (
                not isinstance(name, str) or not _TOKEN.fullmatch(name)
                or name.lower() in _FORBIDDEN_HEADERS
                or not isinstance(value, str)
                or len(value) > 4096
                or any((ord(char) < 32 and char != "\t") or ord(char) > 126 for char in value)
            ):
                raise ProviderTransportRejected("Provider request header is prohibited")
            total_header_bytes += len(name) + len(value) + 4
            if total_header_bytes > 16_384:
                raise ProviderTransportRejected("Provider request headers exceed the size limit")
            checked[name] = value
        return checked

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> ProviderHTTPResponse:
        request_headers = self._validate_request(method, headers, body)
        path = self._request_path(url)
        target = self.egress_policy.resolve_target(url, resolver=self.resolver)
        address = target.addresses[0]
        connection = _PinnedHTTPSConnection(
            target, address, timeout_seconds=self.timeout_seconds,
            context=self.ssl_context,
        )
        try:
            connection.request(method, path, body=None, headers=request_headers)
            response = connection.getresponse()
            raw_headers = response.getheaders()
            if len(raw_headers) > self.max_response_headers:
                raise ProviderTransportRejected("Provider response has too many headers")
            header_bytes = sum(
                len(name.encode("iso-8859-1")) + len(value.encode("iso-8859-1")) + 4
                for name, value in raw_headers
            )
            if header_bytes > self.max_response_header_bytes:
                raise ProviderTransportRejected("Provider response headers exceed the size limit")
            normalized_headers: dict[str, list[str]] = {}
            for name, value in raw_headers:
                normalized_headers.setdefault(name.lower(), []).append(value.strip())
            if any(len(values) > 1 for name, values in normalized_headers.items() if name in {"content-length", "transfer-encoding"}):
                raise ProviderTransportRejected("Provider response framing headers are ambiguous")
            if "content-length" in normalized_headers:
                try:
                    declared_length = int(normalized_headers["content-length"][0])
                except ValueError:
                    raise ProviderTransportRejected("Provider response length is invalid") from None
                if declared_length < 0 or declared_length > self.max_response_bytes:
                    raise ProviderTransportRejected("Provider response body exceeds the size limit")
            if "transfer-encoding" in normalized_headers and (
                normalized_headers["transfer-encoding"] != ["chunked"]
                or "content-length" in normalized_headers
            ):
                raise ProviderTransportRejected("Provider response transfer encoding is prohibited")
            if 300 <= response.status < 400:
                raise ProviderTransportRejected("Provider redirects are prohibited")
            body_bytes = response.read(self.max_response_bytes + 1)
            if len(body_bytes) > self.max_response_bytes:
                raise ProviderTransportRejected("Provider response body exceeds the size limit")
            if method == "GET" and "content-length" in normalized_headers and len(body_bytes) != declared_length:
                raise ProviderTransportRejected("Provider response body length does not match its declaration")
            safe_headers = tuple(
                (name.lower(), value)
                for name, value in raw_headers
                if name.lower() in _SAFE_RESPONSE_HEADERS
            )
            return ProviderHTTPResponse(
                status=response.status, headers=safe_headers, body=body_bytes
            )
        except (ProviderTransportRejected, ProviderEgressRejected):
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError):
            raise ProviderTransportRejected("Provider HTTPS request failed") from None
        finally:
            connection.close()
