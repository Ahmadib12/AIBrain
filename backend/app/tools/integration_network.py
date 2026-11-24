"""Strict URL and DNS validation primitives for future provider transports.

A provider adapter must disable redirects and pin the validated DNS answers to
its socket connection. This module does not perform HTTP requests itself.
"""
import ipaddress
from urllib.parse import urlsplit


class ProviderEgressRejected(PermissionError):
    pass


class ProviderEgressPolicy:
    def __init__(self, allowed_hosts: set[str]) -> None:
        normalized = set()
        for host in allowed_hosts:
            if not isinstance(host, str) or not host or host != host.lower():
                raise ValueError("Provider allowlist hosts must be lowercase DNS names")
            if host.endswith(".") or "/" in host or ":" in host:
                raise ValueError("Provider allowlist host is invalid")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                raise ValueError("Provider allowlist must contain DNS names, not IP addresses")
            normalized.add(host)
        self.allowed_hosts = frozenset(normalized)

    def validate_url(self, url: str) -> str:
        if not isinstance(url, str) or len(url) > 2048:
            raise ProviderEgressRejected("Provider URL is invalid")
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            port = parsed.port
        except ValueError:
            raise ProviderEgressRejected("Provider URL is invalid") from None
        if (
            parsed.scheme != "https" or not host or host != host.lower()
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or port not in (None, 443)
            or host not in self.allowed_hosts
        ):
            raise ProviderEgressRejected("Provider URL is outside the HTTPS host allowlist")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return host
        raise ProviderEgressRejected("IP-literal provider targets are prohibited")

    @staticmethod
    def validate_resolved_addresses(addresses: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        if not addresses:
            raise ProviderEgressRejected("Provider DNS resolution returned no addresses")
        normalized = []
        for raw in addresses:
            try:
                address = ipaddress.ip_address(raw)
            except ValueError:
                raise ProviderEgressRejected("Provider DNS answer is invalid") from None
            if (
                not address.is_global or address.is_private or address.is_loopback
                or address.is_link_local or address.is_multicast or address.is_reserved
                or address.is_unspecified
            ):
                raise ProviderEgressRejected("Provider DNS answer resolves to a prohibited address")
            normalized.append(str(address))
        return tuple(sorted(set(normalized)))
