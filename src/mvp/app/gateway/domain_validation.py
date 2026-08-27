"""
Domain validation helpers for tool URL arguments.

This stage is separate from the policy engine by design. It enforces
URL/hostname constraints tied to tool execution behavior.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from app.models import DomainValidationResult
from app.policy.config_loader import load_tool_registry

_registry = load_tool_registry()
_allowlist = _registry.get("domain_allowlist", [])
DOMAIN_ALLOWLIST: set[str] = {
    str(domain).strip().lower().rstrip(".") for domain in _allowlist if str(domain).strip()
}

_URL_ARG_NAMES: tuple[str, ...] = ("url", "audio_url", "image_url", "document_url")

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private_ip(hostname: str) -> bool:
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETWORKS)


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _is_domain_allowed(hostname: str) -> bool:
    for allowed in DOMAIN_ALLOWLIST:
        if hostname == allowed or hostname.endswith("." + allowed):
            return True
    return False


def _is_domain_user_approved(hostname: str, approved_domains: list[str]) -> bool:
    for approved in approved_domains:
        normalized = _normalize_domain(approved)
        if not normalized:
            continue
        if hostname == normalized or hostname.endswith("." + normalized):
            return True
    return False


def _extract_url_args(tool_args: dict[str, object] | None) -> list[tuple[str, str]]:
    if not tool_args:
        return []

    found: list[tuple[str, str]] = []
    for arg_name in _URL_ARG_NAMES:
        value = tool_args.get(arg_name)
        if isinstance(value, str) and value.strip():
            found.append((arg_name, value.strip()))
    return found


def validate_tool_urls(
    tool_args: dict[str, object] | None,
    approved_domains: list[str] | None = None,
) -> list[DomainValidationResult]:
    """Validate URL-bearing tool arguments against allowlist and approval set."""
    approved_domains = approved_domains or []
    entries: list[DomainValidationResult] = []

    for arg_name, raw_url in _extract_url_args(tool_args):
        url_for_parse = raw_url if "://" in raw_url else f"https://{raw_url}"
        parsed = urlparse(url_for_parse)
        hostname = (parsed.hostname or "").strip().lower().rstrip(".")

        if not hostname:
            entries.append(
                DomainValidationResult(
                    arg_name=arg_name,
                    url=raw_url,
                    hostname="",
                    is_allowed=False,
                    is_approved=False,
                    warning="Could not parse hostname from URL.",
                )
            )
            continue

        if _is_private_ip(hostname):
            entries.append(
                DomainValidationResult(
                    arg_name=arg_name,
                    url=raw_url,
                    hostname=hostname,
                    is_allowed=False,
                    is_approved=False,
                    warning="Hostname resolves to a private/internal address and is blocked.",
                )
            )
            continue

        is_allowed = _is_domain_allowed(hostname)
        is_user_approved = _is_domain_user_approved(hostname, approved_domains)
        is_approved = is_allowed or is_user_approved

        warning = None
        if not is_approved:
            warning = "Domain is not in the allowlist and has not been user-approved."

        entries.append(
            DomainValidationResult(
                arg_name=arg_name,
                url=raw_url,
                hostname=hostname,
                is_allowed=is_allowed,
                is_approved=is_approved,
                warning=warning,
            )
        )

    return entries
