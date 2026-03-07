"""
SSRF (Server-Side Request Forgery) protection for LLM-controlled tool calls.

Validates URLs and search queries before they reach network-calling tools
to prevent the LLM from accessing internal services, cloud metadata endpoints,
or non-HTTP resources.
"""
    
import ipaddress
import re
import socket
import logging
from urllib.parse import urlparse
from typing import Optional

logger = logging.getLogger(__name__)

class SSRFGuard:
    """Validates URLs and queries to prevent SSRF attacks from LLM tool calls."""

    # -- Blocked hostname patterns ----------------------------------------
    BLOCKED_HOSTNAMES = {
        "metadata.google.internal",
        "metadata.google.com",
        "169.254.169.254",          # AWS/GCP/Azure metadata
        "169.254.170.2",            # AWS ECS task metadata
        "fd00::1",                  # IPv6 link-local metadata
        "metadata",
        "kubernetes.default",
        "kubernetes.default.svc",
    }

    BLOCKED_HOSTNAME_PATTERNS = [
        re.compile(r"^localhost$", re.IGNORECASE),
        re.compile(r"^127\.\d+\.\d+\.\d+$"),
        re.compile(r"\.internal$", re.IGNORECASE),
        re.compile(r"\.local$", re.IGNORECASE),
        re.compile(r"^0\.0\.0\.0$"),
        re.compile(r"^\[?::1\]?$"),               # IPv6 loopback
    ]

    ALLOWED_SCHEMES = {"http", "https"}

    def __init__(self, allow_localhost_ports: Optional[list[int]] = None):
        self._allowed_localhost_ports = set(allow_localhost_ports or [])

    def validate_url(self, url: str) -> tuple[bool, str]:
        if not url or not isinstance(url, str):
            return False, "Empty or non-string URL"
        url = url.strip()
        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"URL parse error: {e}"
        if parsed.scheme and parsed.scheme.lower() not in self.ALLOWED_SCHEMES:
            return False, f"Blocked scheme: {parsed.scheme} (only http/https allowed)"
        if not parsed.scheme and not parsed.netloc:
            return True, "Not a URL (plain text query)"
        hostname = parsed.hostname
        if not hostname:
            return False, "No hostname in URL"
        hostname_lower = hostname.lower().strip(".")
        if hostname_lower in self.BLOCKED_HOSTNAMES:
            return False, f"Blocked hostname: {hostname_lower}"
        for pattern in self.BLOCKED_HOSTNAME_PATTERNS:
            if pattern.search(hostname_lower):
                if hostname_lower in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    if port in self._allowed_localhost_ports:
                        return True, f"Localhost port {port} is whitelisted"
                return False, f"Blocked hostname pattern: {hostname_lower}"
        try:
            resolved_ips = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
            for family, _, _, _, sockaddr in resolved_ips:
                ip_str = sockaddr[0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if self._is_blocked_ip(ip):
                        if ip.is_loopback:
                            port = parsed.port or (
                                443 if parsed.scheme == "https" else 80
                            )
                            if port in self._allowed_localhost_ports:
                                continue  # whitelisted
                        return False, (
                            f"Hostname {hostname} resolves to blocked IP: {ip_str}"
                        )
                except ValueError:
                    continue
        except socket.gaierror:
            pass  # DNS failure -- let the HTTP client fail naturally
        return True, "URL is safe"

    def validate_urls_in_text(self, text: str) -> tuple[bool, list[str]]:
        url_pattern = re.compile(
            r'https?://[^\s<>"]+'  # http/https URLs
            r'|(?:ftp|file|data|javascript|vbscript)://[^\s<>"]+',  # other schemes
            re.IGNORECASE,
        )
        urls = url_pattern.findall(text)
        violations: list[str] = []
        for url in urls:
            is_safe, reason = self.validate_url(url)
            if not is_safe:
                violations.append(f"{url} -> {reason}")
        return len(violations) == 0, violations

    def sanitise_search_queries(self, queries: list[str]) -> list[str]:
        safe_queries: list[str] = []
        for q in queries:
            if not isinstance(q, str):
                continue
            all_safe, violations = self.validate_urls_in_text(q)
            if all_safe:
                safe_queries.append(q)
            else:
                logger.warning(
                    "[SSRF] Blocked query with dangerous URL: %r -> %s",
                    q,
                    violations,
                )
                cleaned = re.sub(
                    r'https?://[^\s<>"]+', "[URL-REMOVED]", q
                )
                if cleaned.strip() and len(cleaned.strip()) > 3:
                    safe_queries.append(cleaned.strip())
        return safe_queries

    def sanitise_tag(self, tag: str) -> Optional[str]:
        if not tag or not isinstance(tag, str):
            return None
        cleaned = re.sub(r"[^a-zA-Z0-9\-]", "", tag.strip().lower())
        return cleaned if cleaned else None

    @staticmethod
    def _is_blocked_ip(
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or str(ip).startswith("169.254.")
        )

ssrf_guard = SSRFGuard(allow_localhost_ports=[8001])
