"""Drobne pomocniki do targetów (host/URL)."""
from __future__ import annotations

from urllib.parse import urlparse


def host_of(target: str) -> str:
    """Wyciąga sam host z celu, który może być URL-em, host:port albo IP."""
    t = target.strip()
    if "://" in t:
        return urlparse(t).hostname or t
    # host:port lub host
    if t.count(":") == 1 and not t.startswith("["):
        return t.split(":", 1)[0]
    return t


def is_web_port(port: int, service: str = "") -> bool:
    if port in (80, 443, 8080, 8443, 8000, 8888, 3000):
        return True
    s = (service or "").lower()
    return any(k in s for k in ("http", "https", "ssl/http", "http-proxy"))


def web_url(host: str, port: int, service: str = "") -> str:
    secure = port in (443, 8443) or "https" in (service or "").lower() or "ssl" in (service or "").lower()
    scheme = "https" if secure else "http"
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    return f"{scheme}://{host}" if default else f"{scheme}://{host}:{port}"
