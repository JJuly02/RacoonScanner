"""Rejestr adapterów narzędzi — mapa nazwa -> instancja."""
from __future__ import annotations

from .base import AdapterResult, RunContext, ToolAdapter, ToolUnavailable
from .crtsh import CrtShAdapter
from .dnsrecon import DnsreconAdapter
from .included import IncludedAdapter
from .nmap import NmapAdapter
from .ping import PingAdapter
from .shodan import ShodanAdapter
from .smb import SmbAdapter
from .sqlmap import SqlmapAdapter
from .whatweb import WhatwebAdapter
from .whois import WhoisAdapter

REGISTRY: dict[str, ToolAdapter] = {
    a.name: a for a in (
        WhoisAdapter(),
        CrtShAdapter(),
        ShodanAdapter(),
        PingAdapter(),
        NmapAdapter(),
        WhatwebAdapter(),
        DnsreconAdapter(),
        SmbAdapter(),
        SqlmapAdapter(),
        IncludedAdapter(),
    )
}


def get_adapter(name: str) -> ToolAdapter:
    try:
        return REGISTRY[name]
    except KeyError:
        raise KeyError(f"Nieznany adapter: {name!r}. Dostępne: {', '.join(REGISTRY)}")


__all__ = [
    "REGISTRY", "get_adapter", "ToolAdapter", "RunContext",
    "AdapterResult", "ToolUnavailable",
]
