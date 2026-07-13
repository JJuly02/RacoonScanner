"""Rejestr adapterów narzędzi — mapa nazwa -> instancja."""
from __future__ import annotations

from .base import AdapterResult, RunContext, ToolAdapter, ToolUnavailable
from .dnsrecon import DnsreconAdapter
from .included import IncludedAdapter
from .nmap import NmapAdapter
from .ping import PingAdapter
from .sqlmap import SqlmapAdapter
from .whatweb import WhatwebAdapter

REGISTRY: dict[str, ToolAdapter] = {
    a.name: a for a in (
        PingAdapter(),
        NmapAdapter(),
        WhatwebAdapter(),
        DnsreconAdapter(),
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
