"""Adapter: ping — sprawdzenie dostępności hosta (faza discovery)."""
from __future__ import annotations

import re

from ..findings import Confidence, Finding, Severity
from ..netutil import host_of
from .base import AdapterResult, RunContext, ToolAdapter

_LOSS = re.compile(r"([\d.]+)%\s+packet loss")


class PingAdapter(ToolAdapter):
    name = "ping"
    binary = "ping"

    def run(self, ctx: RunContext) -> AdapterResult:
        host = host_of(ctx.target)
        count = str(int(ctx.options.get("count", 4)))
        rc, out = self._exec(["ping", "-c", count, host], timeout=30)
        return self._parse(out, host)

    def _parse(self, raw: str, host: str) -> AdapterResult:
        m = _LOSS.search(raw)
        loss = float(m.group(1)) if m else 100.0
        if loss < 100.0:
            f = Finding(
                title=f"Host {host} odpowiada na ICMP",
                category="host-alive",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                asset=host,
                tool="ping",
                evidence=f"packet loss: {loss}%",
                recommendation="Host aktywny — kontynuuj enumerację.",
            )
            return AdapterResult(findings=[f], artifacts={"hosts": [host]},
                                 raw_files={"ping.txt": raw})
        f = Finding(
            title=f"Host {host} nie odpowiada na ICMP",
            category="host-alive",
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            asset=host,
            tool="ping",
            evidence="100% packet loss (ICMP może być filtrowany)",
            recommendation="Brak odpowiedzi ICMP nie oznacza, że host jest offline — spróbuj skanu TCP.",
        )
        return AdapterResult(findings=[f], artifacts={}, raw_files={"ping.txt": raw})
