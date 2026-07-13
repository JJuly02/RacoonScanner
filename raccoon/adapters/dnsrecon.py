"""Adapter: dnsrecon — enumeracja DNS (parsuje wyjście JSON `-j`)."""
from __future__ import annotations

import json
import os

from ..findings import Confidence, Finding, Severity
from ..netutil import host_of
from .base import AdapterResult, RunContext, ToolAdapter


class DnsreconAdapter(ToolAdapter):
    name = "dnsrecon"
    binary = "dnsrecon"

    def run(self, ctx: RunContext) -> AdapterResult:
        domain = host_of(ctx.target)
        out_path = os.path.join(ctx.workdir, "dnsrecon.json")
        self._exec(["dnsrecon", "-d", domain, "-j", out_path],
                   timeout=ctx.options.get("timeout", 180))
        raw = ""
        if os.path.exists(out_path):
            with open(out_path, encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        res = self._parse(raw, domain)
        res.raw_files["dnsrecon.json"] = raw
        return res

    def _parse(self, raw: str, domain: str) -> AdapterResult:
        findings: list[Finding] = []
        hosts: list[str] = []
        subdomains: list[str] = []
        try:
            records = json.loads(raw) if raw.strip() else []
        except json.JSONDecodeError:
            records = []
        if isinstance(records, dict):
            records = [records]

        for rec in records:
            if not isinstance(rec, dict):
                continue
            rtype = str(rec.get("type", "")).upper()
            name = rec.get("name") or rec.get("target") or ""
            address = rec.get("address", "")

            if rtype in ("A", "AAAA"):
                if address:
                    hosts.append(address)
                if name:
                    subdomains.append(name)
                findings.append(Finding(
                    title=f"Rekord {rtype}: {name} -> {address}",
                    category="dns-record",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    asset=name or domain,
                    tool="dnsrecon",
                    evidence=f"{name} {rtype} {address}",
                    recommendation="Zinwentaryzuj wszystkie ujawnione hosty/subdomeny.",
                ))
            elif rtype == "AXFR" or "zone transfer" in str(rec.get("zone_transfer", "")).lower():
                findings.append(Finding(
                    title=f"Transfer strefy DNS (AXFR) możliwy dla {name or domain}",
                    category="zone-transfer",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    asset=name or domain,
                    tool="dnsrecon",
                    evidence=json.dumps(rec, ensure_ascii=False)[:400],
                    recommendation="Wyłącz transfer strefy dla nieautoryzowanych hostów — ujawnia pełną mapę DNS.",
                    references=["CWE-200"],
                ))
            elif rtype in ("NS", "MX", "SOA", "TXT", "SRV", "PTR"):
                findings.append(Finding(
                    title=f"Rekord {rtype}: {name}",
                    category="dns-record",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    asset=name or domain,
                    tool="dnsrecon",
                    evidence=json.dumps(rec, ensure_ascii=False)[:300],
                    recommendation="Element powierzchni ataku — uwzględnij w inwentarzu.",
                ))

        artifacts: dict = {}
        if hosts:
            artifacts["hosts"] = list(dict.fromkeys(hosts))
        if subdomains:
            artifacts["subdomains"] = list(dict.fromkeys(subdomains))
        return AdapterResult(findings=findings, artifacts=artifacts)
