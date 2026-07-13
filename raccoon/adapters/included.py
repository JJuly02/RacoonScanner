"""Adapter: INCLUDED — skaner LFI/RFI (parsuje `-of json`).

https://github.com/JJuly02/INCLUDED — CLI zwraca listę potwierdzonych znalezisk
`{module, signal, payload, status, length, evidence}`. INCLUDED weryfikuje każde
trafienie ponownym żądaniem, więc pewność mapujemy na HIGH.
"""
from __future__ import annotations

import json
import os

from ..findings import Confidence, Finding, Severity
from .base import AdapterResult, RunContext, ToolAdapter

# Moduły RCE (wykonanie kodu) vs. read (odczyt plików).
_RCE_MODULES = {"data", "input", "expect", "zip_phar", "log_poison", "filter_chain_rce", "rfi"}


class IncludedAdapter(ToolAdapter):
    name = "included"
    binary = "included"

    def run(self, ctx: RunContext) -> AdapterResult:
        param = ctx.options.get("param", "page")
        profile = ctx.options.get("profile", "all")
        bases = ctx.shared.get("web_targets") or [ctx.target]
        merged = AdapterResult()
        for i, base in enumerate(dict.fromkeys(bases)):
            url = base if "INCLUDE" in base else f"{base.rstrip('/')}/?{param}=INCLUDE"
            out_path = os.path.join(ctx.workdir, f"included_{i}.json")
            argv = ["included", "-w", url, "--profile", profile,
                    "--no-banner", "-o", out_path, "-of", "json"]
            if ctx.options.get("cmd"):
                argv += ["--cmd", ctx.options["cmd"]]
            self._exec(argv, timeout=ctx.options.get("timeout", 300))
            raw = ""
            if os.path.exists(out_path):
                with open(out_path, encoding="utf-8", errors="replace") as fh:
                    raw = fh.read()
            res = self._parse(raw, url)
            merged.findings += res.findings
            merged.raw_files[f"included_{i}.json"] = raw
        return merged

    def _parse(self, raw: str, url: str) -> AdapterResult:
        findings: list[Finding] = []
        try:
            records = json.loads(raw) if raw.strip() else []
        except json.JSONDecodeError:
            records = []
        if isinstance(records, dict):
            records = [records]
        for rec in records:
            if not isinstance(rec, dict):
                continue
            module = str(rec.get("module", "?"))
            is_rce = module in _RCE_MODULES
            findings.append(Finding(
                title=f"{'RCE przez inclusion' if is_rce else 'Local File Inclusion'} "
                      f"({module}) w {url}",
                category="lfi-rfi",
                severity=Severity.CRITICAL if is_rce else Severity.HIGH,
                confidence=Confidence.HIGH,
                asset=url,
                tool="included",
                evidence=f"[{module}] {rec.get('signal', '')} :: {rec.get('payload', '')}\n"
                         f"HTTP {rec.get('status', '?')} ({rec.get('length', '?')}B)\n"
                         f"{str(rec.get('evidence', ''))[:400]}",
                recommendation="Nie przekazuj wejścia użytkownika do include/require — użyj białej listy plików. "
                               "Wyłącz allow_url_include i ogranicz open_basedir.",
                references=["CWE-98", "CWE-22", "OWASP-A03"],
            ))
        return AdapterResult(findings=findings)
