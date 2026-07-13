"""Adapter: sqlmap — wykrywanie SQL injection (parsuje stdout)."""
from __future__ import annotations

import re

from ..findings import Confidence, Finding, Severity
from .base import AdapterResult, RunContext, ToolAdapter

_PARAM = re.compile(r"Parameter:\s*(?P<param>[^\(]+)\((?P<place>[^)]+)\)")
_TYPE = re.compile(r"^\s*Type:\s*(?P<type>.+)$", re.MULTILINE)
_VULN = re.compile(r"is vulnerable|following injection point", re.IGNORECASE)
_NOT_VULN = re.compile(r"all tested parameters do not appear to be injectable", re.IGNORECASE)


class SqlmapAdapter(ToolAdapter):
    name = "sqlmap"
    binary = "sqlmap"

    def run(self, ctx: RunContext) -> AdapterResult:
        urls = ctx.shared.get("web_targets") or [ctx.target]
        merged = AdapterResult()
        for i, url in enumerate(dict.fromkeys(urls)):
            _, out = self._exec(["sqlmap", "-u", url, "--batch"],
                                timeout=ctx.options.get("timeout", 300))
            res = self._parse(out, url)
            merged.findings += res.findings
            merged.raw_files[f"sqlmap_{i}.txt"] = out
        return merged

    def _parse(self, raw: str, url: str) -> AdapterResult:
        findings: list[Finding] = []
        if _VULN.search(raw):
            params = _PARAM.findall(raw)
            types = [m.group("type").strip() for m in _TYPE.finditer(raw)]
            evidence = raw[max(0, raw.lower().find("parameter:")):][:600]
            asset = url
            if params:
                asset = f"{url} (param: {params[0][0].strip()})"
            findings.append(Finding(
                title=f"Potwierdzona podatność SQL injection: {url}",
                category="injection-sqli",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                asset=asset,
                tool="sqlmap",
                evidence=(evidence or "sqlmap potwierdził injection") +
                         (f"\nTypy: {', '.join(types)}" if types else ""),
                recommendation="Użyj zapytań parametryzowanych/ORM i waliduj wejście — nie sklejaj SQL ze stringów.",
                references=["CWE-89", "OWASP-A03"],
            ))
        elif _NOT_VULN.search(raw):
            findings.append(Finding(
                title=f"Brak wykrytego SQL injection: {url}",
                category="injection-sqli",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                asset=url,
                tool="sqlmap",
                evidence="sqlmap: brak podatnych parametrów w tej rundzie",
                recommendation="Brak wykrycia nie jest dowodem bezpieczeństwa — rozważ szersze testy manualne.",
            ))
        return AdapterResult(findings=findings)
