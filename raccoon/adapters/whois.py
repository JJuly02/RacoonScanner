"""Adapter: whois - pierwsza faza rozpoznania domeny/IP.

Odpytuje serwery whois (rejestr domen / RIR), nie dotyka infrastruktury celu -
dlatego traktujemy go jako pasywny. Wyciąga rejestratora, organizację, daty
utworzenia/wygaśnięcia, nameservery i kontakt abuse. Ostrzega o bliskim
wygaśnięciu domeny.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ..findings import Confidence, Finding, Severity
from ..modes import Intensity
from ..netutil import host_of
from .base import AdapterResult, RunContext, ToolAdapter

_FIELDS = {
    "registrar": re.compile(r"^\s*Registrar:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "org": re.compile(r"^\s*(?:Registrant Organization|OrgName|org-name|organisation):\s*(.+)$",
                      re.IGNORECASE | re.MULTILINE),
    "created": re.compile(r"^\s*(?:Creation Date|Created On|created|Registered on):\s*(.+)$",
                          re.IGNORECASE | re.MULTILINE),
    "expires": re.compile(r"^\s*(?:Registry Expiry Date|Expiry Date|Expiration Date|paid-till|Expires On):\s*(.+)$",
                          re.IGNORECASE | re.MULTILINE),
    "abuse": re.compile(r"^\s*(?:Registrar Abuse Contact Email|abuse-mailbox|OrgAbuseEmail):\s*(.+)$",
                        re.IGNORECASE | re.MULTILINE),
}
_NS = re.compile(r"^\s*(?:Name Server|nserver):\s*([A-Za-z0-9.\-]+)", re.IGNORECASE | re.MULTILINE)


def _parse_date(raw: str) -> datetime | None:
    raw = (raw or "").strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d", "%d.%m.%Y"):
        try:
            dt = datetime.strptime(raw.split()[0] if fmt in ("%Y-%m-%d", "%d-%b-%Y") else raw, fmt)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        except (ValueError, IndexError):
            continue
    return None


class WhoisAdapter(ToolAdapter):
    name = "whois"
    binary = "whois"
    intensity = Intensity.PASSIVE

    def run(self, ctx: RunContext) -> AdapterResult:
        domain = host_of(ctx.target)
        _, out = self._exec(["whois", domain], timeout=ctx.options.get("timeout", 40))
        res = self._parse(out, domain)
        res.raw_files["whois.txt"] = out
        return res

    def _parse(self, raw: str, domain: str) -> AdapterResult:
        if not raw.strip():
            return AdapterResult()
        vals = {k: (m.group(1).strip() if (m := rx.search(raw)) else "") for k, rx in _FIELDS.items()}
        nameservers = list(dict.fromkeys(ns.lower() for ns in _NS.findall(raw)))

        summary = "\n".join(
            f"{lbl}: {vals[k]}" for lbl, k in
            (("Rejestrator", "registrar"), ("Organizacja", "org"),
             ("Utworzono", "created"), ("Wygasa", "expires"), ("Abuse", "abuse"))
            if vals.get(k)
        )
        if nameservers:
            summary += ("\n" if summary else "") + "NS: " + ", ".join(nameservers)

        findings = []
        if summary:
            findings.append(Finding(
                title=f"Dane rejestracyjne domeny {domain}",
                category="domain-info",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                asset=domain,
                tool="whois",
                evidence=summary,
                recommendation="Zinwentaryzuj właściciela domeny, nameservery i kontakt abuse "
                               "(przydatne przy zgłaszaniu incydentów).",
            ))

        expires = _parse_date(vals.get("expires", ""))
        if expires:
            days = (expires - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(Finding(
                    title=f"Domena {domain} WYGASŁA ({vals['expires']})",
                    category="domain-expiry", severity=Severity.HIGH, confidence=Confidence.HIGH,
                    asset=domain, tool="whois", evidence=f"Data wygaśnięcia: {vals['expires']}",
                    recommendation="Domena wygasła - ryzyko przejęcia (domain hijacking). Odnów natychmiast.",
                ))
            elif days <= 30:
                findings.append(Finding(
                    title=f"Domena {domain} wygasa za {days} dni",
                    category="domain-expiry", severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                    asset=domain, tool="whois", evidence=f"Data wygaśnięcia: {vals['expires']}",
                    recommendation="Zbliża się wygaśnięcie domeny - odnów, by uniknąć przerw i przejęcia.",
                ))

        artifacts = {"nameservers": nameservers} if nameservers else {}
        return AdapterResult(findings=findings, artifacts=artifacts)
