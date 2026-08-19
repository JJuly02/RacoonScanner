"""Adapter: crt.sh — Certificate Transparency (pasywne odkrywanie subdomen).

Pyta publiczne logi CT przez https://crt.sh (JSON) — zero pakietów do celu.
Certyfikaty TLS ujawniają nazwy hostów (CN + SAN), więc CT to jedno z pierwszych
i najskuteczniejszych źródeł subdomen. Używa stdlib `urllib` (bez zależności).
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from ..findings import Confidence, Finding, Severity
from ..modes import Intensity
from ..netutil import host_of
from .base import AdapterResult, RunContext, ToolAdapter

CRTSH_URL = "https://crt.sh/?q={q}&output=json"


def _looks_like_domain(host: str) -> bool:
    # crt.sh działa dla domen, nie dla samych IP.
    parts = host.split(".")
    return len(parts) >= 2 and not host.replace(".", "").isdigit()


class CrtShAdapter(ToolAdapter):
    name = "crtsh"
    binary = ""
    intensity = Intensity.PASSIVE

    def is_available(self) -> bool:
        return True     # stdlib + publiczne API bez klucza

    def run(self, ctx: RunContext) -> AdapterResult:
        domain = host_of(ctx.target)
        if not _looks_like_domain(domain):
            return AdapterResult()
        timeout = int(ctx.options.get("timeout", 30))
        retries = int(ctx.options.get("retries", 2))
        url = CRTSH_URL.format(q=urllib.parse.quote(f"%.{domain}"))
        # crt.sh bywa przeciążony (502/503) — kilka prób z krótkim backoffem.
        raw = ""
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "RacoonScanner/crtsh"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        raw = resp.read().decode("utf-8", "replace")
                        break
            except urllib.error.HTTPError as exc:
                if exc.code not in (502, 503, 504) or attempt == retries:
                    break
            except (urllib.error.URLError, TimeoutError, OSError):
                if attempt == retries:
                    break
            time.sleep(2 * (attempt + 1))
        res = self._parse(raw, domain)
        res.raw_files["crtsh.json"] = raw
        return res

    def _parse(self, raw: str, domain: str) -> AdapterResult:
        try:
            records = json.loads(raw) if raw.strip() else []
        except json.JSONDecodeError:
            records = []
        if isinstance(records, dict):
            records = [records]

        names: set[str] = set()
        suffix = "." + domain.lower()
        for rec in records:
            if not isinstance(rec, dict):
                continue
            blob = f"{rec.get('common_name', '')}\n{rec.get('name_value', '')}"
            for name in blob.replace("\r", "\n").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if not name:
                    continue
                if name == domain.lower() or name.endswith(suffix):
                    names.add(name)

        subdomains = sorted(names)
        if not subdomains:
            return AdapterResult()

        preview = ", ".join(subdomains[:20]) + ("…" if len(subdomains) > 20 else "")
        findings = [Finding(
            title=f"Certificate Transparency: {len(subdomains)} nazw dla {domain}",
            category="cert-transparency",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            asset=domain,
            tool="crtsh",
            evidence=preview,
            recommendation="Każda subdomena z logów CT to element powierzchni ataku — "
                           "zinwentaryzuj i sprawdź, czy któraś nie jest zapomniana/porzucona.",
            references=["CWE-200"],
        )]
        return AdapterResult(findings=findings, artifacts={"subdomains": subdomains})
