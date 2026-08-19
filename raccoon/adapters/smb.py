"""Adapter: SMB — enumeracja udziałów przez sesję null (smbclient -N -L).

Wyzwalany, gdy nmap wykryje SMB (`smb_targets`). Próbuje anonimowo (null session)
wylistować udziały. Dostępny listing bez uwierzytelnienia to typowy błąd
konfiguracji (`guest ok`, `map to guest = bad user`).
"""
from __future__ import annotations

import re

from ..findings import Confidence, Finding, Severity
from ..modes import Intensity
from ..netutil import host_of
from .base import AdapterResult, RunContext, ToolAdapter

# Udziały domyślne/administracyjne — mniej ciekawe niż własne share'y firmy.
# (porównywane wielkimi literami — patrz s[0].upper() niżej)
_DEFAULT_SHARES = {"IPC$", "PRINT$", "ADMIN$", "C$"}


class SmbAdapter(ToolAdapter):
    name = "smb"
    binary = "smbclient"
    intensity = Intensity.ACTIVE

    def run(self, ctx: RunContext) -> AdapterResult:
        hosts = ctx.shared.get("smb_targets") or [host_of(ctx.target)]
        merged = AdapterResult()
        for host in dict.fromkeys(hosts):
            _, out = self._exec(["smbclient", "-N", "-L", f"//{host}"],
                                timeout=ctx.options.get("timeout", 60))
            res = self._parse(out, host)
            merged.findings += res.findings
            merged.raw_files[f"smb_{host}.txt"] = out
        return merged

    def _parse(self, raw: str, host: str) -> AdapterResult:
        shares = _parse_shares(raw)
        if not shares:
            return AdapterResult()

        findings: list[Finding] = []
        custom = [s for s in shares if s[0].upper() not in _DEFAULT_SHARES]
        findings.append(Finding(
            title=f"SMB null session dozwolona na {host} — {len(shares)} udziałów",
            category="service-exposure",
            severity=Severity.HIGH if custom else Severity.MEDIUM,
            confidence=Confidence.HIGH,
            asset=f"{host}:445",
            tool="smb",
            evidence="Wylistowano udziały bez uwierzytelnienia (null session):\n" +
                     "\n".join(f"  {n}\t{t}\t{c}" for n, t, c in shares),
            recommendation="Wyłącz dostęp gościa (guest ok = no, map to guest = never), "
                           "ogranicz SMB firewallem i wymagaj uwierzytelnienia.",
            references=["CWE-284", "CWE-200"],
        ))
        for name, stype, comment in custom:
            findings.append(Finding(
                title=f"Udział SMB dostępny anonimowo: {name} na {host}",
                category="smb-share",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                asset=f"//{host}/{name}",
                tool="smb",
                evidence=f"{name} ({stype}) — {comment}".strip(" —"),
                recommendation="Zweryfikuj zawartość udziału i ogranicz dostęp do uprawnionych.",
                references=["CWE-284"],
            ))
        return AdapterResult(findings=findings)


_HEADER = re.compile(r"^\s*Sharename\s+Type\s+Comment\s*$", re.IGNORECASE)
_SEP = re.compile(r"^\s*-{3,}\s+-{3,}")
# Linie kończące tabelę udziałów (kolejne sekcje / stopka smbclient).
_END = re.compile(r"^\s*(SMB1|Server\s|Workgroup\s|Reconnecting|Anonymous)", re.IGNORECASE)


def _parse_shares(raw: str) -> list[tuple[str, str, str]]:
    """Parsuje sekcję udziałów z wyjścia `smbclient -N -L`.

    Zwraca listę (nazwa, typ, komentarz). Bierze wiersze między nagłówkiem
    ``Sharename Type Comment`` a końcem tabeli (pusta linia / kolejna sekcja).
    """
    out: list[tuple[str, str, str]] = []
    in_table = False
    for line in raw.splitlines():
        if _HEADER.match(line):
            in_table = True
            continue
        if not in_table:
            continue
        if _SEP.match(line):
            continue
        if not line.strip() or _END.match(line):
            break
        parts = re.split(r"\s{2,}", line.strip())
        name = parts[0].strip()
        if not name or name.lower() == "sharename":
            continue
        stype = parts[1].strip() if len(parts) > 1 else ""
        comment = parts[2].strip() if len(parts) > 2 else ""
        out.append((name, stype, comment))
    return out
