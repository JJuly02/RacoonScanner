"""Adapter: Shodan — pasywna enumeracja hosta (zero pakietów do celu).

Odpytuje *istniejący* zbiór danych Shodana — cały ruch idzie wyłącznie do API
Shodana, nic nie leci do infrastruktury klienta. To flagowe źródło trybu
pasywnego.

Dwa źródła (opcja `api`):
  * ``internetdb`` — https://internetdb.shodan.io — darmowe, bez klucza, bez
    kredytów. Zwraca porty, hostnames, CPE, tagi i CVE (bez bannerów/SSL).
  * ``shodan``     — pełny rekord hosta (https://api.shodan.io). Wymaga klucza
    (`SHODAN_API_KEY`) i kosztuje 1 kredyt zapytania na hosta.
  * ``auto``       — (domyślne) użyj pełnego Shodana, gdy klucz jest ustawiony;
    w przeciwnym razie InternetDB.

Klucz API czytany jest wyłącznie ze zmiennej środowiskowej ``SHODAN_API_KEY``
(nigdy nie jest wpisany w kodzie ani logowany).

Korzysta ze stdlib (`urllib`), więc nie dokłada zależności do RacoonScannera.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request

from ..findings import Confidence, Finding, Severity
from ..modes import Intensity
from ..netutil import host_of, is_web_port, web_url
from .base import AdapterResult, RunContext, ToolAdapter

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
SHODAN_RESOLVE_URL = "https://api.shodan.io/dns/resolve"

# Usługi, których gołe wystawienie na świat traktujemy jako podwyższone ryzyko
# (spójne z adapterem nmap).
_RISKY = {
    23: (Severity.HIGH, "telnet", "Telnet przesyła dane otwartym tekstem — wyłącz na rzecz SSH."),
    21: (Severity.MEDIUM, "ftp", "FTP bez TLS przesyła poświadczenia otwartym tekstem — rozważ SFTP/FTPS."),
    445: (Severity.MEDIUM, "smb", "SMB wystawiony na zewnątrz — ogranicz dostęp firewallem."),
    139: (Severity.MEDIUM, "netbios", "NetBIOS/SMB wystawiony na zewnątrz — ogranicz dostęp."),
    3389: (Severity.MEDIUM, "rdp", "RDP wystawiony publicznie — użyj VPN/bastion i MFA."),
    5900: (Severity.HIGH, "vnc", "VNC często bez silnej autentykacji — ogranicz dostęp."),
    3306: (Severity.MEDIUM, "mysql", "Baza danych dostępna z zewnątrz — ogranicz do zaufanych sieci."),
    5432: (Severity.MEDIUM, "postgresql", "Baza danych dostępna z zewnątrz — ogranicz do zaufanych sieci."),
    27017: (Severity.HIGH, "mongodb", "MongoDB wystawiony publicznie bywa nieuwierzytelniony — ogranicz dostęp."),
    6379: (Severity.HIGH, "redis", "Redis domyślnie bez auth — nie wystawiaj publicznie."),
}


class ShodanAdapter(ToolAdapter):
    name = "shodan"
    binary = ""                       # to jest API HTTP, nie CLI
    intensity = Intensity.PASSIVE

    def is_available(self) -> bool:
        # Zawsze dostępny: używa stdlib i darmowego InternetDB (bez klucza).
        return True

    # --- pomocnicze (sieć) ---
    @staticmethod
    def _api_key() -> str:
        return os.environ.get("SHODAN_API_KEY", "").strip()

    @staticmethod
    def _get_json(url: str, timeout: int) -> dict | None:
        req = urllib.request.Request(url, headers={"User-Agent": "RacoonScanner/shodan"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    return None
                return json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.HTTPError, urllib.error.URLError, ValueError, TimeoutError, OSError):
            return None

    def _resolve(self, host: str, key: str, timeout: int) -> list[str]:
        """Zwraca listę adresów IP dla hosta. Preferuje pasywne dns/resolve
        Shodana (gdy jest klucz), w ostateczności resolver lokalny."""
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        if key:
            q = urllib.parse.urlencode({"hostnames": host, "key": key})
            data = self._get_json(f"{SHODAN_RESOLVE_URL}?{q}", timeout)
            if isinstance(data, dict):
                ips = [ip for ip in data.values() if ip]
                if ips:
                    return list(dict.fromkeys(ips))
        # fallback lokalny (wysyła zapytanie DNS)
        try:
            infos = socket.getaddrinfo(host, None)
            ips = []
            for info in infos:
                ip = info[4][0].split("%")[0]
                if ip not in ips:
                    ips.append(ip)
            return ips
        except (socket.gaierror, UnicodeError, OSError):
            return []

    def run(self, ctx: RunContext) -> AdapterResult:
        key = self._api_key()
        api = str(ctx.options.get("api", "auto")).lower()
        if api == "auto":
            api = "shodan" if key else "internetdb"
        if api == "shodan" and not key:
            api = "internetdb"      # brak klucza — degradujemy do darmowego źródła
        timeout = int(ctx.options.get("timeout", 30))

        host = host_of(ctx.target)
        # Jeśli poprzednie kroki znalazły już IP/subdomeny, wzbogać nimi zapytanie.
        seed_hosts = ctx.shared.get("hosts") or []
        ips: list[str] = []
        for h in [host] + list(seed_hosts):
            ips += self._resolve(h, key, timeout)
        ips = list(dict.fromkeys(ips))

        merged = AdapterResult()
        for ip in ips:
            if api == "internetdb":
                payload = self._get_json(INTERNETDB_URL.format(ip=ip), timeout)
                res = self._parse_internetdb(payload or {}, ip)
            else:
                q = urllib.parse.urlencode({"key": key, "minify": "false"})
                payload = self._get_json(f"{SHODAN_HOST_URL.format(ip=ip)}?{q}", timeout)
                res = self._parse_full(payload or {}, ip)
            merged.findings += res.findings
            for k, v in res.artifacts.items():
                merged.artifacts.setdefault(k, [])
                merged.artifacts[k] += v
            merged.raw_files[f"shodan_{api}_{ip}.json"] = json.dumps(
                payload or {}, ensure_ascii=False, indent=2)
        # deduplikacja artefaktów-list
        for k in list(merged.artifacts):
            merged.artifacts[k] = list(dict.fromkeys(merged.artifacts[k]))
        return merged

    # --- parsowanie (czyste; testowalne bez sieci) ---
    def _port_finding(self, ip: str, port: int, banner: str = "") -> Finding:
        sev, label, rec = _RISKY.get(
            port, (Severity.INFO, "", "Zweryfikuj, czy usługa musi być wystawiona publicznie."))
        svc = label or (banner.split()[0].lower() if banner else "unknown")
        return Finding(
            title=f"Otwarty port {port}/tcp ({svc}) na {ip} [Shodan]",
            category="open-port",
            severity=sev,
            confidence=Confidence.MEDIUM,   # dane pasywne bywają nieaktualne
            asset=f"{ip}:{port}",
            tool="shodan",
            evidence=banner or f"Shodan: port {port} widoczny publicznie",
            recommendation=rec,
            references=["CWE-200"],
        )

    def _vuln_finding(self, ip: str, cve: str, detail: str = "", port: int | None = None,
                      severity: Severity = Severity.HIGH) -> Finding:
        asset = f"{ip}:{port}" if port else ip
        return Finding(
            title=f"Znana podatność {cve} na {ip} [Shodan]",
            category="known-vuln",
            severity=severity,
            confidence=Confidence.MEDIUM,
            asset=asset,
            tool="shodan",
            evidence=(f"{cve} — {detail}".strip(" —") or cve),
            recommendation="Zweryfikuj wersję usługi i zainstaluj poprawki producenta; "
                           "podatność wskazana przez pasywny zbiór Shodana wymaga potwierdzenia.",
            references=[cve, "CWE-1035"] if cve.upper().startswith("CVE-") else [cve],
        )

    def _parse_internetdb(self, payload: dict, ip: str) -> AdapterResult:
        findings: list[Finding] = []
        web_targets: list[str] = []
        ports = sorted(int(p) for p in (payload.get("ports") or []))
        for port in ports:
            findings.append(self._port_finding(ip, port))
            if is_web_port(port):
                web_targets.append(web_url(ip, port))
        for cve in sorted(payload.get("vulns") or []):
            findings.append(self._vuln_finding(ip, cve))
        cpes = payload.get("cpes") or []
        for cpe in cpes:
            findings.append(Finding(
                title=f"Zidentyfikowana technologia (CPE): {cpe} na {ip} [Shodan]",
                category="service-version",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                asset=ip,
                tool="shodan",
                evidence=str(cpe),
                recommendation="Ujawniona wersja ułatwia dobranie exploita — rozważ ukrycie bannera i aktualizację.",
                references=["CWE-200"],
            ))
        artifacts: dict = {"hosts": [ip]}
        if web_targets:
            artifacts["web_targets"] = list(dict.fromkeys(web_targets))
        return AdapterResult(findings=findings, artifacts=artifacts)

    def _parse_full(self, payload: dict, ip: str) -> AdapterResult:
        findings: list[Finding] = []
        web_targets: list[str] = []
        real_ip = payload.get("ip_str", ip)
        host_vulns = set(payload.get("vulns") or [])
        for svc in payload.get("data") or []:
            port = svc.get("port")
            if not isinstance(port, int):
                continue
            product = svc.get("product") or ""
            version = svc.get("version") or ""
            banner = " ".join(x for x in (product, version) if x)
            findings.append(self._port_finding(real_ip, port, banner))
            if banner:
                findings.append(Finding(
                    title=f"Wersja usługi ujawniona: {banner} ({real_ip}:{port}) [Shodan]",
                    category="service-version",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    asset=f"{real_ip}:{port}",
                    tool="shodan",
                    evidence=banner,
                    recommendation="Ujawniona wersja ułatwia dobranie exploita — rozważ ukrycie bannera i aktualizację.",
                    references=["CWE-200"],
                ))
            svc_name = (svc.get("_shodan", {}) or {}).get("module", "") if isinstance(svc.get("_shodan"), dict) else ""
            if is_web_port(port, svc_name) or "http" in str(svc.get("transport", "")) or svc.get("http"):
                web_targets.append(web_url(real_ip, port, svc_name))
            svc_vulns = svc.get("vulns") or {}
            if isinstance(svc_vulns, dict):
                for cve, meta in svc_vulns.items():
                    host_vulns.discard(cve)
                    summary = meta.get("summary", "") if isinstance(meta, dict) else ""
                    findings.append(self._vuln_finding(real_ip, cve, summary, port))
        for cve in sorted(host_vulns):
            findings.append(self._vuln_finding(real_ip, cve))
        artifacts: dict = {"hosts": [real_ip]}
        if web_targets:
            artifacts["web_targets"] = list(dict.fromkeys(web_targets))
        return AdapterResult(findings=findings, artifacts=artifacts)
