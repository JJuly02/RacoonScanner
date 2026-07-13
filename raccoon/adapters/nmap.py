"""Adapter: nmap — skan portów i wersji usług (parsuje wyjście XML `-oX`)."""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET

from ..findings import Confidence, Finding, Severity
from ..netutil import host_of, is_web_port, web_url
from .base import AdapterResult, RunContext, ToolAdapter

# Usługi, których gołe wystawienie na świat traktujemy jako podwyższone ryzyko.
_RISKY = {
    "telnet": (Severity.HIGH, "Telnet przesyła dane (w tym hasła) otwartym tekstem — wyłącz na rzecz SSH."),
    "ftp": (Severity.MEDIUM, "FTP bez TLS przesyła poświadczenia otwartym tekstem — rozważ SFTP/FTPS."),
    "microsoft-ds": (Severity.MEDIUM, "SMB wystawiony na zewnątrz — ogranicz dostęp firewallem."),
    "netbios-ssn": (Severity.MEDIUM, "NetBIOS/SMB wystawiony na zewnątrz — ogranicz dostęp."),
    "rdp": (Severity.MEDIUM, "RDP wystawiony publicznie — użyj VPN/bastion i MFA."),
    "ms-wbt-server": (Severity.MEDIUM, "RDP wystawiony publicznie — użyj VPN/bastion i MFA."),
    "vnc": (Severity.HIGH, "VNC często bez silnej autentykacji — ogranicz dostęp."),
    "mysql": (Severity.MEDIUM, "Baza danych dostępna z zewnątrz — ogranicz do zaufanych sieci."),
    "postgresql": (Severity.MEDIUM, "Baza danych dostępna z zewnątrz — ogranicz do zaufanych sieci."),
    "mongodb": (Severity.HIGH, "MongoDB wystawiony publicznie bywa nieuwierzytelniony — ogranicz dostęp."),
    "redis": (Severity.HIGH, "Redis domyślnie bez auth — nie wystawiaj publicznie."),
}


class NmapAdapter(ToolAdapter):
    name = "nmap"
    binary = "nmap"

    def run(self, ctx: RunContext) -> AdapterResult:
        hosts = ctx.shared.get("hosts") or [host_of(ctx.target)]
        merged = AdapterResult()
        for host in dict.fromkeys(hosts):
            xml_path = os.path.join(ctx.workdir, f"nmap_{host}.xml")
            argv = ["nmap", "-sV", "-oX", xml_path]
            if ctx.options.get("fast", True):
                argv.append("-F")
            if ctx.options.get("ports"):
                argv += ["-p", str(ctx.options["ports"])]
            argv.append(host)
            self._exec(argv, timeout=ctx.options.get("timeout", 300))
            xml = ""
            if os.path.exists(xml_path):
                with open(xml_path, encoding="utf-8", errors="replace") as fh:
                    xml = fh.read()
            res = self._parse(xml, host)
            merged.findings += res.findings
            for k, v in res.artifacts.items():
                merged.artifacts.setdefault(k, [])
                merged.artifacts[k] += v
            merged.raw_files[f"nmap_{host}.xml"] = xml
        return merged

    def _parse(self, raw_xml: str, host: str) -> AdapterResult:
        findings: list[Finding] = []
        open_ports: list[dict] = []
        web_targets: list[str] = []
        if not raw_xml.strip():
            return AdapterResult()
        try:
            root = ET.fromstring(raw_xml)
        except ET.ParseError:
            return AdapterResult()
        for host_el in root.findall("host"):
            # Preferuj adres IP (ipv4/ipv6) — nmap potrafi podać też <address addrtype="mac">.
            addr = host
            ip_addrs = [a for a in host_el.findall("address")
                        if a.get("addrtype") in ("ipv4", "ipv6")]
            if ip_addrs:
                addr = ip_addrs[0].get("addr")
            elif host_el.find("address") is not None:
                addr = host_el.find("address").get("addr")
            for port_el in host_el.findall("./ports/port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = int(port_el.get("portid"))
                proto = port_el.get("protocol", "tcp")
                svc_el = port_el.find("service")
                svc = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""
                banner = " ".join(x for x in (product, version) if x)
                open_ports.append({"host": addr, "port": portid, "proto": proto,
                                   "service": svc, "banner": banner})

                sev, rec = _RISKY.get(svc, (Severity.INFO, "Zweryfikuj, czy usługa musi być wystawiona publicznie."))
                findings.append(Finding(
                    title=f"Otwarty port {portid}/{proto} ({svc or 'unknown'}) na {addr}",
                    category="open-port",
                    severity=sev,
                    confidence=Confidence.HIGH,
                    asset=f"{addr}:{portid}",
                    tool="nmap",
                    evidence=banner or f"{svc or 'unknown'} {proto}/{portid}",
                    recommendation=rec,
                    references=["CWE-200"],
                ))
                if banner:
                    findings.append(Finding(
                        title=f"Wersja usługi ujawniona: {banner} ({addr}:{portid})",
                        category="service-version",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        asset=f"{addr}:{portid}",
                        tool="nmap",
                        evidence=banner,
                        recommendation="Ujawniona wersja ułatwia dobranie exploita — rozważ ukrycie bannera i aktualizację.",
                        references=["CWE-200"],
                    ))
                if is_web_port(portid, svc):
                    web_targets.append(web_url(addr, portid, svc))
        artifacts: dict = {}
        if open_ports:
            artifacts["open_ports"] = open_ports
        if web_targets:
            artifacts["web_targets"] = list(dict.fromkeys(web_targets))
        return AdapterResult(findings=findings, artifacts=artifacts)
