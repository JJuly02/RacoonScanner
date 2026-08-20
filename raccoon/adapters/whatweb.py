"""Adapter: whatweb - fingerprint technologii web (parsuje `--log-json`)."""
from __future__ import annotations

import json
import os

from ..findings import Confidence, Finding, Severity
from ..modes import Intensity
from .base import AdapterResult, RunContext, ToolAdapter

# Pluginy, które oznaczają technologię wartą osobnego findingu (ekspozycja/wersja).
_NOTABLE = {"apache", "nginx", "php", "wordpress", "joomla", "drupal", "iis",
            "openssl", "jquery", "tomcat", "phpmyadmin"}


class WhatwebAdapter(ToolAdapter):
    name = "whatweb"
    binary = "whatweb"
    intensity = Intensity.ACTIVE

    def run(self, ctx: RunContext) -> AdapterResult:
        urls = ctx.shared.get("web_targets") or [ctx.target]
        merged = AdapterResult()
        for i, url in enumerate(dict.fromkeys(urls)):
            out_path = os.path.join(ctx.workdir, f"whatweb_{i}.json")
            self._exec(["whatweb", "-a", "3", "--no-errors",
                        f"--log-json={out_path}", url],
                       timeout=ctx.options.get("timeout", 120))
            raw = ""
            if os.path.exists(out_path):
                with open(out_path, encoding="utf-8", errors="replace") as fh:
                    raw = fh.read()
            res = self._parse(raw, url)
            merged.findings += res.findings
            for k, v in res.artifacts.items():
                merged.artifacts.setdefault(k, [])
                merged.artifacts[k] += v
            merged.raw_files[f"whatweb_{i}.json"] = raw
        return merged

    def _parse(self, raw: str, url: str) -> AdapterResult:
        findings: list[Finding] = []
        tech: list[str] = []
        detail: list[str] = []          # pełny odcisk: plugin => wartości
        target = url
        for obj in _iter_json_objects(raw):
            target = obj.get("target", url)
            status = obj.get("http_status")
            plugins = obj.get("plugins", {}) or {}
            for name, data in sorted(plugins.items(), key=lambda kv: kv[0].lower()):
                version = ""
                extra = ""
                if isinstance(data, dict):
                    v = data.get("version") or []
                    version = ", ".join(map(str, v)) if isinstance(v, list) else str(v)
                    strings = data.get("string") or []
                    if isinstance(strings, list) and strings:
                        extra = "; ".join(map(str, strings[:3]))
                label = f"{name} {version}".strip()
                tech.append(label)
                line = f"  • {name}" + (f" [{version}]" if version else "") + (f" - {extra}" if extra else "")
                detail.append(line)
                if name.lower() in _NOTABLE:
                    findings.append(Finding(
                        title=f"Wykryto technologię: {label}",
                        category="web-tech",
                        severity=Severity.INFO if not version else Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        asset=target,
                        tool="whatweb",
                        evidence=label,
                        recommendation="Zweryfikuj, czy wersja jest aktualna i czy nie ujawnia zbędnych informacji.",
                        references=["CWE-200"],
                    ))

        # Zawsze emituj pełny odcisk web - nawet jeśli nic „notable"/nic nie wykryto,
        # żeby w raporcie było widać, co dokładnie zobaczył fingerprinting.
        head = f"HTTP {status}" if (status := _first_status(raw)) else "odpowiedź web"
        if detail:
            evidence = f"{head} - wykryte technologie ({len(detail)}):\n" + "\n".join(detail)
        else:
            evidence = f"{head}. Narzędzie nie rozpoznało żadnej znanej technologii " \
                       "(brak charakterystycznych nagłówków/sygnatur)."
        findings.append(Finding(
            title=f"Fingerprint web: {target}",
            category="web-fingerprint",
            severity=Severity.INFO,
            confidence=Confidence.HIGH if detail else Confidence.LOW,
            asset=target,
            tool="whatweb",
            evidence=evidence,
            recommendation="Przegląd pełnego odcisku technologicznego - ogranicz ujawniane wersje "
                           "i nagłówki (np. Server, X-Powered-By), które ułatwiają atak.",
            references=["CWE-200"],
        ))

        artifacts = {"web_tech": tech} if tech else {}
        return AdapterResult(findings=findings, artifacts=artifacts)


def _first_status(raw: str):
    """Wyciąga http_status z pierwszego obiektu JSON whatweb (jeśli jest)."""
    for obj in _iter_json_objects(raw):
        st = obj.get("http_status")
        if st:
            return st
    return None


def _iter_json_objects(raw: str):
    """whatweb --log-json bywa tablicą JSON albo obiektami po jednym w linii."""
    raw = raw.strip()
    if not raw:
        return
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            yield from (o for o in data if isinstance(o, dict))
            return
        if isinstance(data, dict):
            yield data
            return
    except json.JSONDecodeError:
        pass
    for line in raw.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                yield obj
        except json.JSONDecodeError:
            continue
