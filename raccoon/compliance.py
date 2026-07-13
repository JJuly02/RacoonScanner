"""Silnik zgodności — mapowanie znalezisk na wymogi regulacyjne.

Każda kategoria znaleziska trafia na zbiór kontroli z frameworków: NIS2,
polska UKSC (Ustawa o Krajowym Systemie Cyberbezpieczeństwa), ISO/IEC 27001
oraz DORA. Mapowanie jest celowo poglądowe (artefakt wspierający audyt, nie
formalna interpretacja prawna) i łatwe do rozszerzenia.
"""
from __future__ import annotations

from dataclasses import dataclass

from .findings import Finding, sort_by_risk

# Ludzko czytelne etykiety kontroli.
CONTROLS: dict[str, str] = {
    "NIS2:art.21.2.a": "NIS2 art. 21(2)(a) — analiza ryzyka i bezpieczeństwo systemów",
    "NIS2:art.21.2.b": "NIS2 art. 21(2)(b) — obsługa incydentów",
    "NIS2:art.21.2.e": "NIS2 art. 21(2)(e) — bezpieczeństwo nabywania, rozwoju i utrzymania systemów",
    "NIS2:art.21.2.f": "NIS2 art. 21(2)(f) — ocena skuteczności środków zarządzania ryzykiem",
    "NIS2:art.21.2.g": "NIS2 art. 21(2)(g) — podstawowa cyberhigiena",
    "NIS2:art.21.2.h": "NIS2 art. 21(2)(h) — kryptografia i szyfrowanie",
    "UKSC:art.8": "UKSC art. 8 — wdrożenie zabezpieczeń adekwatnych do ryzyka",
    "UKSC:art.10": "UKSC art. 10 — utrzymanie i aktualizacja systemów, zarządzanie podatnościami",
    "UKSC:art.14": "UKSC art. 14 — obsługa i zgłaszanie incydentów",
    "ISO27001:A.8.8": "ISO/IEC 27001 A.8.8 — zarządzanie podatnościami technicznymi",
    "ISO27001:A.8.9": "ISO/IEC 27001 A.8.9 — zarządzanie konfiguracją",
    "ISO27001:A.8.20": "ISO/IEC 27001 A.8.20 — bezpieczeństwo sieci",
    "ISO27001:A.8.23": "ISO/IEC 27001 A.8.23 — filtrowanie ruchu web",
    "ISO27001:A.8.24": "ISO/IEC 27001 A.8.24 — kryptografia",
    "ISO27001:A.8.28": "ISO/IEC 27001 A.8.28 — bezpieczne kodowanie",
    "DORA:art.9": "DORA art. 9 — ochrona i prewencja ICT",
    "PCI:4.1": "PCI DSS 4.1 — silna kryptografia w transmisji",
}

# Kategoria znaleziska -> lista kontroli.
CATEGORY_MAP: dict[str, list[str]] = {
    "injection-sqli": ["NIS2:art.21.2.e", "UKSC:art.8", "ISO27001:A.8.28", "DORA:art.9"],
    "lfi-rfi":        ["NIS2:art.21.2.e", "UKSC:art.8", "ISO27001:A.8.28", "DORA:art.9"],
    "open-port":      ["NIS2:art.21.2.a", "UKSC:art.8", "ISO27001:A.8.20"],
    "service-version":["NIS2:art.21.2.f", "UKSC:art.10", "ISO27001:A.8.8"],
    "web-tech":       ["NIS2:art.21.2.g", "ISO27001:A.8.8", "ISO27001:A.8.9"],
    "dns-record":     ["NIS2:art.21.2.a", "ISO27001:A.8.20"],
    "zone-transfer":  ["NIS2:art.21.2.a", "UKSC:art.8", "ISO27001:A.8.20"],
    "tls-issue":      ["NIS2:art.21.2.h", "ISO27001:A.8.24", "PCI:4.1"],
    "host-alive":     ["NIS2:art.21.2.a"],
}


def annotate(findings: list[Finding]) -> list[Finding]:
    """Uzupełnia `finding.compliance` na podstawie kategorii."""
    for f in findings:
        f.compliance = list(CATEGORY_MAP.get(f.category, []))
    return findings


@dataclass
class ControlCoverage:
    control: str
    label: str
    finding_ids: list[str]
    max_severity_rank: int

    @property
    def hits(self) -> int:
        return len(self.finding_ids)


def matrix(findings: list[Finding]) -> list[ControlCoverage]:
    """Macierz zgodności: które kontrole zostały dotknięte i przez ile znalezisk."""
    by_control: dict[str, ControlCoverage] = {}
    for f in findings:
        for ctrl in f.compliance or CATEGORY_MAP.get(f.category, []):
            cov = by_control.get(ctrl)
            if cov is None:
                cov = ControlCoverage(ctrl, CONTROLS.get(ctrl, ctrl), [], 0)
                by_control[ctrl] = cov
            cov.finding_ids.append(f.id)
            cov.max_severity_rank = max(cov.max_severity_rank, f.severity.rank)
    return sorted(by_control.values(), key=lambda c: (c.max_severity_rank, c.hits), reverse=True)


def frameworks_summary(findings: list[Finding]) -> dict[str, int]:
    """Liczba dotkniętych kontroli na framework (prefix przed ':')."""
    out: dict[str, int] = {}
    for cov in matrix(findings):
        fw = cov.control.split(":", 1)[0]
        out[fw] = out.get(fw, 0) + 1
    return out


def risk_summary(findings: list[Finding]) -> dict:
    """Zagregowany obraz ryzyka: liczniki severity + łączny score."""
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    total_risk = 0.0
    for f in findings:
        counts[f.severity.value] += 1
        total_risk += f.risk
    top = sort_by_risk(findings)[:5]
    return {
        "total": len(findings),
        "counts": counts,
        "risk_score": round(total_risk, 1),
        "top": top,
    }
