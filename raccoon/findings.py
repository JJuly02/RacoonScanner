"""Wspólny model znalezisk (Finding) dla wszystkich narzędzi.

Każdy adapter narzędzia sprowadza swój surowy wynik do listy `Finding`, dzięki
czemu pipeline, silnik zgodności i generator raportu operują na jednym schemacie.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEV_RANK[self.value]


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def weight(self) -> float:
        return _CONF_WEIGHT[self.value]


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_CONF_WEIGHT = {"low": 0.4, "medium": 0.7, "high": 1.0}


@dataclass
class Finding:
    """Pojedyncze znalezisko, niezależne od narzędzia, które je wykryło."""

    title: str
    category: str          # open-port, service-version, web-tech, injection-sqli, lfi-rfi, ...
    severity: Severity
    confidence: Confidence
    asset: str             # host / port / URL / parametr, którego dotyczy
    tool: str              # narzędzie źródłowe
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    compliance: list[str] = field(default_factory=list)  # uzupełniane przez silnik zgodności
    id: str = ""           # stabilny skrót (deduplikacja + linkowanie w raporcie)

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if isinstance(self.confidence, str):
            self.confidence = Confidence(self.confidence)
        if not self.id:
            seed = f"{self.tool}|{self.category}|{self.asset}|{self.title}"
            self.id = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]

    @property
    def risk(self) -> float:
        """Prosty score ryzyka: waga severity × pewność (0–4)."""
        return round(self.severity.rank * self.confidence.weight, 2)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["risk"] = self.risk
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            title=d["title"],
            category=d["category"],
            severity=Severity(d["severity"]),
            confidence=Confidence(d["confidence"]),
            asset=d["asset"],
            tool=d["tool"],
            evidence=d.get("evidence", ""),
            recommendation=d.get("recommendation", ""),
            references=list(d.get("references", [])),
            compliance=list(d.get("compliance", [])),
            id=d.get("id", ""),
        )


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Usuwa duplikaty po `id`, zachowując pierwsze wystąpienie."""
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.id, f)
    return list(seen.values())


def sort_by_risk(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.risk, f.severity.rank), reverse=True)
