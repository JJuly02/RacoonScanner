"""Deklaratywne definicje workflow (pipeline'ów) recon.

Workflow to nazwana sekwencja kroków (Stage). Każdy krok wskazuje adapter
narzędzia, jego opcje oraz opcjonalny warunek `requires` — klucz, który musi
pojawić się we współdzielonym kontekście (artefaktach poprzednich kroków), żeby
krok się wykonał. Dzięki temu np. whatweb odpala się tylko, gdy nmap znalazł
`web_targets`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml

WORKFLOWS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "workflows")


@dataclass
class Stage:
    name: str
    adapter: str
    options: dict = field(default_factory=dict)
    requires: str | None = None   # klucz w shared context wymagany do uruchomienia


@dataclass
class Workflow:
    name: str
    description: str
    stages: list[Stage]

    @classmethod
    def from_dict(cls, data: dict) -> "Workflow":
        stages = [
            Stage(
                name=s["name"],
                adapter=s["adapter"],
                options=s.get("options", {}) or {},
                requires=s.get("requires"),
            )
            for s in data.get("stages", [])
        ]
        return cls(name=data["name"], description=data.get("description", ""), stages=stages)

    @classmethod
    def from_yaml(cls, path: str) -> "Workflow":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(yaml.safe_load(fh))


def available_workflows() -> list[tuple[str, Workflow]]:
    """Zwraca listę (slug, Workflow) po plikach w workflows/ (niezależnie od CWD)."""
    out = []
    if os.path.isdir(WORKFLOWS_DIR):
        for fn in sorted(os.listdir(WORKFLOWS_DIR)):
            if fn.endswith((".yaml", ".yml")):
                slug = os.path.splitext(fn)[0]
                out.append((slug, Workflow.from_yaml(os.path.join(WORKFLOWS_DIR, fn))))
    return out


def list_workflows() -> list[Workflow]:
    return [wf for _, wf in available_workflows()]


def load_workflow(slug: str) -> Workflow:
    for ext in (".yaml", ".yml"):
        path = os.path.join(WORKFLOWS_DIR, slug + ext)
        if os.path.exists(path):
            return Workflow.from_yaml(path)
    raise FileNotFoundError(f"Nie znaleziono workflow: {slug}")
