"""Trwałość projektów i uruchomień (runs) na dysku.

Układ katalogów:

    projects/<projekt>/
        runs/<run_id>/
            meta.json        # metadane runu (workflow, cel, status, czasy, statystyki)
            findings.json    # znormalizowane znaleziska
            report.html      # samodzielny raport
            raw/             # surowe wyjścia narzędzi
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
from datetime import datetime, timezone


def safe_name(name: str) -> str:
    """Sanityzacja nazwy projektu (tylko alfanumeryczne, '_' i '-')."""
    return "".join(c for c in (name or "") if c.isalnum() or c in "_-").strip("-_")


class Store:
    def __init__(self, projects_dir: str):
        self.projects_dir = projects_dir
        os.makedirs(projects_dir, exist_ok=True)

    # --- projekty ---
    def project_dir(self, project: str) -> str:
        return os.path.join(self.projects_dir, safe_name(project))

    def list_projects(self) -> list[str]:
        if not os.path.isdir(self.projects_dir):
            return []
        return sorted(
            d for d in os.listdir(self.projects_dir)
            if os.path.isdir(os.path.join(self.projects_dir, d))
        )

    def ensure_project(self, project: str) -> str:
        path = self.project_dir(project)
        os.makedirs(os.path.join(path, "runs"), exist_ok=True)
        return path

    def delete_project(self, project: str) -> None:
        name = safe_name(project)
        if not name:  # pusta nazwa po sanityzacji nie może wskazywać na katalog główny projects/
            return
        path = self.project_dir(name)
        root = os.path.abspath(self.projects_dir)
        if os.path.isdir(path) and os.path.abspath(path) != root \
                and os.path.dirname(os.path.abspath(path)) == root:
            shutil.rmtree(path)

    # --- runy ---
    def new_run_id(self) -> str:
        stamp = datetime.now(timezone.utc).strftime("run_%Y%m%d_%H%M%S")
        return f"{stamp}_{secrets.token_hex(2)}"

    def run_dir(self, project: str, run_id: str) -> str:
        return os.path.join(self.project_dir(project), "runs", safe_name(run_id))

    def create_run(self, project: str, run_id: str) -> str:
        path = self.run_dir(project, run_id)
        os.makedirs(os.path.join(path, "raw"), exist_ok=True)
        return path

    def list_runs(self, project: str) -> list[dict]:
        runs_root = os.path.join(self.project_dir(project), "runs")
        if not os.path.isdir(runs_root):
            return []
        metas = []
        for rid in os.listdir(runs_root):
            meta = self.load_meta(project, rid)
            if meta:
                metas.append(meta)
        return sorted(metas, key=lambda m: m.get("run_id", ""), reverse=True)

    # --- artefakty ---
    def save_meta(self, project: str, run_id: str, meta: dict) -> None:
        with open(os.path.join(self.run_dir(project, run_id), "meta.json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh, ensure_ascii=False, indent=2)

    def load_meta(self, project: str, run_id: str) -> dict | None:
        path = os.path.join(self.run_dir(project, run_id), "meta.json")
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def save_findings(self, project: str, run_id: str, findings: list[dict]) -> None:
        with open(os.path.join(self.run_dir(project, run_id), "findings.json"), "w", encoding="utf-8") as fh:
            json.dump(findings, fh, ensure_ascii=False, indent=2)

    def load_findings(self, project: str, run_id: str) -> list[dict]:
        path = os.path.join(self.run_dir(project, run_id), "findings.json")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def save_report(self, project: str, run_id: str, html: str) -> str:
        path = os.path.join(self.run_dir(project, run_id), "report.html")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return path

    def save_raw(self, project: str, run_id: str, filename: str, content: str) -> None:
        safe = os.path.basename(filename)
        with open(os.path.join(self.run_dir(project, run_id), "raw", safe), "w", encoding="utf-8") as fh:
            fh.write(content or "")
