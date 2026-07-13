"""Executor pipeline'ów — uruchamia workflow asynchronicznie (wątek w tle).

Kroki wykonują się po kolei; artefakty jednego kroku (np. `web_targets` z nmapa)
trafiają do współdzielonego kontekstu i karmią kolejne kroki. Stan runu jest
dostępny na żywo (polling) i utrwalany na dysku po każdym kroku.
"""
from __future__ import annotations

import threading
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import compliance, report
from .adapters import RunContext, ToolUnavailable, get_adapter
from .findings import Finding, dedupe
from .store import Store
from .workflow import Workflow, load_workflow

# Klucze artefaktów będące listami stringów (scalane z deduplikacją).
_STR_LISTS = {"hosts", "web_targets", "subdomains", "web_tech"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class StageState:
    name: str
    adapter: str
    status: str = "pending"   # pending / running / done / skipped / unavailable / error
    findings: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "adapter": self.adapter, "status": self.status,
                "findings": self.findings, "error": self.error}


@dataclass
class RunState:
    project: str
    run_id: str
    workflow_slug: str
    workflow_name: str
    target: str
    status: str = "queued"    # queued / running / done / error
    started: str = ""
    finished: str = ""
    error: str = ""
    stages: list[StageState] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    log: list[str] = field(default_factory=list)

    def status_dict(self) -> dict:
        """Lekki obraz stanu do pollingu (bez pełnych znalezisk)."""
        return {
            "project": self.project,
            "run_id": self.run_id,
            "workflow": self.workflow_name,
            "target": self.target,
            "status": self.status,
            "started": self.started,
            "finished": self.finished,
            "error": self.error,
            "stages": [s.to_dict() for s in self.stages],
            "findings_total": len(self.findings),
            "log": self.log[-20:],
        }

    def meta_dict(self) -> dict:
        risk = compliance.risk_summary(self.findings)
        return {
            "run_id": self.run_id,
            "project": self.project,
            "workflow_slug": self.workflow_slug,
            "workflow": self.workflow_name,
            "target": self.target,
            "status": self.status,
            "started": self.started,
            "finished": self.finished,
            "error": self.error,
            "stages": [s.to_dict() for s in self.stages],
            "findings_total": len(self.findings),
            "risk": {"counts": risk["counts"], "risk_score": risk["risk_score"]},
            "frameworks": compliance.frameworks_summary(self.findings),
        }


class Runner:
    def __init__(self, store: Store):
        self.store = store
        self._active: dict[str, RunState] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(project: str, run_id: str) -> str:
        return f"{project}/{run_id}"

    def submit(self, project: str, workflow_slug: str, target: str) -> str:
        wf = load_workflow(workflow_slug)
        run_id = self.store.new_run_id()
        self.store.ensure_project(project)
        self.store.create_run(project, run_id)
        state = RunState(
            project=project, run_id=run_id,
            workflow_slug=workflow_slug, workflow_name=wf.name, target=target,
            stages=[StageState(s.name, s.adapter) for s in wf.stages],
        )
        with self._lock:
            self._active[self._key(project, run_id)] = state
        self.store.save_meta(project, run_id, state.meta_dict())
        threading.Thread(target=self._execute, args=(state, wf), daemon=True).start()
        return run_id

    def status(self, project: str, run_id: str) -> dict | None:
        with self._lock:
            state = self._active.get(self._key(project, run_id))
        if state is not None:
            return state.status_dict()
        return self.store.load_meta(project, run_id)

    # --- wykonanie ---
    def _execute(self, state: RunState, wf: Workflow) -> None:
        state.status = "running"
        state.started = _now()
        self._persist(state)
        shared: dict = {}
        workdir = self.store.run_dir(state.project, state.run_id) + "/raw"
        try:
            for stage_def, ss in zip(wf.stages, state.stages):
                if stage_def.requires and not shared.get(stage_def.requires):
                    ss.status = "skipped"
                    state.log.append(f"[-] {ss.name}: pominięto (brak {stage_def.requires})")
                    self._persist(state)
                    continue
                adapter = get_adapter(stage_def.adapter)
                if not adapter.is_available():
                    ss.status = "unavailable"
                    state.log.append(f"[!] {ss.name}: narzędzie '{adapter.binary}' niedostępne")
                    self._persist(state)
                    continue
                ss.status = "running"
                state.log.append(f"[*] {ss.name}: start")
                self._persist(state)
                try:
                    ctx = RunContext(target=state.target, workdir=workdir,
                                     options=dict(stage_def.options), shared=shared)
                    res = adapter.run(ctx)
                except ToolUnavailable:
                    ss.status = "unavailable"
                    self._persist(state)
                    continue
                except Exception as exc:  # noqa: BLE001 - izolujemy błąd pojedynczego kroku
                    ss.status = "error"
                    ss.error = str(exc)
                    state.log.append(f"[x] {ss.name}: błąd — {exc}")
                    self._persist(state)
                    continue
                state.findings.extend(res.findings)
                self._merge(shared, res.artifacts)
                for fn, content in res.raw_files.items():
                    self.store.save_raw(state.project, state.run_id, fn, content)
                ss.findings = len(res.findings)
                ss.status = "done"
                state.log.append(f"[+] {ss.name}: {ss.findings} znalezisk")
                self._persist(state)

            self._finalize(state)
        except Exception:  # noqa: BLE001 - awaria całego runu
            state.status = "error"
            state.error = traceback.format_exc(limit=3)
            state.finished = _now()
            self._persist(state)
        finally:
            with self._lock:
                self._active.pop(self._key(state.project, state.run_id), None)

    def _finalize(self, state: RunState) -> None:
        findings = dedupe(state.findings)
        compliance.annotate(findings)
        state.findings = findings
        state.status = "done"
        state.finished = _now()
        self.store.save_findings(state.project, state.run_id, [f.to_dict() for f in findings])
        html = report.generate(findings, meta=state.meta_dict())
        self.store.save_report(state.project, state.run_id, html)
        self._persist(state)

    @staticmethod
    def _merge(shared: dict, artifacts: dict) -> None:
        for key, value in artifacts.items():
            if key in _STR_LISTS:
                merged = shared.get(key, []) + list(value)
                shared[key] = list(dict.fromkeys(merged))
            elif isinstance(value, list):
                shared.setdefault(key, [])
                shared[key].extend(value)
            else:
                shared[key] = value

    def _persist(self, state: RunState) -> None:
        self.store.save_meta(state.project, state.run_id, state.meta_dict())
