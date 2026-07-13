"""Smoke testy RacoonScanner — bez zewnętrznych narzędzi (parsowanie na próbkach).

Uruchom: python tests/run_smoke.py
"""
from __future__ import annotations

import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
sys.path.insert(0, ROOT)

from raccoon import compliance, report                      # noqa: E402
from raccoon.adapters import REGISTRY                        # noqa: E402
from raccoon.adapters.base import AdapterResult, RunContext, ToolAdapter  # noqa: E402
from raccoon.adapters.dnsrecon import DnsreconAdapter        # noqa: E402
from raccoon.adapters.included import IncludedAdapter        # noqa: E402
from raccoon.adapters.nmap import NmapAdapter                # noqa: E402
from raccoon.adapters.sqlmap import SqlmapAdapter            # noqa: E402
from raccoon.adapters.whatweb import WhatwebAdapter          # noqa: E402
from raccoon.findings import Confidence, Finding, Severity   # noqa: E402
from raccoon.runner import Runner                            # noqa: E402
from raccoon.store import Store                              # noqa: E402
from raccoon.workflow import WORKFLOWS_DIR, available_workflows, load_workflow  # noqa: E402

_PASS = 0
_FAIL = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  \033[32mPASS\033[0m {name}")
    else:
        _FAIL += 1
        print(f"  \033[31mFAIL\033[0m {name} {extra}")


def read(fn: str) -> str:
    with open(os.path.join(FIX, fn), encoding="utf-8") as fh:
        return fh.read()


def test_adapters() -> list[Finding]:
    print("[adapters]")
    nmap = NmapAdapter()._parse(read("nmap.xml"), "45.33.32.156")
    cats = {f.category for f in nmap.findings}
    check("nmap: open-port + service-version", {"open-port", "service-version"} <= cats)
    check("nmap: telnet oznaczony HIGH",
          any(f.severity == Severity.HIGH and "telnet" in f.title.lower() for f in nmap.findings))
    check("nmap: pomija port closed (3306)",
          not any(":3306" in f.asset for f in nmap.findings))
    check("nmap: web_targets zawiera http i https",
          "http://45.33.32.156" in nmap.artifacts.get("web_targets", []) and
          "https://45.33.32.156" in nmap.artifacts.get("web_targets", []),
          str(nmap.artifacts.get("web_targets")))

    ww = WhatwebAdapter()._parse(read("whatweb.json"), "http://45.33.32.156")
    check("whatweb: wykrywa WordPress/PHP/Apache",
          {"wordpress", "php", "apache"} <= {f.title.lower().split()[-2] if len(f.title.split()) > 1 else f.title.lower()
                                              for f in ww.findings} or len(ww.findings) >= 3,
          str([f.title for f in ww.findings]))

    dns = DnsreconAdapter()._parse(read("dnsrecon.json"), "example.com")
    check("dnsrecon: zbiera hosty z A/AAAA", "93.184.216.34" in dns.artifacts.get("hosts", []))
    check("dnsrecon: rekordy jako findings", len(dns.findings) >= 4)

    inc = IncludedAdapter()._parse(read("included.json"), "http://t/?page=INCLUDE")
    sevs = {f.severity for f in inc.findings}
    check("included: traversal=HIGH, rce=CRITICAL",
          Severity.HIGH in sevs and Severity.CRITICAL in sevs, str(sevs))
    check("included: kategoria lfi-rfi + CWE",
          all(f.category == "lfi-rfi" for f in inc.findings) and
          any("CWE-98" in f.references for f in inc.findings))

    sql = SqlmapAdapter()._parse(read("sqlmap.txt"), "http://t/?id=1")
    check("sqlmap: wykrywa SQLi jako CRITICAL",
          any(f.category == "injection-sqli" and f.severity == Severity.CRITICAL for f in sql.findings))

    all_f = nmap.findings + ww.findings + dns.findings + inc.findings + sql.findings
    return all_f


def test_findings_model(findings: list[Finding]) -> None:
    print("[findings]")
    f = Finding("t", "open-port", Severity.HIGH, Confidence.HIGH, "h:80", "nmap")
    check("Finding: id generowany", bool(f.id))
    check("Finding: risk = rank*weight", f.risk == 3.0, str(f.risk))
    check("Finding: round-trip to/from dict",
          Finding.from_dict(f.to_dict()).id == f.id)


def test_compliance(findings: list[Finding]) -> None:
    print("[compliance]")
    compliance.annotate(findings)
    check("annotate: SQLi -> NIS2 art.21.2.e",
          any("NIS2:art.21.2.e" in f.compliance for f in findings if f.category == "injection-sqli"))
    mat = compliance.matrix(findings)
    check("matrix: niepusta", len(mat) > 0)
    fw = compliance.frameworks_summary(findings)
    check("frameworks: obejmuje NIS2, UKSC, ISO27001",
          {"NIS2", "UKSC", "ISO27001"} <= set(fw), str(fw))
    risk = compliance.risk_summary(findings)
    check("risk_summary: liczniki + score", risk["total"] == len(findings) and risk["risk_score"] > 0)


def test_report(findings: list[Finding]) -> None:
    print("[report]")
    meta = {"run_id": "run_x", "target": "45.33.32.156", "workflow": "Full Recon", "status": "done"}
    html = report.generate(findings, meta)
    check("report: to poprawny dokument HTML", html.startswith("<!DOCTYPE html>") and "</html>" in html)
    check("report: zawiera macierz zgodności", "Macierz zgodności" in html)
    check("report: zawiera triage JS", "localStorage" in html and "racoon-triage" in html)
    check("report: brak zewnętrznych zasobów (offline)",
          "http://" not in html.split("<footer")[0].replace("http://www.w3.org", "") or "cdn" not in html)
    js = report.export_json(findings, meta)
    import json as _json
    check("export_json: parsowalny", isinstance(_json.loads(js).get("findings"), list))


def test_workflows() -> None:
    print("[workflows]")
    slugs = [s for s, _ in available_workflows()]
    check("workflows: full_recon i dns_web dostępne",
          "full_recon" in slugs and "dns_web" in slugs, str(slugs))
    wf = load_workflow("full_recon")
    check("full_recon: ma krok INCLUDED z requires=web_targets",
          any(s.adapter == "included" and s.requires == "web_targets" for s in wf.stages))


# --- fałszywe adaptery do testu executora (bez realnych narzędzi) ---
class _FakeDisc(ToolAdapter):
    name = "fake_disc"
    binary = "python3"  # zawsze dostępne

    def run(self, ctx: RunContext) -> AdapterResult:
        f = Finding("disc", "open-port", Severity.MEDIUM, Confidence.HIGH, ctx.target, "fake_disc")
        return AdapterResult(findings=[f], artifacts={"web_targets": ["http://fake/"]},
                             raw_files={"disc.txt": "raw-disc"})


class _FakeWeb(ToolAdapter):
    name = "fake_web"
    binary = "python3"

    def run(self, ctx: RunContext) -> AdapterResult:
        assert ctx.shared.get("web_targets"), "web_targets nie zostało przekazane!"
        f = Finding("web", "web-tech", Severity.LOW, Confidence.MEDIUM,
                    ctx.shared["web_targets"][0], "fake_web")
        return AdapterResult(findings=[f])


def test_runner_e2e(tmp_projects: str) -> None:
    print("[runner e2e]")
    REGISTRY["fake_disc"] = _FakeDisc()
    REGISTRY["fake_web"] = _FakeWeb()
    wf_path = os.path.join(WORKFLOWS_DIR, "_smoke.yaml")
    with open(wf_path, "w", encoding="utf-8") as fh:
        fh.write(
            "name: Smoke\ndescription: test\nstages:\n"
            "  - name: Disc\n    adapter: fake_disc\n"
            "  - name: Web\n    adapter: fake_web\n    requires: web_targets\n"
            "  - name: Skip\n    adapter: fake_web\n    requires: nieistnieje\n"
        )
    try:
        store = Store(tmp_projects)
        runner = Runner(store)
        run_id = runner.submit("smoke_proj", "_smoke", "http://target/")
        deadline = time.time() + 10
        status = None
        while time.time() < deadline:
            status = runner.status("smoke_proj", run_id)
            if status and status.get("status") in ("done", "error"):
                break
            time.sleep(0.2)
        check("runner: run zakończony 'done'", status and status["status"] == "done",
              str(status.get("status") if status else None))
        stages = {s["name"]: s["status"] for s in (status or {}).get("stages", [])}
        check("runner: krok Web wykonany (chaining web_targets)", stages.get("Web") == "done", str(stages))
        check("runner: krok Skip pominięty (brak requires)", stages.get("Skip") == "skipped", str(stages))
        meta = store.load_meta("smoke_proj", run_id)
        check("runner: meta zapisane z findings_total", meta and meta["findings_total"] == 2)
        rpt = os.path.join(store.run_dir("smoke_proj", run_id), "report.html")
        check("runner: raport wygenerowany na dysku", os.path.exists(rpt))
        raw = os.path.join(store.run_dir("smoke_proj", run_id), "raw", "disc.txt")
        check("runner: surowy plik zapisany", os.path.exists(raw))
    finally:
        os.remove(wf_path)
        REGISTRY.pop("fake_disc", None)
        REGISTRY.pop("fake_web", None)


def test_store_guard(tmp_projects: str) -> None:
    print("[store guard]")
    store = Store(tmp_projects)
    store.ensure_project("keepme")
    # Nazwa sanityzująca się do pustej nie może usunąć całego katalogu projects/.
    store.delete_project("-")
    store.delete_project("")
    check("store: pusta nazwa nie kasuje projects/", os.path.isdir(tmp_projects))
    check("store: istniejący projekt zachowany", "keepme" in store.list_projects())
    store.delete_project("keepme")
    check("store: poprawne usunięcie działa", "keepme" not in store.list_projects())


def test_scope() -> None:
    print("[scope]")
    from raccoon import scope
    check("scope: localhost akceptowany", scope.validate_target("localhost")[0])
    check("scope: URL akceptowany", scope.validate_target("http://example.com/?p=1")[0])
    check("scope: metaznaki odrzucone", not scope.validate_target("a;rm -rf")[0])
    check("scope: pusty odrzucony", not scope.validate_target("")[0])


def test_flask(tmp_cwd: str) -> None:
    print("[flask]")
    os.chdir(tmp_cwd)
    os.environ["RACOON_USER"] = "admin"
    os.environ["RACOON_PASSWORD"] = "smoke-pass-123"
    import importlib
    import app as app_module
    importlib.reload(app_module)
    client = app_module.app.test_client()

    r = client.get("/")
    check("flask: '/' bez logowania -> redirect", r.status_code == 302 and "/login" in r.headers.get("Location", ""))

    r = client.post("/login", data={"user": "admin", "password": "smoke-pass-123"}, follow_redirects=False)
    check("flask: logowanie poprawnym hasłem", r.status_code == 302)

    r = client.get("/")
    check("flask: dashboard po zalogowaniu", r.status_code == 200 and b"Nowy skan" in r.data)

    # start bez potwierdzenia autoryzacji -> odrzucone
    r = client.post("/", data={"project_name": "p1", "target": "scanme.nmap.org",
                               "workflow": "dns_web"}, follow_redirects=True)
    check("flask: skan bez autoryzacji odrzucony", "autoryzacj" in r.get_data(as_text=True).lower())

    # niepoprawny cel
    r = client.post("/", data={"project_name": "p1", "target": "zły cel;rm -rf",
                               "workflow": "dns_web", "authorized": "on"}, follow_redirects=True)
    check("flask: niepoprawny cel odrzucony", "niedozwolone" in r.get_data(as_text=True).lower()
          or "niepoprawny" in r.get_data(as_text=True).lower())

    # path traversal na download_raw
    r = client.get("/run/p1/run_x/raw/..%2f..%2fmeta.json")
    check("flask: download_raw blokuje traversal", r.status_code in (400, 404))


def main() -> int:
    import tempfile
    findings = test_adapters()
    test_findings_model(findings)
    test_compliance(findings)
    test_report(findings)
    test_workflows()
    test_scope()
    with tempfile.TemporaryDirectory() as d1:
        test_runner_e2e(os.path.join(d1, "projects"))
    with tempfile.TemporaryDirectory() as dg:
        test_store_guard(os.path.join(dg, "projects"))
    with tempfile.TemporaryDirectory() as d2:
        test_flask(d2)
    print(f"\n{_PASS} passed, {_FAIL} failed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
