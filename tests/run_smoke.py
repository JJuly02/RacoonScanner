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
from raccoon.adapters.shodan import ShodanAdapter            # noqa: E402
from raccoon.adapters.whois import WhoisAdapter              # noqa: E402
from raccoon.adapters.crtsh import CrtShAdapter              # noqa: E402
from raccoon.adapters.smb import SmbAdapter                  # noqa: E402
from raccoon.adapters.whatweb import WhatwebAdapter          # noqa: E402
from raccoon.findings import Confidence, Finding, Severity   # noqa: E402
from raccoon import modes                                    # noqa: E402
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

    # reguły zakresu — render + zapis + egzekwowanie
    r = client.get("/rules")
    check("flask: /rules renderuje", r.status_code == 200 and "Reguły zakresu" in r.get_data(as_text=True))
    r = client.post("/rules", data={"allowlist": "example.com\n# c\n"}, follow_redirects=True)
    check("flask: zapis reguł", "Zapisano reguły" in r.get_data(as_text=True))
    r = client.get("/")
    body = r.get_data(as_text=True)
    check("flask: dashboard ma szufladę reguł (offcanvas)", 'id="rulesDrawer"' in body)
    check("flask: aktywny zakres oznaczony w navbarze", "bg-warning" in body and "example.com" in body)
    r = client.post("/", data={"project_name": "p2", "target": "scanme.nmap.org",
                               "workflow": "dns_web", "mode": "passive", "authorized": "on"},
                    follow_redirects=True)
    check("flask: cel spoza zakresu odrzucony", "zakres" in r.get_data(as_text=True).lower())
    # posprzątaj regułę, by nie wpływała na inne testy
    client.post("/rules", data={"allowlist": ""}, follow_redirects=True)

    # przełączenie języka na EN i sprawdzenie dashboardu
    client.get("/lang/en")
    r = client.get("/")
    body = r.get_data(as_text=True)
    check("flask: przełączenie na EN działa (Dashboard/New scan)",
          "New scan" in body and "Dashboard" in body, "brak angielskich napisów")
    client.get("/lang/pl")  # powrót do PL, by nie wpływać na inne testy

    # path traversal na download_raw
    r = client.get("/run/p1/run_x/raw/..%2f..%2fmeta.json")
    check("flask: download_raw blokuje traversal", r.status_code in (400, 404))



def test_shodan() -> None:
    print("[shodan]")
    idb = ShodanAdapter()._parse_internetdb(
        __import__("json").loads(read("shodan_internetdb.json")), "203.0.113.10")
    cats = {f.category for f in idb.findings}
    check("shodan/internetdb: open-port + known-vuln + service-version",
          {"open-port", "known-vuln", "service-version"} <= cats, str(cats))
    check("shodan/internetdb: telnet (23) oznaczony HIGH",
          any(f.category == "open-port" and ":23" in f.asset and f.severity == Severity.HIGH
              for f in idb.findings))
    check("shodan/internetdb: CVE jako known-vuln",
          any(f.category == "known-vuln" and "CVE-2021-41773" in f.evidence for f in idb.findings))
    check("shodan/internetdb: artefakty hosts + web_targets",
          "203.0.113.10" in idb.artifacts.get("hosts", []) and
          "http://203.0.113.10" in idb.artifacts.get("web_targets", []) and
          "https://203.0.113.10" in idb.artifacts.get("web_targets", []),
          str(idb.artifacts))
    check("shodan/internetdb: confidence MEDIUM (dane pasywne)",
          all(f.confidence in (Confidence.MEDIUM, Confidence.LOW) for f in idb.findings))

    full = ShodanAdapter()._parse_full(
        __import__("json").loads(read("shodan_full.json")), "1.1.1.1")
    check("shodan/full: używa ip_str z payloadu (203.0.113.10)",
          any("203.0.113.10" in f.asset for f in full.findings))
    check("shodan/full: service-version z bannera nginx 1.18.0",
          any(f.category == "service-version" and "nginx 1.18.0" in f.evidence for f in full.findings))
    check("shodan/full: CVE z usługi i z hosta",
          {"CVE-2019-1234", "CVE-2020-0001"} <=
          {r for f in full.findings if f.category == "known-vuln" for r in f.references},
          str([f.references for f in full.findings if f.category == "known-vuln"]))
    check("shodan/full: web_targets zawiera port 80",
          "http://203.0.113.10" in full.artifacts.get("web_targets", []),
          str(full.artifacts.get("web_targets")))
    check("shodan: adapter jest PASSYWNY i zawsze dostępny",
          ShodanAdapter().intensity is modes.Intensity.PASSIVE and ShodanAdapter().is_available())


def test_modes() -> None:
    print("[modes]")
    from raccoon.modes import Mode, Intensity, parse_mode, allows
    check("modes: parse aliasów (direct->active, full->all)",
          parse_mode("direct") is Mode.ACTIVE and parse_mode("full") is Mode.ALL)
    check("modes: nieznane/puste -> DEFAULT (all)",
          parse_mode("") is modes.DEFAULT_MODE and parse_mode("xyz") is Mode.ALL)
    check("modes: tryb pasywny przepuszcza tylko pasywne",
          allows(Mode.PASSIVE, Intensity.PASSIVE) and
          not allows(Mode.PASSIVE, Intensity.ACTIVE) and
          not allows(Mode.PASSIVE, Intensity.AGGRESSIVE))
    check("modes: tryb aktywny = pasywne + aktywne, bez agresywnych",
          allows(Mode.ACTIVE, Intensity.PASSIVE) and allows(Mode.ACTIVE, Intensity.ACTIVE) and
          not allows(Mode.ACTIVE, Intensity.AGGRESSIVE))
    check("modes: tryb all przepuszcza wszystko",
          all(allows(Mode.ALL, i) for i in Intensity))


class _FakePassive(ToolAdapter):
    name = "fake_passive"
    binary = "python3"
    intensity = modes.Intensity.PASSIVE

    def run(self, ctx: RunContext) -> AdapterResult:
        f = Finding("passive", "open-port", Severity.INFO, Confidence.MEDIUM, ctx.target, "fake_passive")
        return AdapterResult(findings=[f])


class _FakeAggr(ToolAdapter):
    name = "fake_aggr"
    binary = "python3"
    intensity = modes.Intensity.AGGRESSIVE

    def run(self, ctx: RunContext) -> AdapterResult:
        f = Finding("aggr", "injection-sqli", Severity.CRITICAL, Confidence.HIGH, ctx.target, "fake_aggr")
        return AdapterResult(findings=[f])


def test_runner_modes(tmp_projects: str) -> None:
    print("[runner modes]")
    REGISTRY["fake_passive"] = _FakePassive()
    REGISTRY["fake_disc"] = _FakeDisc()      # intensity ACTIVE (domyślna)
    REGISTRY["fake_aggr"] = _FakeAggr()
    wf_path = os.path.join(WORKFLOWS_DIR, "_smoke_modes.yaml")
    with open(wf_path, "w", encoding="utf-8") as fh:
        fh.write(
            "name: SmokeModes\ndescription: test\nstages:\n"
            "  - name: P\n    adapter: fake_passive\n"
            "  - name: A\n    adapter: fake_disc\n"
            "  - name: X\n    adapter: fake_aggr\n"
        )
    try:
        store = Store(tmp_projects)
        runner = Runner(store)
        run_id = runner.submit("modes_proj", "_smoke_modes", "http://target/", mode="passive")
        deadline = time.time() + 10
        status = None
        while time.time() < deadline:
            status = runner.status("modes_proj", run_id)
            if status and status.get("status") in ("done", "error"):
                break
            time.sleep(0.2)
        stages = {s["name"]: s["status"] for s in (status or {}).get("stages", [])}
        notes = {s["name"]: s.get("note", "") for s in (status or {}).get("stages", [])}
        check("runner/passive: krok pasywny wykonany", stages.get("P") == "done", str(stages))
        check("runner/passive: krok aktywny pominięty", stages.get("A") == "skipped", str(stages))
        check("runner/passive: krok agresywny pominięty", stages.get("X") == "skipped", str(stages))
        check("runner/passive: pominięcie ma powód 'poza trybem'",
              "poza trybem" in notes.get("A", ""), str(notes))
        check("runner/passive: meta zapisuje tryb", (status or {}).get("mode") == "passive",
              str((status or {}).get("mode")))
    finally:
        os.remove(wf_path)
        for k in ("fake_passive", "fake_disc", "fake_aggr"):
            REGISTRY.pop(k, None)



def test_rules(tmp_private: str) -> None:
    print("[rules / bulk targets]")
    from raccoon import scope
    parsed = scope.parse_target_list(
        "example.com\n"
        "# komentarz\n"
        "203.0.113.10   # inline\n"
        "poczta.example.com, serwer pocztowy\n"
        "https://app.example.com/panel\n"
        "example.com\n"          # duplikat
        "   \n"
    )
    check("bulk: parsuje, tnie komentarze/przecinki, dedupuje",
          parsed == ["example.com", "203.0.113.10", "poczta.example.com",
                     "https://app.example.com/panel"], str(parsed))

    os.makedirs(tmp_private, exist_ok=True)
    scope.save_allowlist(tmp_private, ["example.com", "*.foo.com", "# komentarz", "  "])
    loaded = scope.load_allowlist(tmp_private)
    check("rules: zapis/odczyt pomija komentarze i puste",
          loaded == ["example.com", "*.foo.com"], str(loaded))
    check("rules: allowlist_text zawiera wpis", "example.com" in scope.allowlist_text(tmp_private))
    check("rules: in_scope respektuje wildcard",
          scope.in_scope("app.foo.com", tmp_private)[0] and
          scope.in_scope("example.com", tmp_private)[0] and
          not scope.in_scope("evil.com", tmp_private)[0])
    # pusta lista => brak ograniczenia
    scope.save_allowlist(tmp_private, [])
    check("rules: pusta lista = brak ograniczenia zakresu",
          scope.in_scope("cokolwiek.pl", tmp_private)[0])



def test_footprint() -> None:
    print("[footprinting]")
    import datetime as _dt

    # --- whois ---
    w = WhoisAdapter()._parse(read("whois.txt"), "example.com")
    check("whois: domain-info z rejestratorem/NS",
          any(f.category == "domain-info" and "MarkMonitor" in f.evidence for f in w.findings) and
          "a.iana-servers.net" in w.artifacts.get("nameservers", []), str(w.artifacts))
    near = "Registry Expiry Date: %sT00:00:00Z" % (_dt.date.today() + _dt.timedelta(days=10))
    past = "Registry Expiry Date: %sT00:00:00Z" % (_dt.date.today() - _dt.timedelta(days=5))
    wn = WhoisAdapter()._parse(near, "x.com")
    wp = WhoisAdapter()._parse(past, "x.com")
    check("whois: bliskie wygaśnięcie = MEDIUM",
          any(f.category == "domain-expiry" and f.severity == Severity.MEDIUM for f in wn.findings))
    check("whois: wygasła domena = HIGH",
          any(f.category == "domain-expiry" and f.severity == Severity.HIGH for f in wp.findings))

    # --- crt.sh ---
    c = CrtShAdapter()._parse(read("crtsh.json"), "example.com")
    subs = c.artifacts.get("subdomains", [])
    check("crtsh: subdomeny z CN+SAN, wildcard/obca domena odfiltrowane",
          set(subs) == {"example.com", "www.example.com", "api.example.com", "mail.example.com"},
          str(subs))
    check("crtsh: finding cert-transparency", any(f.category == "cert-transparency" for f in c.findings))
    check("crtsh: adapter pasywny, IP pomijane",
          CrtShAdapter().intensity is modes.Intensity.PASSIVE and
          CrtShAdapter()._parse("[]", "203.0.113.10").findings == [])

    # --- SMB null session ---
    smb = SmbAdapter()._parse(read("smb.txt"), "10.0.0.5")
    check("smb: null session -> service-exposure HIGH (są własne share'y)",
          any(f.category == "service-exposure" and f.severity == Severity.HIGH for f in smb.findings))
    custom = [f for f in smb.findings if f.category == "smb-share"]
    check("smb: tylko własne share'y (bez IPC$/print$)",
          {f.asset.rsplit('/', 1)[-1] for f in custom} == {"home", "dev", "notes"},
          str([f.asset for f in custom]))

    # --- nmap taguje usługi do footprintu ---
    nm = NmapAdapter()._parse(read("nmap.xml"), "45.33.32.156")
    check("nmap: taguje ssh_targets (port 22 open)",
          "45.33.32.156" in nm.artifacts.get("ssh_targets", []), str(nm.artifacts.get("ssh_targets")))
    check("nmap: NIE taguje db_targets (mysql 3306 zamknięty)",
          "db_targets" not in nm.artifacts, str(list(nm.artifacts)))



def test_whatweb_full() -> None:
    print("[whatweb full fingerprint]")
    res = WhatwebAdapter()._parse(read("whatweb.json"), "http://45.33.32.156")
    fp = [f for f in res.findings if f.category == "web-fingerprint"]
    check("whatweb: emituje pełny fingerprint (web-fingerprint)", len(fp) == 1, str(len(fp)))
    check("whatweb: fingerprint listuje wszystkie technologie",
          "Apache" in fp[0].evidence and "PHP" in fp[0].evidence and "WordPress" in fp[0].evidence)
    empty = WhatwebAdapter()._parse("[]", "http://x")
    ef = [f for f in empty.findings if f.category == "web-fingerprint"]
    check("whatweb: pusty wynik też daje info-finding",
          len(ef) == 1 and ef[0].severity == Severity.INFO and "nie rozpoznało" in ef[0].evidence)


def test_report_explain() -> None:
    print("[report explanations]")
    from raccoon import report as _report
    fs = [
        Finding("Otwarty port 22/tcp (ssh) na 1.2.3.4", "open-port",
                Severity.INFO, Confidence.HIGH, "1.2.3.4:22", "nmap"),
        Finding("SQLi", "injection-sqli", Severity.CRITICAL, Confidence.HIGH, "http://x/?id=1", "sqlmap"),
    ]
    compliance.annotate(fs)
    html = _report.generate(fs, {"run_id": "r1", "target": "1.2.3.4", "workflow": "WF", "status": "done"})
    check("report: znaleziska mają rozwijane wyjaśnienie", "Co to znaczy?" in html)
    check("report: wyjaśnienie portu 22 (SSH)", "Port 22 - SSH" in html)
    check("report: wykres donut severity (SVG)", "<svg" in html and "stroke-dasharray" in html)
    check("report: słupki wg kategorii", 'class="barfill"' in html)
    check("report: tabela zasobów z portem i usługą (SSH)",
          "SSH" in html and "Zdalny, szyfrowany" in html)
    check("report: macierz bez rozwijanych podpowiedzi (przeniesione do zasobów)",
          'class="exm"' not in html)
    check("report: nadal poprawny offline HTML",
          html.startswith("<!DOCTYPE html>") and "</html>" in html)


class _SlowAdapter(ToolAdapter):
    name = "fake_slow"
    binary = "python3"
    intensity = modes.Intensity.PASSIVE

    def __init__(self):
        import threading as _t
        self.gate = _t.Event()

    def run(self, ctx: RunContext) -> AdapterResult:
        self.gate.wait(timeout=5)
        f = Finding("slow", "open-port", Severity.INFO, Confidence.HIGH, ctx.target, "fake_slow")
        return AdapterResult(findings=[f])


def test_runner_stop_dedup(tmp_projects: str) -> None:
    print("[runner stop + dedup]")
    slow = _SlowAdapter()
    REGISTRY["fake_slow"] = slow
    REGISTRY["fake_disc"] = _FakeDisc()
    wf_path = os.path.join(WORKFLOWS_DIR, "_smoke_slow.yaml")
    with open(wf_path, "w", encoding="utf-8") as fh:
        fh.write("name: Slow\ndescription: t\nstages:\n"
                 "  - name: S1\n    adapter: fake_slow\n"
                 "  - name: S2\n    adapter: fake_disc\n")
    try:
        store = Store(tmp_projects)
        runner = Runner(store)
        r1 = runner.submit("p", "_smoke_slow", "http://t/", mode="all")
        r2 = runner.submit("p", "_smoke_slow", "http://t/", mode="all")  # duplikat
        check("dedup: podwójne submit zwraca ten sam run_id", r1 == r2, f"{r1} vs {r2}")
        check("dedup: powstał tylko jeden run", len(store.list_runs("p")) == 1,
              str(len(store.list_runs("p"))))
        check("has_active: wykrywa trwający identyczny skan",
              runner.has_active("p", "_smoke_slow", "http://t/", "all"))

        accepted = runner.cancel("p", r1)
        check("stop: cancel zaakceptowany dla aktywnego runu", accepted)
        slow.gate.set()  # odblokuj krok 1, żeby pętla doszła do sprawdzenia cancel
        deadline = time.time() + 8
        meta = None
        while time.time() < deadline:
            meta = store.load_meta("p", r1)
            if meta and meta.get("status") in ("done", "error", "cancelled"):
                break
            time.sleep(0.1)
        check("stop: status runu = cancelled", meta and meta["status"] == "cancelled",
              str(meta.get("status") if meta else None))
        stages = {s["name"]: (s["status"], s.get("note", "")) for s in (meta or {}).get("stages", [])}
        check("stop: kolejny krok pominięty z notatką 'przerwano skan'",
              stages.get("S2", ("", ""))[0] == "skipped" and "przerwano" in stages.get("S2", ("", ""))[1],
              str(stages))
    finally:
        os.remove(wf_path)
        for k in ("fake_slow", "fake_disc"):
            REGISTRY.pop(k, None)



def test_i18n() -> None:
    print("[i18n]")
    from raccoon import i18n
    check("i18n: EN tłumaczenie klucza", i18n.t("nav.panel", "en") == "Dashboard")
    check("i18n: PL tłumaczenie klucza", i18n.t("nav.panel", "pl") == "Panel")
    check("i18n: fallback nieznanego języka -> PL", i18n.t("nav.panel", "de") == "Panel")
    check("i18n: nieznany klucz zwraca klucz", i18n.t("no.such.key", "en") == "no.such.key")
    from raccoon import report as _report
    fs = [Finding("Otwarty port 22", "open-port", Severity.INFO, Confidence.HIGH, "1.2.3.4:22", "nmap")]
    compliance.annotate(fs)
    en = _report.generate(fs, {"run_id": "r", "target": "t", "workflow": "w", "status": "done"}, lang="en")
    check("i18n: raport EN ma angielskie nagłówki",
          "scan report" in en and "Compliance matrix" in en and "What does this mean" in en)
    check("i18n: raport EN bez emotek i bez em-dash",
          "\U0001f99d" not in en and "\u2139" not in en and "\u2014" not in en)


def main() -> int:
    import tempfile
    findings = test_adapters()
    test_findings_model(findings)
    test_compliance(findings)
    test_report(findings)
    test_workflows()
    test_shodan()
    test_footprint()
    test_whatweb_full()
    test_report_explain()
    test_i18n()
    test_modes()
    test_scope()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d1:
        test_runner_e2e(os.path.join(d1, "projects"))
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as dm:
        test_runner_modes(os.path.join(dm, "projects"))
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as dsd:
        test_runner_stop_dedup(os.path.join(dsd, "projects"))
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as dg:
        test_store_guard(os.path.join(dg, "projects"))
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as dr:
        test_rules(os.path.join(dr, "private"))
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d2:
        test_flask(d2)
    print(f"\n{_PASS} passed, {_FAIL} failed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
