"""Prosta warstwa i18n dla interfejsu RacoonScannera.

Tłumaczy widoczne napisy UI (szablony, etykiety trybów, nagłówki raportu).
Język wybierany jest w navbarze i trzymany w sesji (`lang`). Treść znalezisk
generowana przez adaptery pozostaje na razie w języku źródłowym (PL) - to
osobna, większa lokalizacja (patrz TODO).
"""
from __future__ import annotations

LANGS = {"pl": "Polski", "en": "English"}
DEFAULT_LANG = "pl"

# Katalog: klucz -> {lang: tekst}. PL jest źródłem; brak EN => fallback do PL => klucza.
_CAT: dict[str, dict[str, str]] = {
    # --- nawigacja / wspólne ---
    "nav.panel": {"pl": "Panel", "en": "Dashboard"},
    "nav.rules": {"pl": "Reguły zakresu", "en": "Scope rules"},
    "nav.logout": {"pl": "wyloguj", "en": "log out"},
    "nav.theme": {"pl": "Przełącz motyw", "en": "Toggle theme"},
    "nav.lang": {"pl": "Język", "en": "Language"},
    "common.back_panel": {"pl": "Panel", "en": "Dashboard"},
    "common.back_project": {"pl": "Projekt", "en": "Project"},
    "common.target": {"pl": "Cel", "en": "Target"},
    "common.workflow": {"pl": "Workflow", "en": "Workflow"},
    "common.mode": {"pl": "Tryb", "en": "Mode"},
    "common.status": {"pl": "Status", "en": "Status"},
    "common.risk_score": {"pl": "Risk score", "en": "Risk score"},
    "common.findings": {"pl": "Znalezisk", "en": "Findings"},
    "common.severity": {"pl": "Severity", "en": "Severity"},
    # --- dashboard ---
    "index.stat_projects": {"pl": "Projekty", "en": "Projects"},
    "index.stat_workflows": {"pl": "Workflow", "en": "Workflows"},
    "index.stat_runs": {"pl": "Uruchomienia", "en": "Runs"},
    "index.stat_modes": {"pl": "Tryby pracy", "en": "Work modes"},
    "index.new_scan": {"pl": "Nowy skan (workflow)", "en": "New scan (workflow)"},
    "index.project_name": {"pl": "Nazwa projektu", "en": "Project name"},
    "index.target_label": {"pl": "Cel", "en": "Target"},
    "index.target_kind": {"pl": "(URL / host / IP)", "en": "(URL / host / IP)"},
    "index.single_hint": {"pl": "Pojedynczy cel - lub użyj listy poniżej dla wielu.",
                          "en": "A single target - or use the list below for many."},
    "index.many_targets": {"pl": "Wiele celów", "en": "Multiple targets"},
    "index.one_per_line": {"pl": "(jeden na linię)", "en": "(one per line)"},
    "index.load_txt": {"pl": "Wczytaj .txt", "en": "Load .txt"},
    "index.targets_detected": {"pl": "celów wykrytych · przecinek/# = komentarz",
                               "en": "targets detected · comma/# = comment"},
    "index.work_mode": {"pl": "Tryb pracy", "en": "Work mode"},
    "help.workflow": {"pl": "Workflow to sekwencja narzedzi (pipeline), ktore uruchamiaja sie po kolei i przekazuja sobie wyniki. Wybierasz CO ma zostac wykonane (np. sam DNS+web, albo pelny recon).",
                      "en": "A workflow is a sequence of tools (a pipeline) that run in order and pass results along. It defines WHAT gets done (e.g. just DNS+web, or full recon)."},
    "help.mode": {"pl": "Tryb to poziom inwazyjnosci (sufit): Pasywny = tylko dane zewnetrzne (0 pakietow do celu), Bezposredni = enumeracja bez exploitow, Pelny = wszystko lacznie z sondowaniem podatnosci. Wybierasz JAK agresywnie dzialac. Tryb nie rozszerza workflow - tylko go ogranicza.",
                  "en": "The mode is an intrusiveness ceiling: Passive = external data only (0 packets to target), Direct = enumeration without exploits, Full = everything incl. vulnerability probing. It defines HOW aggressively to act. The mode never expands a workflow - it only limits it."},
    "index.authorized": {"pl": "Potwierdzam, że mam <strong>autoryzację</strong> do skanowania podanych celów.",
                         "en": "I confirm I am <strong>authorised</strong> to scan the given targets."},
    "index.run_workflow": {"pl": "Uruchom workflow", "en": "Run workflow"},
    "index.running": {"pl": "Uruchamianie…", "en": "Starting…"},
    "index.projects": {"pl": "Projekty", "en": "Projects"},
    "index.no_projects": {"pl": "Brak projektów. Uruchom pierwszy skan.",
                          "en": "No projects yet. Run your first scan."},
    "index.open": {"pl": "Otwórz", "en": "Open"},
    "index.delete": {"pl": "Usuń", "en": "Delete"},
    "index.delete_confirm": {"pl": "Usunąć projekt wraz z wynikami?",
                             "en": "Delete this project and its results?"},
    # --- login ---
    "login.subtitle": {"pl": "Orkiestracja recon & audyt zgodności",
                       "en": "Recon orchestration & compliance audit"},
    "login.title": {"pl": "Logowanie", "en": "Sign in"},
    "login.user": {"pl": "Użytkownik", "en": "User"},
    "login.password": {"pl": "Hasło", "en": "Password"},
    "login.submit": {"pl": "Zaloguj", "en": "Sign in"},
    "login.hint": {"pl": "Hasło startowe generowane jest przy pierwszym uruchomieniu (patrz logi) lub ustaw",
                   "en": "The initial password is generated on first run (see logs) or set"},
    # --- run ---
    "run.stop": {"pl": "Zatrzymaj skan", "en": "Stop scan"},
    "run.stopping": {"pl": "Zatrzymywanie…", "en": "Stopping…"},
    "run.pipeline": {"pl": "Kroki pipeline", "en": "Pipeline steps"},
    "run.findings_total": {"pl": "znalezisk łącznie", "en": "findings total"},
    "run.log": {"pl": "Log", "en": "Log"},
    "run.open_report": {"pl": "Otwórz raport", "en": "Open report"},
    "run.export_json": {"pl": "Eksport JSON", "en": "Export JSON"},
    # --- project ---
    "project.runs": {"pl": "Uruchomienia", "en": "Runs"},
    "project.run": {"pl": "Run", "en": "Run"},
    "project.details": {"pl": "Szczegóły", "en": "Details"},
    "project.report": {"pl": "Raport", "en": "Report"},
    "project.no_runs": {"pl": "Brak uruchomień.", "en": "No runs yet."},
    # --- rules ---
    "rules.title": {"pl": "Reguły zakresu", "en": "Scope rules"},
    "rules.allowlist_title": {"pl": "Biała lista dozwolonych celów", "en": "Allow-list of permitted targets"},
    "rules.allowlist_desc": {
        "pl": "Jeśli lista jest <strong>niepusta</strong>, skanować można wyłącznie cele, które do niej pasują - "
              "to twardy „scope guard\" chroniący przed skanem poza zakresem. Pusta lista = brak ograniczenia.",
        "en": "If the list is <strong>non-empty</strong>, only matching targets may be scanned - a hard "
              "scope guard preventing out-of-scope scans. An empty list means no restriction."},
    "rules.entries": {"pl": "Wpisy", "en": "Entries"},
    "rules.active_entries": {"pl": "aktywnych wpisów", "en": "active entries"},
    "rules.save": {"pl": "Zapisz reguły", "en": "Save rules"},
    "rules.syntax": {"pl": "Składnia", "en": "Syntax"},
    "rules.syntax_exact": {"pl": "dokładny host", "en": "exact host"},
    "rules.syntax_wild": {"pl": "host i wszystkie subdomeny", "en": "host and all subdomains"},
    "rules.syntax_ip": {"pl": "pojedynczy adres IP", "en": "a single IP address"},
    "rules.syntax_comment": {"pl": "komentarz (pomijany)", "en": "comment (ignored)"},
    "rules.active": {"pl": "Aktywne reguły", "en": "Active rules"},
    "rules.no_rules": {"pl": "Brak reguł - skanowanie dozwolone dla dowolnego (poprawnego) celu.",
                       "en": "No rules - scanning allowed for any (valid) target."},
    "rules.active_warning": {"pl": "Aktywna biala lista: skanowac mozna WYLACZNIE te cele. Pusta lista = brak ograniczen (dowolny cel).",
                             "en": "Active allow-list: ONLY these targets may be scanned. Empty list = no restriction (any target)."},
    "rules.scope_on": {"pl": "Zakres aktywny", "en": "Scope active"},
    "rules.open": {"pl": "Reguly zakresu", "en": "Scope rules"},
    # --- etykiety trybów (modes.py trzyma PL; tu EN + spójne PL) ---
    "mode.passive.label": {"pl": "Pasywny", "en": "Passive"},
    "mode.active.label": {"pl": "Bezpośredni", "en": "Direct"},
    "mode.all.label": {"pl": "Pełny", "en": "Full"},
    # --- raport (nagłówki) ---
    "report.title": {"pl": "raport skanowania", "en": "scan report"},
    "report.generated": {"pl": "Wygenerowano", "en": "Generated"},
    "report.fw_coverage": {"pl": "Zgodność - pokrycie frameworków", "en": "Compliance - framework coverage"},
    "report.controls_of": {"pl": "kontroli", "en": "controls"},
    "report.no_fw": {"pl": "brak trafień", "en": "no matches"},
    "report.matrix": {"pl": "Macierz zgodności", "en": "Compliance matrix"},
    "report.col_control": {"pl": "Kontrola", "en": "Control"},
    "report.col_req": {"pl": "Wymóg", "en": "Requirement"},
    "report.col_hits": {"pl": "Trafień", "en": "Hits"},
    "report.col_maxsev": {"pl": "Max severity", "en": "Max severity"},
    "report.no_controls": {"pl": "brak zmapowanych kontroli", "en": "no mapped controls"},
    "report.assets": {"pl": "Zasoby", "en": "Assets"},
    "report.col_asset": {"pl": "Zasób", "en": "Asset"},
    "report.findings": {"pl": "Znaleziska", "en": "Findings"},
    "report.no_findings": {"pl": "Brak znalezisk.", "en": "No findings."},
    "report.f_asset": {"pl": "Zasób:", "en": "Asset:"},
    "report.f_evidence": {"pl": "Dowód:", "en": "Evidence:"},
    "report.f_reco": {"pl": "Rekomendacja:", "en": "Recommendation:"},
    "report.f_refs": {"pl": "Referencje:", "en": "References:"},
    "report.f_compliance": {"pl": "Zgodność:", "en": "Compliance:"},
    "report.whatmeans": {"pl": "Co to znaczy?", "en": "What does this mean?"},
    "report.footer": {
        "pl": "Wygenerowano przez RacoonScanner. Raport poglądowy - mapowanie na wymogi "
              "regulacyjne nie stanowi formalnej interpretacji prawnej.",
        "en": "Generated by RacoonScanner. Advisory report - mapping to regulatory requirements "
              "is not a formal legal interpretation."},
    # --- raport: nowe sekcje (redesign) ---
    "report.overview": {"pl": "Podsumowanie", "en": "Overview"},
    "report.sev_distribution": {"pl": "Rozkład severity", "en": "Severity breakdown"},
    "report.by_category": {"pl": "Znaleziska wg kategorii", "en": "Findings by category"},
    "report.by_severity": {"pl": "wg severity", "en": "by severity"},
    "report.port": {"pl": "Port", "en": "Port"},
    "report.service": {"pl": "Usługa", "en": "Service"},
    "report.what_is": {"pl": "Co to jest / co może działać", "en": "What it is / what may run"},
    "report.assets_note": {"pl": "Wykryte hosty, porty i usługi. Kolumna „Co to jest\" wyjaśnia, "
                                 "czym jest dany port i co zwykle na nim działa.",
                           "en": "Discovered hosts, ports and services. The \"What it is\" column explains "
                                 "what each port is and what typically runs on it."},
    "report.matrix_note": {"pl": "Które wymogi regulacyjne dotykają znaleziska (mapowanie poglądowe).",
                           "en": "Which regulatory requirements the findings touch (advisory mapping)."},
    "report.no_assets": {"pl": "Brak zasobów.", "en": "No assets."},
    "report.recon": {"pl": "Rozpoznanie (footprinting)", "en": "Reconnaissance (footprinting)"},
    "report.recon_note": {"pl": "Pelny zbior danych zebranych w fazie rozpoznania - takze wtedy, "
                                "gdy nie dalo to konkretnego znaleziska.",
                          "en": "Full set of data gathered during reconnaissance - even when it did "
                                "not yield a concrete finding."},
    "report.recon_empty": {"pl": "Brak zebranych danych rozpoznania.", "en": "No reconnaissance data collected."},
    "recon.hosts": {"pl": "Hosty / IP", "en": "Hosts / IPs"},
    "recon.subdomains": {"pl": "Subdomeny", "en": "Subdomains"},
    "recon.web_targets": {"pl": "Cele web", "en": "Web targets"},
    "recon.web_tech": {"pl": "Technologie web", "en": "Web technologies"},
    "recon.nameservers": {"pl": "Nameservery", "en": "Nameservers"},
    "recon.open_ports": {"pl": "Otwarte porty", "en": "Open ports"},
    "recon.services": {"pl": "Wykryte uslugi do enumeracji", "en": "Services detected for enumeration"},
    "report.tools": {"pl": "Uruchomione narzedzia i skrypty", "en": "Tools and scripts executed"},
    "report.tools_note": {"pl": "Kroki pipeline, ktore sie wykonaly. Rozwin kafelek, aby zobaczyc surowe wyjscie narzedzia (podglad terminala).",
                          "en": "Pipeline steps that ran. Expand a tile to see the tool\u0027s raw output (terminal preview)."},
    "report.tool_noraw": {"pl": "Brak zapisanego wyjscia dla tego kroku.", "en": "No saved output for this step."},
    "report.tool_truncated": {"pl": "... (obciete)", "en": "... (truncated)"},
    "report.of_total": {"pl": "z", "en": "of"},
}


def normalize(lang: str | None) -> str:
    l = (lang or "").lower()
    return l if l in LANGS else DEFAULT_LANG


def t(key: str, lang: str = DEFAULT_LANG) -> str:
    """Tłumaczy klucz na dany język (fallback: PL, potem sam klucz)."""
    entry = _CAT.get(key)
    if not entry:
        return key
    return entry.get(normalize(lang)) or entry.get("pl") or key
