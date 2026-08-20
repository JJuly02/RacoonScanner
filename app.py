"""RacoonScanner - web dashboard orkiestracji recon + audytu zgodności."""
from __future__ import annotations

import os

from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_file, send_from_directory, session, url_for)

from raccoon import auth, i18n, modes, scope
from raccoon.runner import Runner
from raccoon.store import Store, safe_name
from raccoon.workflow import available_workflows, load_workflow

# --- ścieżki ---
BASE_DIR = os.getcwd()
PROJECTS_DIR = os.path.join(BASE_DIR, "projects")
PRIVATE_DIR = os.path.join(BASE_DIR, "private")
SECRET_KEY_FILE = os.path.join(PRIVATE_DIR, "secret.key")
os.makedirs(PROJECTS_DIR, exist_ok=True)
os.makedirs(PRIVATE_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # 1 MB - ochrona przed wielkim uploadem

# --- klucz sesji ---
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, encoding="utf-8") as fh:
        app.secret_key = fh.read().strip()
else:
    import secrets as _secrets
    key = _secrets.token_hex(32)
    with open(SECRET_KEY_FILE, "w", encoding="utf-8") as fh:
        fh.write(key)
    app.secret_key = key
    print("[*] Wygenerowano nowy klucz aplikacji w 'private/'.")

auth.ensure_credentials(PRIVATE_DIR)
store = Store(PROJECTS_DIR)
runner = Runner(store)


@app.context_processor
def _inject_i18n():
    lang = i18n.normalize(session.get("lang"))
    return {"t": lambda key: i18n.t(key, lang), "current_lang": lang, "langs": i18n.LANGS}


@app.route("/lang/<code>")
def set_lang(code):
    # Zmiana języka dostępna też przed logowaniem (na stronie logowania).
    session["lang"] = i18n.normalize(code)
    return redirect(request.referrer or url_for("index"))


# --- auth ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("user", "")
        password = request.form.get("password", "")
        if auth.verify(PRIVATE_DIR, user, password):
            session["user"] = user
            auth.audit(PRIVATE_DIR, "login")
            return redirect(request.args.get("next") or url_for("index"))
        flash("Błędny login lub hasło.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    auth.audit(PRIVATE_DIR, "logout")
    session.clear()
    return redirect(url_for("login"))


# --- dashboard ---
@app.route("/", methods=["GET", "POST"])
@auth.login_required
def index():
    if request.method == "POST":
        return _start_scan()
    projects = store.list_projects()
    runs_total = sum(len(store.list_runs(p)) for p in projects)
    return render_template(
        "index.html",
        projects=projects,
        runs_total=runs_total,
        workflows=available_workflows(),
        modes=modes.all_modes(),
        default_mode=modes.DEFAULT_MODE.value,
    )


MAX_BATCH_TARGETS = 64


def _collect_targets() -> list[str]:
    """Zbiera cele z pola pojedynczego, listy (textarea) i wgranego pliku .txt."""
    parts = []
    single = request.form.get("target", "").strip()
    if single:
        parts.append(single)
    textarea = request.form.get("targets", "")
    if textarea.strip():
        parts.append(textarea)
    up = request.files.get("targets_file")
    if up and up.filename:
        try:
            parts.append(up.read().decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001 - uszkodzony plik nie może wywalić żądania
            pass
    return scope.parse_target_list("\n".join(parts))


def _start_scan():
    project = safe_name(request.form.get("project_name", ""))
    workflow_slug = request.form.get("workflow", "")
    mode = modes.parse_mode(request.form.get("mode", "")).value
    authorized = request.form.get("authorized") == "on"

    if not project:
        flash("Podaj poprawną nazwę projektu.", "error")
        return redirect(url_for("index"))
    if not authorized:
        flash("Musisz potwierdzić autoryzację do skanowania celów.", "error")
        return redirect(url_for("index"))

    targets = _collect_targets()
    if not targets:
        flash("Podaj przynajmniej jeden cel (pole, lista lub plik .txt).", "error")
        return redirect(url_for("index"))
    if len(targets) > MAX_BATCH_TARGETS:
        flash(f"Za dużo celów w jednej paczce (max {MAX_BATCH_TARGETS}).", "error")
        return redirect(url_for("index"))
    try:
        load_workflow(workflow_slug)
    except FileNotFoundError:
        flash("Nieznany workflow.", "error")
        return redirect(url_for("index"))
    if not auth.rate_ok(f"scan:{request.remote_addr}", limit=5, window=60):
        flash("Zbyt wiele uruchomień - odczekaj chwilę.", "error")
        return redirect(url_for("index"))

    started: list[tuple[str, str]] = []
    rejected: list[str] = []
    for raw in targets:
        ok, target, err = scope.validate_target(raw)
        if not ok:
            rejected.append(f"{raw} ({err})")
            continue
        in_scope, serr = scope.in_scope(target, PRIVATE_DIR)
        if not in_scope:
            rejected.append(f"{target} (poza zakresem)")
            continue
        run_id = runner.submit(project, workflow_slug, target, mode=mode)
        auth.audit(PRIVATE_DIR, "scan_start", f"{project}/{run_id} {workflow_slug} [{mode}] {target}")
        started.append((target, run_id))

    if not started:
        flash("Żaden cel nie przeszedł walidacji/zakresu: " + "; ".join(rejected[:5]), "error")
        return redirect(url_for("index"))
    if rejected:
        more = "…" if len(rejected) > 5 else ""
        flash(f"Pominięto {len(rejected)} cel(e): " + "; ".join(rejected[:5]) + more, "warning")

    label = modes.parse_mode(mode).label
    if len(started) == 1:
        target, run_id = started[0]
        flash(f"Uruchomiono workflow ({label}) na celu {target}.", "success")
        return redirect(url_for("view_run", project=project, run_id=run_id))
    flash(f"Uruchomiono {len(started)} skanów ({label}) w projekcie {project}.", "success")
    return redirect(url_for("view_project", project=project))


# --- projekty i runy ---
@app.route("/project/<project>")
@auth.login_required
def view_project(project):
    project = safe_name(project)
    if project not in store.list_projects():
        flash("Taki projekt nie istnieje.", "error")
        return redirect(url_for("index"))
    return render_template("project.html", project=project, runs=store.list_runs(project))


@app.route("/run/<project>/<run_id>")
@auth.login_required
def view_run(project, run_id):
    project, run_id = safe_name(project), safe_name(run_id)
    meta = runner.status(project, run_id)
    if not meta:
        flash("Taki run nie istnieje.", "error")
        return redirect(url_for("index"))
    return render_template("run.html", project=project, run_id=run_id, meta=meta)


@app.route("/run/<project>/<run_id>/status")
@auth.login_required
def run_status(project, run_id):
    meta = runner.status(safe_name(project), safe_name(run_id))
    if not meta:
        abort(404)
    return meta


@app.route("/run/<project>/<run_id>/stop", methods=["POST"])
@auth.login_required
def stop_run(project, run_id):
    project, run_id = safe_name(project), safe_name(run_id)
    if runner.cancel(project, run_id):
        auth.audit(PRIVATE_DIR, "scan_stop", f"{project}/{run_id}")
        flash("Wysłano żądanie zatrzymania - skan zakończy bieżący krok i przerwie.", "warning")
    else:
        flash("Skan nie jest już aktywny (zakończony lub nieistniejący).", "error")
    return redirect(url_for("view_run", project=project, run_id=run_id))


@app.route("/run/<project>/<run_id>/report")
@auth.login_required
def run_report(project, run_id):
    project, run_id = safe_name(project), safe_name(run_id)
    meta = store.load_meta(project, run_id)
    rows = store.load_findings(project, run_id)
    if meta is None or not os.path.exists(
            os.path.join(store.run_dir(project, run_id), "findings.json")):
        # raport jeszcze niegotowy lub brak znalezisk zapisanych na dysku
        path = os.path.join(store.run_dir(project, run_id), "report.html")
        if not os.path.exists(path):
            flash("Raport nie jest jeszcze gotowy.", "error")
            return redirect(url_for("view_run", project=project, run_id=run_id))
        return send_file(path)
    # Regeneruj raport w aktualnym języku UI (chrome PL/EN), z zapisanych znalezisk.
    from raccoon.findings import Finding
    from raccoon import report
    findings = [Finding.from_dict(d) for d in rows]
    lang = i18n.normalize(session.get("lang"))
    return report.generate(findings, meta, lang=lang)


@app.route("/run/<project>/<run_id>/export.json")
@auth.login_required
def run_export(project, run_id):
    path = os.path.join(store.run_dir(safe_name(project), safe_name(run_id)), "findings.json")
    if not os.path.exists(path):
        abort(404)
    return send_file(path, mimetype="application/json", as_attachment=True,
                     download_name=f"{safe_name(run_id)}_findings.json")


@app.route("/run/<project>/<run_id>/raw/<path:filename>")
@auth.login_required
def download_raw(project, run_id, filename):
    """Bezpieczne pobieranie surowego wyniku narzędzia (naprawia dawny brak trasy)."""
    raw_dir = os.path.join(store.run_dir(safe_name(project), safe_name(run_id)), "raw")
    if not os.path.isdir(raw_dir):
        abort(404)
    # send_from_directory chroni przed path traversal (odrzuca ../).
    return send_from_directory(raw_dir, filename, as_attachment=True)


# --- reguły zakresu (scope guard) ---
@app.route("/rules", methods=["GET", "POST"])
@auth.login_required
def rules():
    if request.method == "POST":
        text = request.form.get("allowlist", "")
        entries = text.splitlines()
        scope.save_allowlist(PRIVATE_DIR, entries)
        active = [e for e in entries if e.strip() and not e.strip().startswith("#")]
        auth.audit(PRIVATE_DIR, "rules_update", f"{len(active)} wpisów")
        flash(f"Zapisano reguły zakresu ({len(active)} aktywnych wpisów).", "success")
        return redirect(url_for("rules"))
    return render_template(
        "rules.html",
        raw=scope.allowlist_text(PRIVATE_DIR),
        active=scope.load_allowlist(PRIVATE_DIR),
    )


# --- usuwanie ---
@app.route("/project/<project>/delete", methods=["POST"])
@auth.login_required
def delete_project(project):
    project = safe_name(project)
    store.delete_project(project)
    auth.audit(PRIVATE_DIR, "delete_project", project)
    flash(f"Usunięto projekt {project}.", "success")
    return redirect(url_for("index"))


def _open_browser_when_ready(url: str, delay: float = 1.2) -> None:
    """Otwiera UI w domyślnej przeglądarce po chwili (gdy serwer wstanie).

    W trybie debug (reloader) planujemy otwarcie tylko w procesie nadrzędnym,
    żeby nie otwierać karty dwa razy.
    """
    import threading
    import webbrowser
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        return
    threading.Timer(delay, lambda: webbrowser.open(url)).start()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="racoonscanner",
        description="RacoonScanner - lokalny panel orkiestracji recon (jak OpenVAS, tylko lżej).",
    )
    parser.add_argument("--pageview", "--web", dest="pageview", action="store_true",
                        help="uruchom panel i otwórz go w przeglądarce (łatwe ustawianie skanów).")
    parser.add_argument("--no-browser", dest="no_browser", action="store_true",
                        help="z --pageview: uruchom serwer, ale nie otwieraj przeglądarki.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="adres nasłuchu (domyślnie 127.0.0.1; użyj 0.0.0.0 dla sieci).")
    parser.add_argument("--port", type=int, default=5000, help="port (domyślnie 5000).")
    parser.add_argument("--debug", action="store_true", help="tryb debug Flaska (reloader).")
    args = parser.parse_args()

    debug = args.debug or os.getenv("FLASK_DEBUG", "0") == "1"
    view_host = "localhost" if args.host in ("0.0.0.0", "") else args.host
    url = f"http://{view_host}:{args.port}/"

    if args.pageview and not args.no_browser:
        _open_browser_when_ready(url)
    if args.pageview:
        print(f"[*] Panel RacoonScanner: {url}  (Ctrl+C aby zatrzymać)")

    app.run(host=args.host, port=args.port, debug=debug)


if __name__ == "__main__":
    main()
