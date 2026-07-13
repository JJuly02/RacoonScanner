"""RacoonScanner — web dashboard orkiestracji recon + audytu zgodności."""
from __future__ import annotations

import os

from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_file, send_from_directory, session, url_for)

from raccoon import auth, scope
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
    return render_template(
        "index.html",
        projects=store.list_projects(),
        workflows=available_workflows(),
    )


def _start_scan():
    project = safe_name(request.form.get("project_name", ""))
    target_raw = request.form.get("target", "")
    workflow_slug = request.form.get("workflow", "")
    authorized = request.form.get("authorized") == "on"

    if not project:
        flash("Podaj poprawną nazwę projektu.", "error")
        return redirect(url_for("index"))
    if not authorized:
        flash("Musisz potwierdzić autoryzację do skanowania celu.", "error")
        return redirect(url_for("index"))

    ok, target, err = scope.validate_target(target_raw)
    if not ok:
        flash(err, "error")
        return redirect(url_for("index"))
    in_scope, serr = scope.in_scope(target, PRIVATE_DIR)
    if not in_scope:
        flash(serr, "error")
        return redirect(url_for("index"))
    try:
        load_workflow(workflow_slug)
    except FileNotFoundError:
        flash("Nieznany workflow.", "error")
        return redirect(url_for("index"))
    if not auth.rate_ok(f"scan:{request.remote_addr}", limit=5, window=60):
        flash("Zbyt wiele uruchomień — odczekaj chwilę.", "error")
        return redirect(url_for("index"))

    run_id = runner.submit(project, workflow_slug, target)
    auth.audit(PRIVATE_DIR, "scan_start", f"{project}/{run_id} {workflow_slug} {target}")
    flash(f"Uruchomiono workflow na celu {target}.", "success")
    return redirect(url_for("view_run", project=project, run_id=run_id))


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


@app.route("/run/<project>/<run_id>/report")
@auth.login_required
def run_report(project, run_id):
    path = os.path.join(store.run_dir(safe_name(project), safe_name(run_id)), "report.html")
    if not os.path.exists(path):
        flash("Raport nie jest jeszcze gotowy.", "error")
        return redirect(url_for("view_run", project=project, run_id=run_id))
    return send_file(path)


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


# --- usuwanie ---
@app.route("/project/<project>/delete", methods=["POST"])
@auth.login_required
def delete_project(project):
    project = safe_name(project)
    store.delete_project(project)
    auth.audit(PRIVATE_DIR, "delete_project", project)
    flash(f"Usunięto projekt {project}.", "success")
    return redirect(url_for("index"))


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug)
