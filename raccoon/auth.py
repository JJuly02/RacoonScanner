"""Uwierzytelnianie, log audytowy i prosty rate limiting.

Dashboard nie może być otwarty — uruchamianie skanów wymaga zalogowania.
Model jest jednoużytkownikowy: login i hash hasła trzymane w `private/`.
Hasło pochodzi z env `RACOON_PASSWORD`; jeśli go nie ma, generujemy losowe
i wypisujemy raz na starcie (do środowiska developerskiego).
"""
from __future__ import annotations

import functools
import json
import os
import secrets
import time
from datetime import datetime, timezone

from flask import flash, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

_RATE: dict[str, list[float]] = {}


def _creds_path(private_dir: str) -> str:
    return os.path.join(private_dir, "auth.json")


def ensure_credentials(private_dir: str) -> dict:
    """Wczytuje lub inicjalizuje poświadczenia. Zwraca {'user', 'hash'}."""
    os.makedirs(private_dir, exist_ok=True)
    path = _creds_path(private_dir)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    user = os.getenv("RACOON_USER", "admin")
    password = os.getenv("RACOON_PASSWORD")
    if not password:
        password = secrets.token_urlsafe(12)
        print(f"[*] Wygenerowano hasło startowe dla '{user}': {password}")
        print("    (ustaw RACOON_PASSWORD, aby użyć własnego; zapisano hash w private/auth.json)")
    creds = {"user": user, "hash": generate_password_hash(password)}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(creds, fh)
    return creds


def verify(private_dir: str, user: str, password: str) -> bool:
    creds = ensure_credentials(private_dir)
    return user == creds["user"] and check_password_hash(creds["hash"], password)


def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def audit(private_dir: str, action: str, detail: str = "") -> None:
    os.makedirs(private_dir, exist_ok=True)
    line = json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "user": session.get("user", "-"),
        "ip": request.remote_addr if request else "-",
        "action": action,
        "detail": detail,
    }, ensure_ascii=False)
    with open(os.path.join(private_dir, "audit.log"), "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def rate_ok(key: str, limit: int = 5, window: int = 60) -> bool:
    """Prosty token-bucket per klucz (np. IP): max `limit` akcji na `window` s."""
    now = time.time()
    bucket = [t for t in _RATE.get(key, []) if now - t < window]
    if len(bucket) >= limit:
        _RATE[key] = bucket
        return False
    bucket.append(now)
    _RATE[key] = bucket
    return True
