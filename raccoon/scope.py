"""Walidacja celu i „scope guard".

Dwie warstwy ochrony przed skanowaniem czegoś, czego nie wolno:
  1. walidacja formatu celu (host / IP / URL, bez metaznaków powłoki),
  2. opcjonalna biała lista zakresu (`private/scope_allowlist.txt`) — jeśli
     istnieje i jest niepusta, cel musi do niej pasować.
"""
from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse

from .netutil import host_of

# Dozwolone znaki w hoście/URL — świadomie wykluczamy metaznaki powłoki i spacje.
_HOST_RE = re.compile(r"^[A-Za-z0-9._\-]+$")
_URL_RE = re.compile(r"^https?://[A-Za-z0-9._\-]+(:\d+)?(/[^\s]*)?$")


def validate_target(raw: str) -> tuple[bool, str, str]:
    """Zwraca (ok, znormalizowany_cel, komunikat_błędu)."""
    t = (raw or "").strip()
    if not t:
        return False, "", "Podaj cel (host, IP lub URL)."
    if any(c in t for c in " \t\n;|&$`<>()"):
        return False, "", "Cel zawiera niedozwolone znaki."
    if "://" in t:
        if not _URL_RE.match(t):
            return False, "", "Niepoprawny URL."
        return True, t, ""
    host = t.split(":", 1)[0] if t.count(":") == 1 else t
    try:
        ipaddress.ip_address(host)
        return True, t, ""
    except ValueError:
        pass
    # Dopuszczamy zarówno FQDN (z kropką), jak i pojedyncze etykiety (localhost,
    # host wewnętrzny) — _HOST_RE i tak wyklucza metaznaki i znaki spoza ASCII.
    if _HOST_RE.match(host):
        return True, t, ""
    return False, "", "Niepoprawny host/IP/URL."


def _allowlist_path(private_dir: str) -> str:
    return os.path.join(private_dir, "scope_allowlist.txt")


def load_allowlist(private_dir: str) -> list[str]:
    path = _allowlist_path(private_dir)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def in_scope(target: str, private_dir: str) -> tuple[bool, str]:
    """Sprawdza cel względem białej listy. Pusta lista => brak ograniczenia."""
    allow = load_allowlist(private_dir)
    if not allow:
        return True, ""
    host = host_of(target)
    for entry in allow:
        e = entry.lstrip("*.")
        if host == entry or host == e or host.endswith("." + e):
            return True, ""
    return False, f"Cel '{host}' spoza dozwolonego zakresu (scope_allowlist.txt)."
