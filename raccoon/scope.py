"""Walidacja celu i „scope guard".

Dwie warstwy ochrony przed skanowaniem czegoś, czego nie wolno:
  1. walidacja formatu celu (host / IP / URL, bez metaznaków powłoki),
  2. opcjonalna biała lista zakresu (`private/scope_allowlist.txt`) - jeśli
     istnieje i jest niepusta, cel musi do niej pasować.
"""
from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlparse

from .netutil import host_of

# Dozwolone znaki w hoście/URL - świadomie wykluczamy metaznaki powłoki i spacje.
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
    # host wewnętrzny) - _HOST_RE i tak wyklucza metaznaki i znaki spoza ASCII.
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


def allowlist_text(private_dir: str) -> str:
    """Surowa treść pliku zakresu (z komentarzami) - do edytora reguł."""
    path = _allowlist_path(private_dir)
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


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


def parse_target_list(raw: str) -> list[str]:
    """Rozbija tekst (textarea/plik .txt) na listę czystych celów.

    Format tolerancyjny (jak w ShodanScaner/targets.txt):
      * jeden cel na linię,
      * puste linie i linie zaczynające się od ``#`` pomijane,
      * tekst po ``#`` traktowany jako komentarz,
      * pierwsze pole przed przecinkiem to cel (reszta = opis),
      * biały znak kończy token (np. ``url  # coś``).
    Zwraca listę bez duplikatów, z zachowaniem kolejności.
    """
    out: list[str] = []
    for line in (raw or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        line = line.split(",", 1)[0].strip()
        token = line.split()[0] if line.split() else ""
        if token and token not in out:
            out.append(token)
    return out


def save_allowlist(private_dir: str, entries: list[str]) -> None:
    """Zapisuje białą listę zakresu (jeden wpis na linię)."""
    path = _allowlist_path(private_dir)
    os.makedirs(private_dir, exist_ok=True)
    cleaned = [e.strip() for e in entries if e.strip() and not e.strip().startswith("#")]
    with open(path, "w", encoding="utf-8") as fh:
        if cleaned:
            fh.write("\n".join(cleaned) + "\n")
        else:
            fh.write("")
