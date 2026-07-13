"""Warstwa adapterów narzędzi.

Adapter opakowuje jedno narzędzie CLI: buduje komendę, uruchamia ją jako
podproces i sprowadza surowy wynik do listy `Finding`. Logika parsowania
(`_parse`) jest czysta i nie odpala podprocesów — dzięki temu testuje się ją na
próbkach wyjścia bez instalowania Kali.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

from ..findings import Finding


class ToolUnavailable(RuntimeError):
    """Narzędzie nie jest zainstalowane w środowisku uruchomieniowym."""


@dataclass
class RunContext:
    target: str
    workdir: str
    options: dict = field(default_factory=dict)
    shared: dict = field(default_factory=dict)  # artefakty przekazywane między krokami


@dataclass
class AdapterResult:
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict = field(default_factory=dict)   # trafia do shared context
    raw_files: dict = field(default_factory=dict)   # nazwa -> treść, zapisywane przez executor


def available(binary: str) -> bool:
    return shutil.which(binary) is not None


class ToolAdapter:
    name: str = ""
    binary: str = ""

    def is_available(self) -> bool:
        return available(self.binary)

    def run(self, ctx: RunContext) -> AdapterResult:  # pragma: no cover - override
        raise NotImplementedError

    # --- pomocnicze ---
    def _exec(self, argv: list[str], timeout: int = 300, stdin: str | None = None) -> tuple[int, str]:
        """Uruchamia komendę, zwraca (returncode, połączone stdout+stderr).

        Rzuca ToolUnavailable, gdy binarki nie ma; nie używa shell=True.
        """
        if not available(argv[0]):
            raise ToolUnavailable(argv[0])
        try:
            proc = subprocess.run(
                argv,
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
            return proc.returncode, proc.stdout or ""
        except subprocess.TimeoutExpired as exc:
            return 124, (exc.stdout or "") + f"\n[!] Przekroczono limit czasu ({timeout}s)."
