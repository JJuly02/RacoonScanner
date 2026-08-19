"""Tryby pracy skanera i klasyfikacja intensywności narzędzi.

Każdy adapter ma przypisaną **intensywność** (jak inwazyjne jest wobec celu):

  * ``passive``    — zero pakietów do celu; dane pochodzą ze źródeł zewnętrznych
                     (np. Shodan/InternetDB). Bezpieczne bez osobnej zgody na ruch.
  * ``active``     — bezpośrednia, ale nieinwazyjna enumeracja (ping, skan portów,
                     fingerprint web, DNS). Wysyła ruch do infrastruktury celu.
  * ``aggressive`` — aktywne sondowanie podatności (sqlmap, INCLUDED) — może
                     modyfikować stan/logi i generować alerty.

**Tryb pracy** to *pułap* intensywności wybierany przy uruchomieniu:

  * ``passive`` — tylko kroki pasywne,
  * ``active``  — kroki pasywne + aktywne (tzw. „bezpośrednio”, bez exploitów),
  * ``all``     — wszystko, łącznie z agresywnym sondowaniem podatności.

Dzięki temu ten sam workflow można uruchomić „na miękko" (recon pasywny) albo
w pełni — bez definiowania osobnych pipeline'ów.
"""
from __future__ import annotations

from enum import Enum


class Intensity(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"

    @property
    def rank(self) -> int:
        return _INT_RANK[self.value]


class Mode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"     # „bezpośrednio" — pasywne + aktywne, bez exploitów
    ALL = "all"

    @property
    def label(self) -> str:
        return _MODE_LABEL[self.value]

    @property
    def description(self) -> str:
        return _MODE_DESC[self.value]

    @property
    def ceiling(self) -> Intensity:
        return _MODE_CEILING[self]


_INT_RANK = {"passive": 0, "active": 1, "aggressive": 2}

_MODE_CEILING: dict["Mode", Intensity] = {
    Mode.PASSIVE: Intensity.PASSIVE,
    Mode.ACTIVE: Intensity.ACTIVE,
    Mode.ALL: Intensity.AGGRESSIVE,
}

_MODE_LABEL = {
    "passive": "Pasywny",
    "active": "Bezpośredni",
    "all": "Pełny",
}

_MODE_DESC = {
    "passive": "Tylko dane ze źródeł zewnętrznych (Shodan/InternetDB). "
               "Zero pakietów do celu — bezpieczny bez osobnej zgody na ruch.",
    "active": "Bezpośrednia enumeracja (ping, porty, web, DNS). "
              "Bez aktywnego sondowania podatności (sqlmap/INCLUDED).",
    "all": "Pełny łańcuch, łącznie z sondowaniem SQLi/LFI/RFI. "
           "Najbardziej inwazyjny — wymaga pełnej autoryzacji.",
}

DEFAULT_MODE = Mode.ALL


def parse_mode(value: str | None) -> Mode:
    """Mapuje wejście (formularz/CLI) na Mode; nieznane -> DEFAULT_MODE.

    Akceptuje też aliasy: ``direct``/``bezposrednio`` -> active,
    ``full`` -> all.
    """
    v = (value or "").strip().lower()
    aliases = {
        "direct": "active", "bezposrednio": "active", "bezpośrednio": "active",
        "full": "all", "aggressive": "all", "agresywny": "all",
        "pasywny": "passive", "aktywny": "active", "pelny": "all", "pełny": "all",
    }
    v = aliases.get(v, v)
    try:
        return Mode(v)
    except ValueError:
        return DEFAULT_MODE


def allows(mode: Mode, intensity: Intensity) -> bool:
    """Czy krok o danej intensywności mieści się w trybie (pułapie)?"""
    return intensity.rank <= mode.ceiling.rank


def all_modes() -> list[Mode]:
    return [Mode.PASSIVE, Mode.ACTIVE, Mode.ALL]
