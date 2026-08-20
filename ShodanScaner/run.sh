#!/usr/bin/env bash
# Wrapper: passive Shodan recon. Uruchamia skaner w lokalnym venv.
# Użycie:
#   ./run.sh                      # pełny Shodan (wymaga SHODAN_API_KEY), cele z targets.txt
#   ./run.sh --dry-run            # pokaż liczbę celów i koszt w kredytach, nie odpytuj
#   ./run.sh --api internetdb     # darmowe źródło, bez klucza i kredytów
#   ./run.sh --subdomains -v      # dowolne dodatkowe flagi są przekazywane dalej
set -euo pipefail
cd "$(dirname "$0")"

PY="./.venv/bin/python"
[ -x "$PY" ] || { echo "Brak venv. Uruchom najpierw:  python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt" >&2; exit 1; }

# Klucz potrzebny tylko dla pełnego API 'shodan' (domyślne). Dla 'internetdb' nie.
if [[ " $* " != *" --api internetdb "* && -z "${SHODAN_API_KEY:-}" ]]; then
  echo "UWAGA: SHODAN_API_KEY nie jest ustawiony. Ustaw go:  export SHODAN_API_KEY=xxxx" >&2
  echo "       (albo użyj darmowego źródła:  ./run.sh --api internetdb)" >&2
fi

exec "$PY" shodan_passive.py -i targets.txt "$@"
