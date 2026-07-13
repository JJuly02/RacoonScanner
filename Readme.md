# 🦝 RacoonScanner

Automatyzuje "nudny", powtarzalny pierwszy etap pentestu (recon → enumeracja →
wstępne wykrywanie podatności) i produkuje z niego **interaktywny raport gotowy
pod audyt zgodności** (NIS2, UKSC, ISO 27001, DORA).

Zamiast odpalać narzędzia pojedynczo, uruchamiasz **workflow** — pipeline, który
po kolei wykonuje skany i przekazuje wyniki między krokami: nmap znajduje usługi
web → whatweb je fingerprintuje → sqlmap i [INCLUDED](https://github.com/JJuly02/INCLUDED)
testują wykryte cele pod SQLi/LFI/RFI. Wszystkie wyniki lądują w jednym modelu
znalezisk (`Finding`), są mapowane na wymogi regulacyjne i renderowane do
samodzielnego raportu HTML.

## Architektura

```
Workflow (YAML) → Tool Adapters → Finding model → Compliance engine → Report (HTML/JSON)
```

- **Adaptery** (`raccoon/adapters/`) — opakowują narzędzia CLI (nmap, whatweb,
  dnsrecon, sqlmap, INCLUDED, ping) i sprowadzają wynik do wspólnego `Finding`.
- **Executor** (`raccoon/runner.py`) — uruchamia pipeline asynchronicznie
  (wątek w tle), łączy artefakty między krokami, pokazuje status na żywo.
- **Silnik zgodności** (`raccoon/compliance.py`) — mapuje kategorie znalezisk na
  kontrole NIS2 / UKSC / ISO 27001 / DORA i buduje macierz pokrycia.
- **Raport** (`raccoon/report.py`) — offline HTML z filtrem severity, triage
  i macierzą zgodności.

## Uruchomienie (Docker)

```bash
export RACOON_PASSWORD='twoje-haslo'
docker compose up --build          # UI na http://localhost:5000
```

Obraz bazuje na Kali i zawiera nmap, sqlmap, whatweb, dnsrecon, gobuster oraz
INCLUDED. Bez ustawienia `RACOON_PASSWORD` hasło startowe generowane jest losowo
(zobacz logi kontenera).

## Uruchomienie lokalne (dev)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py                      # http://localhost:5000
```

Narzędzia skanujące muszą być zainstalowane lokalnie — brakujące kroki pipeline
oznaczane są jako `unavailable` i pomijane (aplikacja działa dalej).

## Zakres i etyka

Narzędzie służy **wyłącznie do autoryzowanych testów**. Uruchomienie skanu
wymaga potwierdzenia autoryzacji; opcjonalny plik `private/scope_allowlist.txt`
ogranicza dozwolone cele. Każde uruchomienie trafia do `private/audit.log`.

## Testy

```bash
.venv/bin/python tests/run_smoke.py
```
