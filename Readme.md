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

- **Adaptery** (`raccoon/adapters/`) — opakowują narzędzia i sprowadzają wynik do
  wspólnego `Finding`. Warstwa footprintingu (pasywna, „pierwsze narzędzia"):
  **whois** (rejestr domeny, daty, NS), **crt.sh** (Certificate Transparency →
  subdomeny), **Shodan/InternetDB** (porty, CVE) — wszystkie bez pakietów do celu.
  Dalej: **ping**, **nmap** (skan portów; taguje usługi `smb/ftp/snmp/db/...`),
  **whatweb**, **dnsrecon**, **smb** (null session), **sqlmap**, **INCLUDED**.
- **Executor** (`raccoon/runner.py`) — uruchamia pipeline asynchronicznie
  (wątek w tle), łączy artefakty między krokami, pokazuje status na żywo.
- **Silnik zgodności** (`raccoon/compliance.py`) — mapuje kategorie znalezisk na
  kontrole NIS2 / UKSC / ISO 27001 / DORA i buduje macierz pokrycia.
- **Raport** (`raccoon/report.py`) — offline HTML z filtrem severity, triage
  i macierzą zgodności.

## Interfejs i raport

Panel obsługuje **motyw jasny/ciemny** (ciemny domyślnie) oraz **przełącznik języka
PL/EN** (górny pasek). Skan można **zatrzymać** w trakcie, a podwójne kliknięcie
„Uruchom" nie wystartuje dwóch identycznych skanów. Raport HTML ma **rozwijane
wyjaśnienia** przy znaleziskach (np. co oznacza otwarty port 22) i przy kontrolach
w macierzy zgodności; whatweb pokazuje **pełny odcisk technologiczny** celu, nawet
gdy nic krytycznego nie wykryto.

## Tryby pracy

Każdy workflow można uruchomić w jednym z trzech **trybów** (pułap intensywności):

| Tryb | Co robi | Kroki, które przepuszcza |
|------|---------|--------------------------|
| **Pasywny** | Tylko dane ze źródeł zewnętrznych (Shodan/InternetDB). Zero pakietów do celu. | `shodan` |
| **Bezpośredni** | Bezpośrednia, nieinwazyjna enumeracja. Bez sondowania podatności. | + `ping`, `nmap`, `whatweb`, `dnsrecon` |
| **Pełny** | Cały łańcuch, łącznie z aktywnym testowaniem SQLi/LFI/RFI. | + `sqlmap`, `included` |

Tryb wybierasz przy starcie skanu (formularz UI). Dzięki temu ten sam pipeline
(np. `Full Recon`) puszczony „pasywnie" wykona wyłącznie krok Shodan, a puszczony
„pełnie" — całość. Intensywność narzędzia można też nadpisać per-krok w YAML
(`intensity: passive|active|aggressive`).

## Shodan (recon pasywny)

Adapter Shodan działa bez konfiguracji: domyślnie korzysta z darmowego
**InternetDB** (bez klucza, bez kredytów). Jeśli ustawisz klucz, automatycznie
przełącza się na pełny rekord hosta:

```bash
export SHODAN_API_KEY='twoj_klucz'    # opcjonalnie — pełne dane zamiast InternetDB
```

Klucz czytany jest wyłącznie ze zmiennej środowiskowej (nigdy nie trafia do
repozytorium). Samodzielny CLI (`ShodanScaner/shodan_passive.py`) pozostaje
dostępny do użycia poza panelem.

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
python app.py --pageview           # jw. + automatycznie otwiera panel w przeglądarce
```

`--pageview` (alias `--web`) uruchamia lokalny panel i otwiera go w przeglądarce
— wygodne „klikane" ustawianie skanów, w duchu OpenVAS. Flagi: `--host`,
`--port`, `--no-browser`, `--debug`.

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
