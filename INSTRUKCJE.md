# RacoonScanner — roadmapa

## 1. Wizja

**RacoonScanner** automatyzuje "nudny", w pełni powtarzalny pierwszy etap
pentestu (recon + enumeracja + wstępne wykrywanie podatności) i produkuje z
niego **profesjonalny raport gotowy pod audyt zgodności** (NIS2, UKSC, ISO
27001, DORA).

Zamiast klikać narzędzia pojedynczo, użytkownik odpala **workflow** — pipeline,
który po kolei wykonuje skany, przekazuje wyniki między krokami (output nmapa
karmi whatweb, wykryte parametry URL karmią INCLUDED itd.), a na końcu
normalizuje wszystko do jednego modelu znalezisk (**Finding**) i renderuje
interaktywny raport HTML.

Dwie rzeczy odróżniają to od "kolejnego wrappera na nmapa":
1. **Orkiestracja fazami ataku** — skany łączą się w łańcuch, kolejny krok
   działa na tym, co znalazł poprzedni.
2. **Warstwa zgodności** — każde znalezisko mapuje się na wymogi regulacyjne,
   więc raport nadaje się jako artefakt audytowy dla polskiego rynku
   (UKSC / NIS2), nie tylko jako log z terminala.

## 2. Stan obecny (fundament do przebudowy)

| Element | Status |
|---|---|
| Serwer Flask (`app.py`) | działa, 2 trasy: `/` oraz `/project/<name>` |
| Uruchamianie narzędzi | inline w `app.py`, jedno narzędzie na raz, blokująco |
| Docker (Kali + narzędzia) | gotowy; **brak INCLUDED** w obrazie |
| Pobieranie plików | **NIEDZIAŁAJĄCE — brak trasy `download_file`** |
| Model znalezisk / pipeline / raport | brak — do zbudowania |

### Znane błędy do usunięcia w Etapie 0
1. **KRYTYCZNY — brak trasy `download_file`.** `templates/project.html:17` woła
   `url_for('download_file', ...)`, której nie ma w `app.py` → `BuildError` przy
   wejściu na projekt z plikami.
2. **`debug=True` na `0.0.0.0`** (`app.py:100`) — RCE przez debugger Werkzeug w
   wystawionym kontenerze.
3. **Brakujące ikony Bootstrap** — szablony używają klas `bi`, `base.html` nie
   ładuje `bootstrap-icons`.
4. **`private/` nie jest wolumenem** — `secret.key` regeneruje się przy restarcie.

## 3. Architektura docelowa

```
[ Workflow / Pipeline ]  ->  definicja sekwencji kroków (stage) + zależności
        |
        v
[ Tool Adapters ]        ->  nmap, whatweb, dnsrecon, sqlmap, INCLUDED, ...
        |                    każdy zwraca znormalizowane Findings
        v
[ Finding model ]        ->  wspólny schemat (severity, confidence, evidence,
        |                    referencje CWE/CVE, mapowanie compliance)
        v
[ Compliance engine ]    ->  kategoria findingu -> wymogi NIS2 / UKSC / ISO 27001
        |
        v
[ Report generator ]     ->  samodzielny interaktywny HTML + eksport JSON
```

### Model `Finding` (wspólny dla wszystkich narzędzi)
- `id`, `title`
- `severity` (info / low / medium / high / critical)
- `confidence` (low / medium / high) — INCLUDED daje `confirmed=True` po
  re-fetchu, więc mapujemy to na wysoką pewność
- `category` (open-port, service-version, web-tech, injection-sqli, lfi-rfi,
  dns-misconfig, tls-issue, ...)
- `asset` / `target` (host, port, URL, parametr)
- `evidence` (surowy dowód: payload + fragment odpowiedzi)
- `recommendation`
- `references` (CWE, CVE, linki)
- `compliance` (trafione kontrole, np. `NIS2:art.21`, `UKSC:§...`)

### Integracja INCLUDED
INCLUDED to CLI (`included -w "URL?p=INCLUDE" ... -o out.json -of json`).
JSON to lista rekordów `{module, signal, payload, status, length, evidence}`.
Adapter uruchamia `included` jako podproces (jak reszta narzędzi w `app.py`),
czyta JSON i mapuje każdy rekord na `Finding` (kategoria `lfi-rfi`, confidence
`high` dla potwierdzonych). Punkty wstrzyknięcia (`INCLUDE`) bierzemy z
parametrów URL wykrytych na etapie web-fingerprint.

## 4. Domyślny workflow "Full Recon" (przykład pipeline'u)

| # | Faza | Narzędzie | Wejście | Wyjście |
|---|------|-----------|---------|---------|
| 1 | Discovery / host-up | ping, dnsrecon | domena/IP | żywe hosty, subdomeny, rekordy DNS |
| 2 | Skan portów/usług | nmap `-sV` | hosty z (1) | otwarte porty + wersje usług |
| 3 | Fingerprint web | whatweb | porty http/https z (2) | tech-stack, CMS, nagłówki |
| 4 | Wykrywanie podatności | sqlmap, **INCLUDED** | URL-e/parametry z (3) | potwierdzone SQLi / LFI / RFI |
| 5 | Normalizacja + scoring | (silnik) | findings z 1–4 | ujednolicone `Finding[]` |
| 6 | Mapowanie zgodności | (silnik) | findings | trafienia NIS2/UKSC/ISO |
| 7 | Raport | generator | wszystko | interaktywny HTML + JSON |

Workflow definiujemy deklaratywnie (YAML/JSON) — użytkownik ma móc składać
własne pipeline'y (np. "tylko DNS + web fingerprint", "pełny recon + LFI").

## 5. Roadmapa (etapy)

> Status: **Etapy 0–5 zrealizowane w v0.1.0.** Etap 6 pozostaje backlogiem.

### Etap 0 — decyzja o stacku + stabilizacja ✅
- [x] **Decyzja o stacku: zostajemy przy Pythonie/Flask.** INCLUDED jest w
      Pythonie, a ekosystem narzędzi (python-nmap itd.) najlepiej integruje się
      od tej strony. Web (Flask) rozdzielony od skanów — te lecą w wątku workera
      (`raccoon/runner.py`), więc request się nie blokuje.
- [x] Trasa pobierania plików (`download_raw` + `send_from_directory`, ochrona
      przed path traversal) — dawny `BuildError` naprawiony.
- [x] `debug` sterowany `FLASK_DEBUG`; produkcyjnie gunicorn (Dockerfile CMD).
- [x] Ikony Bootstrap naprawione (doładowany `bootstrap-icons`).
- [x] Wolumeny `projects/` i `private/` w `docker-compose.yml` (trwały secret/auth).
- [x] INCLUDED instalowane w obrazie (`git clone` najnowszego main + `pip install`).

### Etap 1 — model danych i adaptery narzędzi ✅
- [x] Dataclass `Finding` (`raccoon/findings.py`) + serializacja JSON + risk score.
- [x] Bazowy `ToolAdapter` (`raccoon/adapters/base.py`) — czyste `_parse` (testowalne).
- [x] Adaptery: `nmap` (XML `-oX`), `whatweb` (`--log-json`), `dnsrecon` (`-j`),
      `sqlmap` (stdout), `included` (`-of json`), `ping`.
- [x] `app.py` zrefaktorowany — inline-komendy zastąpione adapterami + pipeline.

### Etap 2 — silnik workflow (pipeline) ✅
- [x] Deklaratywne workflow w YAML (`workflows/*.yaml`), kroki + `requires`.
- [x] Executor (`raccoon/runner.py`) — kroki po kolei, artefakty karmią kolejne
      (web_targets z nmapa -> whatweb/sqlmap/INCLUDED).
- [x] Wykonanie asynchroniczne (wątek workera) + status na żywo (polling).
- [x] Wbudowane workflow: "Full Recon" + lekki "DNS + Web".
- [x] **(task usera)** Narzędzia dociągane na obraz Docker w najnowszych wersjach —
      apt z kali-rolling (nmap/sqlmap/whatweb/dnsrecon/gobuster) + `git clone`
      najnowszego INCLUDED. Adapter, którego binarki brak, oznacza krok jako
      `unavailable` i pomija (apka działa dalej).

### Etap 3 — silnik zgodności (NIS2 / UKSC) ✅
- [x] Mapowanie `category` -> kontrole (`raccoon/compliance.py`): NIS2 art. 21(2),
      UKSC, ISO 27001 Annex A, DORA.
- [x] Macierz zgodności (pokrycie kontroli + max severity) i podsumowanie frameworków.
- [x] Scoring ryzyka (severity × confidence) + top znalezisk.

### Etap 4 — raport (interaktywny HTML) ✅
- [x] Samodzielny raport offline (`raccoon/report.py`) — bez CDN, inline CSS/JS.
- [x] Interaktywność: filtr severity, rozwijanie szczegółów, triage (localStorage).
- [x] Panel per-asset + macierz zgodności.
- [x] Eksport HTML + JSON. (PDF — backlog.)

### Etap 5 — bezpieczeństwo produktu i UX ✅
- [x] Uwierzytelnianie (`raccoon/auth.py`) — dashboard za loginem.
- [x] Scope guard: walidacja hosta/IP/URL + potwierdzenie autoryzacji +
      opcjonalny `private/scope_allowlist.txt`.
- [x] Rate limiting uruchomień + log audytowy (`private/audit.log`).
- [x] Usuwanie projektów, historia runów + znaczniki czasu.

### Etap 6 — rozbudowa (backlog)
- [ ] Więcej narzędzi w pipeline: `gobuster` (już w Dockerfile), `subfinder`,
      `nikto`, skan TLS.
- [ ] OSINT: hunter.io (e-maile domeny), AlienVault OTX (threat intel) — z TODO
      w `Readme.md`. Klucze API w `private/`.
- [ ] Biblioteka gotowych workflow (per typ celu: web-app, sieć, domena).
- [ ] Crawler parametrów URL do zasilania INCLUDED (teraz domyślny `?page=INCLUDE`).
- [ ] Eksport raportu do PDF; usuwanie pojedynczych runów z UI.
- [ ] Ochrona CSRF na akcjach POST (start skanu, usuwanie) — obecnie brak;
      akceptowalne dla jednoosobowego dashboardu na localhost, do dodania przy
      wystawieniu wieloużytkownikowym.

## 6. Kolejny krok

v0.1.0 domyka etapy 0–5. Następny naturalny krok to **Etap 6**: crawler
parametrów (żeby INCLUDED dostawał realne punkty wstrzyknięcia zamiast
domyślnego `?page=INCLUDE`) oraz kolejne narzędzia w pipeline.

## 7. Uruchomienie

```bash
docker compose up --build      # UI na http://localhost:5000
```