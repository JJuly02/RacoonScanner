# Rekonesans pasywny przez Shodan

Wsadowa enumeracja hostów na potrzeby autoryzowanych testów penetracyjnych.
Na wejściu przyjmuje domeny, adresy www, pojedyncze IP i zakresy CIDR — resztę
ustala sam.

Skrypt odpytuje **istniejące** dane Shodana. Do sieci klienta **nie wysyła
żadnego pakietu** — cały ruch idzie wyłącznie do API Shodana. Dzięki temu
mieści się w fazie pasywnej standardowego zlecenia.

Wyniki (raporty, komunikaty, nagłówki kolumn) są domyślnie po polsku.
Przełącznik `--lang en` przywraca wersję angielską.

---

## Zanim uruchomisz

Pasywnie nadal znaczy *w zakresie*. Upewnij się, że otrzymane adresy faktycznie
należą do klienta — Shodan chętnie zwróci dane o cudzej podsieci, jeśli wkleisz
zły zakres, a takie zapytanie zostanie zalogowane na Twoim kluczu API. Trzymaj
podpisaną autoryzację i listę celów w tym samym katalogu co wyniki.

---

## 1. Instalacja

```bash
pip install requests
chmod +x shodan_passive.py
```

Klucz API pobierzesz z <https://account.shodan.io>:

```bash
# Linux / macOS
export SHODAN_API_KEY="twoj_klucz"

# Windows PowerShell
$env:SHODAN_API_KEY = "twoj_klucz"

# Windows CMD
set SHODAN_API_KEY=twoj_klucz
```

Dopisz to do `~/.bashrc` / `~/.zshrc`, żeby ustawienie było trwałe. Nie wpisuj
klucza na sztywno w skrypcie i nie commituj go do repozytorium.

---

## 2. Plik z celami

Jedna pozycja w linii. Skrypt sam rozpoznaje, co dostał — **domeny, adresy www,
pojedyncze IP i zakresy CIDR mogą być wymieszane w jednym pliku**. Komentarze po
`#` są ignorowane, a wszystko po przecinku traktowane jest jako opis.

`targets.txt`:

```
# Zakres zewnętrzny Acme Sp. z o.o. — autoryzacja 2026-08-19
your.domena.com
mini.domena.com
https://sklep.domena.com/panel        # URL — ścieżka i port są obcinane
poczta.domena.com, serwer pocztowy    # opis po przecinku
203.0.113.10                          # zwykłe IP też przejdzie
198.51.100.0/29                       # CIDR (wymaga --expand-cidr)
```

Normalizacja obsługuje: schematy `http://`/`https://`, ścieżki, parametry,
porty (`:8443`), `user:pass@host`, wielkie litery, kropkę na końcu oraz nazwy
IDN z polskimi znakami (`żółw.pl` → `xn--w-uga1v8h.pl`).

### Co się dzieje dalej

1. Domeny są rozwiązywane na adresy IP.
2. Adresy są **deduplikowane** — jeśli dziesięć subdomen wskazuje na ten sam
   serwer, zapłacisz za **jeden** kredyt, nie dziesięć. Przy typowym hostingu
   współdzielonym to największa oszczędność w całym procesie.
3. Każdy unikalny adres jest odpytywany w Shodanie.
4. W raporcie zachowana jest informacja zwrotna: kolumna `domeny_zrodlowe`
   mówi, która domena doprowadziła do danego adresu.

### Tryby rozwiązywania (`--resolve`)

| Tryb | Opis |
|---|---|
| `shodan` | **Domyślny.** Rozwiązywanie przez API Shodana. Darmowe, nie zużywa kredytów zapytań i — co ważne — **nie generuje żadnego ruchu DNS w stronę serwerów klienta**. Zwraca jeden rekord A na nazwę. |
| `local` | Twój systemowy resolver. Zwraca **wszystkie** rekordy A i AAAA, więc lepiej pokrywa load balancing i round-robin. Wysyła jednak realne zapytania DNS, które mogą trafić do serwerów autorytatywnych klienta. |
| `both` | Scala oba źródła. Najszersze pokrycie. |
| `none` | Nie rozwiązuj — użyj wyłącznie cache'u DNS i adresów podanych wprost. |

Jeśli zależy Ci na pełnej pasywności (zero śladu po Twojej stronie), zostaw
`shodan`. Jeśli ważniejsza jest kompletność listy adresów, użyj `both`.

Adresy **IPv6 są domyślnie pomijane** — Shodan ma dla nich znikome pokrycie, a
podwajają koszt w kredytach. Włącz je przez `--include-ipv6`.

### Automatyczne wyszukiwanie subdomen

Jeśli chcesz, żeby skrypt sam poszerzył listę:

```bash
python3 shodan_passive.py -i targets.txt -o acme-recon --subdomains
```

Dla każdej domeny nadrzędnej (`mini.domena.com` → `domena.com`) odpytuje
Shodan `/dns/domain` i dokłada do zakresu wszystkie znane subdomeny wraz z ich
rekordami A. **Koszt: 1 kredyt na domenę** — dostaniesz pytanie potwierdzające.

Wykrywanie domeny nadrzędnej rozumie sufiksy wieloczłonowe (`com.pl`, `co.uk`,
`gov.pl` itd.), więc `sklep.domena.com.pl` daje `domena.com.pl`, a nie `com.pl`.

> **Ostrożnie:** subdomeny znalezione automatycznie **nie są objęte Twoją
> autoryzacją**. Shodan zwróci wszystko, co widział dla danej domeny, łącznie z
> hostami należącymi do innych podmiotów albo wycofanymi z użycia. Zweryfikuj
> listę z klientem, zanim cokolwiek trafi do testów aktywnych.

---

## 3. Uruchomienie

Najpierw zawsze tryb próbny, żeby zobaczyć koszt:

```bash
python3 shodan_passive.py -i targets.txt -o acme-recon --dry-run
```

Potem właściwe uruchomienie:

```bash
python3 shodan_passive.py -i targets.txt -o acme-recon
```

Dostaniesz informację o planie i liczbie kredytów oraz pytanie potwierdzające
(`[t/N]`), zanim cokolwiek zostanie zużyte. `-y` pomija pytanie w trybie
skryptowym.

### Rozwijanie CIDR

Bloki CIDR są ignorowane, o ile nie włączysz tego jawnie — `/16` wyczerpałoby
kredyty w kilka sekund:

```bash
python3 shodan_passive.py -i targets.txt -o acme-recon --expand-cidr
```

Zakresy większe niż 1024 adresy są odrzucane. Limit podnosisz przez
`--max-expand`, ale tylko jeśli wiesz, że masz kredyty.

---

## 4. Pilnowanie kredytów

Promocja „5 dolarów dożywotnio" to tier **Membership**, który daje miesięczny
przydział kredytów zapytań, a nie nieograniczone wyszukiwania. Jedno zapytanie
`--api shodan` = **1 kredyt**, więc zakres 300 adresów nie zmieści się w jednym
miesiącu na tym planie. Skrypt na starcie odczytuje Twój rzeczywisty stan
kredytów z `/api-info` i ostrzega, jeśli zakres go przekracza.

Dwie rzeczy obniżają koszt:

**Wyniki są cache'owane.** Każda odpowiedź trafia do
`<katalog>/raw-<api>/<ip>.json`. Ponowne uruchomienie na tym samym zakresie
czyta z dysku i nie kosztuje nic. Jeśli przebieg padnie w połowie — po prostu
uruchom ponownie, wznowi od miejsca przerwania. `--force` stosuj wyłącznie
wtedy, gdy świadomie chcesz świeże dane.

**Jest darmowa alternatywa.** `https://internetdb.shodan.io` nie wymaga klucza
i nie zużywa kredytów:

```bash
python3 shodan_passive.py -i targets.txt -o acme-recon --api internetdb
```

Zwraca otwarte porty, nazwy hostów, CPE, tagi i CVE — ale bez bannerów, bez
szczegółów certyfikatów TLS i bez organizacji/ASN/geolokalizacji. Przy dużym
zakresie sensowna taktyka to: przemiel całość przez `internetdb`, a prawdziwe
kredyty (`--api shodan`) wydaj tylko na te hosty, które wyglądają ciekawie.

---

## 5. Wyniki

```
acme-recon/
├── hosty.csv           jeden wiersz na host: domeny źródłowe, porty, organizacja,
│                       ASN, flaga CDN, liczba CVE
├── uslugi.csv          jeden wiersz na usługę: produkt, wersja, CPE,
│                       CN i data wygaśnięcia TLS, tytuł HTTP, fragment bannera
├── podatnosci.csv      spłaszczona lista IP → CVE, gotowa do triage'u
├── domeny.csv          mapa domena → adresy IP, ze statusem rozwiązania
├── podsumowanie.txt    najczęstsze porty, hosty z CVE, hosty za CDN, statystyki
├── dns-cache.json      zapamiętane wyniki DNS (kasowalne)
├── run.log             pełny log przebiegu
└── raw-shodan/         surowy JSON w cache, jeden plik na adres IP
```

Pliki CSV używają **średnika** jako separatora i kodowania **UTF-8 z BOM**, więc
polska wersja Excela otwiera je poprawnie dwuklikiem, z zachowaniem ogonków.
(Przy `--lang en` separatorem jest przecinek.)

---

## Opcje

| Flaga | Znaczenie |
|---|---|
| `-i, --input` | Plik(i) z celami. Można podać kilka. |
| `-o, --outdir` | Katalog wyników (domyślnie `results`). |
| `--api` | `shodan` (pełne dane, 1 kredyt) lub `internetdb` (darmowe, mniej szczegółów). |
| `--lang` | `pl` (domyślnie) lub `en` — język raportów i komunikatów. |
| `--resolve` | `shodan` (domyślnie), `local`, `both` lub `none` — sposób rozwiązywania domen. |
| `--subdomains` | Dociąga subdomeny przez Shodan `/dns/domain`. **1 kredyt na domenę.** |
| `--include-ipv6` | Odpytuj też adresy IPv6 (domyślnie pomijane). |
| `--key` | Klucz API, jeśli nie chcesz używać zmiennej środowiskowej. |
| `--delay` | Odstęp między zapytaniami (domyślnie `1.1`; limit Shodana to 1/s). |
| `--history` | Pełna historia bannerów. Ten sam koszt, znacznie więcej danych. |
| `--expand-cidr` | Rozwija zakresy CIDR na pojedyncze adresy. |
| `--max-expand` | Odrzuca CIDR większe niż podana liczba (domyślnie `1024`). |
| `--force` | Ignoruje cache i odpytuje ponownie. **Zużywa kredyty od nowa.** |
| `--dry-run` | Pokazuje liczbę celów i koszt, po czym kończy pracę. |
| `-y, --yes` | Pomija pytanie potwierdzające. |
| `-v, --verbose` | Logowanie diagnostyczne. |

---

## Interpretacja wyników

Dwa zastrzeżenia, które warto przenieść do raportu:

**Dane są historyczne.** Rekord w Shodanie może mieć tygodnie albo miesiące.
Port opisany jako otwarty może być już zamknięty, a host bez żadnego rekordu może
działać i być po prostu odfiltrowany dla crawlerów Shodana. Brak dowodu nie jest
dowodem braku — wyniki pasywne zawężają obszar testów aktywnych, ale ich nie
zastępują.

**Uważaj na CDN.** Jeśli domena stoi za Cloudflare, Akamai czy podobnym
proxy, rozwiązany adres należy do **dostawcy CDN, nie do klienta**. Skrypt
wykrywa to po organizacji i tagach, oznacza kolumną `cdn` i wypisuje osobną
sekcję ostrzegawczą w podsumowaniu. Takich adresów nie wolno raportować jako
zasobów klienta ani testować aktywnie bez zgody właściciela infrastruktury —
to najczęstszy sposób na przypadkowe wyjście poza zakres przy pracy na
domenach. Prawdziwy adres origin trzeba ustalić inaczej (historyczne rekordy
DNS, certyfikaty, nagłówki poczty).

**CVE są wnioskowane.** Shodan dopasowuje numery wersji z bannerów do baz CVE.
Nie sprawdza, czy poprawka została zbackportowana (bardzo częste w pakietach
RHEL/Debian) ani czy podatny komponent jest w ogóle włączony. Wszystko z
`podatnosci.csv` traktuj jako trop do weryfikacji podczas testów aktywnych, nigdy
jako potwierdzone ustalenie. Wysłanie klientowi niezweryfikowanych CVE z Shodana
to jeden z szybszych sposobów na podważenie zaufania do całego raportu.

---

## Rozwiązywanie problemów

| Objaw | Przyczyna |
|---|---|
| `401 brak autoryzacji` | Zły lub nieustawiony klucz. Sprawdź `echo $SHODAN_API_KEY`. |
| `403` | Brak kredytów zapytań albo plan bez dostępu do API. |
| Częste `429` | Zwolnij tempo: `--delay 2`. |
| „Nie znaleziono żadnych poprawnych adresów publicznych" | Wszystkie linie były prywatne, błędne lub to nierozwinięte CIDR. Zajrzyj do `run.log`. |
| Wszystko zwraca „brak danych" | Normalne dla hostów, których nikt nie zindeksował — często oznaka porządnego filtrowania ruchu wychodzącego. |
| Domena się nie rozwiązuje | Sprawdź `domeny.csv` — status `brak`. Częste dla rekordów wyłącznie MX/CNAME albo nazw już nieistniejących. Spróbuj `--resolve both`. |
| Wszystkie domeny dają jeden adres | Normalne przy hostingu współdzielonym lub CDN. Sprawdź kolumnę `cdn` w `hosty.csv`. |
| Krzaki zamiast ogonków w Excelu | Otwórz przez Dane → Z pliku tekstowego, kodowanie UTF-8, separator średnik. |
