"""Baza wiedzy „co to znaczy" - wyjaśnienia do raportu.

Dostarcza ludzkie objaśnienia dla: portów/usług, kategorii znalezisk oraz
kontroli zgodności. Używane przez generator raportu do rozwijanych sekcji
(sekcje „Co to znaczy?"), żeby czytelnik nie musiał znać na pamięć numerów portów
ani oznaczeń NIS2/ISO.
"""
from __future__ import annotations

import re

# --- Porty / usługi ---------------------------------------------------------
PORT_INFO: dict[int, tuple[str, str]] = {
    21: ("FTP", "Transfer plików. Bez TLS przesyła login i hasło otwartym tekstem."),
    22: ("SSH", "Zdalny, szyfrowany dostęp do powłoki. Kluczowa usługa - pilnuj wersji, kluczy i uwierzytelniania."),
    23: ("Telnet", "Zdalna powłoka BEZ szyfrowania - przestarzała, przesyła hasła jawnie. Zastąp SSH."),
    25: ("SMTP", "Serwer poczty wychodzącej. Może ujawniać użytkowników (VRFY/EXPN) i być open-relay."),
    53: ("DNS", "Serwer nazw. Źle skonfigurowany pozwala na transfer strefy (AXFR) = mapa całej domeny."),
    80: ("HTTP", "Serwer WWW bez szyfrowania. Ruch (w tym sesje) może być podsłuchany - przekieruj na HTTPS."),
    110: ("POP3", "Odbiór poczty. Bez TLS przesyła poświadczenia jawnie."),
    111: ("RPCbind", "Mapper portów RPC (często z NFS) - ujawnia usługi do dalszej enumeracji."),
    135: ("MSRPC", "Windows RPC endpoint mapper - punkt startowy enumeracji Windows."),
    139: ("NetBIOS-SSN", "Starsza usługa SMB przez NetBIOS. Często dostępna anonimowo (null session)."),
    143: ("IMAP", "Odbiór poczty. Bez TLS przesyła poświadczenia jawnie."),
    161: ("SNMP", "Zarządzanie urządzeniami. Domyślny community string 'public' ujawnia mnóstwo informacji."),
    389: ("LDAP", "Katalog (np. Active Directory). Może pozwalać na anonimowe zapytania o użytkowników."),
    443: ("HTTPS", "Serwer WWW z TLS. Sprawdź wersję TLS, certyfikat i konfigurację szyfrów."),
    445: ("SMB/CIFS", "Udostępnianie plików. Null session i udziały gościa to klasyczny błąd konfiguracji."),
    465: ("SMTPS", "Poczta wychodząca po TLS."),
    587: ("SMTP (submission)", "Wysyłka poczty przez klienta - wymaga uwierzytelnienia i TLS."),
    993: ("IMAPS", "IMAP po TLS."),
    995: ("POP3S", "POP3 po TLS."),
    1433: ("MSSQL", "Microsoft SQL Server. Baza wystawiona publicznie to poważne ryzyko."),
    1521: ("Oracle TNS", "Oracle DB listener. Podatny na enumerację SID i słabe hasła."),
    3306: ("MySQL", "Baza danych. Nie powinna być dostępna z internetu."),
    3389: ("RDP", "Zdalny pulpit Windows. Wystawiony publicznie = cel ataków brute-force; użyj VPN/MFA."),
    5432: ("PostgreSQL", "Baza danych. Nie powinna być dostępna z internetu."),
    5900: ("VNC", "Zdalny pulpit. Często słaba lub brak autentykacji."),
    6379: ("Redis", "Baza in-memory. Domyślnie BEZ uwierzytelniania - nie wystawiaj publicznie."),
    8080: ("HTTP-alt", "Alternatywny port WWW (proxy, panele aplikacji)."),
    8443: ("HTTPS-alt", "Alternatywny port HTTPS (panele administracyjne)."),
    27017: ("MongoDB", "Baza NoSQL. Historycznie wystawiana bez auth - poważny wyciek danych."),
}


# --- Kategorie znalezisk ----------------------------------------------------
CATEGORY_INFO: dict[str, str] = {
    "open-port": "Otwarty port oznacza usługę nasłuchującą i osiągalną z sieci. Każdy otwarty port "
                 "to powiększenie powierzchni ataku - zweryfikuj, czy usługa musi być wystawiona.",
    "service-version": "Ujawniona nazwa i wersja oprogramowania. Atakujący dobiera po niej gotowe exploity, "
                       "dlatego banner warto ukryć, a oprogramowanie aktualizować.",
    "web-tech": "Technologia wykryta na stronie (serwer, CMS, framework, biblioteka). Znajomość stacku "
                "ułatwia dobranie znanych podatności dla konkretnej wersji.",
    "web-fingerprint": "Pełny odcisk technologiczny celu web - wszystko, co rozpoznało narzędzie "
                       "fingerprintujące (nagłówki, serwer, CMS, biblioteki), także gdy nic krytycznego nie znaleziono.",
    "injection-sqli": "SQL Injection - wstrzyknięcie zapytań do bazy przez niewalidowane wejście. "
                      "Pozwala czytać/modyfikować dane, czasem przejąć serwer. Jedna z najgroźniejszych podatności web.",
    "lfi-rfi": "Local/Remote File Inclusion - dołączanie plików sterowane wejściem użytkownika. "
               "Prowadzi do odczytu wrażliwych plików, a niekiedy do zdalnego wykonania kodu (RCE).",
    "dns-record": "Rekord DNS ujawniony podczas enumeracji. Buduje mapę infrastruktury (hosty, poczta, subdomeny).",
    "zone-transfer": "Transfer strefy DNS (AXFR) dostępny dla nieuprawnionych - zrzuca CAŁĄ zawartość strefy, "
                     "czyli pełną mapę hostów domeny. Powinien być ograniczony do zaufanych serwerów.",
    "known-vuln": "Znana podatność (CVE) przypisana do wersji usługi na podstawie danych pasywnych (Shodan). "
                  "Wymaga potwierdzenia, ale wskazuje prawdopodobny, łatwy do wykorzystania błąd.",
    "cert-transparency": "Nazwy hostów wyciągnięte z publicznych logów Certificate Transparency (certyfikaty TLS). "
                         "Ujawniają subdomeny - także zapomniane/testowe, które bywają najsłabszym ogniwem.",
    "domain-info": "Dane rejestracyjne domeny (whois): właściciel, rejestrator, daty, nameservery. "
                   "Element inwentaryzacji i kontaktu przy incydentach.",
    "domain-expiry": "Data wygaśnięcia domeny. Wygasła/wygasająca domena grozi przejęciem (domain hijacking) "
                     "i przerwą w działaniu usług.",
    "smb-share": "Udział SMB dostępny anonimowo (bez logowania). Może zawierać wrażliwe pliki firmy.",
    "service-exposure": "Usługa wystawiona w sposób umożliwiający enumerację bez uwierzytelnienia "
                        "(np. SMB null session). Typowy błąd konfiguracji.",
    "host-alive": "Host odpowiedział (lub nie) na sondę - informacja z fazy odkrywania (discovery).",
    "tls-issue": "Problem z konfiguracją TLS/SSL (słabe szyfry, przestarzały protokół, zły certyfikat).",
}


# --- Kontrole zgodności -----------------------------------------------------
CONTROL_INFO: dict[str, str] = {
    "NIS2:art.21.2.a": "Wymaga polityk analizy ryzyka i bezpieczeństwa systemów informatycznych - "
                       "inwentaryzacja zasobów i powierzchni ataku to jej fundament.",
    "NIS2:art.21.2.b": "Obsługa incydentów - wykrywanie, zgłaszanie i reagowanie na zdarzenia bezpieczeństwa.",
    "NIS2:art.21.2.e": "Bezpieczeństwo nabywania, rozwoju i utrzymania systemów, w tym podatności - "
                       "np. SQLi/LFI to naruszenia bezpiecznego wytwarzania oprogramowania.",
    "NIS2:art.21.2.f": "Ocena skuteczności środków zarządzania ryzykiem - m.in. zarządzanie podatnościami i wersjami.",
    "NIS2:art.21.2.g": "Podstawowa cyberhigiena i szkolenia - aktualizacje, konfiguracja, higiena ekspozycji usług.",
    "NIS2:art.21.2.h": "Kryptografia i szyfrowanie - poprawne użycie TLS i ochrona danych w tranzycie.",
    "UKSC:art.8": "Ustawa o KSC - wdrożenie zabezpieczeń adekwatnych do oszacowanego ryzyka.",
    "UKSC:art.10": "Ustawa o KSC - utrzymanie i aktualizacja systemów oraz zarządzanie podatnościami.",
    "UKSC:art.14": "Ustawa o KSC - obsługa i zgłaszanie incydentów do właściwego CSIRT.",
    "ISO27001:A.8.8": "Zarządzanie podatnościami technicznymi - identyfikacja i usuwanie znanych luk.",
    "ISO27001:A.8.9": "Zarządzanie konfiguracją - bezpieczne, kontrolowane ustawienia systemów i usług.",
    "ISO27001:A.8.20": "Bezpieczeństwo sieci - kontrola dostępu do usług sieciowych i ograniczanie ekspozycji.",
    "ISO27001:A.8.23": "Filtrowanie ruchu web - ochrona przed niebezpiecznymi treściami i żądaniami.",
    "ISO27001:A.8.24": "Użycie kryptografii - polityki i poprawne wdrożenie szyfrowania.",
    "ISO27001:A.8.28": "Bezpieczne kodowanie - zapobieganie podatnościom takim jak injection.",
    "DORA:art.9": "DORA - ochrona i prewencja ICT: zabezpieczenia techniczne minimalizujące ryzyko operacyjne.",
    "PCI:4.1": "PCI DSS - silna kryptografia podczas transmisji danych kart przez sieci publiczne.",
}


_PORT_RE = re.compile(r":(\d{1,5})\b")


def port_from_asset(asset: str) -> int | None:
    """Wyłuskuje numer portu z zasobu typu 'host:22' / 'host:445 (...)'."""
    m = _PORT_RE.search(asset or "")
    if m:
        p = int(m.group(1))
        if 0 < p < 65536:
            return p
    return None


def explain_finding(category: str, asset: str) -> str:
    """Zwraca wyjaśnienie znaleziska: opis kategorii + (jeśli jest) opis portu."""
    parts = []
    cat = CATEGORY_INFO.get(category)
    if cat:
        parts.append(cat)
    port = port_from_asset(asset)
    if port and port in PORT_INFO:
        name, desc = PORT_INFO[port]
        parts.append(f"Port {port} - {name}: {desc}")
    return "\n\n".join(parts)


def explain_control(control: str) -> str:
    return CONTROL_INFO.get(control, "")


def service_for_asset(asset: str) -> tuple[str, str, str]:
    """Best-effort (port, nazwa_uslugi, opis) na podstawie zasobu.

    Obsluguje 'host:port', URL-e (schemat -> port) i zwykle hosty.
    """
    port = port_from_asset(asset)
    if port is None:
        a = (asset or "").lower()
        if a.startswith("https://"):
            port = 443
        elif a.startswith("http://"):
            port = 80
    if port and port in PORT_INFO:
        name, desc = PORT_INFO[port]
        return (str(port), name, desc)
    if port:
        return (str(port), "", "")
    return ("", "", "")
