#!/usr/bin/env python3
"""
shodan_passive.py - Passive host enumeration for authorised penetration tests.

Queries Shodan's *existing* dataset. It sends ZERO packets to the target
network: all traffic goes to Shodan's API only.

Two data sources:
  --api shodan      Full host record. Costs 1 query credit per IP.
  --api internetdb  InternetDB (https://internetdb.shodan.io). Free, no API
                    key, no credits. Returns ports, hostnames, CPEs, tags,
                    CVEs -- but no banners, no SSL detail, no geo/org.

Results are cached to disk, so re-running never spends a credit twice.

Author: generated for authorised engagement use only.
"""

from __future__ import annotations

import argparse
import csv
import html as _html
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Missing dependency. Run:  pip install requests")

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
SHODAN_INFO_URL = "https://api.shodan.io/api-info"
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

LOG = logging.getLogger("passive")

# Konsola Windows (cp852/cp1250) nie obsluguje polskich znakow - wymuszamy UTF-8
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# --------------------------------------------------------------------------
# Localisation / Lokalizacja
# --------------------------------------------------------------------------
MESSAGES = {
    "pl": {
        "skipped_private": "Pominięto %d adres(ów) nieroutowalnych (Shodan nie posiada dla nich danych): %s",
        "skipped_bad": "Pominięto %d błędny(ch) lub zbyt duży(ch) wpis(ów): %s",
        "cidr_hint": "%s (CIDR – użyj --expand-cidr)",
        "cidr_too_big": "%s (%d adresów > --max-expand %d)",
        "no_reach": "Brak połączenia z Shodan: %s",
        "bad_key_401": "Shodan odrzucił klucz API (401). Sprawdź zmienną SHODAN_API_KEY.",
        "info_http": "api-info zwróciło HTTP %s: %s",
        "plan_info": "Plan Shodan=%s | kredyty zapytań=%s | kredyty skanowania=%s",
        "net_error": "%s: błąd sieci (%s), próba %d",
        "unauth": "%s: 401 brak autoryzacji – nieprawidłowy klucz API. Przerywam.",
        "forbidden": "%s: 403 – brak kredytów zapytań lub plan nie obejmuje dostępu.",
        "backoff": "%s: HTTP %s, oczekiwanie %ss (próba %d)",
        "http_other": "%s: HTTP %s %s",
        "no_targets": "Nie znaleziono żadnych poprawnych adresów publicznych w pliku wejściowym.",
        "scope": "Zakres: %d unikalny(ch) adres(ów) | z pamięci podręcznej: %d | do odpytania: %d",
        "dry_run": "TRYB PRÓBNY – zużyto by około %d kredyt(ów) zapytań.",
        "and_more": "... oraz %d więcej",
        "no_key": "Brak klucza API. Ustaw SHODAN_API_KEY lub użyj --key.",
        "low_credits": "Pozostało tylko %d kredyt(ów), a do odpytania jest %d adres(ów). "
                       "Praca zostanie przerwana po wyczerpaniu kredytów.",
        "confirm": "Odpytać %d adres(ów), koszt ok. %d kredyt(ów)? [t/N] ",
        "yes_answers": ("t", "tak", "y", "yes"),
        "aborted": "Przerwano przez użytkownika.",
        "corrupt_cache": "%s: uszkodzony plik pamięci podręcznej, pomijam",
        "querying": "[%d/%d] odpytuję %s",
        "done": "Gotowe. Raporty zapisano w katalogu %s/",
        "interrupted": "\nPrzerwano. Wyniki w pamięci podręcznej są zachowane; uruchom ponownie, aby wznowić.",
        # nazwy plikow
        "skipped_v6": "Pominięto %d adres(ów) IPv6 (użyj --include-ipv6, aby je odpytać)",
        "dns_start": "Rozwiązywanie %d nazw(y) DNS (tryb: %s)...",
        "dns_done": "Rozwiązano %d/%d nazw(y) → %d unikalny(ch) adres(ów) IP",
        "dns_fail": "Nie rozwiązano %d nazw(y): %s",
        "dns_cache": "Wczytano %d wpis(ów) DNS z pamięci podręcznej",
        "dns_no_key": "Tryb --resolve shodan wymaga klucza API; przechodzę na rozwiązywanie lokalne.",
        "subs_start": "Wyszukiwanie subdomen dla %d domen(y) (koszt: %d kredyt(ów))...",
        "subs_found": "%s: znaleziono %d subdomen(y)",
        "subs_warn": "UWAGA: subdomeny wykryte automatycznie mogą wykraczać poza uzgodniony zakres. "
                     "Zweryfikuj je z klientem przed testami.",
        "dedup": "Deduplikacja: %d nazw(a) → %d unikalny(ch) adres(ów) IP (oszczędność: %d kredyt(ów))",
        "f_domains": "domeny.csv",
        "domains_hdr": "DOMENY I ICH ADRESY",
        "cdn_warn": "HOSTY ZA CDN / PROXY (prawdopodobnie NIE należą do klienta)",
        "in_scope_hosts": "Nazw DNS w zakresie",
        "resolved": "Rozwiązanych nazw",
        "unresolved": "Nierozwiązanych nazw",
        "cdn_footer": "UWAGA: adresy oznaczone jako CDN należą do dostawcy (Cloudflare, Akamai itp.),\n"
                      "a nie do klienta. Nie umieszczaj ich w raporcie jako zasobów klienta i nie\n"
                      "testuj ich aktywnie bez osobnej zgody właściciela infrastruktury.",
        "f_hosts": "hosty.csv",
        "f_services": "uslugi.csv",
        "f_vulns": "podatnosci.csv",
        "f_summary": "podsumowanie.txt",
        # naglowki raportu
        "title": "PODSUMOWANIE REKONESANSU PASYWNEGO",
        "generated": "Wygenerowano (UTC)",
        "source": "Źródło danych",
        "in_scope": "Adresów w zakresie",
        "with_data": "Z danymi",
        "no_data": "Brak danych",
        "errors": "Błędy",
        "from_cache": "Z pamięci podręcznej",
        "credits_spent": "Zużyte kredyty (szac.)",
        "total_services": "Wykrytych usług łącznie",
        "hosts_with_cves": "Hostów ze znanymi CVE",
        "distinct_cves": "Unikalnych CVE",
        "top_ports": "NAJCZĘŚCIEJ WYSTĘPUJĄCE PORTY",
        "cve_hosts": "HOSTY ZE ZGŁOSZONYMI PODATNOŚCIAMI",
        "none": "  (brak)",
        "cve_count": "CVE",
        "ports_label": "porty",
        "footer": "UWAGA: Dane Shodan mają charakter historyczny i mogą być nieaktualne lub błędne.\n"
                  "Wpisy CVE są wnioskowane z numerów wersji w bannerach i MUSZĄ zostać ręcznie\n"
                  "zweryfikowane, zanim trafią do jakiegokolwiek raportu dla klienta.",
    },
    "en": {
        "skipped_private": "Skipped %d non-routable IP(s) (Shodan holds no data for these): %s",
        "skipped_bad": "Skipped %d unparsable/oversized entr(ies): %s",
        "cidr_hint": "%s (CIDR, use --expand-cidr)",
        "cidr_too_big": "%s (%d addrs > --max-expand %d)",
        "no_reach": "Could not reach Shodan: %s",
        "bad_key_401": "Shodan rejected the API key (401). Check SHODAN_API_KEY.",
        "info_http": "api-info returned HTTP %s: %s",
        "plan_info": "Shodan plan=%s | query credits=%s | scan credits=%s",
        "net_error": "%s: network error (%s), attempt %d",
        "unauth": "%s: 401 unauthorised - bad API key. Aborting.",
        "forbidden": "%s: 403 - out of query credits or plan lacks access.",
        "backoff": "%s: HTTP %s, backing off %ss (attempt %d)",
        "http_other": "%s: HTTP %s %s",
        "no_targets": "No valid public IPs found in input.",
        "scope": "Scope: %d unique IP(s) | cached: %d | to query: %d",
        "dry_run": "DRY RUN - would spend approximately %d query credit(s).",
        "and_more": "... and %d more",
        "no_key": "No API key. Set SHODAN_API_KEY or pass --key.",
        "low_credits": "Only %d credit(s) left but %d IP(s) to query. "
                       "The run will stop when credits run out.",
        "confirm": "Query %d IP(s), ~%d credit(s)? [y/N] ",
        "yes_answers": ("y", "yes"),
        "aborted": "Aborted by user.",
        "corrupt_cache": "%s: corrupt cache file, skipping",
        "querying": "[%d/%d] querying %s",
        "done": "Done. Reports written to %s/",
        "interrupted": "\nInterrupted. Cached results are preserved; re-run to resume.",
        "skipped_v6": "Skipped %d IPv6 address(es) (use --include-ipv6 to query them)",
        "dns_start": "Resolving %d hostname(s) (mode: %s)...",
        "dns_done": "Resolved %d/%d hostname(s) -> %d unique IP(s)",
        "dns_fail": "Failed to resolve %d hostname(s): %s",
        "dns_cache": "Loaded %d DNS entr(ies) from cache",
        "dns_no_key": "--resolve shodan needs an API key; falling back to local resolution.",
        "subs_start": "Enumerating subdomains for %d domain(s) (cost: %d credit(s))...",
        "subs_found": "%s: found %d subdomain(s)",
        "subs_warn": "NOTE: auto-discovered subdomains may fall outside the agreed scope. "
                     "Confirm them with the client before testing.",
        "dedup": "Deduplication: %d hostname(s) -> %d unique IP(s) (saved: %d credit(s))",
        "f_domains": "domains.csv",
        "domains_hdr": "DOMAINS AND THEIR ADDRESSES",
        "cdn_warn": "HOSTS BEHIND CDN / PROXY (probably NOT owned by the client)",
        "in_scope_hosts": "Hostnames in scope",
        "resolved": "Resolved",
        "unresolved": "Unresolved",
        "cdn_footer": "NOTE: addresses flagged as CDN belong to the provider (Cloudflare, Akamai etc.),\n"
                      "not to the client. Do not list them as client assets and do not test them\n"
                      "actively without separate permission from the infrastructure owner.",
        "f_hosts": "hosts.csv",
        "f_services": "services.csv",
        "f_vulns": "vulns.csv",
        "f_summary": "summary.txt",
        "title": "PASSIVE RECON SUMMARY",
        "generated": "Generated (UTC)",
        "source": "Data source",
        "in_scope": "Targets in scope",
        "with_data": "With data",
        "no_data": "No data",
        "errors": "Errors",
        "from_cache": "Served from cache",
        "credits_spent": "Credits spent (approx)",
        "total_services": "Total exposed services",
        "hosts_with_cves": "Hosts with known CVEs",
        "distinct_cves": "Distinct CVEs",
        "top_ports": "TOP PORTS",
        "cve_hosts": "HOSTS WITH REPORTED CVEs",
        "none": "  (none)",
        "cve_count": "CVE(s)",
        "ports_label": "ports",
        "footer": "NOTE: Shodan data is historical and may be stale or wrong. CVE entries are\n"
                  "inferred from banner version strings and MUST be manually verified before\n"
                  "they appear in any client-facing report.",
    },
}

# Naglowki kolumn CSV / CSV column headers
HEADERS = {
    "pl": {
        "ip": "ip", "hostnames": "nazwy_hostow", "org": "organizacja", "isp": "isp",
        "asn": "asn", "country": "kraj", "os": "system", "open_ports": "otwarte_porty",
        "port_count": "liczba_portow", "vuln_count": "liczba_podatnosci",
        "vulns": "podatnosci", "tags": "tagi", "last_update": "ostatnia_aktualizacja",
        "port": "port", "transport": "protokol", "product": "produkt",
        "version": "wersja", "cpe": "cpe", "http_title": "tytul_http",
        "ssl_cn": "ssl_cn", "ssl_expires": "ssl_wygasa",
        "timestamp": "znacznik_czasu", "banner_snippet": "fragment_bannera",
        "cve": "cve", "sources": "domeny_zrodlowe", "cdn": "cdn",
        "domain": "domena", "ips": "adresy_ip", "ip_count": "liczba_ip",
        "status": "status",
    },
    "en": {},  # klucze wewnetrzne sa juz angielskie
}

T: dict = MESSAGES["pl"]
H: dict = HEADERS["pl"]
DELIM: str = ";"   # PL Excel domyślnie oczekuje średnika


# --------------------------------------------------------------------------
# Target loading
# --------------------------------------------------------------------------
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

# Wieloczłonowe sufiksy publiczne (skrócona lista – wystarcza dla PL/EU/US).
MULTI_SUFFIXES = {
    "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl", "info.pl", "biz.pl",
    "waw.pl", "krakow.pl", "wroc.pl", "poznan.pl", "gda.pl", "lodz.pl",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "com.au", "net.au",
    "org.au", "co.jp", "co.nz", "com.br", "com.tr", "com.ua", "co.za",
    "com.de", "co.il", "com.cn", "com.mx", "com.es",
}

CDN_ORGS = ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula",
            "imperva", "sucuri", "ddos-guard", "stackpath", "edgecast",
            "azure front door", "google llc", "quic.cloud", "bunnycdn",
            "cdn77", "keycdn", "limelight")


def ip_key(value: str):
    """Klucz sortowania odporny na mieszanie IPv4 i IPv6."""
    try:
        addr = ipaddress.ip_address(value)
        return (addr.version, int(addr))
    except ValueError:
        return (9, 0)


def normalise_hostname(raw: str) -> str | None:
    """https://Sub.Domena.PL:8443/sciezka?x=1  ->  sub.domena.pl"""
    text = raw.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    elif text.startswith("//"):
        text = text[2:]
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in text:                      # user:pass@host
        text = text.rsplit("@", 1)[1]
    if text.startswith("["):             # [::1]:443
        return None
    if text.count(":") == 1:             # host:port
        text = text.split(":", 1)[0]
    text = text.rstrip(".").strip().lower()
    if not text:
        return None
    try:                                 # IDN: żółw.pl -> xn--...
        text = text.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return None
    return text if HOSTNAME_RE.match(text) else None


def apex_of(hostname: str) -> str:
    """mini.domena.com.pl -> domena.com.pl"""
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    if ".".join(parts[-2:]) in MULTI_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def load_scope(paths: list[str], expand_cidr: bool, max_expand: int):
    """Zwraca (ip_sources, hostnames). Wejście: IP, CIDR, domeny lub URL-e."""
    ip_sources: dict[str, set[str]] = {}
    hostnames: dict[str, None] = {}
    skipped_private, skipped_bad = [], []

    for path in paths:
        for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            line = line.split(",")[0].strip()      # "host, opis"
            if not line:
                continue

            # 1) CIDR
            if "/" in line and "://" not in line:
                try:
                    net = ipaddress.ip_network(line, strict=False)
                except ValueError:
                    pass
                else:
                    if not expand_cidr:
                        skipped_bad.append(T["cidr_hint"] % line)
                    elif net.num_addresses > max_expand:
                        skipped_bad.append(
                            T["cidr_too_big"] % (line, net.num_addresses, max_expand))
                    else:
                        for addr in (list(net.hosts()) or [net.network_address]):
                            _add(addr, ip_sources, skipped_private, "")
                    continue

            # 2) goly adres IP (ewentualnie z portem)
            bare = line.split(":", 1)[0] if line.count(":") == 1 else line
            try:
                _add(ipaddress.ip_address(bare), ip_sources, skipped_private, "")
                continue
            except ValueError:
                pass

            # 3) domena lub URL
            host = normalise_hostname(line)
            if host:
                hostnames.setdefault(host, None)
            else:
                skipped_bad.append(line)

    if skipped_private:
        LOG.warning(T["skipped_private"], len(skipped_private),
                    ", ".join(skipped_private[:5])
                    + (" ..." if len(skipped_private) > 5 else ""))
    if skipped_bad:
        LOG.warning(T["skipped_bad"], len(skipped_bad), ", ".join(skipped_bad[:5]))

    return ip_sources, list(hostnames)


def _add(addr, ip_sources: dict, skipped_private: list, source: str) -> None:
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        if source:
            LOG.debug("%s -> %s (nieroutowalny, pomijam)", source, addr)
        skipped_private.append(str(addr))
        return
    entry = ip_sources.setdefault(str(addr), set())
    if source:
        entry.add(source)


# --------------------------------------------------------------------------
# API calls
# --------------------------------------------------------------------------
SHODAN_RESOLVE_URL = "https://api.shodan.io/dns/resolve"
SHODAN_DOMAIN_URL = "https://api.shodan.io/dns/domain/{domain}"


def resolve_via_shodan(hosts: list[str], key: str, session) -> dict[str, list[str]]:
    """Rozwiązywanie przez API Shodana. Darmowe, nie zużywa kredytów zapytań,
    i nie generuje ruchu DNS w kierunku infrastruktury klienta."""
    out: dict[str, list[str]] = {}
    for i in range(0, len(hosts), 100):
        chunk = hosts[i:i + 100]
        try:
            r = session.get(SHODAN_RESOLVE_URL,
                            params={"hostnames": ",".join(chunk), "key": key},
                            timeout=30)
            if r.status_code != 200:
                LOG.warning(T["http_other"], "dns/resolve", r.status_code, r.text[:120])
                continue
            for host, ip in (r.json() or {}).items():
                if ip:
                    out.setdefault(host, []).append(ip)
        except (requests.RequestException, ValueError) as exc:
            LOG.warning(T["net_error"], "dns/resolve", exc, 1)
        time.sleep(1.1)
    return out


def resolve_locally(hosts: list[str]) -> dict[str, list[str]]:
    """Lokalny resolver. Zwraca wszystkie rekordy A i AAAA, ale wysyła
    zapytania DNS (potencjalnie do serwerów klienta)."""
    out: dict[str, list[str]] = {}
    for host in hosts:
        try:
            infos = socket.getaddrinfo(host, None)
        except (socket.gaierror, UnicodeError):
            continue
        ips = []
        for info in infos:
            ip = info[4][0].split("%")[0]
            if ip not in ips:
                ips.append(ip)
        if ips:
            out[host] = ips
    return out


def enumerate_subdomains(domains: list[str], key: str, session) -> dict[str, list[str]]:
    """Shodan /dns/domain – zwraca znane subdomeny wraz z rekordami A.
    Koszt: 1 kredyt zapytania na domenę."""
    found: dict[str, list[str]] = {}
    for domain in domains:
        try:
            r = session.get(SHODAN_DOMAIN_URL.format(domain=domain),
                            params={"key": key}, timeout=30)
        except requests.RequestException as exc:
            LOG.warning(T["net_error"], domain, exc, 1)
            continue
        if r.status_code == 404:
            continue
        if r.status_code != 200:
            LOG.warning(T["http_other"], domain, r.status_code, r.text[:120])
            continue
        payload = r.json() or {}
        for rec in payload.get("data") or []:
            if rec.get("type") not in ("A", "AAAA"):
                continue
            sub = rec.get("subdomain") or ""
            fqdn = f"{sub}.{domain}" if sub else domain
            value = rec.get("value")
            if value:
                found.setdefault(fqdn, [])
                if value not in found[fqdn]:
                    found[fqdn].append(value)
        LOG.info(T["subs_found"], domain, len(payload.get("subdomains") or []))
        time.sleep(1.1)
    return found


def check_api_info(key: str, session: requests.Session) -> dict | None:
    try:
        r = session.get(SHODAN_INFO_URL, params={"key": key}, timeout=20)
    except requests.RequestException as exc:
        LOG.error(T["no_reach"], exc)
        return None

    if r.status_code == 401:
        LOG.error(T["bad_key_401"])
        return None
    if r.status_code != 200:
        LOG.error(T["info_http"], r.status_code, r.text[:200])
        return None

    info = r.json()
    LOG.info(T["plan_info"],
             info.get("plan"), info.get("query_credits"), info.get("scan_credits"))
    return info


def fetch_host(ip: str, args, session: requests.Session) -> tuple[str, dict | None]:
    """Return (status, payload). status in {ok, notfound, error}."""
    if args.api == "internetdb":
        url = INTERNETDB_URL.format(ip=ip)
        params = {}
    else:
        url = SHODAN_HOST_URL.format(ip=ip)
        params = {"key": args.key, "minify": "false"}
        if args.history:
            params["history"] = "true"

    backoff = 5
    for attempt in range(1, args.retries + 2):
        try:
            r = session.get(url, params=params, timeout=args.timeout)
        except requests.RequestException as exc:
            LOG.warning(T["net_error"], ip, exc, attempt)
            time.sleep(backoff)
            backoff *= 2
            continue

        if r.status_code == 200:
            return "ok", r.json()
        if r.status_code == 404:
            # Shodan has never observed this host. No credit is charged.
            return "notfound", None
        if r.status_code == 401:
            LOG.error(T["unauth"], ip)
            raise SystemExit(2)
        if r.status_code == 403:
            LOG.error(T["forbidden"], ip)
            raise SystemExit(2)
        if r.status_code in (429, 502, 503, 504):
            LOG.warning(T["backoff"], ip, r.status_code, backoff, attempt)
            time.sleep(backoff)
            backoff *= 2
            continue

        LOG.warning(T["http_other"], ip, r.status_code, r.text[:150])
        return "error", None

    return "error", None


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------
def _dig(obj, *keys, default=""):
    for k in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(k)
        if obj is None:
            return default
    return obj


def normalise(ip: str, payload: dict, api: str, sources: set[str] | None = None) -> tuple[dict, list[dict]]:
    """Zwraca (wiersz podsumowania hosta, [wiersze uslug])."""
    src = ";".join(sorted(sources or []))
    if api == "internetdb":
        vulns = payload.get("vulns") or []
        host = {
            "ip": ip,
            "sources": src,
            "hostnames": ";".join(payload.get("hostnames") or []),
            "org": "", "isp": "", "asn": "", "country": "", "os": "", "cdn": "",
            "open_ports": ";".join(str(p) for p in sorted(payload.get("ports") or [])),
            "port_count": len(payload.get("ports") or []),
            "vuln_count": len(vulns),
            "vulns": ";".join(sorted(vulns)),
            "tags": ";".join(payload.get("tags") or []),
            "last_update": "",
        }
        services = [
            {
                "ip": ip, "sources": src, "port": p, "transport": "",
                "product": "", "version": "",
                "cpe": ";".join(payload.get("cpes") or []), "http_title": "",
                "ssl_cn": "", "ssl_expires": "", "hostnames": host["hostnames"],
                "org": "", "vulns": host["vulns"], "tags": host["tags"],
                "timestamp": "", "banner_snippet": "",
            }
            for p in sorted(payload.get("ports") or [])
        ]
        return host, services

    # ---- full Shodan record ----
    top_vulns = payload.get("vulns") or []
    org_text = (payload.get("org") or "") + " " + (payload.get("isp") or "")
    is_cdn = any(c in org_text.lower() for c in CDN_ORGS) or \
        "cdn" in [t.lower() for t in (payload.get("tags") or [])]
    host = {
        "ip": payload.get("ip_str", ip),
        "sources": src,
        "cdn": ("tak" if is_cdn else "nie") if T is MESSAGES["pl"] else ("yes" if is_cdn else "no"),
        "hostnames": ";".join(payload.get("hostnames") or []),
        "org": payload.get("org") or "",
        "isp": payload.get("isp") or "",
        "asn": payload.get("asn") or "",
        "country": payload.get("country_name") or "",
        "os": payload.get("os") or "",
        "open_ports": ";".join(str(p) for p in sorted(payload.get("ports") or [])),
        "port_count": len(payload.get("ports") or []),
        "vuln_count": len(top_vulns),
        "vulns": ";".join(sorted(top_vulns)),
        "tags": ";".join(payload.get("tags") or []),
        "last_update": payload.get("last_update") or "",
    }

    services = []
    for svc in payload.get("data") or []:
        svc_vulns = svc.get("vulns") or {}
        if isinstance(svc_vulns, dict):
            svc_vulns = list(svc_vulns.keys())
        banner = (svc.get("data") or "").strip().replace("\r", " ").replace("\n", " ")
        cpe = svc.get("cpe23") or svc.get("cpe") or []
        services.append({
            "ip": svc.get("ip_str", ip),
            "sources": src,
            "port": svc.get("port", ""),
            "transport": svc.get("transport", ""),
            "product": svc.get("product") or "",
            "version": svc.get("version") or "",
            "cpe": ";".join(cpe) if isinstance(cpe, list) else str(cpe),
            "http_title": _dig(svc, "http", "title"),
            "ssl_cn": _dig(svc, "ssl", "cert", "subject", "CN"),
            "ssl_expires": _dig(svc, "ssl", "cert", "expires"),
            "hostnames": ";".join(svc.get("hostnames") or []),
            "org": svc.get("org") or "",
            "vulns": ";".join(sorted(svc_vulns)),
            "tags": ";".join(svc.get("tags") or []),
            "timestamp": svc.get("timestamp", ""),
            "banner_snippet": banner[:300],
        })
    return host, services


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    # utf-8-sig = BOM, dzieki czemu Excel poprawnie pokazuje polskie znaki
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        csv.writer(fh, delimiter=DELIM).writerow([H.get(f, f) for f in fields])
        csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore",
                       delimiter=DELIM).writerows(rows)


HOST_FIELDS = ["ip", "sources", "hostnames", "org", "isp", "asn", "country", "os",
               "cdn", "open_ports", "port_count", "vuln_count", "vulns", "tags",
               "last_update"]
SVC_FIELDS = ["ip", "sources", "port", "transport", "product", "version", "cpe", "http_title",
              "ssl_cn", "ssl_expires", "hostnames", "org", "vulns", "tags",
              "timestamp", "banner_snippet"]


DOMAIN_FIELDS = ["domain", "ips", "ip_count", "status"]


def _md(cell) -> str:
    return str(cell).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _md_table(headers: list[str], rows: list[list], empty: str) -> list[str]:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join(["---"] * len(headers)) + "|"]
    if not rows:
        out.append("| " + empty + " |" + " |" * (len(headers) - 1))
        return out
    for r in rows:
        out.append("| " + " | ".join(_md(c) for c in r) + " |")
    return out


def write_markdown_report(path: Path, hosts, services, stats, args,
                          top_ports, vuln_rows, cdn_hosts, dom_rows=None) -> None:
    """Zbiorczy raport Markdown z pelnego skanu (domyslnie raport_data.md)."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    none = (T["none"].strip() or "-")
    L = [
        f"# {T['title']}",
        "",
        f"- **{T['generated']}:** {now}",
        f"- **{T['source']}:** {args.api}",
        f"- **{T['in_scope_hosts']}:** {stats.get('hostnames', 0)}",
        f"- **{T['resolved']}:** {stats.get('resolved', 0)}",
        f"- **{T['unresolved']}:** {stats.get('unresolved', 0)}",
        f"- **{T['in_scope']}:** {stats['total']}",
        f"- **{T['with_data']}:** {stats['ok']}",
        f"- **{T['no_data']}:** {stats['notfound']}",
        f"- **{T['errors']}:** {stats['error']}",
        f"- **{T['from_cache']}:** {stats['cached']}",
        f"- **{T['credits_spent']}:** {stats['api_calls'] if args.api == 'shodan' else 0}",
        f"- **{T['total_services']}:** {len(services)}",
        f"- **{T['hosts_with_cves']}:** {sum(1 for h in hosts if h['vuln_count'])}",
        f"- **{T['distinct_cves']}:** {len({r['cve'] for r in vuln_rows})}",
        "",
    ]
    if dom_rows:
        L += ["", f"## {T['domains_hdr']}", ""]
        L += _md_table([H.get("domain", "domain"), H.get("ips", "ips"),
                        H.get("ip_count", "ip_count"), H.get("status", "status")],
                       [[d["domain"], d["ips"], d["ip_count"], d["status"]]
                        for d in dom_rows], none)

    L += ["", f"## {T['top_ports']}", ""]
    L += _md_table([H.get("port", "port"), "count"],
                   [[p, c] for p, c in top_ports], none)

    host_cols = ["ip", "hostnames", "org", "country", "cdn",
                 "open_ports", "vuln_count", "tags", "last_update"]
    L += ["", f"## {H.get('ip', 'host').upper()} ({len(hosts)})", ""]
    L += _md_table([H.get(c, c) for c in host_cols],
                   [[h.get(c, "") for c in host_cols] for h in hosts], none)

    svc_cols = ["ip", "port", "transport", "product", "version",
                "http_title", "ssl_cn", "hostnames"]
    L += ["", f"## {T['total_services']} ({len(services)})", ""]
    L += _md_table([H.get(c, c) for c in svc_cols],
                   [[s.get(c, "") for c in svc_cols] for s in services], none)

    L += ["", f"## {T['cve_hosts']}", ""]
    L += _md_table([H.get("cve", "cve"), H.get("ip", "ip"),
                    H.get("hostnames", "hostnames"), H.get("open_ports", "open_ports")],
                   [[r["cve"], r["ip"], r["hostnames"], r["open_ports"]]
                    for r in vuln_rows], none)

    if cdn_hosts:
        L += ["", f"## {T['cdn_warn']}", ""]
        L += _md_table([H.get("ip", "ip"), H.get("org", "org"),
                        H.get("sources", "sources")],
                       [[h["ip"], h["org"], h.get("sources", "")]
                        for h in cdn_hosts], none)
        L += ["", "> " + T["cdn_footer"].replace("\n", "\n> ")]

    L += ["", "---", "", "> " + T["footer"].replace("\n", "\n> "), ""]
    path.write_text("\n".join(L), encoding="utf-8")


_HTML_CSS = """
:root { --bg:#f5f6f8; --fg:#1c2430; --muted:#5b6673; --card:#ffffff;
        --line:#e2e6ea; --accent:#1f6feb; --warn:#b42318; --warnbg:#fff4f2;
        --head:#0f1b2d; --headfg:#eef2f7; --chip:#eef2f7; }
@media (prefers-color-scheme: dark){
  :root { --bg:#0e1218; --fg:#e6ebf1; --muted:#9aa6b2; --card:#161c26;
          --line:#26303d; --accent:#4d9bff; --warn:#ff6b5e; --warnbg:#2a1512;
          --head:#0a0e14; --headfg:#e6ebf1; --chip:#1e2632; } }
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
     font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header{background:var(--head);color:var(--headfg);padding:28px 24px}
header h1{margin:0 0 6px;font-size:20px;letter-spacing:.2px}
header .meta{color:#a9b6c6;font-size:13px}
main{max-width:1200px;margin:0 auto;padding:24px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);
   margin:34px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-top:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card .k{display:block;font-size:12px;color:var(--muted)}
.card .v{display:block;font-size:22px;font-weight:600;margin-top:2px}
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);
      white-space:nowrap;vertical-align:top}
th{background:var(--chip);position:sticky;top:0;font-weight:600}
tbody tr:last-child td{border-bottom:none}
tr.vuln td{background:var(--warnbg)}
td.empty{color:var(--muted);text-align:center;white-space:normal}
.note{background:var(--warnbg);border:1px solid var(--line);border-left:3px solid var(--warn);
      border-radius:8px;padding:12px 14px;color:var(--fg);white-space:pre-wrap;margin-top:14px;font-size:13px}
footer{max-width:1200px;margin:0 auto;padding:8px 24px 40px;color:var(--muted);font-size:12px}
"""


def _h(x) -> str:
    return _html.escape(str(x), quote=True)


def _html_table(headers, rows, empty, classes=None) -> list[str]:
    out = ['<div class="tw"><table><thead><tr>']
    out += [f"<th>{_h(hd)}</th>" for hd in headers]
    out.append("</tr></thead><tbody>")
    if not rows:
        out.append(f'<tr><td class="empty" colspan="{len(headers)}">{_h(empty)}</td></tr>')
    else:
        for i, r in enumerate(rows):
            cls = f' class="{classes[i]}"' if classes and classes[i] else ""
            out.append(f"<tr{cls}>" + "".join(f"<td>{_h(c)}</td>" for c in r) + "</tr>")
    out.append("</tbody></table></div>")
    return out


def write_html_report(path: Path, hosts, services, stats, args,
                      top_ports, vuln_rows, cdn_hosts, dom_rows=None) -> None:
    """Czytelny, samodzielny raport HTML z pelnego skanu (domyslnie raport_data.html)."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    none = (T["none"].strip() or "-")
    cards = [
        (T["source"], args.api),
        (T["in_scope_hosts"], stats.get("hostnames", 0)),
        (T["resolved"], stats.get("resolved", 0)),
        (T["unresolved"], stats.get("unresolved", 0)),
        (T["in_scope"], stats["total"]),
        (T["with_data"], stats["ok"]),
        (T["no_data"], stats["notfound"]),
        (T["errors"], stats["error"]),
        (T["from_cache"], stats["cached"]),
        (T["credits_spent"], stats["api_calls"] if args.api == "shodan" else 0),
        (T["total_services"], len(services)),
        (T["hosts_with_cves"], sum(1 for h in hosts if h["vuln_count"])),
        (T["distinct_cves"], len({r["cve"] for r in vuln_rows})),
    ]
    P = [
        "<!doctype html>", '<html lang="pl">', "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_h(T['title'])}</title>",
        f"<style>{_HTML_CSS}</style>", "</head>", "<body>",
        f"<header><h1>{_h(T['title'])}</h1>"
        f"<div class='meta'>{_h(T['generated'])}: {_h(now)}</div></header>",
        "<main>",
        '<div class="cards">',
    ]
    P += [f'<div class="card"><span class="k">{_h(k)}</span>'
          f'<span class="v">{_h(v)}</span></div>' for k, v in cards]
    P.append("</div>")

    if dom_rows:
        P += [f"<h2>{_h(T['domains_hdr'])}</h2>"]
        P += _html_table([H.get("domain", "domain"), H.get("ips", "ips"),
                          H.get("ip_count", "ip_count"), H.get("status", "status")],
                         [[d["domain"], d["ips"], d["ip_count"], d["status"]]
                          for d in dom_rows], none)

    P += [f"<h2>{_h(T['top_ports'])}</h2>"]
    P += _html_table([H.get("port", "port"), "count"],
                     [[p, c] for p, c in top_ports], none)

    host_cols = ["ip", "hostnames", "org", "country", "cdn",
                 "open_ports", "vuln_count", "tags", "last_update"]
    P += [f"<h2>{_h(H.get('ip', 'host').upper())} ({len(hosts)})</h2>"]
    P += _html_table([H.get(c, c) for c in host_cols],
                     [[h.get(c, "") for c in host_cols] for h in hosts], none,
                     classes=["vuln" if h["vuln_count"] else "" for h in hosts])

    svc_cols = ["ip", "port", "transport", "product", "version",
                "http_title", "ssl_cn", "hostnames"]
    P += [f"<h2>{_h(T['total_services'])} ({len(services)})</h2>"]
    P += _html_table([H.get(c, c) for c in svc_cols],
                     [[s.get(c, "") for c in svc_cols] for s in services], none)

    P += [f"<h2>{_h(T['cve_hosts'])}</h2>"]
    P += _html_table([H.get("cve", "cve"), H.get("ip", "ip"),
                      H.get("hostnames", "hostnames"), H.get("open_ports", "open_ports")],
                     [[r["cve"], r["ip"], r["hostnames"], r["open_ports"]]
                      for r in vuln_rows], none)

    if cdn_hosts:
        P += [f"<h2>{_h(T['cdn_warn'])}</h2>"]
        P += _html_table([H.get("ip", "ip"), H.get("org", "org"),
                          H.get("sources", "sources")],
                         [[h["ip"], h["org"], h.get("sources", "")]
                          for h in cdn_hosts], none)
        P += [f'<div class="note">{_h(T["cdn_footer"])}</div>']

    P += [f'<div class="note">{_h(T["footer"])}</div>', "</main>",
          f"<footer>passive-recon &middot; {_h(args.api)} &middot; {_h(now)}</footer>",
          "</body></html>"]
    path.write_text("\n".join(P), encoding="utf-8")


def write_reports(outdir: Path, hosts: list[dict], services: list[dict],
                  stats: dict, args, dns_map: dict | None = None) -> None:
    write_csv(outdir / T["f_hosts"], hosts, HOST_FIELDS)
    write_csv(outdir / T["f_services"], services, SVC_FIELDS)

    vuln_rows = []
    for h in hosts:
        for cve in filter(None, h["vulns"].split(";")):
            vuln_rows.append({"ip": h["ip"], "cve": cve, "hostnames": h["hostnames"],
                              "org": h["org"], "open_ports": h["open_ports"]})
    vuln_rows.sort(key=lambda r: (r["cve"], r["ip"]))
    write_csv(outdir / T["f_vulns"], vuln_rows,
              ["ip", "cve", "hostnames", "org", "open_ports"])

    dom_rows: list[dict] = []
    if dns_map is not None:
        dom_rows = [
            {"domain": h, "ips": ";".join(ips), "ip_count": len(ips),
             "status": ("OK" if ips else ("brak" if T is MESSAGES["pl"] else "none"))}
            for h, ips in sorted(dns_map.items())
        ]
        write_csv(outdir / T["f_domains"], dom_rows, DOMAIN_FIELDS)

    port_tally: dict[str, int] = {}
    for s in services:
        port_tally[str(s["port"])] = port_tally.get(str(s["port"]), 0) + 1
    top_ports = sorted(port_tally.items(), key=lambda kv: (-kv[1], int(kv[0] or 0)))[:20]

    w = 24  # szerokosc etykiety
    lines = [
        T["title"],
        "=" * 68,
        f"{T['generated']:<{w}}: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"{T['source']:<{w}}: {args.api}",
        f"{T['in_scope_hosts']:<{w}}: {stats.get('hostnames', 0)}",
        f"{T['resolved']:<{w}}: {stats.get('resolved', 0)}",
        f"{T['unresolved']:<{w}}: {stats.get('unresolved', 0)}",
        f"{T['in_scope']:<{w}}: {stats['total']}",
        f"{T['with_data']:<{w}}: {stats['ok']}",
        f"{T['no_data']:<{w}}: {stats['notfound']}",
        f"{T['errors']:<{w}}: {stats['error']}",
        f"{T['from_cache']:<{w}}: {stats['cached']}",
        f"{T['credits_spent']:<{w}}: {stats['api_calls'] if args.api == 'shodan' else 0}",
        "",
        f"{T['total_services']:<{w}}: {len(services)}",
        f"{T['hosts_with_cves']:<{w}}: {sum(1 for h in hosts if h['vuln_count'])}",
        f"{T['distinct_cves']:<{w}}: {len({r['cve'] for r in vuln_rows})}",
        "",
        T["top_ports"],
        "-" * 68,
    ]
    lines += [f"  {p:>6}  x{c}" for p, c in top_ports] or [T["none"]]
    lines += ["", T["cve_hosts"], "-" * 68]
    flagged = sorted((h for h in hosts if h["vuln_count"]),
                     key=lambda h: -h["vuln_count"])
    lines += [f"  {h['ip']:<16} {h['vuln_count']:>3} {T['cve_count']}  "
              f"{T['ports_label']}: {h['open_ports']}" for h in flagged] or [T["none"]]
    cdn_hosts = [h for h in hosts if h.get("cdn") in ("tak", "yes")]
    if cdn_hosts:
        lines += ["", T["cdn_warn"], "-" * 68]
        lines += [f"  {h['ip']:<16} {h['org'][:28]:<28} {h['sources'][:40]}"
                  for h in cdn_hosts]
        lines += ["", T["cdn_footer"]]

    lines += ["", T["footer"], ""]

    (outdir / T["f_summary"]).write_text("\n".join(lines), encoding="utf-8")
    md_name = getattr(args, "md_file", "raport_data.md")
    if md_name:
        write_markdown_report(outdir / md_name, hosts, services, stats, args,
                              top_ports, vuln_rows, cdn_hosts, dom_rows)
    html_name = getattr(args, "html_file", "raport_data.html")
    if html_name:
        write_html_report(outdir / html_name, hosts, services, stats, args,
                          top_ports, vuln_rows, cdn_hosts, dom_rows)
    print("\n".join(lines))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Passive host enumeration via Shodan. No packets are sent to targets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n"
               "  export SHODAN_API_KEY=xxxx\n"
               "  python3 shodan_passive.py -i targets.txt -o results/\n",
    )
    p.add_argument("-i", "--input", nargs="+", required=True,
                   help="File(s) with one IP or CIDR per line.")
    p.add_argument("-o", "--outdir", default="results",
                   help="Output directory (default: results)")
    p.add_argument("--md-file", default="raport_data.md",
                   help="Nazwa zbiorczego raportu Markdown w katalogu wynikow "
                        "(domyslnie raport_data.md; pusty ciag = nie zapisuj).")
    p.add_argument("--html-file", default="raport_data.html",
                   help="Nazwa czytelnego raportu HTML w katalogu wynikow "
                        "(domyslnie raport_data.html; pusty ciag = nie zapisuj).")
    p.add_argument("--api", choices=["shodan", "internetdb"], default="shodan",
                   help="shodan = full record, 1 credit/IP. internetdb = free, less detail.")
    p.add_argument("--key", default=os.environ.get("SHODAN_API_KEY", ""),
                   help="API key. Prefer the SHODAN_API_KEY env var.")
    p.add_argument("--delay", type=float, default=1.1,
                   help="Seconds between requests (default 1.1; Shodan limit is 1/s).")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--history", action="store_true",
                   help="Shodan only: include full banner history.")
    p.add_argument("--expand-cidr", action="store_true",
                   help="Expand CIDR ranges into individual IPs.")
    p.add_argument("--max-expand", type=int, default=1024,
                   help="Refuse to expand a CIDR larger than this (default 1024).")
    p.add_argument("--force", action="store_true",
                   help="Ignore cache and re-query (spends credits again).")
    p.add_argument("--dry-run", action="store_true",
                   help="Show target count and credit cost, then exit.")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip the confirmation prompt.")
    p.add_argument("--resolve", choices=["shodan", "local", "both", "none"],
                   default="both",
                   help="Sposób rozwiązywania domen: both (lokalnie + pasywnie Shodan, "
                        "domyślne – najpewniejsze), local (tylko własny resolver, "
                        "wszystkie rekordy A/AAAA), shodan (tylko pasywny DNS Shodana, "
                        "bywa pusty dla mniejszych domen), none.")
    p.add_argument("--include-ipv6", action="store_true",
                   help="Uwzglednij adresy IPv6 z DNS. Domyslnie pomijane – Shodan ma "
                        "dla nich znikome pokrycie, a podwajaja koszt w kredytach.")
    p.add_argument("--subdomains", action="store_true",
                   help="Wyszukaj subdomeny przez Shodan /dns/domain. Koszt: 1 kredyt na domenę.")
    p.add_argument("--lang", choices=["pl", "en"], default="pl",
                   help="Język wyników / output language (domyślnie: pl)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    global T, H, DELIM
    T = MESSAGES[args.lang]
    H = HEADERS[args.lang]
    DELIM = ";" if args.lang == "pl" else ","

    outdir = Path(args.outdir)
    rawdir = outdir / f"raw-{args.api}"
    rawdir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stderr),
                  logging.FileHandler(outdir / "run.log", encoding="utf-8")],
    )

    session = requests.Session()
    session.headers["User-Agent"] = "passive-recon/1.1"

    ip_sources, hostnames = load_scope(args.input, args.expand_cidr, args.max_expand)

    # ---- rozwiazywanie DNS ----
    dns_cache_file = outdir / "dns-cache.json"
    dns_map: dict[str, list[str]] = {}
    if dns_cache_file.exists() and not args.force:
        try:
            dns_map = json.loads(dns_cache_file.read_text(encoding="utf-8"))
            LOG.info(T["dns_cache"], len(dns_map))
        except json.JSONDecodeError:
            dns_map = {}

    mode = args.resolve
    if mode in ("shodan", "both") and not args.key:
        LOG.warning(T["dns_no_key"])
        mode = "local" if mode == "shodan" else "local"

    if args.subdomains and hostnames:
        if not args.key:
            LOG.error(T["no_key"])
            return 1
        apexes = sorted({apex_of(h) for h in hostnames})
        LOG.info(T["subs_start"], len(apexes), len(apexes))
        if args.yes or input(T["confirm"] % (len(apexes), len(apexes))
                             ).strip().lower() in T["yes_answers"]:
            discovered = enumerate_subdomains(apexes, args.key, session)
            LOG.warning(T["subs_warn"])
            for fqdn, ips in discovered.items():
                dns_map.setdefault(fqdn, [])
                for ip in ips:
                    if ip not in dns_map[fqdn]:
                        dns_map[fqdn].append(ip)
                if fqdn not in hostnames:
                    hostnames.append(fqdn)

    pending_hosts = [h for h in hostnames if h not in dns_map]
    if pending_hosts and mode != "none":
        LOG.info(T["dns_start"], len(pending_hosts), mode)
        resolved: dict[str, list[str]] = {}
        if mode in ("shodan", "both"):
            resolved.update(resolve_via_shodan(pending_hosts, args.key, session))
        if mode in ("local", "both"):
            for host, ips in resolve_locally(pending_hosts).items():
                merged = resolved.setdefault(host, [])
                for ip in ips:
                    if ip not in merged:
                        merged.append(ip)
        dns_map.update(resolved)

    for host in hostnames:
        dns_map.setdefault(host, [])
    if dns_map:
        dns_cache_file.write_text(json.dumps(dns_map, indent=2), encoding="utf-8")

    skipped_private: list[str] = []
    skipped_v6 = 0
    considered = 0
    for host, ips in dns_map.items():
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version == 6 and not args.include_ipv6:
                skipped_v6 += 1
                continue
            considered += 1
            _add(addr, ip_sources, skipped_private, host)
    if skipped_v6:
        LOG.info(T["skipped_v6"], skipped_v6)

    ok_hosts = sum(1 for h in hostnames if dns_map.get(h))
    if hostnames:
        LOG.info(T["dns_done"], ok_hosts, len(hostnames), len(ip_sources))
        failed = [h for h in hostnames if not dns_map.get(h)]
        if failed:
            LOG.warning(T["dns_fail"], len(failed), ", ".join(failed[:5])
                        + (" ..." if len(failed) > 5 else ""))
        if considered > len(ip_sources):
            LOG.info(T["dedup"], len(hostnames), len(ip_sources), considered - len(ip_sources))

    targets = sorted(ip_sources, key=ip_key)
    if not targets:
        LOG.error(T["no_targets"])
        return 1

    pending = [ip for ip in targets
               if args.force or not (rawdir / f"{ip}.json").exists()]
    cached_count = len(targets) - len(pending)

    LOG.info(T["scope"], len(targets), cached_count, len(pending))

    if args.dry_run:
        cost = len(pending) if args.api == "shodan" else 0
        LOG.info(T["dry_run"], cost)
        for ip in targets[:25]:
            print(ip)
        if len(targets) > 25:
            print(T["and_more"] % (len(targets) - 25))
        return 0

    if args.api == "shodan" and pending:
        if not args.key:
            LOG.error(T["no_key"])
            return 1
        info = check_api_info(args.key, session)
        if info is None:
            return 1
        credits = info.get("query_credits", 0)
        if isinstance(credits, int) and credits < len(pending):
            LOG.warning(T["low_credits"], credits, len(pending))
        if not args.yes and pending:
            reply = input(T["confirm"] % (len(pending), len(pending)))
            if reply.strip().lower() not in T["yes_answers"]:
                LOG.info(T["aborted"])
                return 0

    stats = {"total": len(targets), "ok": 0, "notfound": 0,
             "error": 0, "cached": cached_count, "api_calls": 0,
             "hostnames": len(hostnames), "resolved": ok_hosts,
             "unresolved": len(hostnames) - ok_hosts}
    hosts, services = [], []

    for idx, ip in enumerate(targets, 1):
        cache_file = rawdir / f"{ip}.json"

        if cache_file.exists() and not args.force:
            try:
                payload = json.loads(cache_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                LOG.warning(T["corrupt_cache"], ip)
                stats["error"] += 1
                continue
            if payload.get("_status") == "notfound":
                stats["notfound"] += 1
                continue
            payload.pop("_status", None)
            stats["ok"] += 1
        else:
            LOG.info(T["querying"], idx, len(targets), ip)
            status, payload = fetch_host(ip, args, session)
            stats["api_calls"] += 1
            time.sleep(args.delay)

            if status == "notfound":
                stats["notfound"] += 1
                cache_file.write_text(json.dumps({"_status": "notfound"}), encoding="utf-8")
                continue
            if status == "error" or payload is None:
                stats["error"] += 1
                continue
            stats["ok"] += 1
            cache_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        host_row, svc_rows = normalise(ip, payload, args.api, ip_sources.get(ip))
        hosts.append(host_row)
        services.extend(svc_rows)

    hosts.sort(key=lambda h: ip_key(h["ip"]))
    services.sort(key=lambda s: (ip_key(s["ip"]), int(s["port"] or 0)))

    write_reports(outdir, hosts, services, stats, args, dns_map if hostnames else None)
    LOG.info(T["done"], outdir)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(MESSAGES["pl"]["interrupted"], file=sys.stderr)
        sys.exit(130)
