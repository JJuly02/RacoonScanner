# Passive Recon via Shodan

Batch passive host enumeration for authorised penetration tests.

The script queries Shodan's **existing** dataset. It sends **zero packets to the
client's network** — all traffic goes to Shodan's API. This keeps it inside the
"passive" phase of a normal engagement.

---

## Before you run it

Passive still means *in scope*. Confirm the IPs you were given are actually the
client's before you query them — Shodan is happy to return data on someone
else's netblock if you paste in the wrong range, and that lookup is logged
against your API key. Keep the signed authorisation and the target list in the
same folder as your results.

---

## 1. Setup

```bash
pip install requests
chmod +x shodan_passive.py
```

Get your API key from <https://account.shodan.io> and export it:

```bash
# Linux / macOS
export SHODAN_API_KEY="your_key_here"

# Windows PowerShell
$env:SHODAN_API_KEY = "your_key_here"

# Windows CMD
set SHODAN_API_KEY=your_key_here
```

Add it to `~/.bashrc` / `~/.zshrc` to make it permanent. Don't hardcode it into
the script or commit it to a repo.

---

## 2. Build your target file

One IP or CIDR per line. `#` comments are allowed, and the parser tolerates
messy scope docs — it strips trailing ports (`1.2.3.4:443`) and anything after
a comma (`1.2.3.4, web-prod`).

`targets.txt`:

```
# Acme Corp external scope — authorised 2026-08-19
203.0.113.10
203.0.113.11:443
198.51.100.7, web-prod
198.51.100.0/29
10.0.0.0/8          # RFC1918 — skipped automatically
```

Duplicates and non-routable addresses (RFC1918, loopback, link-local,
multicast) are dropped before any credits are spent.

---

## 3. Run it

Always dry-run first to see the credit cost:

```bash
python3 shodan_passive.py -i targets.txt -o acme-recon --dry-run
```

Then the real run:

```bash
python3 shodan_passive.py -i targets.txt -o acme-recon
```

You'll get a plan/credit readout and a confirmation prompt before anything is
spent. Add `-y` to skip the prompt in a scripted run.

### Expanding CIDRs

CIDR blocks are ignored unless you opt in, since a `/16` would drain your
credits instantly:

```bash
python3 shodan_passive.py -i targets.txt -o acme-recon --expand-cidr
```

Anything larger than 1024 addresses is refused. Raise it with `--max-expand`
only if you know you have the credits.

---

## 4. Watch your credits

The `$5 lifetime` deal is the Shodan **Membership** tier, which comes with a
monthly allowance of query credits rather than unlimited lookups. One
`--api shodan` lookup = **1 credit**, so a 300-IP scope will not finish in one
month on that allowance. The script reads your real balance from `/api-info` at
startup and warns you if the scope exceeds it.

Two things keep the cost down:

**Results are cached.** Every response is written to `<outdir>/raw-<api>/<ip>.json`.
Re-running the same scope re-reads from disk and spends nothing. If a run dies
halfway, just re-run it — it resumes. Use `--force` only when you deliberately
want fresh data.

**There's a free tier.** `https://internetdb.shodan.io` needs no key and burns
no credits:

```bash
python3 shodan_passive.py -i targets.txt -o acme-recon --api internetdb
```

It returns open ports, hostnames, CPEs, tags and CVEs — but no banners, no SSL
certificate details, no org/ASN/geo. A good strategy for a large scope is to
sweep everything with `internetdb` first, then spend your real credits on
`--api shodan` for the handful of hosts that look interesting.

---

## 5. Output

```
acme-recon/
├── hosts.csv          one row per host: ports, org, ASN, CVE count
├── services.csv       one row per exposed service: product, version, CPE,
│                      TLS CN + expiry, HTTP title, banner snippet
├── vulns.csv          flattened IP → CVE list, ready for triage
├── summary.txt        top ports, hosts with CVEs, run statistics
├── run.log            full log of the run
└── raw-shodan/        cached raw JSON, one file per IP
```

The CSVs open directly in Excel or import cleanly into your reporting tool.

---

## Options

| Flag | Purpose |
|---|---|
| `-i, --input` | Target file(s). Accepts several. |
| `-o, --outdir` | Output directory (default `results`). |
| `--api` | `shodan` (full, 1 credit) or `internetdb` (free, less detail). |
| `--key` | API key, if you'd rather not use the env var. |
| `--delay` | Seconds between requests (default `1.1`; Shodan's limit is 1/s). |
| `--history` | Include full banner history. Same credit cost, much more data. |
| `--expand-cidr` | Expand CIDR ranges into individual IPs. |
| `--max-expand` | Refuse CIDRs larger than this (default `1024`). |
| `--force` | Ignore the cache and re-query. **Spends credits again.** |
| `--dry-run` | Show target count and cost, then exit. |
| `-y, --yes` | Skip the confirmation prompt. |
| `-v, --verbose` | Debug logging. |

---

## Interpreting the results

Two caveats worth carrying into the report:

**The data is historical.** A Shodan record can be weeks or months old. A port
listed as open may be closed now, and a host with no record may be live and
firewalled against Shodan's crawlers. Absence of evidence isn't evidence of
absence — passive results narrow your active testing, they don't replace it.

**The CVEs are inferred.** Shodan matches banner version strings against CVE
databases. It doesn't check whether a patch was backported (very common on
RHEL/Debian packages) or whether the vulnerable feature is even enabled. Treat
everything in `vulns.csv` as a lead to verify during active testing, never as a
confirmed finding. Shipping unverified Shodan CVEs to a client is one of the
faster ways to lose their confidence in the whole report.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `401 unauthorised` | Bad or unset API key. Check `echo $SHODAN_API_KEY`. |
| `403` | Out of query credits, or your plan lacks API access. |
| Frequent `429` | Lower the rate: `--delay 2`. |
| "No valid public IPs found" | Every line was private, malformed, or an unexpanded CIDR. Check `run.log`. |
| Everything returns "no data" | Normal for hosts that have never been crawled — often a sign of decent egress filtering. |
