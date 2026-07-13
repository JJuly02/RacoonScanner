"""Generator samodzielnego, interaktywnego raportu HTML.

Raport jest w pełni offline (bez CDN): CSS i JS są wstawione inline, więc plik
otwiera się w przeglądarce także bez sieci. Zawiera podsumowanie ryzyka,
macierz zgodności (NIS2/UKSC/ISO/DORA), filtr severity, triage (localStorage)
oraz grupowanie znalezisk per zasób.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from . import compliance
from .findings import Finding, sort_by_risk

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {
    "critical": "#e5484d", "high": "#f76808", "medium": "#f5d90a",
    "low": "#46a758", "info": "#5b9dd9",
}


def export_json(findings: list[Finding], meta: dict) -> str:
    return json.dumps(
        {"meta": meta, "findings": [f.to_dict() for f in findings]},
        ensure_ascii=False, indent=2,
    )


def generate(findings: list[Finding], meta: dict) -> str:
    findings = sort_by_risk(findings)
    risk = compliance.risk_summary(findings)
    matrix = compliance.matrix(findings)
    frameworks = compliance.frameworks_summary(findings)
    run_id = html.escape(str(meta.get("run_id", "")))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    tiles = "".join(
        f'<div class="tile"><span class="tile-num" style="color:{_SEV_COLOR[s]}">'
        f'{risk["counts"][s]}</span><span class="tile-label">{s}</span></div>'
        for s in _SEV_ORDER
    )
    fw_chips = "".join(
        f'<span class="chip">{html.escape(k)}: <b>{v}</b> kontroli</span>'
        for k, v in sorted(frameworks.items())
    ) or '<span class="muted">brak trafień</span>'

    matrix_rows = "".join(
        f'<tr><td><code>{html.escape(c.control)}</code></td>'
        f'<td>{html.escape(c.label)}</td>'
        f'<td class="center">{c.hits}</td>'
        f'<td class="center"><span class="badge" style="background:{_color_for_rank(c.max_severity_rank)}">'
        f'{_name_for_rank(c.max_severity_rank)}</span></td></tr>'
        for c in matrix
    ) or '<tr><td colspan="4" class="muted center">brak zmapowanych kontroli</td></tr>'

    cards = "".join(_finding_card(f) for f in findings) or \
        '<p class="muted">Brak znalezisk.</p>'

    assets = _assets_summary(findings)

    return _TEMPLATE.format(
        run_id=run_id,
        target=html.escape(str(meta.get("target", ""))),
        workflow=html.escape(str(meta.get("workflow", ""))),
        status=html.escape(str(meta.get("status", ""))),
        generated=generated,
        total=risk["total"],
        risk_score=risk["risk_score"],
        tiles=tiles,
        fw_chips=fw_chips,
        matrix_rows=matrix_rows,
        assets=assets,
        cards=cards,
    )


def _color_for_rank(rank: int) -> str:
    return _SEV_COLOR[_name_for_rank(rank)]


def _name_for_rank(rank: int) -> str:
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}[rank]


def _assets_summary(findings: list[Finding]) -> str:
    by_asset: dict[str, int] = {}
    for f in findings:
        by_asset[f.asset] = by_asset.get(f.asset, 0) + 1
    if not by_asset:
        return '<p class="muted">—</p>'
    rows = "".join(
        f'<tr><td><code>{html.escape(a)}</code></td><td class="center">{n}</td></tr>'
        for a, n in sorted(by_asset.items(), key=lambda x: x[1], reverse=True)
    )
    return f'<table class="grid"><thead><tr><th>Zasób</th><th>Znalezisk</th></tr></thead><tbody>{rows}</tbody></table>'


def _finding_card(f: Finding) -> str:
    refs = " ".join(f'<span class="ref">{html.escape(r)}</span>' for r in f.references)
    ctrls = " ".join(f'<span class="ctrl">{html.escape(c)}</span>' for c in f.compliance)
    return f'''
<div class="card sev-{f.severity.value}" data-sev="{f.severity.value}" data-id="{f.id}">
  <div class="card-head" onclick="toggle('{f.id}')">
    <input type="checkbox" class="triage" data-id="{f.id}" onclick="event.stopPropagation();triage(this)">
    <span class="badge" style="background:{_SEV_COLOR[f.severity.value]}">{f.severity.value}</span>
    <span class="conf">conf: {f.confidence.value}</span>
    <span class="tool">{html.escape(f.tool)}</span>
    <span class="title">{html.escape(f.title)}</span>
    <span class="risk">risk {f.risk}</span>
  </div>
  <div class="card-body" id="body-{f.id}">
    <div class="kv"><b>Zasób:</b> <code>{html.escape(f.asset)}</code></div>
    <div class="kv"><b>Dowód:</b><pre>{html.escape(f.evidence)}</pre></div>
    <div class="kv"><b>Rekomendacja:</b> {html.escape(f.recommendation)}</div>
    {f'<div class="kv"><b>Referencje:</b> {refs}</div>' if refs else ''}
    {f'<div class="kv"><b>Zgodność:</b> {ctrls}</div>' if ctrls else ''}
  </div>
</div>'''


_TEMPLATE = """<!DOCTYPE html>
<html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RacoonScanner — raport {run_id}</title>
<style>
:root{{--bg:#0f1419;--panel:#1a2029;--line:#2a323d;--fg:#e6edf3;--muted:#8b98a5;--accent:#2dd4bf;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1100px;margin:0 auto;padding:24px}}
header{{border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:24px}}
h1{{margin:0 0 4px;font-size:22px}}
h1 .rc{{color:var(--accent)}}
h2{{font-size:16px;margin:28px 0 12px;border-left:3px solid var(--accent);padding-left:10px}}
.meta{{color:var(--muted);font-size:13px}}
.meta code{{color:var(--fg)}}
.tiles{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.tile{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 18px;min-width:92px;text-align:center}}
.tile-num{{display:block;font-size:26px;font-weight:700}}
.tile-label{{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.5px}}
.scorebox{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 18px;text-align:center}}
.scorebox .tile-num{{color:var(--accent)}}
.chip{{display:inline-block;background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:4px 12px;margin:3px;font-size:12px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
table.grid{{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
th,td{{padding:8px 12px;border-bottom:1px solid var(--line);text-align:left}}
th{{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}}
.center{{text-align:center}}
.muted{{color:var(--muted)}}
code{{background:#0009;padding:1px 5px;border-radius:4px;font-size:12px}}
.badge{{color:#0f1419;font-weight:700;border-radius:5px;padding:1px 8px;font-size:11px;text-transform:uppercase}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}}
.filters button{{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:20px;padding:5px 14px;cursor:pointer;font-size:12px}}
.filters button.off{{opacity:.35}}
.card{{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:8px;margin:8px 0}}
.card.sev-critical{{border-left-color:#e5484d}}.card.sev-high{{border-left-color:#f76808}}
.card.sev-medium{{border-left-color:#f5d90a}}.card.sev-low{{border-left-color:#46a758}}.card.sev-info{{border-left-color:#5b9dd9}}
.card-head{{display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;flex-wrap:wrap}}
.card-head .title{{flex:1;min-width:180px}}
.conf,.tool,.risk{{color:var(--muted);font-size:12px}}
.tool{{background:#0006;padding:1px 7px;border-radius:4px}}
.card-body{{display:none;padding:0 14px 14px;border-top:1px solid var(--line)}}
.card-body.open{{display:block}}
.kv{{margin:10px 0}}
pre{{background:#0009;padding:10px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:12px;margin:6px 0 0}}
.ref,.ctrl{{display:inline-block;background:#0006;border:1px solid var(--line);border-radius:4px;padding:1px 7px;margin:2px;font-size:11px}}
.ctrl{{color:var(--accent)}}
.card.done .title{{text-decoration:line-through;opacity:.5}}
footer{{margin-top:32px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:12px}}
</style></head>
<body><div class="wrap">
<header>
  <h1>🦝 <span class="rc">Racoon</span>Scanner — raport skanowania</h1>
  <div class="meta">
    Cel: <code>{target}</code> &nbsp;·&nbsp; Workflow: <code>{workflow}</code>
    &nbsp;·&nbsp; Run: <code>{run_id}</code> &nbsp;·&nbsp; Status: <code>{status}</code>
    &nbsp;·&nbsp; Wygenerowano: {generated}
  </div>
</header>

<div class="tiles">
  <div class="scorebox"><span class="tile-num">{risk_score}</span><span class="tile-label">Risk score</span></div>
  <div class="tile"><span class="tile-num">{total}</span><span class="tile-label">Znalezisk</span></div>
  {tiles}
</div>

<h2>Zgodność — pokrycie frameworków</h2>
<div>{fw_chips}</div>

<h2>Macierz zgodności</h2>
<table class="grid"><thead><tr><th>Kontrola</th><th>Wymóg</th><th>Trafień</th><th>Max severity</th></tr></thead>
<tbody>{matrix_rows}</tbody></table>

<h2>Zasoby</h2>
{assets}

<h2>Znaleziska</h2>
<div class="filters" id="filters">
  <button data-sev="critical">critical</button>
  <button data-sev="high">high</button>
  <button data-sev="medium">medium</button>
  <button data-sev="low">low</button>
  <button data-sev="info">info</button>
</div>
{cards}

<footer>Wygenerowano przez RacoonScanner. Raport poglądowy — mapowanie na wymogi
regulacyjne nie stanowi formalnej interpretacji prawnej.</footer>
</div>
<script>
var RUN = "{run_id}";
function toggle(id){{document.getElementById('body-'+id).classList.toggle('open');}}
function triage(cb){{
  var card=cb.closest('.card'); card.classList.toggle('done',cb.checked);
  var key='racoon-triage-'+RUN; var s=JSON.parse(localStorage.getItem(key)||'{{}}');
  s[cb.dataset.id]=cb.checked; localStorage.setItem(key,JSON.stringify(s));
}}
(function(){{
  var key='racoon-triage-'+RUN; var s=JSON.parse(localStorage.getItem(key)||'{{}}');
  document.querySelectorAll('.triage').forEach(function(cb){{
    if(s[cb.dataset.id]){{cb.checked=true;cb.closest('.card').classList.add('done');}}
  }});
  var hidden={{}};
  document.querySelectorAll('#filters button').forEach(function(b){{
    b.onclick=function(){{
      var sev=b.dataset.sev; hidden[sev]=!hidden[sev]; b.classList.toggle('off',hidden[sev]);
      document.querySelectorAll('.card[data-sev="'+sev+'"]').forEach(function(c){{
        c.style.display=hidden[sev]?'none':'';
      }});
    }};
  }});
}})();
</script>
</body></html>"""
