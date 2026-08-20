"""Generator samodzielnego, interaktywnego raportu HTML.

Raport jest w pelni offline (bez CDN): CSS, JS i wykresy (inline SVG) sa
osadzone w pliku, wiec otwiera sie w przegladarce takze bez sieci. Zawiera
podsumowanie ryzyka z wykresami, tabele zasobow z objasnieniem portow, macierz
zgodnosci (NIS2/UKSC/ISO/DORA), filtr severity, triage (localStorage) oraz
znaleziska z rozwijanym wyjasnieniem. Chrome tlumaczony jest przez i18n; tresc
znalezisk pozostaje w jezyku zrodlowym adapterow.
"""
from __future__ import annotations

import html
import json
import math
from collections import Counter
from datetime import datetime, timezone

from . import compliance, explain, i18n
from .findings import Finding, sort_by_risk

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEV_COLOR = {
    "critical": "#e5484d", "high": "#f76808", "medium": "#f5d90a",
    "low": "#46a758", "info": "#5b9dd9",
}


def export_json(findings: list[Finding], meta: dict) -> str:
    return json.dumps(
        {"meta": meta, "findings": [f.to_dict() for f in findings]},
        ensure_ascii=False, indent=2,
    )


def generate(findings: list[Finding], meta: dict, lang: str = "pl") -> str:
    lang = i18n.normalize(lang)

    def L(key: str) -> str:
        return i18n.t(key, lang)

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
    donut = _severity_donut(risk["counts"], risk["total"], L)
    cat_bars = _category_bars(findings)
    recon_html = _recon_section(meta.get("recon") or {}, findings, L)

    fw_chips = "".join(
        f'<span class="chip">{html.escape(k)}: <b>{v}</b> {L("report.controls_of")}</span>'
        for k, v in sorted(frameworks.items())
    ) or f'<span class="muted">{L("report.no_fw")}</span>'

    matrix_rows = "".join(_matrix_row(c) for c in matrix) or \
        f'<tr><td colspan="4" class="muted center">{L("report.no_controls")}</td></tr>'

    cards = "".join(_finding_card(f, L) for f in findings) or \
        f'<p class="muted">{L("report.no_findings")}</p>'

    assets = _assets_table(findings, L)

    return _TEMPLATE.format(
        lang=lang,
        run_id=run_id,
        target=html.escape(str(meta.get("target", ""))),
        workflow=html.escape(str(meta.get("workflow", ""))),
        status=html.escape(str(meta.get("status", ""))),
        generated=generated,
        total=risk["total"],
        risk_score=risk["risk_score"],
        tiles=tiles,
        donut=donut,
        cat_bars=cat_bars,
        recon=recon_html,
        fw_chips=fw_chips,
        matrix_rows=matrix_rows,
        assets=assets,
        cards=cards,
        L_title=L("report.title"),
        L_target=L("common.target"),
        L_workflow=L("common.workflow"),
        L_run="Run",
        L_status=L("common.status"),
        L_generated=L("report.generated"),
        L_risk_score=L("common.risk_score"),
        L_findings=L("common.findings"),
        L_overview=L("report.overview"),
        L_sev_distribution=L("report.sev_distribution"),
        L_by_category=L("report.by_category"),
        L_recon=L("report.recon"),
        L_fw_coverage=L("report.fw_coverage"),
        L_matrix=L("report.matrix"),
        L_matrix_note=L("report.matrix_note"),
        L_col_control=L("report.col_control"),
        L_col_req=L("report.col_req"),
        L_col_hits=L("report.col_hits"),
        L_col_maxsev=L("report.col_maxsev"),
        L_assets=L("report.assets"),
        L_assets_note=L("report.assets_note"),
        L_findings_h=L("report.findings"),
        L_footer=L("report.footer"),
    )


def _color_for_rank(rank: int) -> str:
    return _SEV_COLOR[_name_for_rank(rank)]


def _name_for_rank(rank: int) -> str:
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}[rank]


_RECON_LABELS = [
    ("hosts", "recon.hosts"), ("subdomains", "recon.subdomains"),
    ("web_targets", "recon.web_targets"), ("web_tech", "recon.web_tech"),
    ("nameservers", "recon.nameservers"),
]
_SERVICE_LABELS = {
    "smb_targets": "SMB", "ftp_targets": "FTP", "snmp_targets": "SNMP",
    "db_targets": "DB", "mail_targets": "Mail", "rdp_targets": "RDP", "ssh_targets": "SSH",
}


def _rchips(items) -> str:
    return "".join(f'<span class="rchip">{html.escape(str(x))}</span>' for x in items)


def _recon_card(title: str, count: int, body: str) -> str:
    return (f'<div class="recon-card"><div class="rc-h"><span>{html.escape(title)}</span>'
            f'<span class="rc-count">{count}</span></div><div class="rc-items">{body}</div></div>')


def _collect_open_ports(recon: dict, findings: list[Finding]) -> list[str]:
    seen: dict[str, str] = {}
    for op in recon.get("open_ports") or []:
        if isinstance(op, dict):
            hp = f'{op.get("host", "")}:{op.get("port", "")}'
            svc = op.get("service", "")
            seen[hp] = hp + (f" ({svc})" if svc else "")
    for f in findings:
        if f.category == "open-port":
            hp = f.asset.split(" ")[0]
            seen.setdefault(hp, hp)
    return list(seen.values())


def _recon_section(recon: dict, findings: list[Finding], L) -> str:
    """Inwentarz footprintingu - wszystko, co recon zebral, nawet bez konkretnego znaleziska."""
    cards: list[str] = []
    for key, lkey in _RECON_LABELS:
        vals = recon.get(key) or []
        if vals:
            cards.append(_recon_card(L(lkey), len(vals), _rchips(vals)))
    ports = _collect_open_ports(recon, findings)
    if ports:
        cards.append(_recon_card(L("recon.open_ports"), len(ports), _rchips(ports)))
    svc_rows = ""
    svc_total = 0
    for key, label in _SERVICE_LABELS.items():
        hosts = recon.get(key) or []
        if hosts:
            svc_total += len(hosts)
            svc_rows += f'<div class="rsvc"><span class="rsvc-l">{label}</span> {_rchips(hosts)}</div>'
    if svc_rows:
        cards.append(_recon_card(L("recon.services"), svc_total, svc_rows))
    if not cards:
        return f'<p class="muted">{L("report.recon_empty")}</p>'
    return (f'<p class="section-note">{L("report.recon_note")}</p>'
            f'<div class="recon-grid">{"".join(cards)}</div>')


# --- wykresy (inline SVG / CSS) --------------------------------------------
def _severity_donut(counts: dict, total: int, L) -> str:
    """Pierscien (donut) rozkladu severity - czysty SVG, offline."""
    r, cx, cy, sw = 52, 70, 70, 20
    circ = 2 * math.pi * r
    segments = ""
    offset = 0.0
    present = [(s, counts[s]) for s in _SEV_ORDER if counts.get(s)]
    if total and present:
        for sev, n in present:
            frac = n / total
            seg = frac * circ
            segments += (
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                f'stroke="{_SEV_COLOR[sev]}" stroke-width="{sw}" '
                f'stroke-dasharray="{seg:.2f} {circ - seg:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" '
                f'transform="rotate(-90 {cx} {cy})"><title>{sev}: {n}</title></circle>'
            )
            offset += seg
    else:
        segments = (f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                    f'stroke="#2a323d" stroke-width="{sw}"></circle>')
    legend = "".join(
        f'<div class="lg-row"><span class="lg-dot" style="background:{_SEV_COLOR[s]}"></span>'
        f'<span class="lg-name">{s}</span><span class="lg-val">{counts.get(s, 0)}</span></div>'
        for s in _SEV_ORDER
    )
    svg = (f'<svg viewBox="0 0 140 140" width="140" height="140" role="img">{segments}'
           f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" fill="#e6edf3" '
           f'font-size="26" font-weight="700">{total}</text>'
           f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" fill="#8b98a5" '
           f'font-size="11">{html.escape(L("common.findings"))}</text></svg>')
    return f'<div class="donut-wrap">{svg}<div class="legend">{legend}</div></div>'


def _category_bars(findings: list[Finding]) -> str:
    """Poziome slupki: liczba znalezisk wg kategorii (kolor = max severity)."""
    if not findings:
        return '<p class="muted">-</p>'
    counts: Counter = Counter(f.category for f in findings)
    max_rank: dict[str, int] = {}
    for f in findings:
        max_rank[f.category] = max(max_rank.get(f.category, 0), _SEV_RANK[f.severity.value])
    top = counts.most_common()
    mx = top[0][1] if top else 1
    rows = ""
    for cat, n in top:
        pct = max(6, round(n / mx * 100))
        color = _color_for_rank(max_rank.get(cat, 0))
        rows += (
            f'<div class="barrow"><span class="barlabel" title="{html.escape(cat)}">{html.escape(cat)}</span>'
            f'<span class="bartrack"><span class="barfill" style="width:{pct}%;background:{color}"></span></span>'
            f'<span class="barval">{n}</span></div>'
        )
    return f'<div class="bars">{rows}</div>'


def _assets_table(findings: list[Finding], L) -> str:
    """Tabela zasobow wzbogacona o objasnienie portu/uslugi."""
    agg: dict[str, int] = {}
    for f in findings:
        agg[f.asset] = agg.get(f.asset, 0) + 1
    if not agg:
        return f'<p class="muted">{L("report.no_assets")}</p>'
    rows = ""
    for asset, n in sorted(agg.items(), key=lambda x: x[1], reverse=True):
        port, name, desc = explain.service_for_asset(asset)
        port_cell = html.escape(port) if port else "-"
        svc_cell = html.escape(name) if name else "-"
        what_cell = html.escape(desc) if desc else '<span class="muted">-</span>'
        rows += (
            f'<tr><td><code>{html.escape(asset)}</code></td>'
            f'<td class="center">{port_cell}</td>'
            f'<td>{svc_cell}</td>'
            f'<td class="what">{what_cell}</td>'
            f'<td class="center">{n}</td></tr>'
        )
    return (
        f'<p class="section-note">{html.escape(L("report.assets_note"))}</p>'
        f'<table class="grid"><thead><tr>'
        f'<th>{L("report.col_asset")}</th><th class="center">{L("report.port")}</th>'
        f'<th>{L("report.service")}</th><th>{L("report.what_is")}</th>'
        f'<th class="center">{L("common.findings")}</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
    )


def _matrix_row(c) -> str:
    # Bez rozwijanych podpowiedzi przy kontroli - etykieta wymogu jest samoopisowa,
    # a objasnienia trzymamy przy zasobach/znaleziskach.
    return (f'<tr><td><code>{html.escape(c.control)}</code></td>'
            f'<td>{html.escape(c.label)}</td>'
            f'<td class="center">{c.hits}</td>'
            f'<td class="center"><span class="badge" style="background:{_color_for_rank(c.max_severity_rank)}">'
            f'{_name_for_rank(c.max_severity_rank)}</span></td></tr>')


def _finding_card(f: Finding, L) -> str:
    refs = " ".join(f'<span class="ref">{html.escape(r)}</span>' for r in f.references)
    ctrls = " ".join(f'<span class="ctrl">{html.escape(c)}</span>' for c in f.compliance)
    _ex = explain.explain_finding(f.category, f.asset)
    expl = (f'<div class="kv"><details class="ex"><summary>{L("report.whatmeans")}</summary>'
            f'<div class="ex-body">{html.escape(_ex)}</div></details></div>') if _ex else ''
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
    <div class="kv"><b>{L("report.f_asset")}</b> <code>{html.escape(f.asset)}</code></div>
    <div class="kv"><b>{L("report.f_evidence")}</b><pre>{html.escape(f.evidence)}</pre></div>
    <div class="kv"><b>{L("report.f_reco")}</b> {html.escape(f.recommendation)}</div>
    {expl}
    {f'<div class="kv"><b>{L("report.f_refs")}</b> {refs}</div>' if refs else ''}
    {f'<div class="kv"><b>{L("report.f_compliance")}</b> {ctrls}</div>' if ctrls else ''}
  </div>
</div>'''


_TEMPLATE = """<!DOCTYPE html>
<html lang="{lang}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RacoonScanner - {L_title} {run_id}</title>
<style>
:root{{--bg:#0f1419;--panel:#1a2029;--panel2:#141a21;--line:#2a323d;--fg:#e6edf3;--muted:#8b98a5;--accent:#2dd4bf;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1120px;margin:0 auto;padding:24px}}
header{{border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:20px}}
h1{{margin:0 0 4px;font-size:22px}}
h1 .rc{{color:var(--accent)}}
h2{{font-size:15px;margin:26px 0 12px;border-left:3px solid var(--accent);padding-left:10px;text-transform:uppercase;letter-spacing:.4px}}
.meta{{color:var(--muted);font-size:13px}}
.meta code{{color:var(--fg)}}
.section-note{{color:var(--muted);font-size:12.5px;margin:0 0 10px}}
.tiles{{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}}
.tile,.scorebox{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:88px;text-align:center}}
.tile-num{{display:block;font-size:24px;font-weight:700}}
.tile-label{{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.5px}}
.scorebox .tile-num{{color:var(--accent)}}
.overview{{display:grid;grid-template-columns:minmax(240px,1fr) minmax(260px,1.3fr);gap:16px;align-items:stretch}}
@media(max-width:720px){{.overview{{grid-template-columns:1fr}}}}
.ov-card{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}}
.ov-title{{font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:12px}}
.donut-wrap{{display:flex;gap:18px;align-items:center;flex-wrap:wrap}}
.legend{{display:flex;flex-direction:column;gap:4px;min-width:130px}}
.lg-row{{display:flex;align-items:center;gap:8px;font-size:12.5px}}
.lg-dot{{width:10px;height:10px;border-radius:50%}}
.lg-name{{flex:1;text-transform:capitalize;color:var(--muted)}}
.lg-val{{font-weight:700}}
.bars{{display:flex;flex-direction:column;gap:8px}}
.barrow{{display:flex;align-items:center;gap:10px;font-size:12.5px}}
.barlabel{{width:130px;flex:none;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.bartrack{{flex:1;height:12px;background:var(--panel2);border-radius:6px;overflow:hidden}}
.barfill{{display:block;height:100%;border-radius:6px}}
.barval{{width:26px;text-align:right;font-weight:700}}
.chip{{display:inline-block;background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:4px 12px;margin:3px;font-size:12px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
table.grid{{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
th,td{{padding:8px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
th{{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase}}
td.what{{color:var(--muted);font-size:12.5px;max-width:420px}}
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
details.ex{{margin:4px 0}}
details.ex summary{{cursor:pointer;color:var(--accent);font-size:12px;user-select:none}}
.ex-body{{white-space:pre-line;color:var(--muted);font-size:12.5px;margin:6px 0 2px;padding:8px 10px;background:#0006;border-radius:6px;border:1px solid var(--line)}}
.recon-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(258px,1fr));gap:12px}}
.recon-card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}}
.rc-h{{display:flex;justify-content:space-between;align-items:center;font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted);margin-bottom:8px}}
.rc-count{{background:var(--panel2);border:1px solid var(--line);border-radius:20px;padding:0 9px;font-weight:700;color:var(--fg)}}
.rc-items{{display:flex;flex-wrap:wrap;gap:5px;max-height:168px;overflow:auto}}
.rchip{{background:#0006;border:1px solid var(--line);border-radius:5px;padding:2px 7px;font-size:11.5px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
.rsvc{{width:100%;margin:2px 0;display:flex;flex-wrap:wrap;gap:5px;align-items:center}}
.rsvc-l{{min-width:42px;color:var(--accent);font-weight:700;font-size:11px}}
footer{{margin-top:32px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:12px}}
</style></head>
<body><div class="wrap">
<header>
  <h1><span class="rc">Racoon</span>Scanner - {L_title}</h1>
  <div class="meta">
    {L_target}: <code>{target}</code> &nbsp;&middot;&nbsp; {L_workflow}: <code>{workflow}</code>
    &nbsp;&middot;&nbsp; {L_run}: <code>{run_id}</code> &nbsp;&middot;&nbsp; {L_status}: <code>{status}</code>
    &nbsp;&middot;&nbsp; {L_generated}: {generated}
  </div>
</header>

<div class="tiles">
  <div class="scorebox"><span class="tile-num">{risk_score}</span><span class="tile-label">{L_risk_score}</span></div>
  <div class="tile"><span class="tile-num">{total}</span><span class="tile-label">{L_findings}</span></div>
  {tiles}
</div>

<h2>{L_overview}</h2>
<div class="overview">
  <div class="ov-card"><div class="ov-title">{L_sev_distribution}</div>{donut}</div>
  <div class="ov-card"><div class="ov-title">{L_by_category}</div>{cat_bars}</div>
</div>

<h2>{L_recon}</h2>
{recon}

<h2>{L_assets}</h2>
{assets}

<h2>{L_fw_coverage}</h2>
<div>{fw_chips}</div>

<h2>{L_matrix}</h2>
<p class="section-note">{L_matrix_note}</p>
<table class="grid"><thead><tr><th>{L_col_control}</th><th>{L_col_req}</th><th class="center">{L_col_hits}</th><th class="center">{L_col_maxsev}</th></tr></thead>
<tbody>{matrix_rows}</tbody></table>

<h2>{L_findings_h}</h2>
<div class="filters" id="filters">
  <button data-sev="critical">critical</button>
  <button data-sev="high">high</button>
  <button data-sev="medium">medium</button>
  <button data-sev="low">low</button>
  <button data-sev="info">info</button>
</div>
{cards}

<footer>{L_footer}</footer>
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
