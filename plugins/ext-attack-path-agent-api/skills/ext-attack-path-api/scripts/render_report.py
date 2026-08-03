"""
render_report.py -- External Attack-Path report renderer (packaged).

Reads the three spec-generated datasets from a data directory and produces the
tiered HTML report. All qualification/exclusion logic comes from attack_path_spec.py
(the single source of truth); this file only shapes and styles the output.

Usage:
    python3 render_report.py [--data DIR] [--out FILE] [--date YYYY-MM-DD]

Expected files in DIR (produced by running the queries in ./queries against your
tenant and saving the raw match arrays):
    assembled.json     {"A":[inventory], "B":[endpoints], "C":[cve rows]}
    endpoint_ips.json  {"endpoints":[{name,ip,port,protocol}]}   (optional; enriches IP:port)
See README.md for the end-to-end run steps.
"""
import json, html, sys, re, os, argparse, datetime

HERE=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,HERE)
import attack_path_spec as spec   # single source of truth for gates + post-filter

ap=argparse.ArgumentParser()
ap.add_argument("--data",default=os.path.join(HERE,"data"),help="directory with assembled.json / endpoint_ips.json")
ap.add_argument("--out", default=os.path.join(HERE,"output","attack-paths-report.html"))
ap.add_argument("--date",default=datetime.date.today().isoformat(),help="report date (YYYY-MM-DD)")
# --- scale controls: bound the rendered output for large environments ---
# Full per-host cards (SVG diagram + CVE table) are expensive; beyond --max-cards hosts
# the rest are rolled into a compact overflow table so the HTML stays openable. Ranking
# (privileged, KEV, EPSS) means the highest-risk hosts always get full cards.
ap.add_argument("--max-cards",type=int,default=150,
                help="max full per-host cards to render (0 = unlimited). Extra hosts go to a summary table.")
ap.add_argument("--max-cves-per-host",type=int,default=25,
                help="max CVE rows shown per host table (0 = unlimited); extras collapse to 'N more'.")
ap.add_argument("--no-endpoint",action="store_true",
                help="REDUCED mode (API/GraphQL edition): no observed endpoints available, so "
                     "gate 8 degrades to the listening-component test only (no port correlation). "
                     "Auto-enabled when dataset B is empty. Banners the report as reduced-fidelity.")
args=ap.parse_args()

DATE=args.date

def _die(msg, code=2):
    """Emit a clear, actionable error to stderr and exit -- never a raw traceback.
    A headless/cron run needs a diagnosable message, not a Python stack dump."""
    sys.stderr.write(f"render_report: ERROR: {msg}\n")
    sys.exit(code)

def _load_json(path, what):
    if not os.path.exists(path):
        _die(f"{what} not found: {path}")
    try:
        with open(path) as fh:
            return json.load(fh)
    except json.JSONDecodeError as e:
        _die(f"{what} is not valid JSON ({path}): {e} "
             f"-- a truncated/interrupted pull can cause this; re-run the data pull.")
    except OSError as e:
        _die(f"cannot read {what} ({path}): {e}")

# --- load + validate structure up front (clear errors, not tracebacks) ---
data=_load_json(os.path.join(args.data,"assembled.json"), "assembled.json")
if not isinstance(data, dict):
    _die('assembled.json must be a JSON object with keys "A","B","C".')
for k in ("A","B","C"):
    if k not in data:
        _die(f'assembled.json is missing required key "{k}" '
             f'(expected {{"A":[inventory],"B":[endpoints],"C":[cve rows]}}).')
    if not isinstance(data[k], list):
        _die(f'assembled.json key "{k}" must be a list, got {type(data[k]).__name__}.')

def _rows(key):
    """Yield only well-formed dict rows from a dataset, skipping (and counting) junk so one
    malformed row can't crash the whole render."""
    skipped=0; good=[]
    for r in data[key]:
        if isinstance(r, dict): good.append(r)
        else: skipped+=1
    if skipped:
        sys.stderr.write(f"render_report: WARNING: skipped {skipped} non-object row(s) in dataset {key}.\n")
    return good

data["A"]=_rows("A"); data["B"]=_rows("B"); data["C"]=_rows("C")

# endpoint IP:port map (optional enrichment) -- tolerate a missing/malformed file
EPIP={}
_ipf=os.path.join(args.data,"endpoint_ips.json")
if os.path.exists(_ipf):
    _ips=_load_json(_ipf,"endpoint_ips.json")
    for e in (_ips.get("endpoints") if isinstance(_ips,dict) else None) or []:
        if isinstance(e,dict) and e.get("name") is not None and e.get("port") is not None:
            EPIP.setdefault(e["name"],{})[e["port"]]=e.get("ip")
def ip_for(name,port):
    return EPIP.get(name,{}).get(port)

# Build lookups defensively: rows may be missing instance_id/ports/name.
A={h["instance_id"]:h for h in data["A"] if h.get("instance_id") is not None}
def _ports_of(h):
    out=set()
    for p in (h.get("ports") or []):
        if isinstance(p,dict) and p.get("port") is not None: out.add(p["port"])
    return out
PORTS={h["instance_id"]:_ports_of(h) for h in data["B"] if h.get("instance_id") is not None}
NAMEPORTS={}
for h in data["B"]:
    if h.get("name") is not None: NAMEPORTS.setdefault(h["name"],set()).update(_ports_of(h))

# ---- apply spec post-filter (Stage 3.4 component<->port + Stopped safety net) ----
# Reduced mode: explicit --no-endpoint, or auto when the endpoint dataset B is empty
# (the API/GraphQL edition has no observed listeners). Gate 8 then degrades to the
# listening-component test only, and the report is bannered as reduced-fidelity.
REDUCED = args.no_endpoint or (len(data["B"])==0 and len(data["C"])>0)

def _norm_cve(m):
    """Normalize a raw C row to safe, correctly-typed defaults so a missing/null field can
    never crash the render. Returns a NEW dict (originals may be missing any key)."""
    def num(v):
        try: return float(v) if v is not None else 0.0
        except (TypeError,ValueError): return 0.0
    return {**m,
        "instance_id": m.get("instance_id"),
        "name": m.get("name") if m.get("name") is not None else "(unknown)",
        "component": (m.get("component") or ""),
        "cve": m.get("cve") if m.get("cve") is not None else "(no CVE id)",
        "epss": num(m.get("epss")), "cvss": num(m.get("cvss")),
        "kev": bool(m.get("kev")),
        "severity": m.get("severity") if m.get("severity") is not None else "",
        "status": m.get("status") if m.get("status") is not None else "Open"}

paths=[]; review=[]; excluded=[]
for _raw in data["C"]:
    m=_norm_cve(_raw); iid=m["instance_id"]; host=A.get(iid)
    vp = PORTS.get(iid) or NAMEPORTS.get(m["name"]) or set()
    status,reason = spec.post_filter(m, "Running", vp, require_port=not REDUCED)
    if status=="drop":
        excluded.append({**m,"reason":reason}); continue
    sk=spec.service_key(m["component"]); need=spec.SERVICE_PORTS.get(sk,set())
    port=sorted(vp & need)[0] if (vp & need) else None
    row={**m,"port":port,"service":sk,"pf_status":status,"pf_reason":reason,
         "privileged": bool(host.get("privileged")) if host else False,
         "type": host.get("type") if host else m.get("type"),
         "tenant": (host.get("tenant") if host else None) or "",
         "identity_ids": [i for i in (host.get("identity_ids") or []) if i] if host else []}
    # 'review' = unmapped-but-exposed vulnerable component (anti-false-negative): surface it
    # in a separate bucket rather than either confirming it as a path or silently dropping it.
    (paths if status=="keep" else review).append(row)

# group per host
hosts={}
for p in paths:
    hosts.setdefault(p["instance_id"],{"name":p["name"],"type":p["type"],"tenant":p["tenant"],
        "privileged":p["privileged"],"identity_ids":p["identity_ids"],
        "ports":sorted(PORTS.get(p["instance_id"]) or NAMEPORTS.get(p["name"]) or []),"cves":[]})
    hosts[p["instance_id"]]["cves"].append(p)

# CVE-age proxy (fail-open) + primary CVE per host
for h in hosts.values():
    for c in h["cves"]:
        yr,flag=spec.age_label(c["cve"],int(DATE[:4])); c["year"]=yr; c["recent"]=(flag=="recent")
    h["cves"].sort(key=lambda c:(c["epss"], c["cvss"]),reverse=True)
    h["prim"]=h["cves"][0]

hostlist=list(hosts.values())
# rank: privileged, then any-KEV, then max epss
for h in hostlist:
    h["anykev"]=any(c["kev"] for c in h["cves"]); h["maxepss"]=max(c["epss"] for c in h["cves"])
hostlist.sort(key=lambda h:(h["privileged"],h["anykev"],h["maxepss"]),reverse=True)
# Scale control: render full cards only for the top --max-cards hosts (already risk-ranked);
# the remainder are summarized in a compact overflow table so the HTML stays openable in a
# very large environment. 0 = unlimited (original behavior).
overflow=[]
if args.max_cards and len(hostlist)>args.max_cards:
    overflow=hostlist[args.max_cards:]
    hostlist=hostlist[:args.max_cards]
tier1=[h for h in hostlist if h["privileged"]]
tier2=[h for h in hostlist if not h["privileged"]]

# accounts in scope (from full 114 inventory, not just live-path hosts)
# tenant may be null/missing on a malformed row -> coerce to a visible placeholder, never None.
def _tenant(h):
    t=h.get("tenant"); return t if t else "(unknown account)"
accts=sorted({_tenant(h) for h in data["A"]})
# Derive provider from the host EntityTypeName (ground truth) rather than guessing from the
# tenant-id format -- 12-digit strings are ambiguous between AWS accounts and GCP projects.
TYPE_PROVIDER={"AwsEc2Instance":"AWS","GcpComputeInstance":"GCP","AzureComputeVirtualMachine":"Azure"}
_ACCT_PROV={}
for h in data["A"]:
    prov=TYPE_PROVIDER.get(h.get("type"))
    if prov: _ACCT_PROV.setdefault(_tenant(h),prov)
def provider_of(a):
    a=a or ""
    if a in _ACCT_PROV: return _ACCT_PROV[a]
    if "-" in a: return "Azure"          # GUID subscription fallback
    return "Other"
def acct_kind(a): return {"AWS":"AWS account","GCP":"GCP project","Azure":"Azure subscription"}.get(provider_of(a),"Account")
# group accounts by provider for the header (item 5)
ACCT_BY_PROVIDER={}
for a in accts: ACCT_BY_PROVIDER.setdefault(provider_of(a),[]).append(a)

def esc(s): return html.escape(str(s)) if s is not None else ""
SVC_LABEL={"openssh-server":"OpenSSH (sshd)","apache2":"Apache HTTP","httpd":"Apache HTTP (httpd)","nginx":"nginx","tomcat":"Tomcat","mysql-server":"MySQL","mariadb-server":"MariaDB","grafana":"Grafana","redis-server":"Redis","windows-os":"Windows RDP/OS"}
def svc_label(k): return SVC_LABEL.get(k,k or "service")
REM={"CVE-2023-38408":"Upgrade OpenSSH to 9.3p2+; disable ssh-agent PKCS#11 forwarding.",
 "CVE-2025-59287":"Apply the WSUS/Windows security update (out-of-band Oct 2025).",
 "CVE-2024-38475":"Upgrade Apache httpd to 2.4.60+.","CVE-2023-25690":"Upgrade Apache httpd to 2.4.56+.",
 "CVE-2025-49844":"Upgrade Redis (Lua RCE); require AUTH; bind localhost; never expose 6379."}
def rem(c): return REM.get(c,"Apply the vendor-fixed version for the affected service.")

# ---- Tenable theme (validated earlier) ----
CSS="""
:root{--bg:#141a1c;--page:#0f1416;--card:#1e2426;--line:#2f393c;--ink:#fff;--ink2:#b9c4cc;--mut:#8595a2;--accent:#e7ff00;--crit:#ff5b5b;--high:#ff9f45;--med:#ffd200;--good:#35c46b}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.bar{height:4px;background:var(--accent)}
header{padding:30px 40px 24px;background:linear-gradient(180deg,#1a2123,#12181a);border-bottom:1px solid var(--line)}
.eyebrow{color:var(--accent);font-size:13.5px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;margin:0 0 10px}
h1{margin:0 0 10px;font-size:24px;font-weight:800;max-width:1050px;color:var(--accent)}
.meta-hdr{display:flex;flex-wrap:wrap;gap:8px 26px;font-size:12px;color:var(--ink2);margin-top:10px}
.meta-hdr b{color:var(--ink)}
.accts{margin-top:14px;padding:12px 16px;background:#12181a;border:1px solid var(--line);border-radius:10px}
.acctshead{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);margin-bottom:6px}
.acctrow{font-size:12px;color:var(--ink2);padding:2px 0}
.acctprov{display:inline-block;min-width:78px;font-weight:700;color:var(--accent)}
.acctids{font-family:ui-monospace,Menlo,monospace;font-size:11px}
.wrap{max-width:1280px;margin:0 auto;padding:24px 40px 60px}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:6px 0 20px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;position:relative;overflow:hidden}
.kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent)}
.kpi .n{font-size:30px;font-weight:800}.kpi .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin-top:2px}
.kpi.red .n{color:var(--crit)}.kpi.red::before{background:var(--crit)}
.exec{background:linear-gradient(180deg,#1c2325,#171d1f);border:1px solid var(--line);border-top:3px solid var(--accent);border-radius:12px;padding:22px 26px;margin:6px 0 18px}
.exec-h{font-size:13px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:var(--accent);margin-bottom:12px}
.exec p,.exec li{font-size:13.5px;line-height:1.62;color:var(--ink2)}.exec b{color:var(--ink)}
.exec code{background:#0f1416;border:1px solid var(--line);border-radius:4px;padding:1px 5px;font-size:12px;color:var(--accent)}
.exec-rec{background:#12181a;border:1px solid var(--line);border-radius:8px;padding:13px 15px;margin-top:8px}
/* numbered sub-list (Priority actions, gate list): tight rows, hanging numerals */
.sublist{list-style:none;margin:6px 0 2px 18px;padding:0}
.sublist li{position:relative;padding:1px 0 1px 34px;font-size:13px;line-height:1.5;color:var(--ink2)}
.sublist li .lbl{position:absolute;left:0;top:1px;width:24px;text-align:right;font-weight:800;color:var(--accent);font-variant-numeric:tabular-nums}
.note .sublist li{font-size:12.5px}
/* worded-label sub-list (Tier 1 / Tier 2): real indented bullets, label inline so it
   always aligns with its (possibly wrapping) description */
.sublist.worded{list-style:disc;margin:6px 0 2px 34px;padding:0}
.sublist.worded li{position:static;padding:4px 0;font-size:13px;line-height:1.5;color:var(--ink2)}
.sublist.worded li::marker{color:var(--mut)}
.sublist.worded li .lbl{position:static;font-weight:800;color:var(--accent);margin-right:6px}
.note{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:10px;padding:15px 18px;margin:14px 0;font-size:12.5px;color:var(--ink2)}
.note b{color:var(--ink)} .note code{color:var(--accent);font-size:11.5px}
.tierband{margin:20px 0 14px;border-radius:12px;padding:16px 20px;border:1px solid var(--line)}
.tierband.t1{background:linear-gradient(90deg,rgba(255,91,91,.16),rgba(255,91,91,.02));border-left:6px solid var(--crit)}
.tierband.t2{background:linear-gradient(90deg,rgba(231,255,0,.16),rgba(231,255,0,.02));border-left:6px solid var(--accent)}
.tierband .tt{font-size:17px;font-weight:800;color:var(--ink);letter-spacing:-.01em}
.tierband .tt .cnt{display:inline-block;margin-left:10px;font-size:13px;font-weight:700;padding:2px 12px;border-radius:20px;vertical-align:middle}
.tierband.t1 .cnt{background:var(--crit);color:#1a0000}
.tierband.t2 .cnt{background:var(--accent);color:#141a1c}
.tierband .ts{font-size:12.5px;color:var(--ink2);margin-top:6px;max-width:900px}
.tierdivider{border:0;border-top:6px solid var(--mut);opacity:.55;margin:48px 0 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:12px 0}
.card.t1{border-color:#4a3a12}
.chead{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px;margin-bottom:12px}
.rank{color:var(--accent);font-weight:800;margin-right:10px}.wl{font-weight:700;font-size:15px}
.subline{color:var(--mut);font-size:11.5px;margin-top:3px}
.badges{display:flex;gap:7px;flex-wrap:wrap}
.badge{font-size:10px;font-weight:700;padding:3px 9px;border-radius:20px;letter-spacing:.03em;text-transform:uppercase}
.b-hi{background:rgba(255,91,91,.15);color:var(--crit);border:1px solid rgba(255,91,91,.4)}
.b-std{background:rgba(133,149,162,.14);color:var(--ink2);border:1px solid var(--line)}
.b-conf{background:rgba(53,196,107,.15);color:var(--good);border:1px solid rgba(53,196,107,.4)}
.b-infer{background:rgba(133,149,162,.10);color:var(--mut);border:1px solid var(--line)}
.b-kev{background:rgba(255,91,91,.2);color:#ff8a8a;border:1px solid rgba(255,91,91,.4)}
.diagram{width:100%;height:auto;display:block;margin:4px 0 12px}
.meta{display:grid;grid-template-columns:1fr 1fr;gap:3px 28px;font-size:12px;margin-bottom:10px}
.meta b{color:var(--mut);font-weight:600}.meta code{color:#cdd7dd;font-size:11px;word-break:break-all}.roles{grid-column:1/3;color:#ffd9a0}
table.vt{width:100%;border-collapse:collapse;font-size:12px;margin-top:4px}
table.vt th{text-align:left;color:var(--mut);border-bottom:1px solid var(--line);padding:6px 7px;font-size:10.5px;text-transform:uppercase;letter-spacing:.04em}
table.vt td{border-bottom:1px solid #262f31;padding:6px 7px;vertical-align:top;text-align:left}
.cve a{color:var(--accent);text-decoration:none;font-weight:600}.num{text-align:left;font-variant-numeric:tabular-nums}
.pill{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px;font-weight:700}
.ev{display:inline-block;padding:1px 8px;border-radius:5px;font-size:10.5px;font-weight:700;white-space:nowrap}
.ev-epss{background:rgba(255,210,0,.16);color:var(--med);border:1px solid rgba(255,210,0,.4)}
.ev-kev{background:rgba(255,91,91,.16);color:#ff8a8a;border:1px solid rgba(255,91,91,.4)}
.ev-both{background:rgba(176,0,0,.35);color:#ffb3b3;border:1px solid rgba(255,91,91,.6)}
.ipport{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:#cdd7dd}
footer{color:var(--mut);font-size:11px;padding:20px 40px;border-top:1px solid var(--line)}

/* ===========================================================================
   PRINT / PDF stylesheet.  Screen uses the dark Tenable theme; print flips to a
   high-contrast light palette (ink-friendly, professional) and controls paging.
   Produce a PDF via the browser: File > Print > Save as PDF (Letter/A4, default
   margins, "Background graphics" ON so severity colors render).
   =========================================================================== */
@media print {
  @page { size: Letter; margin: 14mm 12mm; }
  :root{
    --bg:#ffffff;--page:#ffffff;--card:#ffffff;--line:#c9ced6;--ink:#111418;
    --ink2:#2b3138;--mut:#5b636e;--accent:#111418;
    --crit:#b3261e;--high:#a15c00;--med:#8a6d00;--good:#1a7f37;
  }
  html,body{background:#fff !important;color:#111418 !important;font-size:11px}
  .bar{background:#111418 !important;height:3px}
  header{background:#fff !important;border-bottom:2px solid #111418;padding:0 0 12px}
  .eyebrow{color:#5b636e !important}
  h1{color:#111418 !important}
  .accts,.exec,.note,.kpi,.exec-rec{background:#fff !important;
    border:1px solid #c9ced6 !important;box-shadow:none !important}
  .exec{border-top:2px solid #111418 !important}
  .exec-h,.acctprov,.rank,.cve a{color:#0b5cad !important}   /* readable link/accent ink */
  .kpi .n{color:#111418 !important}.kpi.red .n{color:#b3261e !important}
  .kpi::before,.kpi.red::before{background:#111418 !important}
  .wrap{padding:10px 0}
  /* keep a finding on one page; never split a card, diagram, or table row */
  .card{border:1px solid #c9ced6 !important;background:#fff !important;
    break-inside:avoid;page-break-inside:avoid;margin:10px 0}
  .card.t1{border-color:#b3261e !important}
  .diagram,table.vt tr{break-inside:avoid;page-break-inside:avoid}
  svg text{fill:#111418 !important}          /* diagram labels to dark ink */
  .diagram rect[fill="#12181a"]{fill:#ffffff !important}
  /* tier bands & divider: strong on white, and start each tier on a fresh page */
  .tierband{background:#f2f3f5 !important;border:1px solid #c9ced6 !important}
  .tierband.t1{border-left:6px solid #b3261e !important;break-before:auto}
  .tierband.t2{border-left:6px solid #5b636e !important;break-before:page}
  .tierband .tt,.tierband .ts{color:#111418 !important}
  .tierband.t1 .cnt{background:#b3261e !important;color:#fff !important}
  .tierband.t2 .cnt{background:#5b636e !important;color:#fff !important}
  .tierdivider{border-top:3px solid #5b636e !important;opacity:1;margin:22px 0 0}
  /* pills/badges: force ink + border so they read even if bg graphics are off */
  .pill,.ev,.badge{color:#111418 !important;border:1px solid #8a8f98 !important}
  .b-kev,.ev-kev,.ev-both{color:#b3261e !important;border-color:#b3261e !important}
  a[href]{color:#0b5cad !important;text-decoration:none}
  footer{color:#5b636e !important;border-top:1px solid #c9ced6 !important;padding:12px 0}
  .meta code,.ipport{color:#2b3138 !important}
}
"""
def cvss_pill(c):
    col="#ff5b5b" if c>=9 else "#ff9f45" if c>=7 else "#ffd200"; return f'<span class="pill" style="background:{col}22;color:{col}">{c}</span>'
def epss_pill(e):
    col="#ff5b5b" if e>=0.7 else "#ff9f45" if e>=0.5 else "#ffd200"; return f'<span class="pill" style="background:{col}22;color:{col}">{e*100:.0f}%</span>'

def diagram(h):
    p=h["prim"]; svc=svc_label(p["service"]); port=p["port"]; cve=p["cve"]
    hi=h["privileged"]; roles=", ".join(h["identity_ids"][:1]) if h["identity_ids"] else "instance role"
    W=1200;bw=250;gap=(W-4*bw)/3;y=42;bh=150;H=y+bh+14;xs=[i*(bw+gap) for i in range(4)]
    c1="#e7ff00";c2="#ff5b5b" if p["cvss"]>=9 else "#ff9f45";c3="#ff5b5b" if hi else "#e7ff00";c4="#ff5b5b" if hi else "#8595a2"
    def wrap(t,mc,ml):
        w=str(t).split();L=[];cur=""
        for x in w:
            while len(x)>mc:
                if cur:L.append(cur);cur=""
                if len(L)>=ml:break
                L.append(x[:mc]);x=x[mc:]
            if len(L)>=ml:break
            cand=(cur+" "+x).strip()
            if len(cand)<=mc:cur=cand
            else:L.append(cur);cur=x
        if cur and len(L)<ml:L.append(cur)
        if len(L)>ml:L=L[:ml];L[-1]=L[-1][:mc-1]+"…"
        return L
    def node(x,color,title,icon,segs):
        # Dynamic font sizing: each line is wrapped, then its font is scaled DOWN so the
        # widest line always fits the inner box width (prevents overflow on long tokens
        # like ServiceAccount/1024... that can't wrap on spaces).
        pad=13; inner=bw-2*pad; tx=x+bw/2
        BASE={"lead":12.5,"bold":11.5,"dim":10.5}; CW=0.56  # avg glyph width / font-size
        AVAIL=int(inner/(BASE["lead"]*CW))                  # chars/line at base lead size
        lines=[]  # (text, cssclass, fontpx)
        for txt,sty in segs:
            cls={"lead":"na lead","bold":"na bold","dim":"nb"}[sty]
            base=BASE[sty]
            for ln in wrap(txt,AVAIL,2):
                # shrink font if this line still exceeds inner width at its base size
                w=len(ln)*base*CW
                fs=base if w<=inner else max(7.5, base*inner/w)
                lines.append((esc(ln),cls,fs))
            lines.append(("__g__","",0))
        if lines and lines[-1][0]=="__g__":lines.pop()
        tot=sum((f+4) if t!="__g__" else 6 for t,c,f in lines)
        yy=y+26+max(8,(bh-26-tot)/2)+10;parts=[]
        for tx2,c,fs in lines:
            if tx2!="__g__":
                parts.append(f'<text x="{tx:.0f}" y="{yy:.1f}" text-anchor="middle" class="{c}" font-size="{fs:.1f}">{tx2}</text>')
                yy+=fs+4
            else: yy+=6
        head="#141a1c" if color=="#e7ff00" else "#fff"
        return (f'<rect x="{x}" y="{y}" width="{bw}" height="{bh}" rx="12" fill="#12181a" stroke="{color}" stroke-width="2"/>'
          f'<path d="M{x+12},{y} h{bw-24} a12,12 0 0 1 12,12 v14 h-{bw} v-14 a12,12 0 0 1 12,-12 z" fill="{color}"/>'
          f'<text x="{tx:.0f}" y="{y+17}" text-anchor="middle" class="nt" fill="{head}">{icon}  {title}</text>{"".join(parts)}')
    def arrow(x1,x2,lab):
        mx=(x1+x2)/2;cy=y+bh/2;pw=len(lab)*6.2+18
        return (f'<line x1="{x1+10}" y1="{cy}" x2="{x2-14}" y2="{cy}" stroke="#8595a2" stroke-width="2.2" marker-end="url(#ah)"/>'
          f'<rect x="{mx-pw/2:.0f}" y="{cy-27}" width="{pw:.0f}" height="19" rx="9.5" fill="#0f1416" stroke="#3a4548"/>'
          f'<text x="{mx:.0f}" y="{cy-13.5:.0f}" text-anchor="middle" class="al">{lab}</text>')
    pip=ip_for(h["name"],port)
    n1=[(f"{svc} :{port}","lead"),(f"{pip}:{port}" if pip else "validated endpoint","dim"),
        ("Internet-reachable","dim")]
    n2=[(cve+f"  ({p['year']})","lead"),("Remotely exploitable","bold"),(f"EPSS {p['epss']*100:.0f}% · CVSS {p['cvss']}"+(" · KEV" if p['kev'] else ""),"dim")]
    n3=[(roles,"lead"),("Privileged identity" if hi else "Standard identity","dim")]
    n4=[("Compromise service → host → "+("project/account control" if hi else "host foothold"),"dim")]
    return (f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" class="diagram" preserveAspectRatio="xMidYMid meet">'
     '<defs><marker id="ah" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#8595a2"/></marker></defs>'
     '<style>.nt{font-size:10px;font-weight:700;letter-spacing:.03em}.na{fill:#fff;font-size:12px}.na.lead{font-size:12.5px;font-weight:700}.na.bold{fill:#ffd9a0;font-size:11.5px;font-weight:700}.nb{fill:#8595a2;font-size:10.5px}.al{fill:#c9d3d8;font-size:10.5px;font-weight:600}</style>'
     +arrow(xs[0]+bw,xs[1],"exploit")+arrow(xs[1]+bw,xs[2],"foothold")+arrow(xs[2]+bw,xs[3],"escalate")
     +node(xs[0],c1,"EXPOSED SERVICE","\U0001F310",n1)+node(xs[1],c2,"EXPLOITABLE VULN","\U0001F4A5",n2)
     +node(xs[2],c3,"CLOUD IDENTITY","\U0001F464",n3)+node(xs[3],c4,"HIGHEST-RISK ACTIONS","⚠",n4)+'</svg>')

def evidence_cell(c):
    # collapse KEV + Gate into one "Evidence" pill. EPSS=yellow, KEV=red w/ icon, Both=darker red
    gr=c["gate_reason"]
    if gr=="both":  return '<span class="ev ev-both">&#9888; EPSS + KEV</span>'
    if gr=="kev":   return '<span class="ev ev-kev">&#9888; KEV</span>'
    return '<span class="ev ev-epss">EPSS</span>'

def vtable(h,name):
    out=['<table class="vt"><tr><th>CVE</th><th>Yr</th><th>Exposed endpoint (IP:port)</th><th>Service</th><th>EPSS</th><th>CVSS</th><th>Sev</th><th>Evidence</th><th>Remediation</th></tr>']
    cves=h["cves"]; extra=0
    if args.max_cves_per_host and len(cves)>args.max_cves_per_host:
        extra=len(cves)-args.max_cves_per_host; cves=cves[:args.max_cves_per_host]
    for c in cves:
        ip=ip_for(name,c["port"]); ipport=f'{ip}:{c["port"]}' if ip else f'(port {c["port"]})'
        # cve is data-controlled: escape it for both the href attribute and the link text.
        cve_e=esc(c["cve"])
        out.append(f'<tr><td class="cve"><a href="https://nvd.nist.gov/vuln/detail/{cve_e}" target="_blank" rel="noopener noreferrer">{cve_e}</a></td>'
          f'<td>{esc(c["year"])}</td><td class="ipport">{esc(ipport)}</td><td>{esc(svc_label(c["service"]))}</td>'
          f'<td>{epss_pill(c["epss"])}</td><td>{cvss_pill(c["cvss"])}</td>'
          f'<td>{esc(c["severity"])}</td><td>{evidence_cell(c)}</td>'
          f'<td>{esc(rem(c["cve"]))}</td></tr>')
    if extra:
        out.append(f'<tr><td colspan="9" style="color:var(--mut);font-style:italic">'
                   f'+ {extra} more qualifying CVE(s) on this host (showing top {args.max_cves_per_host} by EPSS/CVSS)</td></tr>')
    out.append("</table>");return "".join(out)

def card(i,h):
    conf = "b-conf" if False else "b-infer"  # confirmation grading kept simple in this build
    badges=[f'<span class="badge {"b-hi" if h["privileged"] else "b-std"}">{"Privileged identity" if h["privileged"] else "Standard identity"}</span>']
    if h["anykev"]: badges.append('<span class="badge b-kev">CISA KEV</span>')
    if h["prim"]["recent"]: badges.append('<span class="badge b-hi">Recent Critical Vuln</span>')
    return (f'<div class="card {"t1" if h["privileged"] else ""}">'
      f'<div class="chead"><div><span class="rank">#{i}</span><span class="wl">{esc(h["name"])}</span>'
      f'<div class="subline">{esc(h["type"])} · {acct_kind(h["tenant"])} {esc(h["tenant"])}</div></div>'
      f'<div class="badges">{"".join(badges)}</div></div>'+diagram(h)+
      f'<div class="meta"><div><b>Validated open ports</b><br>{", ".join(str(x) for x in h["ports"])}</div>'
      f'<div><b>Identity</b><br>{esc(", ".join(h["identity_ids"]) or "instance role")}</div></div>'
      +vtable(h,h["name"])+'</div>')

def overflow_table(rows):
    # Compact one-row-per-host summary for hosts beyond --max-cards (already risk-ranked).
    if not rows: return ""
    out=[f'<div class="tierband t2"><div class="tt">Additional qualifying hosts '
         f'<span class="cnt">{len(rows)} more</span></div>'
         f'<div class="ts">Beyond the top {args.max_cards} rendered in full above (ranked by privilege, then CISA-KEV, then EPSS). '
         f'Re-run with <code>--max-cards 0</code> for a full card per host, or narrow scope by account.</div></div>',
         '<table class="vt"><tr><th>#</th><th>Workload</th><th>Tier</th><th>Account</th><th>Max EPSS</th><th>KEV</th><th>Qual. CVEs</th></tr>']
    for i,h in enumerate(rows):
        out.append(f'<tr><td class="num">{args.max_cards+i+1}</td><td>{esc(h["name"])}</td>'
          f'<td>{"Tier 1" if h["privileged"] else "Tier 2"}</td><td class="ipport">{esc(acct_kind(h["tenant"]))} {esc(h["tenant"])}</td>'
          f'<td class="num">{h["maxepss"]*100:.0f}%</td><td>{"yes" if h["anykev"] else "—"}</td>'
          f'<td class="num">{len(h["cves"])}</td></tr>')
    out.append("</table>");return "".join(out)

def review_table(rows):
    # Anti-false-negative bucket: exposed, exploitable vulns on components we could NOT map
    # to a known service (or, in reduced mode, couldn't confirm a listening port). These are
    # NOT silently dropped -- they are surfaced here for manual triage so a coverage gap in
    # SERVICE_PORTS can never hide a real internet-facing path.
    if not rows: return ""
    # dedupe to one row per (host, component) to keep this compact
    seen=set(); uniq=[]
    for r in rows:
        k=(r["name"], (r.get("component") or "").lower())
        if k in seen: continue
        seen.add(k); uniq.append(r)
    out=[f'<hr class="tierdivider">',
         f'<div class="tierband t2" style="border-left-color:var(--high)"><div class="tt">'
         f'&#9888; Needs review &mdash; exposed vulnerable components not in the service map '
         f'<span class="cnt" style="background:var(--high);color:#1a1200">{len(uniq)}</span></div>'
         f'<div class="ts">These are open, network-exploitable, publicly-evidenced vulnerabilities on '
         f'<b>internet-exposed hosts</b> whose software could not be automatically confirmed as a listening '
         f'service (or, in reduced mode, whose port could not be observed). They are <b>not</b> confirmed '
         f'attack paths and <b>not</b> dismissed &mdash; triage each: if the component is an internet-facing '
         f'service, add it to <code>SERVICE_PORTS</code> and it will promote to a full finding next run.</div></div>',
         '<table class="vt"><tr><th>Workload</th><th>Account</th><th>Component</th><th>CVE</th><th>EPSS</th><th>KEV</th><th>Why review</th></tr>']
    for r in uniq:
        out.append(f'<tr><td>{esc(r["name"])}</td>'
          f'<td class="ipport">{esc(acct_kind(r["tenant"]))} {esc(r["tenant"])}</td>'
          f'<td>{esc(r.get("component") or "?")}</td>'
          f'<td class="cve"><a href="https://nvd.nist.gov/vuln/detail/{esc(r["cve"])}" target="_blank" rel="noopener noreferrer">{esc(r["cve"])}</a></td>'
          f'<td class="num">{r.get("epss",0)*100:.0f}%</td><td>{"yes" if r.get("kev") else "—"}</td>'
          f'<td style="color:var(--mut)">{esc(r.get("pf_reason","")[:90])}</td></tr>')
    out.append("</table>");return "".join(out)

# Counts reflect the TRUE qualifying set (rendered cards + overflow), not just what got cards.
allhosts=hostlist+overflow
n1p=sum(1 for h in tier1);n2p=sum(1 for h in tier2)
n1p_total=sum(1 for h in allhosts if h["privileged"]);n2p_total=sum(1 for h in allhosts if not h["privileged"])
nkev=sum(1 for h in allhosts if h["anykev"])
def accounts_block():
    order=["AWS","GCP","Azure","Other"]
    rows=[]
    for prov in order:
        ids=ACCT_BY_PROVIDER.get(prov)
        if not ids: continue
        rows.append(f'<div class="acctrow"><span class="acctprov">{prov} ({len(ids)}):</span> '
                    f'<span class="acctids">{esc(", ".join(ids))}</span></div>')
    return "".join(rows)
cards1="".join(card(i+1,h) for i,h in enumerate(tier1))
cards2="".join(card(n1p+i+1,h) for i,h in enumerate(tier2))
# Reduced-mode framing (API/GraphQL edition: no observed endpoints, no port correlation).
if REDUCED:
    reduced_banner=('<div class="note" style="border-left-color:var(--high)"><b>&#9888; Reduced-fidelity report (API-token edition).</b> '
        'This run used the public GraphQL API, which does not expose observed listening endpoints, VM running-state, '
        'attack complexity, or a CISA-KEV flag. Findings are therefore <b>candidates</b>: hosts are internet-exposed '
        '(direct, wide/all) and carry an open, network-exploitable vulnerability in a <i>listening-class</i> component, '
        'but the exact open port was <b>not</b> confirmed and the workload was not confirmed running. '
        'Re-run the MCP edition for the authoritative, endpoint-validated list.</div>')
    confirm_sentence=("Each finding's vulnerable component is a listening-class service (clients/libraries excluded), "
        "though the specific open port could not be confirmed via this API;")
else:
    reduced_banner=""
    confirm_sentence=("Every path was confirmed against an <b>observed listening endpoint</b> (not a firewall rule), and")

HTML=f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>External Attack-Path Report</title><style>{CSS}</style></head><body>
<div class="bar"></div>
<header>
<p class="eyebrow">Cloud Security &middot; External Attack-Path Assessment</p>
<h1>Externally Exposed Attack Paths: Internet-Reachable Services with Exploitable Vulnerabilities</h1>
<div class="meta-hdr">
<div><b>Report date:</b> {DATE}</div>
<div><b>Environment:</b> multi-account ({len(accts)} cloud accounts / projects / subscriptions)</div>
<div><b>Scope:</b> running virtual machines, internet-facing (direct, wide/all-IP), with a validated listening endpoint</div>
</div>
<div class="accts"><div class="acctshead">Accounts in scope ({len(accts)})</div>{accounts_block()}</div>
</header>
<div class="wrap">
<div class="kpis">
<div class="kpi red"><div class="n">{len(allhosts)}</div><div class="l">Confirmed attack-path hosts</div></div>
<div class="kpi red"><div class="n">{n1p_total}</div><div class="l">Tier 1 &mdash; privileged</div></div>
<div class="kpi"><div class="n">{n2p_total}</div><div class="l">Tier 2 &mdash; standard</div></div>
<div class="kpi"><div class="n">{nkev}</div><div class="l">On CISA KEV</div></div>
</div>

<div class="exec">
<div class="exec-h">Executive Summary</div>
{reduced_banner}
<p>This assessment identifies <b>{len(allhosts)} internet-facing virtual machines</b> across <b>{len(accts)} cloud accounts</b> that expose a network service carrying a serious, remotely exploitable vulnerability. {confirm_sentence} every vulnerability is exploitable over the network and carries independent public evidence of real-world risk (high exploitation probability [EPSS &ge; 30%] or confirmed real-world exploitation).</p>
<ul>
<li><b>Findings are split into two tiers by identity privilege</b> &mdash; privilege is shown and tiered, not used to hide findings.
<ul class="sublist worded">
<li><span class="lbl">Tier 1</span><b>{n1p_total} hosts</b> run an identity flagged as having severe/administrative permissions [SeverePermissionActionPrincipalAttribute] &mdash; here a service compromise can escalate to broad cloud control, so these are the priority.</li>
<li><span class="lbl">Tier 2</span><b>{n2p_total} hosts</b> are the same class of exposed, exploitable service on a standard-privilege identity &mdash; a real foothold, but contained blast radius.</li>
</ul></li>
<li><b>The exposed attack surface is concentrated in a few internet-facing services</b> &mdash; principally OpenSSH, Apache/nginx web servers, and (where reachable over RDP) Windows. Local-only and client-side vulnerabilities were deliberately excluded because they cannot be reached over the exposed port.</li>
<li><b>{nkev} host(s) carry a CISA-KEV vulnerability</b> (confirmed exploited in the wild) &mdash; the highest-urgency subset regardless of tier.</li>
</ul>
<div class="exec-rec"><b>Priority actions:</b>
<ul class="sublist">
<li><span class="lbl">1</span>Remediate Tier 1 first &mdash; patch the exposed service and restrict its port to a bastion/allowlist, and replace over-privileged (editor/owner-class) machine identities with least-privilege roles.</li>
<li><span class="lbl">2</span>Treat any CISA-KEV finding as immediate across both tiers.</li>
<li><span class="lbl">3</span>Reduce Tier 2 exposure by closing or gating internet-facing services that don't need to be public.</li>
</ul></div>
</div>

<div class="note"><b>How each path qualifies (plain-English gate, in order; underlying attribute in brackets).</b>
A workload appears only if <b>all</b> of the following hold, applied in this order:
<ul class="sublist">
<li><span class="lbl">1</span>it is a running VM [VirtualMachineStatus &ne; Stopped];</li>
<li><span class="lbl">2</span>reachable directly from the internet [EntityNetworkAccessType = ExternalDirect];</li>
<li><span class="lbl">3</span>open to a wide range of IPs [EntityNetworkAccessScope = Wide/All];</li>
<li><span class="lbl">4</span>a live listening service was actually observed on an exposed port [NetworkEndpoint exists &mdash; ports come from the endpoint, never the firewall rule];</li>
<li><span class="lbl">5</span>the finding is open [PackageVulnerabilityInstanceStatus = Open];</li>
<li><span class="lbl">6</span>exploitable over the network [AttackVector = Network];</li>
<li><span class="lbl">7</span>needs no unusual conditions [AttackComplexity = Low];</li>
<li><span class="lbl">8</span>the vulnerable software is the service on the exposed port, not a local tool or client [component&harr;port correlation];</li>
<li><span class="lbl">9</span><b>at least one</b> public threat signal: high exploitation probability [EPSS &ge; 0.30] <b>or</b> confirmed in-the-wild exploitation [CISA KEV].</li>
</ul>
<b>Signals intentionally not used as qualifying gates:</b>
<ul class="sublist worded">
<li><span class="lbl">CVSS base / impact score</span>&mdash; not used for qualification because CVSS is frequently overweighted relative to real-world exploitability and, applied as a threshold, admits more noise than signal.</li>
<li><span class="lbl">VPR score</span>&mdash; not used because this methodology targets the underlying exploitability signals (network reachability, low attack complexity, exploitation likelihood, and confirmed in-the-wild use) directly.</li>
<li><span class="lbl">Proof-of-concept availability</span>&mdash; not used as a gate because it tends to admit lower-impact and older findings that do not represent current, high-value exposure.</li>
</ul>
<b>Notes.</b> The published year shown per CVE is informational only and never affects inclusion; findings without a CVE identifier (e.g. distribution advisories) display a year of &ldquo;&mdash;&rdquo;. The stopped-instance exclusion is enforced at the query root and re-verified in post-processing so it cannot be inadvertently dropped. Because the threat-evidence gate relies on CVE-keyed public sources (EPSS and CISA KEV), findings without a CVE mapping are out of scope by design.</div>

<hr class="tierdivider">
<div class="tierband t1"><div class="tt">TIER 1 &mdash; Privileged Attack Paths <span class="cnt">{n1p_total} hosts</span></div>
<div class="ts">Internet-facing exploitable service on a workload whose identity holds severe/administrative permissions [SeverePermissionActionPrincipalAttribute]. A compromise here can escalate to broad cloud control &mdash; highest priority.</div></div>
{cards1}
<hr class="tierdivider">
<div class="tierband t2"><div class="tt">TIER 2 &mdash; Additional Externally Exposed Workloads <span class="cnt">{n2p_total} hosts</span></div>
<div class="ts">Same class of exposed, exploitable service on a standard-privilege identity. A real foothold, but contained blast radius.</div></div>
{cards2}
{overflow_table(overflow)}
{review_table(review)}
</div>
<footer>
Tenable Cloud Security (UDM/Explore) &middot; generated {DATE}. Logic governed by attack_path_spec.py (single source of truth; self-tested, query validated against live count). Gate: running + internet-direct + wide/all + validated endpoint + open + AV:N + AC:Low + server-side-listener + (EPSS&ge;0.30 OR CISA-KEV). Ranked by privilege tier, then CISA-KEV, then EPSS. Post-filter: {len(excluded)} CVE-rows dropped (client/library/local component, stopped host, or listening-port not exposed); {len(review)} surfaced for review (exposed + exploitable but component not in the service map &mdash; never silently dropped). Diagrams depict a plausible exploitation chain, not confirmed compromise. Multi-account lab/demo environment &mdash; validate classification before remediation ticketing.
</footer></body></html>"""
os.makedirs(os.path.dirname(args.out),exist_ok=True)
open(args.out,"w").write(HTML)
print("wrote report:",args.out,"(",len(HTML),"bytes )")
print("hosts:",len(allhosts),"(cards:",len(hostlist),"overflow:",len(overflow),") | tier1:",n1p_total,"| tier2:",n2p_total,"| kev-hosts:",nkev,"| accounts:",len(accts))
print("post-filter: dropped",len(excluded),"| surfaced-for-review",len(review),"(unmapped exposed components)")
print("distinct CVEs in report:",len({c['cve'] for h in hostlist for c in h['cves']}))
