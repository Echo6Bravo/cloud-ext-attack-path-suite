#!/usr/bin/env bash
# Portable test runner for the Cloud External Attack-Path Suite.
# Runs everything that does NOT need a live tenant: spec self-tests, the plan CLI,
# assemble + render (both MCP and reduced/--no-endpoint modes), and the GraphQL caller's
# HTTP-status handling against a local mock (proves old-curl portability, no token needed).
#
# Usage:  bash tests/run_tests.sh
# Exit 0 = all passed. Used by CI (.github/workflows/ci.yml) across a Python matrix.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || { echo "cannot cd to repo root" >&2; exit 1; }
FAIL=0
ok(){ echo "  [PASS] $1"; }
bad(){ echo "  [FAIL] $1"; FAIL=1; }

echo "== 1. spec self-tests =="
python3 attack_path_spec.py >/dev/null 2>&1 && ok "attack_path_spec self-tests" || bad "spec self-tests"

echo "== 2. plan CLI (deterministic chunk selection) =="
printf '{"accounts":{"a":10,"b":9000},"regions":{"b|r1":9000}}' > /tmp/_sizes.json
M1=$(python3 attack_path_spec.py plan /tmp/_sizes.json 20000 | python3 -c 'import json,sys;print(json.load(sys.stdin)["mode"])' 2>/dev/null)
[ "$M1" = "tenant" ] && ok "plan -> tenant when it fits" || bad "plan tenant (got '$M1')"
M2=$(python3 attack_path_spec.py plan /tmp/_sizes.json 4000 | python3 -c 'import json,sys;print(json.load(sys.stdin)["mode"])' 2>/dev/null)
[ "$M2" = "region" ] && ok "plan -> region when an account is oversized" || bad "plan region (got '$M2')"
# bad operator input fails cleanly (exit 2, no Python traceback) — dim-3 for the CLI itself
PERR=$(python3 attack_path_spec.py plan /tmp/nonexistent-sizes.json 2>&1; echo "rc=$?")
if echo "$PERR" | grep -q "rc=2" && ! echo "$PERR" | grep -q "Traceback"; then
  ok "plan CLI fails cleanly on bad input (no traceback)"
else bad "plan CLI bad-input handling: $PERR"; fi
# zero/negative budget must be REJECTED (exit 2), not silently accepted or defaulted.
printf '{"accounts":{"a":10}}' > /tmp/_bsz.json
BZERO=$(python3 attack_path_spec.py plan /tmp/_bsz.json 0 2>&1; echo "rc=$?")
BNEG=$(python3 attack_path_spec.py plan /tmp/_bsz.json -5 2>&1; echo "rc=$?")
if echo "$BZERO" | grep -q "rc=2" && echo "$BNEG" | grep -q "rc=2" \
   && ! echo "$BNEG" | grep -q '"budget": 4000'; then
  ok "plan CLI rejects zero/negative budget (no silent default)"
else bad "plan budget guard: zero='$BZERO' neg='$BNEG'"; fi

echo "== 3. assemble + render (MCP full-gate mode, synthetic sample) =="
python3 render_report.py --data ./data/sample --out /tmp/_r.html >/dev/null 2>&1 \
  && ! grep -q "Reduced-fidelity report" /tmp/_r.html && ok "MCP render (no reduced banner)" || bad "MCP render"

echo "== 4. render (reduced / --no-endpoint mode) =="
python3 render_report.py --data ./data/sample --no-endpoint --out /tmp/_r2.html >/dev/null 2>&1 \
  && grep -q "Reduced-fidelity report" /tmp/_r2.html && ok "--no-endpoint render (reduced banner present)" || bad "--no-endpoint render"

echo "== 4b. gate-4 endpoint requirement: a host with NO validated endpoint never leaks into keep/review =="
# Regression for the live-lab bug: CVE rows whose host has no observed listening endpoint must be
# DROPPED (failed gate 4), not surfaced for review. Two hosts w/ the same unmapped component; only
# one has an endpoint. The no-endpoint host must not appear anywhere in the MCP report.
G4=$(python3 - <<'PY'
import json,subprocess,tempfile,os,sys
d=tempfile.mkdtemp()
A=[{"instance_id":"h-exposed","name":"exposed","type":"AwsEc2Instance","tenant":"t","status":"Running","privileged":False,"identity_ids":[]},
   {"instance_id":"h-noendpoint","name":"noendpoint","type":"AwsEc2Instance","tenant":"t","status":"Running","privileged":False,"identity_ids":[]}]
B=[{"instance_id":"h-exposed","name":"exposed","ports":[{"port":6379,"protocol":"TCP"}]}]
mk=lambda iid,nm,cve:{"instance_id":iid,"name":nm,"type":"AwsEc2Instance","cve":cve,"component":"somelib","cvss":9.8,"epss":0.9,"kev":False,"severity":"High","poc":True,"gate_reason":"epss","status":"Open"}
C=[mk("h-exposed","exposed","CVE-2025-0001"),mk("h-noendpoint","noendpoint","CVE-2025-0002")]
json.dump({"A":A,"B":B,"C":C},open(os.path.join(d,"assembled.json"),"w"))
out=os.path.join(d,"r.html")
subprocess.run([sys.executable,"render_report.py","--data",d,"--out",out],capture_output=True,text=True)
html=open(out).read()
# assert on the DISTINCTIVE cve ids, not the word "exposed" (which appears in static prose):
# the endpoint-bearing host's CVE must appear; the no-endpoint host's CVE must NOT.
print("Y" if ("CVE-2025-0002" not in html and "CVE-2025-0001" in html) else "N")
PY
)
[ "$G4" = "Y" ] && ok "gate-4: no-endpoint host excluded from keep/review" || bad "gate-4 endpoint requirement leak (got '$G4')"

echo "== 4c. review table shows the exposed IP:port (so customers can locate the source) =="
# The 'Needs review' bucket must surface the host's observed endpoint, not just the component.
RC=$(python3 - <<'PY'
import json,subprocess,tempfile,os,sys
d=tempfile.mkdtemp()
A=[{"instance_id":"h1","name":"reviewhost","type":"AwsEc2Instance","tenant":"t","status":"Running","privileged":False,"identity_ids":[]}]
B=[{"instance_id":"h1","name":"reviewhost","ports":[{"port":6379,"protocol":"TCP"}]}]
# unmapped component 'somelib' on an EXPOSED host -> lands in review
C=[{"instance_id":"h1","name":"reviewhost","type":"AwsEc2Instance","cve":"CVE-2025-9999","component":"somelib","cvss":9.8,"epss":0.9,"kev":False,"severity":"High","poc":True,"gate_reason":"epss","status":"Open"}]
ips={"endpoints":[{"name":"reviewhost","ip":"203.0.113.77","port":6379,"protocol":"TCP"}]}
json.dump({"A":A,"B":B,"C":C},open(os.path.join(d,"assembled.json"),"w"))
json.dump(ips,open(os.path.join(d,"endpoint_ips.json"),"w"))
out=os.path.join(d,"r.html")
subprocess.run([sys.executable,"render_report.py","--data",d,"--out",out],capture_output=True,text=True)
html=open(out).read()
seg=html.split("Needs review")[1] if "Needs review" in html else ""
# the review section must carry the endpoint header AND the actual IP:port for the host
print("Y" if ("Exposed endpoint(s) (IP:port)" in html and "203.0.113.77:6379" in seg) else "N")
PY
)
[ "$RC" = "Y" ] && ok "review table shows exposed IP:port" || bad "review table missing endpoint (got '$RC')"

echo "== 5. GraphQL caller HTTP handling (local mock; proves portability w/o a token) =="
if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
  CALLER="plugins/ext-attack-path-agent-api/skills/ext-attack-path-api/scripts/tcs_graphql.sh"
  python3 - <<'PY' &
import http.server, json
S={"flaky":0}
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0)); self.rfile.read(n)
        if "flaky" in self.path:            # 429 twice (with Retry-After) then 200
            S["flaky"]+=1
            if S["flaky"]<3:
                self.send_response(429); self.send_header("Retry-After","1"); self.end_headers()
                self.wfile.write(b'{"errors":[{"message":"rate limited"}]}'); return
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"data":{"ok":true}}'); return
        code=200 if "good" in self.path else 401
        self.send_response(code); self.send_header("Content-Type","application/json"); self.end_headers()
        b={"data":{"__typename":"Query"}} if code==200 else {"errors":[{"message":"unauthorized"}]}
        self.wfile.write(json.dumps(b).encode())
    def log_message(self,*a): pass
try: http.server.HTTPServer(("127.0.0.1",8099),H).serve_forever()
except Exception: pass
PY
  MOCK=$!; sleep 2
  OUT=$(TENABLE_CS_API_URL=http://127.0.0.1:8099/good TENABLE_CS_API_TOKEN=x bash "$CALLER" <<<'query{__typename}' 2>/dev/null)
  echo "$OUT" | grep -q '"__typename"' && ok "caller 2xx returns body" || bad "caller 2xx"
  TENABLE_CS_API_URL=http://127.0.0.1:8099/bad TENABLE_CS_API_TOKEN=x bash "$CALLER" <<<'query{__typename}' >/dev/null 2>&1
  [ $? -ne 0 ] && ok "caller fails loud on HTTP 401 (not retryable)" || bad "caller error path (should be non-zero)"
  # retry/backoff: /flaky returns 429 twice then 200 -> caller must retry and ultimately succeed
  ROUT=$(TCS_BACKOFF_BASE=1 TENABLE_CS_API_URL=http://127.0.0.1:8099/flaky TENABLE_CS_API_TOKEN=x bash "$CALLER" <<<'query{__typename}' 2>/dev/null)
  echo "$ROUT" | grep -q '"ok"' && ok "caller retries 429 w/ backoff then succeeds" || bad "caller 429 retry"
  kill $MOCK 2>/dev/null
else
  echo "  [SKIP] curl/jq not present; skipping caller test"
fi

echo "== 6. gate-8 false-negatives: exposed services surface, not silently dropped =="
python3 - <<'PY' && ok "gate-8 keep/review/drop taxonomy" || bad "gate-8 taxonomy"
import sys, attack_path_spec as s
def st(comp,ports,**k): return s.post_filter({"component":comp},"Running",ports,**k)[0]
checks = [
  # (component, ports, expected) -- the classes the coverage audit found silently dropped
  ("postgresql-14",{5432},"keep"), ("mongodb-org-server",{27017},"keep"),
  ("elasticsearch",{9200},"keep"), ("docker-ce",{2375},"keep"), ("kubelet",{10250},"keep"),
  ("vsftpd",{21},"keep"), ("bind9",{53},"keep"),
  ("nginx",{443},"keep"),
  ("some-inhouse-daemon",{8443},"review"),          # unknown exposed -> surfaced, never dropped
  ("acme-proprietary-broker",{9999},"review"),      # 'tar' substring must NOT false-match
  ("libgnutls30",{443},"drop"), ("openssh-client",{22},"drop"), ("thunderbird",{443},"drop"),
]
fails=[(c,p,e,st(c,p)) for c,p,e in checks if st(c,p)!=e]
if fails:
    for c,p,e,got in fails: print(f"    FAIL {c} {p}: expected {e}, got {got}")
    sys.exit(1)
PY

echo "== 6b. service-table invariant: an unmapped service is REVIEWED, never silently dropped =="
python3 - <<'PY' && ok "SERVICE_ALIASES<->SERVICE_PORTS invariant + unmapped-service review path" || bad "service-table invariant"
import sys, attack_path_spec as s
fails=[]
# (a) The invariant itself: every alias must resolve to a key that HAS a port mapping. Without
# this, adding an alias and forgetting the ports entry loses that service's findings.
orphans=sorted({v for v in s.SERVICE_ALIASES.values() if v not in s.SERVICE_PORTS})
if orphans: fails.append(f"SERVICE_ALIASES targets missing from SERVICE_PORTS: {orphans}")
# (b) The safety net for when (a) is broken anyway: an alias resolving to an unmapped key must
# come back 'review' (surfaced), NOT 'drop'. With `SERVICE_PORTS.get(sk, set())` the intersection
# below it is unconditionally empty, so this returns 'drop' -- a silent false negative that reads
# in the report as "not reachable". Inject a deliberately orphaned alias to exercise the branch.
s.SERVICE_ALIASES["orphansvc"]="orphan-service-with-no-ports"
try:
    status, reason = s.post_filter({"component":"orphansvc"}, "Running", {8443})
finally:
    del s.SERVICE_ALIASES["orphansvc"]
if status!="review": fails.append(f"unmapped service: expected 'review', got '{status}' ({reason})")
if "SERVICE_PORTS" not in reason: fails.append(f"review reason must name the table gap, got: {reason}")
if fails:
    for f in fails: print("    FAIL",f)
    sys.exit(1)
PY

echo "== 7. XSS/injection: malicious data in every field is neutralized (DOM-level check) =="
python3 - <<'PY' && ok "report is injection-safe" || bad "XSS: live injection found"
import json, os, subprocess, sys, html.parser, tempfile
d=tempfile.mkdtemp()
X="<script>alert(1)</script>"; ATTR='"><img src=x onerror=alert(2)>'
A=[{"instance_id":"i-1","name":X,"type":ATTR,"tenant":"</td><script>a</script>","privileged":True,"identity_ids":["<svg onload=alert(4)>r"]}]
B=[{"instance_id":"i-1","name":X,"ports":[{"port":443,"protocol":"HTTPS"}]}]
C=[{"instance_id":"i-1","name":X,"type":ATTR,"cve":"CVE-<script>alert(5)</script>","component":"nginx","cvss":9.1,"epss":0.6,"kev":True,"severity":"<b>c</b>","poc":False,"gate_reason":"both","status":"Open"}]
json.dump({"A":A,"B":B,"C":C},open(os.path.join(d,"assembled.json"),"w"))
out=os.path.join(d,"r.html")
subprocess.run([sys.executable,"render_report.py","--data",d,"--out",out],check=True,capture_output=True)
bad=[]
class P(html.parser.HTMLParser):
    in_s=False
    def handle_starttag(self,t,attrs):
        for k,v in attrs:
            if k.startswith("on"): bad.append(("event-attr",t,k))
        if t=="script": self.in_s=True
    def handle_endtag(self,t):
        if t=="script": self.in_s=False
    def handle_data(self,data):
        if self.in_s and "alert(" in data: bad.append(("script-body",data[:30]))
p=P(); p.feed(open(out).read())
if bad:
    for b in bad: print("    XSS FAIL:",b)
    sys.exit(1)
PY

echo "== 8. robustness: messy/malformed data fails cleanly (no traceback), exit contract =="
python3 - <<'PY' && ok "messy-data handling (clean errors + defensive rows)" || bad "messy-data handling"
import json,os,subprocess,sys,tempfile
d=tempfile.mkdtemp(); PY=sys.executable
def run(payload, fname="assembled.json", write=True):
    sub=tempfile.mkdtemp()
    if write: open(os.path.join(sub,fname),"w").write(payload)
    r=subprocess.run([PY,"render_report.py","--data",sub,"--out",os.path.join(sub,"r.html")],
                     capture_output=True,text=True)
    return r.returncode, (r.stderr or "")
fails=[]
# input errors -> exit 2, a clean 'render_report: ERROR' message, and NO python traceback
for name,payload in [
    ("missing-key",'{"A":[],"B":[]}'),
    ("bad-json",'{"A":[],"B":[],"C":[{'),
    ("wrong-type",'{"A":[],"B":[],"C":{}}'),
    ("not-object",'[]'),
]:
    rc,err=run(payload)
    if rc!=2: fails.append((name,f"exit {rc}, want 2"))
    if "Traceback" in err: fails.append((name,"leaked a Python traceback"))
    if "render_report: ERROR" not in err: fails.append((name,"no clean ERROR message"))
# missing dir -> exit 2, clean
rc,err=run("",write=False)
if rc!=2 or "Traceback" in err: fails.append(("missing-dir",f"exit {rc}"))
# empty datasets -> success (exit 0)
rc,err=run('{"A":[],"B":[],"C":[]}')
if rc!=0: fails.append(("empty",f"exit {rc}, want 0"))
# null/missing per-row fields -> success (exit 0), not a crash
messy=json.dumps({"A":[{"instance_id":"i-1","name":None,"type":"AwsEc2Instance","tenant":None,"identity_ids":None}],
 "B":[{"instance_id":"i-1","name":"x","ports":[{"port":443,"protocol":"HTTPS"}]}],
 "C":[{"instance_id":"i-1","name":"x","cve":None,"epss":None,"cvss":None,"kev":None,"severity":None,"status":"Open"}]})
rc,err=run(messy)
if rc!=0: fails.append(("null-fields",f"exit {rc}, want 0; {err[:80]}"))
if fails:
    for f in fails: print("    FAIL",f)
    sys.exit(1)
PY

echo "== 8b. --date is validated: no silent bogus year, no raw traceback =="
python3 - <<'PY' && ok "--date rejects non-dates (rc=2, clean message)" || bad "--date validation"
import os,subprocess,sys,tempfile
PY_=sys.executable; fails=[]
# `--date 99` used to reach int(DATE[:4]) -> year 99, making every CVE read as decades old while
# the render still exited 0 -- a wrong report that looks right. `--date not-a-date` raised a bare
# ValueError traceback. Both must now be one clean rc=2.
for bad_date in ("99","not-a-date","2026-13-45","08/09/2026",""):
    sub=tempfile.mkdtemp(); open(os.path.join(sub,"assembled.json"),"w").write('{"A":[],"B":[],"C":[]}')
    r=subprocess.run([PY_,"render_report.py","--data",sub,"--out",os.path.join(sub,"r.html"),
                      "--date",bad_date],capture_output=True,text=True)
    if r.returncode!=2: fails.append((bad_date,f"exit {r.returncode}, want 2"))
    if "Traceback" in r.stderr: fails.append((bad_date,"raw traceback"))
    if "render_report: ERROR" not in r.stderr: fails.append((bad_date,"no clean ERROR message"))
# and a valid date is still accepted
sub=tempfile.mkdtemp(); open(os.path.join(sub,"assembled.json"),"w").write('{"A":[],"B":[],"C":[]}')
out=os.path.join(sub,"r.html")
r=subprocess.run([PY_,"render_report.py","--data",sub,"--out",out,"--date","2026-08-09"],
                 capture_output=True,text=True)
if r.returncode!=0: fails.append(("2026-08-09",f"exit {r.returncode}, want 0"))
elif "2026-08-09" not in open(out).read(): fails.append(("2026-08-09","date not in report"))
if fails:
    for f in fails: print("    FAIL",f)
    sys.exit(1)
PY

echo "== 8c. import safety: importing the renderer has no side effects (__main__ guard) =="
python3 - <<'PY' && ok "render_report imports cleanly (no argv parse, no file write)" || bad "__main__ guard"
import os,subprocess,sys,tempfile
PY_=sys.executable; fails=[]
# Importing this module used to parse sys.argv, read assembled.json and WRITE the output HTML as
# an import side effect -- so any importer passing its own flags got argparse's sys.exit() instead.
probe=("import sys; sys.argv=['pytest','-k','foo','--tb=short']\n"
       "import render_report as rr\n"
       "assert callable(rr.main), 'main() missing'\n"
       "assert callable(rr.evidence_cell) and callable(rr.epss_pill), 'helpers not importable'\n"
       "print('OK')\n")
r=subprocess.run([PY_,"-c",probe],capture_output=True,text=True,cwd=os.getcwd())
if r.returncode!=0: fails.append(("import-with-foreign-argv",f"exit {r.returncode}: {r.stderr.strip()[:120]}"))
# and it must not write the default output path just by being imported
outdir=tempfile.mkdtemp(); target=os.path.join(outdir,"must-not-exist.html")
r=subprocess.run([PY_,"-c",f"import sys; sys.argv=['x','--out',{target!r}]; import render_report"],
                 capture_output=True,text=True,cwd=os.getcwd())
if os.path.exists(target): fails.append(("import-side-effect","import wrote the output file"))
if fails:
    for f in fails: print("    FAIL",f)
    sys.exit(1)
PY

echo "== 8d. evidence pills never overstate: absent EPSS is 'n/a'/'no public signal', not 0%/EPSS =="
python3 - <<'PY' && ok "evidence claim matches the data the row carries" || bad "false evidence claim"
import json,os,re,subprocess,sys,tempfile
PY_=sys.executable; fails=[]
def render(C, extra=()):
    d=tempfile.mkdtemp()
    A=[{"instance_id":"i-1","name":"h","type":"AwsEc2Instance","tenant":"1","privileged":False,"identity_ids":[]}]
    B=[{"instance_id":"i-1","name":"h","ports":[{"port":443,"protocol":"HTTPS"}]}]
    json.dump({"A":A,"B":B,"C":C},open(os.path.join(d,"assembled.json"),"w"))
    out=os.path.join(d,"r.html")
    r=subprocess.run([PY_,"render_report.py","--data",d,"--out",out,*extra],capture_output=True,text=True)
    return r.returncode, (open(out).read() if os.path.exists(out) else "")
base=dict(instance_id="i-1",name="h",component="nginx",severity="Critical",status="Open")
# Match the RENDERED pill markup, not the class name: 'ev-epss' also appears in the stylesheet,
# so a bare substring test would pass on every report and prove nothing.
EPSS_PILL='class="ev ev-epss"'; UNK_PILL='class="ev ev-unknown"'; BOTH_PILL='class="ev ev-both"'
# (1) malformed EPSS feed value: must NOT render as a 0% row carrying an "EPSS" evidence pill.
rc,h=render([{**base,"cve":"CVE-2024-1","cvss":9.1,"epss":"n/a","kev":False}])
if rc!=0: fails.append(("malformed-epss",f"exit {rc}"))
if ">0%<" in h: fails.append(("malformed-epss","rendered a fabricated 0% score"))
if EPSS_PILL in h: fails.append(("malformed-epss","claimed EPSS evidence with no EPSS value"))
if UNK_PILL not in h: fails.append(("malformed-epss","no 'no public signal' pill rendered"))
if "no public signal" not in h: fails.append(("malformed-epss","gap not surfaced in the Evidence cell"))
if "pill-na" not in h: fails.append(("malformed-epss","absent score not shown as an n/a pill"))
# (2) a MALFORMED feed and a GENUINE boundary value must render DIFFERENTLY (the review check
# the dimension-3 finding asks for -- if they are identical, the report cannot be trusted).
rc2,h2=render([{**base,"cve":"CVE-2024-1","cvss":9.1,"epss":0.0,"kev":False}])
if rc2!=0: fails.append(("zero-epss",f"exit {rc2}"))
if h==h2: fails.append(("indistinguishable","malformed EPSS renders identically to a genuine 0.0"))
# (3) an input-supplied gate_reason must not override what the row's own values support.
rc3,h3=render([{**base,"cve":"CVE-2024-1","cvss":9.1,"epss":None,"kev":False,"gate_reason":"epss"}])
if EPSS_PILL in h3: fails.append(("supplied-gate_reason","trusted a gate_reason the data contradicts"))
# (4) a real KEV row still gets its KEV pill (the fix must not suppress genuine evidence).
rc4,h4=render([{**base,"cve":"CVE-2024-2","cvss":9.1,"epss":0.94,"kev":True}])
if BOTH_PILL not in h4: fails.append(("kev+epss","lost the EPSS+KEV evidence pill"))
if fails:
    for f in fails: print("    FAIL",f)
    sys.exit(1)
PY

echo "== 8e. reduced mode never claims CISA-KEV for the API's ExploitMaturity substitute =="
python3 - <<'PY' && ok "KEV wording matches the signal the run actually read" || bad "reduced mode overstates KEV"
import json,os,re,subprocess,sys,tempfile
PY_=sys.executable; fails=[]
def render(extra=()):
    d=tempfile.mkdtemp()
    A=[{"instance_id":"i-1","name":"h","type":"AwsEc2Instance","tenant":"1","privileged":True,"identity_ids":[]}]
    # B empty in reduced mode is supplied by the caller via --no-endpoint; keep the endpoint for MCP.
    B=[{"instance_id":"i-1","name":"h","ports":[{"port":443,"protocol":"HTTPS"}]}]
    C=[{"instance_id":"i-1","name":"h","component":"nginx","cve":"CVE-2024-1","cvss":9.1,
        "epss":0.94,"kev":True,"severity":"Critical","status":"Open"}]
    json.dump({"A":A,"B":B,"C":C},open(os.path.join(d,"assembled.json"),"w"))
    out=os.path.join(d,"r.html")
    r=subprocess.run([PY_,"render_report.py","--data",d,"--out",out,*extra],capture_output=True,text=True)
    return r.returncode, (open(out).read() if os.path.exists(out) else "")
rc,mcp=render()
rc2,red=render(("--no-endpoint",))
if rc!=0 or rc2!=0: fails.append(("exit",f"mcp={rc} reduced={rc2}"))
# The MCP edition reads the REAL CISA-KEV field, so it must still say so -- the fix must not
# water down the authoritative edition's wording.
if 'class="badge b-kev">CISA KEV<' not in mcp: fails.append(("mcp","lost the CISA KEV host badge"))
if "&#9888; EPSS + KEV" not in mcp: fails.append(("mcp","lost the EPSS + KEV evidence pill"))
if "On CISA KEV" not in mcp: fails.append(("mcp","lost the CISA KEV KPI label"))
# The reduced edition has NO CISA-KEV field: assemble_api.py substitutes ExploitMaturity. Naming
# CISA KEV there cites a source the run never read AND contradicts the reduced banner's own
# sentence that the API exposes no CISA-KEV flag.
banner="does not expose observed listening endpoints"
if banner not in red: fails.append(("reduced","reduced banner missing -- test proves nothing"))
# Assert only on surfaces reduced mode actually RENDERS. spec.post_filter with require_port=False
# returns review/drop and never 'keep' (asserted below), so reduced mode emits no host cards --
# and therefore no host badge, no evidence pill and no diagram. Asserting their absence here
# would pass no matter what the labeller does; the review-table header and the summary/methodology
# prose are the reduced-mode surfaces with real discriminating power.
if "<th>exploit maturity</th>" not in red:
    fails.append(("reduced","review-table column still headed KEV"))
if "On CISA KEV" in red: fails.append(("reduced","KPI tile claims CISA KEV"))
if "confirmed exploited in the wild" in red:
    fails.append(("reduced","asserts confirmed in-the-wild exploitation the API cannot support"))
if "exploit maturity" not in red: fails.append(("reduced","never names the substitute signal"))
# Exactly ONE literal CISA-KEV may remain in reduced mode: the banner's own statement that the
# field is absent. Any other occurrence is the report re-asserting what the banner denies.
extra_kev=[m.start() for m in re.finditer("CISA.KEV", red)]
if len(extra_kev)!=1:
    ctx=[red[max(0,i-60):i+40].replace("\n"," ") for i in extra_kev]
    fails.append(("reduced",f"expected 1 CISA-KEV mention (the banner), found {len(extra_kev)}: {ctx}"))
# Pin the premise the two skipped assertions above rest on. If a future change lets reduced mode
# emit a 'keep' (and thus cards, badges and evidence pills), those surfaces become reachable and
# untested -- this fails and says so rather than leaving a silent hole.
import attack_path_spec as spec
_out={spec.post_filter({"component":c},"Running",p,require_port=False)[0]
      for c in list(spec.SERVICE_PORTS)+list(spec.SERVICE_ALIASES)+["thunderbird","unknown-thing",""]
      for p in (set(),{443},{22,3389})}
if "keep" in _out:
    fails.append(("premise","reduced mode now yields 'keep' -- host cards/badges/evidence pills "
                            "render in reduced mode and need their own KEV-wording assertions"))
if fails:
    for f in fails: print("    FAIL",f)
    sys.exit(1)
PY

echo "== 9. remediation guidance is specific for mapped services + a real generic fallback =="
python3 - <<'PY' && ok "remediation: per-CVE / per-service / generic layers" || bad "remediation layering"
import re,sys
src=open("render_report.py").read()
ns={"esc":lambda s:s if s is not None else ""}
class FakeSpec: EPSS_FLOOR=0.30
ns["spec"]=FakeSpec
block=src[src.index("REM_CVE={"): src.index("def esc_txt")+len("def esc_txt(s): return str(s) if s is not None else \"\"")]
exec(block, ns); rem=ns["rem"]
checks=[
  (rem({"cve":"CVE-2024-38475","service":"apache2","port":443}), "Apache httpd"),   # exact CVE
  (rem({"cve":"X","service":"postgresql","port":5432}), "5432"),                     # per-service names the port
  (rem({"cve":"X","service":"docker","port":2375}), "daemon API"),                   # per-service docker warning
  (rem({"cve":"X","service":None,"component":"weird","port":8443}), "weird"),         # generic names the component
]
bad=[(got,want) for got,want in checks if want not in got]
# generic must NOT be the old one-liner-only; must mention restrict exposure
if "restrict its internet exposure" not in rem({"cve":"X","service":None,"component":"z","port":1}): bad.append(("generic","missing restrict advice"))
if bad:
    for g,w in bad: print(f"    FAIL: expected '{w}' in: {g[:80]}")
    sys.exit(1)
PY

echo "== 10. schema-drift canary: covers query fields, passes intact, fires on a rename =="
python3 - <<'PY' && ok "schema-drift canary" || bad "schema-drift canary"
import sys, attack_path_spec as s
# REQUIRED_FIELDS must cover every field the queries reference (guards against falling behind)
ref=set()
def w(o):
    if isinstance(o,dict):
        for k in ("propertyIdentifier","relationPropertyIdentifier"):
            if isinstance(o.get(k),str): ref.add(o[k])
        if isinstance(o.get("identifier"),str) and o.get("queryId"): ref.add(o["identifier"])
        for v in o.values(): w(v)
    elif isinstance(o,list):
        for v in o: w(v)
for b in (s.build_population_query,s.build_inventory_query,s.build_endpoints_query,s.build_cve_query): w(b())
declared=set().union(*s.REQUIRED_FIELDS.values())
gap=ref-declared
fails=[]
if gap: fails.append(("REQUIRED_FIELDS misses query fields",gap))
# intact metadata -> ok
intact={t:list(f) for t,f in s.REQUIRED_FIELDS.items()}
if not s.check_schema(intact)["ok"]: fails.append(("intact check not ok",None))
# a rename -> fires with the exact field
drift=dict(intact); drift["Vulnerability"]=[x for x in intact["Vulnerability"] if x!="VulnerabilityEpssScore"]
r=s.check_schema(drift)
if r["ok"] or not any(m["field"]=="VulnerabilityEpssScore" for m in r["missing"]):
    fails.append(("rename not detected",r))
# markdown parse (the shape the MCP tool returns)
if "VirtualMachineStatus" not in s.parse_metadata_identifiers("|Identifier|\n|---|\n|VirtualMachineStatus|Status|CommonEnum|null|"):
    fails.append(("markdown parse",None))
if fails:
    for f in fails: print("    FAIL",f)
    sys.exit(1)
PY

echo "== 11. instance-Id parsing: structural, correct across provider shapes + edge cases =="
python3 - <<'PY' && ok "instance-Id component parsing" || bad "instance-Id parsing"
import sys, assemble
cases=[
 ("cve-2011-3389/libgnutls30/3.7.1/Linux///compute.googleapis.com/projects/8/instances/vm","cve-2011-3389","libgnutls30"),
 ("cve-2013-0758/Thunderbird/10/Windows/arn:aws:ec2:us-east-2:896850635108:instance/i-0b","cve-2013-0758","Thunderbird"),
 ("cve-2025-59287/windows os/10/Windows/arn:aws:ec2:us-east-2:120:instance/i-0c","cve-2025-59287","windows os"),
 ("cve-2014-0114/commons-beanutils:commons-beanutils/1.8/Linux/824f/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm","cve-2014-0114","commons-beanutils:commons-beanutils"),
 ("/cve-2020-1/openssh-server/8.9/Linux/x","cve-2020-1","openssh-server"),   # leading slash
 ("dla-2761-1/libxml2/2.9/Linux/x","dla-2761-1","libxml2"),                  # non-CVE advisory
 ("","",""), ("garbage","",""), ("notacve/pkg/1/Linux/x","",""),             # degenerate/unsafe -> no component
]
fails=[(i[:30],assemble.parse_instance_id(i),(c,comp)) for i,c,comp in cases if assemble.parse_instance_id(i)!=(c,comp)]
if fails:
    for f in fails: print("    FAIL",f)
    sys.exit(1)
PY

echo "== 12. --max-rows memory bound: caps to highest-risk + banners (never silent) =="
python3 - <<'PY' && ok "--max-rows memory safety valve" || bad "--max-rows"
import json,os,subprocess,sys,tempfile
d=tempfile.mkdtemp()
A=[{"instance_id":"i-1","name":"h","type":"AwsEc2Instance","tenant":"1","privileged":False,"identity_ids":[]}]
B=[{"instance_id":"i-1","name":"h","ports":[{"port":443,"protocol":"HTTPS"}]}]
C=[{"instance_id":"i-1","name":"h","cve":f"CVE-2024-{i}","component":"nginx","cvss":9,"epss":e,"kev":k,"severity":"Critical","status":"Open"}
   for i,e,k in [(1,0.1,False),(2,0.9,True),(3,0.5,False),(4,0.95,False),(5,0.2,True)]]
json.dump({"A":A,"B":B,"C":C},open(os.path.join(d,"assembled.json"),"w"))
out=os.path.join(d,"r.html")
r=subprocess.run([sys.executable,"render_report.py","--data",d,"--out",out,"--max-rows","2"],capture_output=True,text=True)
html=open(out).read()
fails=[]
if r.returncode!=0: fails.append(("exit",r.returncode))
if "TRUNCATED" not in html: fails.append(("no truncation banner",None))
if "CVE-2024-2" not in html or "CVE-2024-5" not in html: fails.append(("dropped a KEV row",None))  # both KEV must survive
if "CVE-2024-1" in html: fails.append(("kept a low-risk row over a high one",None))
if fails:
    for f in fails: print("    FAIL",f)
    sys.exit(1)
PY

echo "== 13. orchestrator end-to-end (run_attack_path.sh, mocked claude CLI) =="
# size -> plan -> fan-out -> merge -> render, both tenant + per-account modes + guards.
if bash tests/test_orchestrator.sh >/tmp/_orch.log 2>&1; then
  ok "orchestrator: $(grep -Eo '[0-9]+ passed' /tmp/_orch.log | head -1) (tenant+fanout+guards)"
else
  bad "orchestrator end-to-end"; sed -n 's/^/    /p' /tmp/_orch.log | grep -i fail | head
fi

echo ""
[ $FAIL -eq 0 ] && echo "ALL TESTS PASSED" || echo "SOME TESTS FAILED"
exit $FAIL
