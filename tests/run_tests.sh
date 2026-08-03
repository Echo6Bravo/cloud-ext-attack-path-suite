#!/usr/bin/env bash
# Portable test runner for the Cloud External Attack-Path Suite.
# Runs everything that does NOT need a live tenant: spec self-tests, the plan CLI,
# assemble + render (both MCP and reduced/--no-endpoint modes), and the GraphQL caller's
# HTTP-status handling against a local mock (proves old-curl portability, no token needed).
#
# Usage:  bash tests/run_tests.sh
# Exit 0 = all passed. Used by CI (.github/workflows/ci.yml) across a Python matrix.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
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

echo "== 3. assemble + render (MCP full-gate mode, synthetic sample) =="
python3 render_report.py --data ./data/sample --out /tmp/_r.html >/dev/null 2>&1 \
  && ! grep -q "Reduced-fidelity report" /tmp/_r.html && ok "MCP render (no reduced banner)" || bad "MCP render"

echo "== 4. render (reduced / --no-endpoint mode) =="
python3 render_report.py --data ./data/sample --no-endpoint --out /tmp/_r2.html >/dev/null 2>&1 \
  && grep -q "Reduced-fidelity report" /tmp/_r2.html && ok "--no-endpoint render (reduced banner present)" || bad "--no-endpoint render"

echo "== 5. GraphQL caller HTTP handling (local mock; proves portability w/o a token) =="
if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
  CALLER="plugins/ext-attack-path-agent-api/skills/ext-attack-path-api/scripts/tcs_graphql.sh"
  python3 - <<'PY' &
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0)); self.rfile.read(n)
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
  [ $? -ne 0 ] && ok "caller fails loud on HTTP 401" || bad "caller error path (should be non-zero)"
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

echo ""
[ $FAIL -eq 0 ] && echo "ALL TESTS PASSED" || echo "SOME TESTS FAILED"
exit $FAIL
