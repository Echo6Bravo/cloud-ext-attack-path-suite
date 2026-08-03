"""
attack_path_spec.py  --  SINGLE SOURCE OF TRUTH for the
External Attack-Path report logic (Tenable Cloud Security / UDM).

Why this file exists
--------------------
Across development we repeatedly hit the same failure modes:
  * the "not Stopped" gate got silently dropped when a query was rooted on
    NetworkEndpoint or Vulnerability instead of the VM (status isn't in scope there);
  * miscalibrated noise signals (CVSS>=9, VPR floor, PoC-only, malware-obs) kept
    creeping back into the qualifying gate;
  * client-side / local CVEs slipped in because only the boolean flags were used;
  * hand-written UDM JSON drifted from the documented logic;
  * invalid GUIDs (non-hex) broke queries at runtime.

To make the report packageable, the gates are declared ONCE, in order, as data.
The UDM query is BUILT from that declaration, and validate_spec()/build_* refuse
to emit anything that violates the invariants. If a future edit weakens a gate,
the self-tests at the bottom fail loudly.

Run:  python3 attack_path_spec.py        # runs self-tests, prints the query JSON
"""

from __future__ import annotations
import json, re, uuid

# ----------------------------------------------------------------------------
# 0. Enforced invariants (the things that MUST never regress)
# ----------------------------------------------------------------------------
ROOT_OBJECT_TYPE = "IVirtualMachine"          # MUST root here so Status is in scope
EPSS_FLOOR       = 0.30                        # public FIRST.org metric
PRIVILEGE_ATTR   = "SeverePermissionActionPrincipalAttribute"  # tiering, NOT a gate

# Signals we deliberately REJECTED, with the evidence-based reason. If any of
# these field identifiers appears in the qualifying query, that's a regression.
REJECTED_SIGNALS = {
    "VulnerabilityCvssScore":   "CVSS base re-admits NVD-over-scored legacy noise "
                                 "(nginx log-injection scored 9.8); ballooned 2731->1048.",
    "VulnerabilityCvssImpactScore": "Impact sub-score is identical (5.9) for real RCE and "
                                 "log-injection noise; does not discriminate.",
    "VulnerabilityVprScore":    "Proprietary (not all customers license VPR); fails packaging bar.",
    "VulnerabilityVprSeverity": "Proprietary VPR.",
    "VulnerabilityVprV2Score":  "Proprietary VPR v2.",
    "VulnerabilityVprV2MalwareObservationsIntensityLast30":
                                 "Proprietary VPR v2 AND non-discriminating (VeryLow for real RCE "
                                 "and noise alike on tested data).",
    "VulnerabilityVprV2MetricsExploitCodeMaturity":
                                 "Proprietary VPR v2; read 'Poc' for everything tested.",
}
# NOTE: VulnerabilityVprV2MetricsOnCisaKev is the ONE VprV2 field we allow, because it
# is a passthrough of the public CISA KEV catalog (vendor-neutral in substance).
ALLOWED_KEV_FIELD = "VulnerabilityVprV2MetricsOnCisaKev"

# PoC is allowed as a DISPLAY column but MUST NOT be a qualifying gate (it re-admitted
# 2003-2016 low-impact findings and truncated pulls before real RCEs).
POC_FIELD = "VulnerabilityProofOfConceptAvailable"
POC_IS_GATE = False

# ----------------------------------------------------------------------------
# 1. The gates, declared in application order.  This list IS the spec.
#    stage: 1 workload | 2 exposure | 3 vuln-structural | 3E vuln-evidence(OR)
#    enforced_in: "query" (server-side UDM) or "post" (deterministic reconcile)
# ----------------------------------------------------------------------------
class Gate:
    def __init__(self, gid, stage, plain, field, op, value, rationale,
                 enforced_in="query", mandatory=True, evidence_or=False):
        self.gid=gid; self.stage=stage; self.plain=plain; self.field=field
        self.op=op; self.value=value; self.rationale=rationale
        self.enforced_in=enforced_in; self.mandatory=mandatory; self.evidence_or=evidence_or

GATES = [
    # ---- Stage 1: which workloads are even candidates (root = IVirtualMachine) ----
    Gate("1.1","1","Only running virtual machines (a stopped VM is not a live path).",
         "VirtualMachineStatus","NotIn",["Stopped"],
         "Structurally enforced by rooting the query on IVirtualMachine so status is in scope; "
         "also re-checked in post-filter. This is the gate that silently vanished when queries "
         "were rooted on NetworkEndpoint/Vulnerability."),
    Gate("1.2","1","Reachable directly from the internet (not via an indirect path).",
         "EntityNetworkAccessType","In",["ExternalDirect"],
         "Direct internet exposure, not indirect chaining."),
    Gate("1.3","1","Open to a wide range of IPs / the whole internet (not a few admin IPs).",
         "EntityNetworkAccessScope","In",["Wide","All"],
         "Broad exposure, not a locked-down admin CIDR."),
    # ---- Stage 2: a service is actually listening (validated, not firewall-rule) ----
    Gate("2.1","2","A live listening service was actually observed on an internet-facing port "
         "(validated endpoint), not merely a firewall rule allowing it.",
         "NetworkDynamicAnalysisResourceNetworkEndpoints","RelationExists",None,
         "Dynamic-analysis NetworkEndpoint proves something answers on the port. Ports come from "
         "the endpoint, NEVER from security-group scope."),
    # ---- Stage 3: the vulnerability is a real remote, server-side threat ----
    Gate("3.1","3","The finding is still open (not remediated).",
         "PackageVulnerabilityInstanceStatus","In",["Open"],"Open findings only."),
    Gate("3.2","3","Exploitable over the network.",
         "VulnerabilityAttackVector","In",["Network"],"AV:N — network-reachable."),
    Gate("3.3","3","No unusual conditions required to exploit it.",
         "VulnerabilityAttackComplexity","In",["Low"],
         "AC:Low. Drops conditional MITM/race findings (e.g. the OpenSSH client CVE-2020-14145)."),
    Gate("3.4","3","The vulnerable software is the service listening on the exposed port "
         "(not a local tool or client program).",
         "__component_port_correlation__","PostRule",None,
         "Excludes local-privilege-escalation and client-side CVEs (kernel, sudo, glibc, "
         "telnet client, Thunderbird, *-client) that cannot be reached over the open port. "
         "Enforced in post-filter via package->service->validated-port map.",
         enforced_in="post"),
    # ---- Stage 3E: at least ONE independent, PUBLIC threat signal ----
    Gate("3E.a","3E","Public data shows real exploitation likelihood (EPSS >= 30%).",
         "VulnerabilityEpssScore","Gte",EPSS_FLOOR,
         "EPSS (FIRST.org, public). Rises before KEV, covering most KEV lag.",
         evidence_or=True),
    Gate("3E.b","3E","On CISA's Known Exploited Vulnerabilities catalog (confirmed exploited in the wild).",
         ALLOWED_KEV_FIELD,"Equals",True,
         "CISA KEV (public). Proven non-redundant with PoC: 9 KEV CVEs here had no PoC flag.",
         evidence_or=True),
]

# ----------------------------------------------------------------------------
# 2. Guards
# ----------------------------------------------------------------------------
def hexguid():
    """Return a valid UDM GUID (hex only). Fixes the recurring 'non-hex GUID' runtime error."""
    return str(uuid.UUID(int=0)).replace("00000000-0000-0000-0000-000000000000",
           uuid.uuid4().hex[:8]+"-"+uuid.uuid4().hex[:4]+"-"+uuid.uuid4().hex[:4]+"-"
           +uuid.uuid4().hex[:4]+"-"+uuid.uuid4().hex[:12])

_HEX_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
def assert_guid(g):
    assert _HEX_GUID.match(g), f"INVALID GUID (non-hex will break UDM at runtime): {g}"
    return g

def validate_spec():
    """Fail loudly if the gate list violates any invariant. Called before any query is built."""
    errs=[]
    fields=[g.field for g in GATES]
    # (a) Stopped gate present and first
    if not (GATES[0].gid=="1.1" and GATES[0].field=="VirtualMachineStatus"):
        errs.append("Gate 1.1 (not Stopped) must be present and FIRST.")
    # (b) rejected signals must not appear
    for g in GATES:
        if g.field in REJECTED_SIGNALS:
            errs.append(f"REJECTED signal '{g.field}' present in gate {g.gid}: {REJECTED_SIGNALS[g.field]}")
    # (c) PoC must not be a gate
    if POC_IS_GATE or POC_FIELD in fields:
        errs.append("PoC must NOT be a qualifying gate (display-only).")
    # (d) evidence arm must be exactly EPSS + KEV
    ev={g.field for g in GATES if g.evidence_or}
    if ev != {"VulnerabilityEpssScore", ALLOWED_KEV_FIELD}:
        errs.append(f"Evidence-OR arm must be exactly EPSS+KEV, got {ev}")
    # (e) ordering: stages must be non-decreasing in declared order
    order={"1":1,"2":2,"3":3,"3E":4}
    seq=[order[g.stage] for g in GATES]
    if seq!=sorted(seq):
        errs.append(f"Gates out of stage order: {[g.gid for g in GATES]}")
    # (f) root object
    if ROOT_OBJECT_TYPE!="IVirtualMachine":
        errs.append("ROOT_OBJECT_TYPE must be IVirtualMachine so the Stopped gate is in scope.")
    if errs:
        raise AssertionError("SPEC VALIDATION FAILED:\n  - "+"\n  - ".join(errs))
    return True

# ----------------------------------------------------------------------------
# 3. Build the UDM query FROM the spec (query cannot drift from the gate list)
# ----------------------------------------------------------------------------
def _rule(field, op, values, negate=False):
    return {"typeName":"UdmQueryRule","id":assert_guid(hexguid()),"ignored":False,
            "not":negate,"operator":op,"propertyIdentifier":field,"values":values}

def _group(rules, operator="And", negate=False):
    return {"typeName":"UdmQueryRuleGroup","id":assert_guid(hexguid()),"collapsed":False,
            "name":"","not":negate,"ignored":False,"operator":operator,"rules":rules}

def build_population_query():
    """Emit the authoritative UDM count/inventory query for the running,
    internet-facing, exploitable-vuln population. Stage-3.4 (component<->port) and
    the final Stopped re-check are applied in post-filter, by design."""
    validate_spec()
    qid=assert_guid(hexguid())

    # Stage 1 (workload-level rules, incl. the structural Stopped gate)
    s1=[]
    for g in GATES:
        if g.stage!="1": continue
        negate = (g.op=="NotIn")
        op = "In" if g.op=="NotIn" else g.op
        s1.append(_rule(g.field, op, g.value, negate=negate))

    # Stage 3 vuln filter: structural AND-group + evidence OR-group, inside the
    # PackageVulnerabilityInstance -> Vulnerability relation.
    # NOTE: gate 3.1 (status=Open) is enforced on the PackageVulnerabilityInstance
    # (below), not inside the Vulnerability relation, so exclude it here to avoid a
    # duplicate rule in the wrong scope.
    structural=[_rule(g.field,g.op,g.value) for g in GATES
                if g.stage=="3" and g.enforced_in=="query"
                and g.field!="PackageVulnerabilityInstanceStatus"]
    evidence=[_rule(g.field,g.op,[g.value] if not isinstance(g.value,list) else g.value)
              for g in GATES if g.stage=="3E"]
    vuln_group=_group([_group(structural,"And"), _group(evidence,"Or")],"And")

    vuln_rel={"typeName":"UdmQueryRelationRule","id":assert_guid(hexguid()),"ignored":False,
        "not":False,"relationPropertyIdentifier":"PackageVulnerabilityInstanceVulnerability",
        "ruleGroup":vuln_group}
    open_rule=_rule("PackageVulnerabilityInstanceStatus","In",["Open"])
    pkg_rel={"typeName":"UdmQueryRelationRule","id":assert_guid(hexguid()),"ignored":False,
        "not":False,"relationPropertyIdentifier":"EntityPackageVulnerabilityInstances",
        "ruleGroup":_group([_group([open_rule],"And"), vuln_rel],"And")}

    # Stage 2 endpoint-exists relation
    ep_rel={"typeName":"UdmQueryRelationRule","id":assert_guid(hexguid()),"ignored":False,
        "not":False,"relationPropertyIdentifier":"NetworkDynamicAnalysisResourceNetworkEndpoints",
        "ruleGroup":_group([],"And")}

    root=_group(s1+[ep_rel,pkg_rel],"And")
    return {"typeName":"UdmQuery","objectTypeName":ROOT_OBJECT_TYPE,"groupLevel":0,
        "collapsed":False,"objectResultHidden":False,"timeZoneId":None,"id":qid,"joins":[],
        "properties":[{"identifier":"EntityName","queryId":qid,"groupLevel":0,"aggregation":None,
                       "sort":None,"startOfWeek":None,"transform":None}],
        "ruleGroup":root}

def build_account_sizing_query():
    """SIZING -- qualifying-host count grouped per cloud account (EntityTenant).
    One cheap grouped call (validated live) returns a small result: [(account, count), ...],
    used by the per-account chunk driver to (a) enumerate accounts to pull, (b) order them,
    and (c) flag any single account too large to pull in one context (-> sub-chunk/fail loud).
    Same gate chain as build_population_query, but group-by EntityTenant with ValueCount."""
    q=build_population_query()
    qid=q["id"]
    q["groupLevel"]=1
    q["properties"]=[
        {"identifier":"EntityTenant","queryId":qid,"groupLevel":1,"aggregation":None,
         "sort":None,"startOfWeek":None,"transform":None},
        {"identifier":"EntityTenant","queryId":qid,"groupLevel":0,"aggregation":"ValueCount",
         "sort":{"direction":"Descending","ordinal":0},"startOfWeek":None,"transform":None},
    ]
    return q

# --- reusable sub-builders so the WHOLE pipeline is generated from the spec ---------
def _workload_rules(account=None):
    """Stage-1 workload rules (running + internet-direct + wide), incl. structural Stopped gate.
    If `account` is given, also scope to that tenant (EntityTenant In [account]) so the pull can
    be chunked per cloud account -- the key large-environment scaling lever for the MCP edition
    (each account is pulled in its own run/context; results merge in assemble.py). One account
    or a list of accounts is accepted."""
    out=[]
    for g in GATES:
        if g.stage!="1": continue
        out.append(_rule(g.field,("In" if g.op=="NotIn" else g.op),g.value,negate=(g.op=="NotIn")))
    if account:
        vals=account if isinstance(account,list) else [account]
        out.append(_rule("EntityTenant","In",vals))
    return out

def _vuln_relation():
    """The Stage-3 + Stage-3E vulnerability filter as a PackageVulnerabilityInstance relation.
    Reused by every pull so the qualifying logic can never differ between queries."""
    structural=[_rule(g.field,g.op,g.value) for g in GATES
                if g.stage=="3" and g.enforced_in=="query"
                and g.field!="PackageVulnerabilityInstanceStatus"]
    evidence=[_rule(g.field,g.op,[g.value] if not isinstance(g.value,list) else g.value)
              for g in GATES if g.stage=="3E"]
    vuln_group=_group([_group(structural,"And"), _group(evidence,"Or")],"And")
    vuln_rel={"typeName":"UdmQueryRelationRule","id":assert_guid(hexguid()),"ignored":False,
        "not":False,"relationPropertyIdentifier":"PackageVulnerabilityInstanceVulnerability","ruleGroup":vuln_group}
    return {"typeName":"UdmQueryRelationRule","id":assert_guid(hexguid()),"ignored":False,"not":False,
        "relationPropertyIdentifier":"EntityPackageVulnerabilityInstances",
        "ruleGroup":_group([_group([_rule("PackageVulnerabilityInstanceStatus","In",["Open"])],"And"),vuln_rel],"And")}

def _props(qid, idents):
    return [{"identifier":i,"queryId":qid,"groupLevel":0,"aggregation":None,"sort":None,
             "startOfWeek":None,"transform":None} for i in idents]

def build_inventory_query(account=None):
    """DATASET A -- one row per qualifying workload with tiering + identity fields.
    Root = IVirtualMachine (Stopped gate structurally in scope).
    `account` (optional): scope to one tenant for per-account chunked pulls."""
    validate_spec(); qid=assert_guid(hexguid())
    ep_rel={"typeName":"UdmQueryRelationRule","id":assert_guid(hexguid()),"ignored":False,"not":False,
        "relationPropertyIdentifier":"NetworkDynamicAnalysisResourceNetworkEndpoints","ruleGroup":_group([],"And")}
    root=_group(_workload_rules(account)+[ep_rel,_vuln_relation()],"And")
    return {"typeName":"UdmQuery","objectTypeName":ROOT_OBJECT_TYPE,"groupLevel":0,"collapsed":False,
        "objectResultHidden":False,"timeZoneId":None,"id":qid,"joins":[],
        "properties":_props(qid,["EntityName","EntityTypeName","EntityTenant","VirtualMachineStatus",
            "EntityAttributes","OriginatorEntityServiceIdentities"]),"ruleGroup":root}

def build_endpoints_query(account=None):
    """DATASET B -- validated listening endpoints (IP:port:protocol) for the qualifying population.
    Root = NetworkEndpoint, joined to the resource; population filter on the relation.
    `account` (optional): scope to one tenant for per-account chunked pulls.
    NOTE: status is NOT selectable here, which is exactly why the Stopped gate must also live
    on the IVirtualMachine-rooted queries and in post_filter()."""
    validate_spec(); qid=assert_guid(hexguid()); jid=assert_guid(hexguid())
    join={"typeName":"UdmQueryJoin","id":jid,"collapsed":False,"objectResultHidden":False,
        "propertyIdentifier":"NetworkEndpointNetworkDynamicAnalysisResource","type":"Inner","joins":[],
        "ruleGroup":_group([],"And")}
    # population filter (minus Stopped, which isn't in scope on this relation target)
    wl=[g for g in _workload_rules(account) if g["propertyIdentifier"]!="VirtualMachineStatus"]
    res_rel={"typeName":"UdmQueryRelationRule","id":assert_guid(hexguid()),"ignored":False,"not":False,
        "relationPropertyIdentifier":"NetworkEndpointNetworkDynamicAnalysisResource",
        "ruleGroup":_group(wl+[_vuln_relation()],"And")}
    props=_props(qid,["NetworkEndpointHost","NetworkEndpointPort","NetworkEndpointProtocolType"])
    props.append({"identifier":"EntityName","queryId":jid,"groupLevel":0,"aggregation":None,
                  "sort":None,"startOfWeek":None,"transform":None})
    return {"typeName":"UdmQuery","objectTypeName":"NetworkEndpoint","groupLevel":0,"collapsed":False,
        "objectResultHidden":False,"timeZoneId":None,"id":qid,"joins":[join],
        "properties":props,"ruleGroup":_group([res_rel],"And")}

def build_cve_query(account=None):
    """DATASET C -- per-host qualifying CVEs (with scores) for the population.
    Root = PackageVulnerabilityInstanceModel; joins expose the CVE and host.
    `account` (optional): scope to one tenant for per-account chunked pulls.
    Post-filter still applies Stage-3.4 (component<->listening-port) to these rows."""
    validate_spec(); qid=assert_guid(hexguid()); jv=assert_guid(hexguid()); je=assert_guid(hexguid())
    # vuln-side structural+evidence rules, reused verbatim
    structural=[_rule(g.field,g.op,g.value) for g in GATES
                if g.stage=="3" and g.enforced_in=="query" and g.field!="PackageVulnerabilityInstanceStatus"]
    evidence=[_rule(g.field,g.op,[g.value] if not isinstance(g.value,list) else g.value) for g in GATES if g.stage=="3E"]
    vuln_rel={"typeName":"UdmQueryRelationRule","id":assert_guid(hexguid()),"ignored":False,"not":False,
        "relationPropertyIdentifier":"PackageVulnerabilityInstanceVulnerability",
        "ruleGroup":_group([_group(structural,"And"),_group(evidence,"Or")],"And")}
    wl=[g for g in _workload_rules(account) if g["propertyIdentifier"]!="VirtualMachineStatus"]
    ent_rel={"typeName":"UdmQueryRelationRule","id":assert_guid(hexguid()),"ignored":False,"not":False,
        "relationPropertyIdentifier":"PackageVulnerabilityInstanceEntity","ruleGroup":_group(wl,"And")}
    joinV={"typeName":"UdmQueryJoin","id":jv,"collapsed":False,"objectResultHidden":False,
        "propertyIdentifier":"PackageVulnerabilityInstanceVulnerability","type":"Inner","joins":[],"ruleGroup":_group([],"And")}
    joinE={"typeName":"UdmQueryJoin","id":je,"collapsed":False,"objectResultHidden":False,
        "propertyIdentifier":"PackageVulnerabilityInstanceEntity","type":"Inner","joins":[],"ruleGroup":_group([],"And")}
    props=_props(qid,["PackageVulnerabilityInstanceStatus"])
    props+= [{"identifier":i,"queryId":jv,"groupLevel":0,"aggregation":None,"sort":None,"startOfWeek":None,"transform":None}
             for i in ["VulnerabilityCvssScore","VulnerabilityEpssScore",ALLOWED_KEV_FIELD,
                       "VulnerabilitySeverity",POC_FIELD]]
    props+= [{"identifier":i,"queryId":je,"groupLevel":0,"aggregation":None,"sort":None,"startOfWeek":None,"transform":None}
             for i in ["EntityName","EntityTypeName"]]
    root=_group([_rule("PackageVulnerabilityInstanceStatus","In",["Open"]),vuln_rel,ent_rel],"And")
    return {"typeName":"UdmQuery","objectTypeName":"PackageVulnerabilityInstanceModel","groupLevel":0,
        "collapsed":False,"objectResultHidden":False,"timeZoneId":None,"id":qid,"joins":[joinV,joinE],
        "properties":props,"ruleGroup":root}

# ----------------------------------------------------------------------------
# 4. Post-filter gates (deterministic, applied to query results) -- the safety net
# ----------------------------------------------------------------------------
# Package(component) -> the validated listening ports that make it internet-reachable.
SERVICE_PORTS = {
    "openssh-server":{22}, "openssh-sftp-server":{22},
    "apache2":{80,443}, "httpd":{80,443}, "nginx":{80,443}, "tomcat":{80,443,8080},
    "mysql-server":{3306}, "mariadb-server":{3306}, "grafana":{3000}, "redis-server":{6379},
    "windows-os":{3389,445,135,139},
}
# Components explicitly treated as NON-listening (client/local) -> never a live path.
NON_LISTENING = ("kernel","linux-","sudo","glibc","libc","telnet","thunderbird","curl",
                 "libcurl","bind9","libgnutls","openssl","libssl","-client","apt","python",
                 "grub","cpio","coreutils","open-vm-tools","expat","sqlite")

def component_is_listening(pkg:str)->bool:
    p=pkg.lower()
    if p.startswith("windows"): return True   # Windows OS network services (RDP/SMB/RPC/WSUS)
    if any(tok in p for tok in NON_LISTENING): return False
    return any(p.startswith(k) or k in p for k in
               ("openssh-server","openssh-sftp","apache2","httpd","nginx","tomcat",
                "mysql-server","mariadb-server","grafana","redis-server"))

def service_key(pkg:str):
    p=pkg.lower()
    if p.startswith("openssh"): return "openssh-server"
    if p.startswith("windows"): return "windows-os"   # 'Windows Server 2016/2019/2022', 'Windows OS', etc.
    for k in ("apache2","httpd","nginx","tomcat","mysql-server","mariadb-server","grafana","redis-server"):
        if k in p: return k
    return None

def post_filter(match, host_status:str, validated_ports:set, require_port:bool=True):
    """Stage 1.1 re-check + Stage 3.4 component<->port correlation. Returns (kept, reason).

    require_port=True  (default, MCP edition): full gate 8 -- the component must be a
        listening service AND an observed endpoint must expose one of its ports.
    require_port=False (reduced/API edition, which has no observed endpoints): degrade
        gate 8 to the listening-component test ONLY -- keep sshd/nginx/etc., still drop
        clients/libs (Thunderbird, libgnutls, kernel, ...). This is weaker (it cannot
        confirm the service is actually reachable on a port) and MUST be labeled reduced.
    """
    if (host_status or "").lower()=="stopped":
        return (False, "host is Stopped (post-filter safety net)")
    sk=service_key(match["component"])
    if sk is None or not component_is_listening(match["component"]):
        return (False, f"component '{match['component']}' is not an internet-listening service")
    if not require_port:
        return (True, f"listening component: {sk} (reduced: no observed-port correlation)")
    need=SERVICE_PORTS.get(sk,set())
    if not (validated_ports & need):
        return (False, f"service {sk} needs {sorted(need)}; host exposes {sorted(validated_ports)}")
    return (True, f"reachable: {sk} on {sorted(validated_ports & need)}")

# ----------------------------------------------------------------------------
# 5. CVE-age proxy (fail-open: never excludes; only annotates / escalates)
# ----------------------------------------------------------------------------
def cve_year(vuln_id:str):
    m=re.match(r"^CVE-(\d{4})-\d+$", (vuln_id or "").upper())
    return int(m.group(1)) if m else None   # None for DLS-/USN-/GHSA- etc. -> "Unknown"

def age_label(vuln_id:str, current_year=2026):
    y=cve_year(vuln_id)
    if y is None: return ("Unknown","")           # non-CVE IDs: shown as '-', never filtered
    return (str(y), "recent" if current_year-y<=2 else "")

# ----------------------------------------------------------------------------
# Self-tests -- fail loudly if any invariant regresses
# ----------------------------------------------------------------------------
def _selftests():
    validate_spec()
    q=build_population_query()
    assert q["objectTypeName"]=="IVirtualMachine"
    blob=json.dumps(q)
    for bad in REJECTED_SIGNALS: assert bad not in blob, f"rejected signal {bad} leaked into query"
    assert POC_FIELD not in blob, "PoC must not be in the qualifying query"
    assert "VirtualMachineStatus" in blob, "Stopped gate missing"
    # every GUID valid hex
    def walk(o):
        if isinstance(o,dict):
            if "id" in o and isinstance(o["id"],str): assert_guid(o["id"])
            for v in o.values(): walk(v)
        elif isinstance(o,list):
            for v in o: walk(v)
    walk(q)
    # component/port correlation behaves
    assert component_is_listening("nginx-core") is True
    assert component_is_listening("openssh-client") is False
    assert component_is_listening("linux-modules-gcp") is False
    assert component_is_listening("Windows Server 2016") is True    # regression guard
    assert service_key("Windows Server 2022")=="windows-os"          # regression guard
    assert post_filter({"component":"apache2"},"Running",{22})[0] is False   # apache needs 80/443
    assert post_filter({"component":"apache2"},"Running",{80})[0] is True
    assert post_filter({"component":"Windows Server 2016"},"Running",{3389})[0] is True  # RDP-exposed Windows
    assert post_filter({"component":"Windows Server 2016"},"Running",{22})[0] is False   # no RDP => not reachable
    assert post_filter({"component":"openssh-server"},"Stopped",{22})[0] is False
    # reduced mode (require_port=False, API edition: no observed ports available):
    assert post_filter({"component":"apache2"},"Running",set(),require_port=False)[0] is True   # listening-class kept w/o port
    assert post_filter({"component":"thunderbird"},"Running",set(),require_port=False)[0] is False  # client still dropped
    assert post_filter({"component":"libgnutls30"},"Running",set(),require_port=False)[0] is False  # lib still dropped
    assert post_filter({"component":"apache2"},"Stopped",set(),require_port=False)[0] is False  # stopped net still enforced
    # age proxy fail-open
    assert age_label("CVE-2023-38408")[0]=="2023"
    assert age_label("DLS-2761-1")==("Unknown","")     # non-CVE: never filtered
    assert age_label("CVE-2026-41089")[1]=="recent"
    # Rejected/PoC signals may appear as DISPLAY properties, but never as a FILTER RULE.
    def rule_fields(o):
        out=set()
        if isinstance(o,dict):
            if o.get("typeName")=="UdmQueryRule" and "propertyIdentifier" in o: out.add(o["propertyIdentifier"])
            for v in o.values(): out|=rule_fields(v)
        elif isinstance(o,list):
            for v in o: out|=rule_fields(v)
        return out
    for builder in (build_inventory_query, build_endpoints_query, build_cve_query):
        qq=builder(); walk(qq); rf=rule_fields(qq["ruleGroup"])
        for bad in REJECTED_SIGNALS:
            assert bad not in rf, f"{builder.__name__}: rejected signal {bad} used as a FILTER RULE"
        assert POC_FIELD not in rf, f"{builder.__name__}: PoC used as a filter rule"
    # endpoint query must NOT carry a Stopped rule (not in scope there) but inventory MUST
    assert "VirtualMachineStatus" in json.dumps(build_inventory_query())
    assert "VirtualMachineStatus" not in json.dumps(build_endpoints_query()["ruleGroup"])
    # per-account chunk scoping: EntityTenant rule present iff account passed, on all 3 builders
    for builder in (build_inventory_query, build_endpoints_query, build_cve_query):
        assert "EntityTenant" not in rule_fields(builder()["ruleGroup"]), \
            f"{builder.__name__}: EntityTenant leaked into unscoped query"
        scoped=builder(account="123456789012")
        assert "EntityTenant" in rule_fields(scoped["ruleGroup"]), \
            f"{builder.__name__}: account scope not applied"
        assert "123456789012" in json.dumps(scoped["ruleGroup"])
        walk(scoped)  # scoped queries must still have valid GUIDs / no rejected signals
    # sizing query is a valid grouped count over EntityTenant
    sz=build_account_sizing_query(); assert sz["groupLevel"]==1
    assert any(p.get("aggregation")=="ValueCount" for p in sz["properties"])
    print("ALL SELF-TESTS PASSED")
    return q

if __name__=="__main__":
    q=_selftests()
    print("\n--- gate order ---")
    for g in GATES:
        print(f"  [{g.gid:4}] stage {g.stage:2} ({g.enforced_in:5}) {g.plain}")
    print("\n--- generated population query (paste-ready for udm_get_query_results_count) ---")
    print(json.dumps(q))
