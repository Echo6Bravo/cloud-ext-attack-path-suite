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

import json
import re
import sys
import uuid

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

def build_account_sizing_query(by="region"):
    """SIZING -- qualifying CVE-ROW count grouped per cloud account (and optionally region).

    Rooted on PackageVulnerabilityInstanceModel and grouped on the joined EntityTenant, so it
    counts the QUALIFYING CVE ROWS (dataset C) -- the quantity that actually drives the pull
    volume / context cost -- NOT host count (a low-host account can still have thousands of
    CVE rows; validated live: 13 hosts -> 663 rows). One cheap grouped call returns a small
    result [(account, cve_row_count), ...] used by plan_chunks() to pick tenant/account/region.

    by="region" also groups by EntityRegion (two group dimensions) so an oversized account can
    be split by region without a second query; by="account" groups by account only.
    """
    q=build_cve_query()
    je=next(j["id"] for j in q["joins"] if j["propertyIdentifier"]=="PackageVulnerabilityInstanceEntity")
    q["groupLevel"]=1
    props=[{"identifier":"EntityTenant","queryId":je,"groupLevel":1,"aggregation":None,
            "sort":None,"startOfWeek":None,"transform":None}]
    if by=="region":
        props.append({"identifier":"EntityRegion","queryId":je,"groupLevel":1,"aggregation":None,
                      "sort":None,"startOfWeek":None,"transform":None})
    props.append({"identifier":"EntityTenant","queryId":je,"groupLevel":0,"aggregation":"ValueCount",
                  "sort":{"direction":"Descending","ordinal":0},"startOfWeek":None,"transform":None})
    q["properties"]=props
    return q

# Rows-per-run budget: the max qualifying CVE rows to pull in ONE model context/run. Each row
# is a small object; ~4-6k rows is a conservative ceiling that leaves context headroom for the
# query echo, tool schemas, and assembly reasoning. Tune per model/context window if needed.
ROWS_PER_RUN = 4000

def plan_chunks(account_sizes, region_sizes=None, budget=ROWS_PER_RUN):
    """Deterministically choose the pull strategy from measured CVE-row counts.

    account_sizes: {account_id: cve_row_count}   (from build_account_sizing_query(by="account"))
    region_sizes:  {(account_id, region): count}  (optional; from by="region") -- used to split
                   accounts that individually exceed the budget.
    budget: max CVE rows per single run/context.

    Returns a dict:
      {"mode": "tenant"|"account"|"region",
       "chunks": [ {"scope":"tenant"} ] | [ {"account":id}, ... ]
                 | [ {"account":id}, {"account":id,"region":r}, ... ],
       "oversized": [ list of scopes still over budget after region split -> caller must
                      narrow further or accept truncation, and MUST surface this, never silent ] }

    Rules (in order):
      * total <= budget                      -> one tenant run (cheapest; no per-run overhead x N)
      * every account <= budget              -> one run per account
      * some account > budget                -> that account split by region; regions still
                                                 over budget are reported as "oversized"
    """
    total=sum(account_sizes.values())
    if total<=budget:
        return {"mode":"tenant","chunks":[{"scope":"tenant"}],"oversized":[]}
    big=[a for a,c in account_sizes.items() if c>budget]
    if not big:
        chunks=[{"account":a} for a,_ in sorted(account_sizes.items(),key=lambda kv:-kv[1])]
        return {"mode":"account","chunks":chunks,"oversized":[]}
    # at least one account is over budget -> region-split those; keep others whole
    chunks=[]; oversized=[]
    for a,c in sorted(account_sizes.items(),key=lambda kv:-kv[1]):
        if c<=budget:
            chunks.append({"account":a}); continue
        if not region_sizes:
            oversized.append({"account":a,"count":c,"why":"account over budget; no region_sizes provided to split"})
            chunks.append({"account":a}); continue
        for (_ra,region),rc in sorted(((k,v) for k,v in region_sizes.items() if k[0]==a),key=lambda kv:-kv[1]):
            chunks.append({"account":a,"region":region})
            if rc>budget:
                oversized.append({"account":a,"region":region,"count":rc,
                                  "why":"region still over budget; narrow further (e.g. by severity window) or accept truncation"})
    return {"mode":"region","chunks":chunks,"oversized":oversized}

# ----------------------------------------------------------------------------
# 2b. Schema-drift canary
# ----------------------------------------------------------------------------
# Every UDM field the generated queries depend on, grouped by the object type it must exist
# on. If Tenable renames/removes a field, a query would silently return empty (or error);
# check_schema() compares this against live metadata (udm_get_object_type_metadata) so the
# agent can FAIL LOUD with a precise "field X missing on type Y" instead of shipping an empty
# report. Keep this in sync with the build_* functions -- the self-tests assert it covers
# exactly the fields the queries reference, so it can't silently fall behind.
REQUIRED_FIELDS = {
    "IVirtualMachine": {
        "VirtualMachineStatus","EntityNetworkAccessType","EntityNetworkAccessScope",
        "NetworkDynamicAnalysisResourceNetworkEndpoints","EntityPackageVulnerabilityInstances",
        "EntityName","EntityTypeName","EntityTenant","EntityAttributes",
        "OriginatorEntityServiceIdentities","EntityRegion",
    },
    "NetworkEndpoint": {
        "NetworkEndpointHost","NetworkEndpointPort","NetworkEndpointProtocolType",
        "NetworkEndpointNetworkDynamicAnalysisResource",
    },
    "PackageVulnerabilityInstanceModel": {
        "PackageVulnerabilityInstanceStatus","PackageVulnerabilityInstanceVulnerability",
        "PackageVulnerabilityInstanceEntity",
    },
    "Vulnerability": {
        "VulnerabilityAttackVector","VulnerabilityAttackComplexity","VulnerabilityEpssScore",
        ALLOWED_KEV_FIELD,"VulnerabilityCvssScore","VulnerabilitySeverity",POC_FIELD,
    },
}

def parse_metadata_identifiers(md):
    """Extract the set of property identifiers from one udm_get_object_type_metadata result.
    Accepts either the raw markdown table string that the MCP tool returns, or a pre-parsed
    list of identifier strings / list of dicts with an 'Identifier'/'identifier' key."""
    ids=set()
    if md is None: return ids
    if isinstance(md, str):
        for line in md.splitlines():
            line=line.strip()
            if not line.startswith("|"): continue
            cell=line.strip("|").split("|",1)[0].strip()
            # skip the header row and separator row
            if not cell or cell in ("Identifier",) or set(cell)<=set("-: "): continue
            ids.add(cell)
        return ids
    if isinstance(md, (list,tuple,set)):
        for x in md:
            if isinstance(x,str): ids.add(x)
            elif isinstance(x,dict):
                v=x.get("Identifier") or x.get("identifier")
                if v: ids.add(v)
    return ids

def check_schema(metadata_by_type):
    """Compare REQUIRED_FIELDS against live metadata. `metadata_by_type` maps object-type name
    -> whatever udm_get_object_type_metadata returned for it (markdown or parsed). Returns
    {"ok":bool, "missing":[{type,field}], "unchecked":[types not supplied]}. The caller (agent
    or --schema-check) fails loud on any missing field rather than emitting an empty report."""
    missing=[]; unchecked=[]
    for typ, fields in REQUIRED_FIELDS.items():
        if typ not in metadata_by_type or metadata_by_type[typ] is None:
            unchecked.append(typ); continue
        have=parse_metadata_identifiers(metadata_by_type[typ])
        for f in sorted(fields):
            if f not in have:
                missing.append({"type":typ,"field":f})
    return {"ok": not missing, "missing":missing, "unchecked":unchecked}

# --- reusable sub-builders so the WHOLE pipeline is generated from the spec ---------
def _workload_rules(account=None, region=None):
    """Stage-1 workload rules (running + internet-direct + wide), incl. structural Stopped gate.
    If `account` is given, also scope to that tenant (EntityTenant In [account]) so the pull can
    be chunked per cloud account -- the key large-environment scaling lever for the MCP edition
    (each account is pulled in its own run/context; results merge in assemble.py). `region`
    (EntityRegion In [region]) further sub-chunks an account too large to fit one context.
    Each accepts a single value or a list."""
    out=[]
    for g in GATES:
        if g.stage!="1": continue
        out.append(_rule(g.field,("In" if g.op=="NotIn" else g.op),g.value,negate=(g.op=="NotIn")))
    if account:
        out.append(_rule("EntityTenant","In",account if isinstance(account,list) else [account]))
    if region:
        out.append(_rule("EntityRegion","In",region if isinstance(region,list) else [region]))
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

def build_inventory_query(account=None, region=None):
    """DATASET A -- one row per qualifying workload with tiering + identity fields.
    Root = IVirtualMachine (Stopped gate structurally in scope).
    `account` (optional): scope to one tenant for per-account chunked pulls."""
    validate_spec(); qid=assert_guid(hexguid())
    ep_rel={"typeName":"UdmQueryRelationRule","id":assert_guid(hexguid()),"ignored":False,"not":False,
        "relationPropertyIdentifier":"NetworkDynamicAnalysisResourceNetworkEndpoints","ruleGroup":_group([],"And")}
    root=_group(_workload_rules(account, region)+[ep_rel,_vuln_relation()],"And")
    return {"typeName":"UdmQuery","objectTypeName":ROOT_OBJECT_TYPE,"groupLevel":0,"collapsed":False,
        "objectResultHidden":False,"timeZoneId":None,"id":qid,"joins":[],
        "properties":_props(qid,["EntityName","EntityTypeName","EntityTenant","VirtualMachineStatus",
            "EntityAttributes","OriginatorEntityServiceIdentities"]),"ruleGroup":root}

def build_endpoints_query(account=None, region=None):
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
    wl=[g for g in _workload_rules(account, region) if g["propertyIdentifier"]!="VirtualMachineStatus"]
    res_rel={"typeName":"UdmQueryRelationRule","id":assert_guid(hexguid()),"ignored":False,"not":False,
        "relationPropertyIdentifier":"NetworkEndpointNetworkDynamicAnalysisResource",
        "ruleGroup":_group(wl+[_vuln_relation()],"And")}
    props=_props(qid,["NetworkEndpointHost","NetworkEndpointPort","NetworkEndpointProtocolType"])
    props.append({"identifier":"EntityName","queryId":jid,"groupLevel":0,"aggregation":None,
                  "sort":None,"startOfWeek":None,"transform":None})
    return {"typeName":"UdmQuery","objectTypeName":"NetworkEndpoint","groupLevel":0,"collapsed":False,
        "objectResultHidden":False,"timeZoneId":None,"id":qid,"joins":[join],
        "properties":props,"ruleGroup":_group([res_rel],"And")}

def build_cve_query(account=None, region=None):
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
    wl=[g for g in _workload_rules(account, region) if g["propertyIdentifier"]!="VirtualMachineStatus"]
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
# This is a KEEP-list of known internet-facing services and their default listening ports.
# Aliases (distro/version variants) are resolved to these keys by service_key().
# IMPORTANT: this list is necessarily incomplete; a component that is NEITHER here NOR in
# NON_LISTENING is NOT silently dropped -- it is surfaced for review (see post_filter).
SERVICE_PORTS = {
    # remote access
    "openssh-server":{22}, "openssh-sftp-server":{22},
    # web / app servers
    "apache2":{80,443}, "httpd":{80,443}, "nginx":{80,443}, "tomcat":{80,443,8080},
    "haproxy":{80,443}, "lighttpd":{80,443}, "caddy":{80,443}, "envoy":{80,443,10000},
    "php-fpm":{80,443}, "gunicorn":{80,443,8000}, "node":{80,443,3000,8080},
    # databases / caches
    "mysql-server":{3306}, "mariadb-server":{3306}, "postgresql":{5432},
    "mongodb":{27017,27018}, "redis-server":{6379}, "memcached":{11211},
    "elasticsearch":{9200,9300}, "opensearch":{9200,9300}, "cassandra":{9042},
    "couchdb":{5984}, "influxdb":{8086}, "mssql-server":{1433}, "oracle-db":{1521},
    # message queues / streaming
    "rabbitmq-server":{5672,15672}, "kafka":{9092}, "activemq":{61616,8161},
    # dirs / auth / mail / dns / ftp
    "slapd":{389,636}, "bind":{53}, "named":{53}, "unbound":{53},
    "postfix":{25,587,465}, "exim4":{25,587}, "sendmail":{25}, "dovecot":{110,143,993,995},
    "vsftpd":{21}, "proftpd":{21}, "pure-ftpd":{21},
    # infra / mgmt / observability (frequently exposed, high-value)
    "docker":{2375,2376}, "dockerd":{2375,2376}, "kubelet":{10250}, "kube-apiserver":{6443},
    "etcd":{2379,2380}, "consul":{8500}, "grafana":{3000}, "prometheus":{9090},
    "kibana":{5601}, "jenkins":{8080}, "gitlab":{80,443}, "samba":{445,139},
    # windows network services (RDP/SMB/RPC/WSUS/WinRM)
    "windows-os":{3389,445,135,139,5985,5986,8530,8531},
}
# Alias fragments -> canonical SERVICE_PORTS key. Matched as substrings (case-insensitive)
# so distro/version variants resolve: 'postgresql-14' -> postgresql, 'mongodb-org-server' ->
# mongodb, 'apache2-bin' -> apache2, 'openssh-server' -> openssh-server, etc.
SERVICE_ALIASES = {
    "openssh":"openssh-server", "sshd":"openssh-server",
    "apache2":"apache2", "apache-":"httpd", "httpd":"httpd", "nginx":"nginx", "tomcat":"tomcat",
    "haproxy":"haproxy", "lighttpd":"lighttpd", "caddy":"caddy", "envoy":"envoy",
    "php-fpm":"php-fpm", "php7":"php-fpm", "php8":"php-fpm", "gunicorn":"gunicorn",
    "nodejs":"node", "node-":"node",
    "mysql":"mysql-server", "mariadb":"mariadb-server", "postgresql":"postgresql", "postgres":"postgresql",
    "mongodb":"mongodb", "mongo-":"mongodb", "redis":"redis-server", "memcached":"memcached",
    "elasticsearch":"elasticsearch", "opensearch":"opensearch", "cassandra":"cassandra",
    "couchdb":"couchdb", "influxdb":"influxdb", "mssql":"mssql-server", "sqlserver":"mssql-server",
    "rabbitmq":"rabbitmq-server", "kafka":"kafka", "activemq":"activemq",
    "slapd":"slapd", "openldap":"slapd", "bind9":"bind", "bind-":"bind", "named":"named", "unbound":"unbound",
    "postfix":"postfix", "exim":"exim4", "sendmail":"sendmail", "dovecot":"dovecot",
    "vsftpd":"vsftpd", "proftpd":"proftpd", "pure-ftpd":"pure-ftpd",
    "docker":"docker", "dockerd":"dockerd", "containerd":"docker",
    "kubelet":"kubelet", "kube-apiserver":"kube-apiserver", "apiserver":"kube-apiserver",
    "etcd":"etcd", "consul":"consul", "grafana":"grafana", "prometheus":"prometheus",
    "kibana":"kibana", "jenkins":"jenkins", "gitlab":"gitlab", "samba":"samba", "smbd":"samba",
    "windows":"windows-os",
}
# Components explicitly treated as NON-listening (client / library / local tool / OS
# component) -> never a live network path, even on an exposed host. NOTE: entries must be
# genuine non-services -- do NOT list server packages here (this is why 'bind9' was REMOVED:
# bind9 is the BIND DNS *server*, now correctly in SERVICE_PORTS).
NON_LISTENING = ("kernel","linux-","linux-image","linux-headers","sudo","glibc","libc6",
                 "telnet-client","thunderbird","firefox","chromium","curl","wget",
                 "libcurl","libgnutls","openssl","libssl","libxml","zlib","libpng","libjpeg",
                 "-client","apt","dpkg","rpm","yum","dnf","python2","python3","perl","ruby",
                 "grub","cpio","coreutils","util-linux","open-vm-tools","expat","sqlite",
                 "tar","gzip","bzip2","xz-utils","bash","dash","tzdata","ca-certificates",
                 "gnupg","less","vim","nano","git","binutils","gcc","make")

def _tokens(p:str):
    # split a package name into tokens on common separators so we match whole tokens, not
    # substrings -- prevents 'tar' matching 'proprietary', 'git' matching 'digital', etc.
    return set(re.split(r"[-_/.\s]+", p.lower()))

def _tok_match(marker:str, toks:set)->bool:
    """A marker matches a token if the token equals the marker OR starts with it (so 'libgnutls'
    matches token 'libgnutls30', 'python' matches 'python3'). No middle-substring matches."""
    return any(t==marker or t.startswith(marker) for t in toks)

def _prefix_marker_match(marker:str, toks:set)->bool:
    """For markers written with a trailing/leading '-' (e.g. 'node-', 'linux-', '-client'):
    anchor to a TOKEN so 'node-' matches token 'node' but NOT 'anode'. Trailing '-foo' means
    'a token equal to foo' (suffix sub-package); leading 'foo-' means 'a token starting foo'."""
    core=marker.strip("-")
    if marker.endswith("-"):      # e.g. 'linux-','mongo-','node-' : token == core or startswith core
        return any(t==core or t.startswith(core) for t in toks)
    if marker.startswith("-"):    # e.g. '-client' : some token equals the core
        return core in toks
    return False

def _matches_nonlistening(p:str)->bool:
    """True iff a NON_LISTENING marker matches on a token boundary. Markers with a leading/
    trailing '-' keep bounded-substring semantics ('-client', 'linux-'); others match a whole
    token or token-prefix. Rejects middle-substring false positives ('tar' in 'proprietary')."""
    p=p.lower(); toks=_tokens(p)
    for m in NON_LISTENING:
        if m.startswith("-") or m.endswith("-"):
            if _prefix_marker_match(m, toks): return True
        elif _tok_match(m, toks):
            return True
    return False

def service_key(pkg:str):
    """Resolve a package/component name to a canonical SERVICE_PORTS key, or None if unknown.
    Matches alias fragments on TOKEN boundaries (not raw substring) so 'node' does not match
    'anode' etc. Fragments ending in '-' keep prefix semantics ('mongo-' matches 'mongo-tools')."""
    p=(pkg or "").lower()
    if p.startswith("windows"): return "windows-os"   # 'Windows Server 2016/2019/2022', 'Windows OS'
    toks=_tokens(p)
    # longest alias fragment first so 'openssh-server' beats a shorter match
    for frag in sorted(SERVICE_ALIASES, key=len, reverse=True):
        if frag.endswith("-"):
            if _prefix_marker_match(frag, toks): return SERVICE_ALIASES[frag]  # e.g. 'mongo-','node-'
        elif _tok_match(frag, toks):                         # whole token or token-prefix only
            return SERVICE_ALIASES[frag]
    return None

def component_is_listening(pkg:str)->bool:
    """True iff the component classifies as a known internet-facing service (respects the
    non-service sub-package/library precedence, so 'openssh-client' is False)."""
    return classify_component(pkg)[0]=="service"

# Sub-package suffixes that mean "not the running service" even when the name contains a
# service token: e.g. 'openssh-client', 'postgresql-client', 'mysql-common', 'nginx-doc'.
# These are client/support sub-packages, not the listening daemon.
NONSERVICE_SUFFIXES = ("-client","-clients","-common","-doc","-dev","-devel","-libs","-lib",
                       "-data","-utils","-dbg","-test","-docs")

def classify_component(pkg:str):
    """Return ('service'|'nonlistening'|'unknown', service_key_or_None). Single source for the
    keep/drop/review decision so callers and self-tests share one taxonomy.

    Order matters: an explicit non-service SUB-PACKAGE suffix (-client/-common/-doc/...) or a
    known non-service token is checked BEFORE the service-alias match, so 'openssh-client'
    and 'postgresql-client' are correctly non-listening rather than mistaken for their daemon."""
    p=(pkg or "").lower()
    if any(p.endswith(sfx) or (sfx+".") in p or (sfx+"-") in p for sfx in NONSERVICE_SUFFIXES):
        return ("nonlistening", None)     # client/support sub-package, not the daemon
    if _matches_nonlistening(p):          # known non-service (library/tool/OS component)
        return ("nonlistening", None)
    sk=service_key(p)
    if sk is not None:                    # known listening service
        return ("service", sk)
    return ("unknown", None)              # neither -> must be surfaced, never silently dropped

def post_filter(match, host_status:str, validated_ports:set, require_port:bool=True):
    """Stage 1.1 re-check + Stage 3.4 component<->port correlation.
    Returns (status, reason) where status is one of:
      'keep'   -- a known listening service whose port is observed exposed (a real path).
      'review' -- a vulnerable component we could NOT map to a known service or a known
                  non-service: it must be SURFACED for manual review, never silently dropped
                  (this is the anti-false-negative safeguard). Also used for a known service
                  in reduced/no-port mode where reachability can't be confirmed.
      'drop'   -- a known non-service (library/client/kernel/tool), a stopped host, or a
                  known service whose listening port is NOT observed exposed.

    require_port=True (MCP edition): full gate 8 (service AND observed port).
    require_port=False (reduced/API edition, no observed endpoints): can't correlate ports,
        so known services and unknowns both become 'review'; non-services still 'drop'.

    Back-compat: bool(status=='keep') preserves the old truthy 'kept' meaning for callers
    that do `if not keep`. Prefer checking the string.
    """
    if (host_status or "").lower()=="stopped":
        return ("drop", "host is Stopped (post-filter safety net)")
    kind, sk = classify_component(match.get("component"))
    if kind=="nonlistening":
        return ("drop", f"component '{match.get('component')}' is a client/library/local tool, not a network service")
    if kind=="unknown":
        return ("review", f"component '{match.get('component')}' is not in the known-service map "
                          f"and not a known non-service -- SURFACED for manual review (possible coverage gap)")
    # kind == "service"
    if not require_port:
        return ("review", f"listening service '{sk}' but no observed-port data (reduced mode) -- reachability unconfirmed")
    need=SERVICE_PORTS.get(sk,set())
    if not (validated_ports & need):
        return ("drop", f"service {sk} listens on {sorted(need)} but host exposes {sorted(validated_ports)} -- not reachable")
    return ("keep", f"reachable: {sk} on {sorted(validated_ports & need)}")

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
    # --- component/port correlation: three-way keep/review/drop contract ---
    def pf(comp,ports,**kw): return post_filter({"component":comp},"Running",ports,**kw)[0]
    # known services with their port observed -> keep
    assert pf("nginx-core",{443})=="keep"
    assert pf("apache2",{80})=="keep"
    assert pf("Windows Server 2016",{3389})=="keep"          # regression guard (windows)
    assert service_key("Windows Server 2022")=="windows-os"   # regression guard
    # known service, WRONG port observed -> drop (not reachable), not review
    assert pf("apache2",{22})=="drop"                         # apache needs 80/443
    assert pf("Windows Server 2016",{22})=="drop"
    # clients / libraries / local tools -> drop (correctly excluded, no noise)
    assert pf("openssh-client",{22})=="drop"
    assert pf("linux-modules-gcp",{22})=="drop"
    assert pf("thunderbird",{443})=="drop"
    assert pf("libgnutls30",{443})=="drop"
    # stopped host -> drop regardless
    assert post_filter({"component":"openssh-server"},"Stopped",{22})[0]=="drop"
    # ANTI-FALSE-NEGATIVE regressions: previously-silently-dropped exposed services must now
    # be KEPT (mapped) -- these are the exact gaps found in the coverage audit.
    assert pf("postgresql-14",{5432})=="keep"
    assert pf("mongodb-org-server",{27017})=="keep"
    assert pf("redis-server",{6379})=="keep"
    assert pf("elasticsearch",{9200})=="keep"
    assert pf("docker-ce",{2375})=="keep"
    assert pf("kubelet",{10250})=="keep"
    assert pf("vsftpd",{21})=="keep"
    assert pf("postfix",{25})=="keep"
    assert pf("bind9",{53})=="keep"    # bind9 is the DNS SERVER -- was wrongly in NON_LISTENING
    # unknown component on an exposed host -> REVIEW (surfaced, never silently dropped)
    assert pf("some-inhouse-daemon",{8443})=="review"
    assert pf("acme-proprietary-broker",{9999})=="review"
    # reduced mode (require_port=False): services + unknowns -> review; non-services -> drop
    assert pf("apache2",set(),require_port=False)=="review"       # can't confirm port
    assert pf("some-inhouse-daemon",set(),require_port=False)=="review"
    assert pf("thunderbird",set(),require_port=False)=="drop"      # client still dropped
    assert post_filter({"component":"apache2"},"Stopped",set(),require_port=False)[0]=="drop"
    # classify_component taxonomy is self-consistent
    assert classify_component("nginx")[0]=="service"
    assert classify_component("curl")[0]=="nonlistening"
    assert classify_component("mystery-svc")[0]=="unknown"
    # token-boundary matching: middle-substring must NOT false-match (regression guards for the
    # bugs the coverage audit found -- 'tar' in 'proprietary', 'node' in 'anode', 'git' in 'digital')
    assert classify_component("acme-proprietary-broker")[0]=="unknown"   # not 'tar'
    assert classify_component("anode-agent")[0]=="unknown"               # not 'node'
    assert classify_component("digital-signer")[0]=="unknown"            # not 'git'
    assert classify_component("libgnutls30")[0]=="nonlistening"          # token-prefix still works
    assert classify_component("python3")[0]=="nonlistening"
    assert classify_component("postgresql-client")[0]=="nonlistening"    # -client sub-pkg, not daemon
    assert classify_component("nodejs")==("service","node")              # real node still maps
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
    # sizing query is a valid grouped CVE-row count (rooted on the vuln instance, not the VM)
    sz=build_account_sizing_query(); assert sz["groupLevel"]==1
    assert sz["objectTypeName"]=="PackageVulnerabilityInstanceModel"   # counts CVE ROWS, not hosts
    assert any(p.get("aggregation")=="ValueCount" for p in sz["properties"])
    assert "EntityRegion" in json.dumps(sz["properties"])              # by="region" default
    assert "EntityRegion" not in json.dumps(build_account_sizing_query(by="account")["properties"])
    # region scoping on the pull builders
    rq=build_cve_query(account="a1",region="us-east-1")
    assert "EntityRegion" in rule_fields(rq["ruleGroup"]) and "us-east-1" in json.dumps(rq["ruleGroup"])
    assert "EntityRegion" not in rule_fields(build_cve_query(account="a1")["ruleGroup"])
    # plan_chunks: deterministic tenant/account/region selection + loud oversized reporting
    small={"a":10,"b":20}
    assert plan_chunks(small,budget=100)["mode"]=="tenant"
    mid={"a":300,"b":250}
    assert plan_chunks(mid,budget=400)["mode"]=="account" and len(plan_chunks(mid,budget=400)["chunks"])==2
    big={"a":900,"b":50}
    p=plan_chunks(big,budget=400)                       # 'a' over budget, no region info
    assert p["mode"]=="region" and p["oversized"] and p["oversized"][0]["account"]=="a"
    p2=plan_chunks(big,region_sizes={("a","r1"):350,("a","r2"):350},budget=400)
    assert p2["oversized"]==[]                            # region split resolves it
    p3=plan_chunks(big,region_sizes={("a","r1"):900},budget=400)
    assert p3["oversized"] and "narrow further" in p3["oversized"][0]["why"]  # still-too-big flagged
    # --- schema-drift canary ---
    # REQUIRED_FIELDS must cover EXACTLY the query-referenced fields (minus EntityRegion, used
    # only for optional region chunking) so the canary can't silently fall behind the queries.
    referenced=set()
    def _walk(o):
        if isinstance(o,dict):
            for k in ("propertyIdentifier","relationPropertyIdentifier"):
                if isinstance(o.get(k),str): referenced.add(o[k])
            if isinstance(o.get("identifier"),str) and o.get("queryId"): referenced.add(o["identifier"])
            for v in o.values(): _walk(v)
        elif isinstance(o,list):
            for v in o: _walk(v)
    for b in (build_population_query,build_inventory_query,build_endpoints_query,build_cve_query): _walk(b())
    declared=set().union(*REQUIRED_FIELDS.values())
    missing_from_canary=referenced - declared
    assert not missing_from_canary, f"REQUIRED_FIELDS missing query fields: {missing_from_canary}"
    # parse_metadata_identifiers handles the markdown-table shape the MCP tool returns
    md="|Identifier|Title|DataType|Relation|\n|---|---|---|---|\n|VirtualMachineStatus|Status|CommonEnum|null|\n|EntityName|Name|InfraString|null|"
    ids=parse_metadata_identifiers(md); assert "VirtualMachineStatus" in ids and "Identifier" not in ids
    # check_schema: all present -> ok; a renamed field -> loud miss; missing type -> unchecked
    full={t:list(f) for t,f in REQUIRED_FIELDS.items()}
    assert check_schema(full)["ok"] is True
    drift=dict(full); drift["IVirtualMachine"]=[x for x in full["IVirtualMachine"] if x!="VirtualMachineStatus"]
    r=check_schema(drift); assert r["ok"] is False and any(m["field"]=="VirtualMachineStatus" for m in r["missing"])
    assert "Vulnerability" in check_schema({"IVirtualMachine":full["IVirtualMachine"]})["unchecked"]
    print("ALL SELF-TESTS PASSED")
    return q

def _cli_plan(argv):
    """`python3 attack_path_spec.py plan <sizes.json> [budget]` -> deterministic chunk plan (JSON).

    sizes.json: {"accounts": {"<id>": <cve_row_count>, ...},
                 "regions": {"<id>|<region>": <count>, ...}   # optional, for oversized accounts
                }  -- produced by running build_account_sizing_query() and tallying results.
    Prints the plan_chunks() result as JSON for the shell driver to consume.
    """
    def _die(msg):
        sys.stderr.write(f"attack_path_spec plan: ERROR: {msg}\n")
        sys.stderr.write("usage: attack_path_spec.py plan <sizes.json> [budget] [--tsv]\n")
        sys.exit(2)
    if not argv or argv[0].startswith("-"):
        _die("missing <sizes.json> path argument")
    path=argv[0]
    budget=ROWS_PER_RUN
    if len(argv)>1 and not argv[1].startswith("-"):
        try: budget=int(argv[1])
        except ValueError: _die(f"budget must be an integer, got {argv[1]!r}")
    try:
        with open(path) as _f: data=json.load(_f)
    except FileNotFoundError:
        _die(f"sizes file not found: {path}")
    except (OSError, ValueError) as e:
        _die(f"cannot read/parse sizes file {path}: {e}")
    if not isinstance(data, dict):
        _die('sizes file must be a JSON object with an "accounts" key')
    try:
        accounts={str(k):int(v) for k,v in (data.get("accounts") or {}).items()}
    except (TypeError, ValueError) as e:
        _die(f'"accounts" values must be integers: {e}')
    if not accounts:
        _die('sizes file has no "accounts" entries')
    regions=None
    if data.get("regions"):
        regions={}
        try:
            for k,v in data["regions"].items():
                a,_,r=str(k).partition("|"); regions[(a,r)]=int(v)
        except (AttributeError, TypeError, ValueError) as e:
            _die(f'"regions" must map "<account>|<region>" -> integer: {e}')
    plan=plan_chunks(accounts,region_sizes=regions,budget=budget)
    plan["budget"]=budget; plan["total_rows"]=sum(accounts.values())
    if "--tsv" in argv:
        # machine-readable for shells: first line "MODE\t<mode>\t<oversized_count>",
        # then one "<tag>\t<account>\t<region>" line per chunk (account/region empty for tenant).
        import sys as _s
        _s.stdout.write(f"MODE\t{plan['mode']}\t{len(plan['oversized'])}\n")
        for c in plan["chunks"]:
            a=c.get("account",""); r=c.get("region","")
            tag = "tenant" if c.get("scope")=="tenant" else (f"{a}_{r}" if r else a)
            _s.stdout.write(f"{tag}\t{a}\t{r}\n")
        return plan
    print(json.dumps(plan,indent=2))
    return plan

if __name__=="__main__":
    import sys
    if len(sys.argv)>1 and sys.argv[1]=="plan":
        _cli_plan(sys.argv[2:]); sys.exit(0)
    q=_selftests()
    print("\n--- gate order ---")
    for g in GATES:
        print(f"  [{g.gid:4}] stage {g.stage:2} ({g.enforced_in:5}) {g.plain}")
    print("\n--- generated population query (paste-ready for udm_get_query_results_count) ---")
    print(json.dumps(q))
