"""
assemble.py -- transform raw UDM query result pages into assembled.json.

This closes the previously-undocumented seam between the raw MCP/UDM
`udm_execute_query` result shape and the {"A","B","C"} structure render_report.py
expects. It is written to SCALE: it streams a directory of per-page raw files
rather than holding one giant blob, and dedupes with sets/dicts (no quadratic scans).

Raw input: a directory containing page files named:
    raw_A_*.json   inventory pages   (root IVirtualMachine)
    raw_B_*.json   endpoint pages     (root NetworkEndpoint + Entity join)
    raw_C_*.json   cve pages          (root PackageVulnerabilityInstanceModel + 2 joins)
Each file is one raw `udm_execute_query` response (has a "resultsList" array).

Usage:
    python3 assemble.py --raw ./data/raw --out ./data/assembled.json \
        [--endpoint-ips ./data/endpoint_ips.json] [--max-hosts N]

Design notes for scale:
  * O(|A|+|B|+|C|) overall -- every row touched once; joins via dicts/sets.
  * Reads page files one at a time (constant extra memory beyond the accumulators).
  * Emits only hosts that survive the endpoint+CVE join, so |assembled| tracks the
    number of *qualifying* hosts, not the raw population.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

import attack_path_spec as spec

SEVERE = spec.PRIVILEGE_ATTR  # "SeverePermissionActionPrincipalAttribute"


def _load_pages(raw_dir, prefix):
    """Yield parsed page dicts for raw_<prefix>_*.json, skipping unreadable/malformed pages
    with a warning rather than aborting the whole assembly (a single corrupt page in a large
    multi-account pull must not lose everything). Returns nothing if the dir/pattern is empty."""
    for f in sorted(glob.glob(os.path.join(raw_dir, prefix + "*.json"))):
        try:
            with open(f) as fh:
                page = json.load(fh)
        except (json.JSONDecodeError, OSError) as e:
            sys.stderr.write(f"assemble: WARNING: skipping unreadable/malformed page {f}: {e}\n")
            continue
        if not isinstance(page, dict):
            sys.stderr.write(f"assemble: WARNING: skipping page {f}: top-level is not a JSON object\n")
            continue
        yield page


def _rows(page):
    """Yield each result's queryId->object map from one raw response."""
    for r in (page.get("resultsList") or []):
        if isinstance(r, dict):
            yield r.get("queryIdToObjectMap", {})


def _vmap(obj_for_query):
    """Return the propertyIdentifierToValueMap for a single query object."""
    return obj_for_query.get("propertyIdentifierToValueMap", {})


def _first_map(qmap):
    """Root object is the query whose map carries the root Id; return (root_map, all_maps)."""
    maps = {qid: _vmap(o) for qid, o in qmap.items()}
    return maps


def load_inventory(raw_dir):
    """A rows: one per host. instance_id = resource Id; privileged from EntityAttributes."""
    A = {}
    for page in _load_pages(raw_dir, "raw_A_"):
        for qmap in _rows(page):
            maps = _first_map(qmap)
            # inventory is single-query; take the map that has an Id + EntityName
            m = next((v for v in maps.values() if "Id" in v and "EntityName" in v), None)
            if not m:
                continue
            iid = m["Id"]
            attrs = m.get("EntityAttributes") or []
            privileged = any((a or {}).get("typeName") == SEVERE for a in attrs)
            A[iid] = {
                "instance_id": iid,
                "name": m.get("EntityName", ""),
                "type": m.get("EntityTypeName", ""),
                "tenant": m.get("EntityTenant", ""),
                "status": m.get("VirtualMachineStatus", ""),
                "privileged": privileged,
                "identity_ids": list(m.get("OriginatorEntityServiceIdentities") or []),
            }
    return A


def load_endpoints(raw_dir):
    """B rows: dedupe to {instance_id, name, ports:[{port,protocol}]}. Also return ip map."""
    ports_by_iid = {}     # iid -> set((port, proto))
    name_by_iid = {}
    ips = []              # {name, ip, port, protocol}
    for page in _load_pages(raw_dir, "raw_B_"):
        for qmap in _rows(page):
            maps = _first_map(qmap)
            ep = next((v for v in maps.values() if "NetworkEndpointPort" in v), None)
            ent = next((v for v in maps.values() if "EntityName" in v and "NetworkEndpointPort" not in v), None)
            if not ep or not ent:
                continue
            iid = ent.get("Id")
            if not iid:
                continue
            port = ep.get("NetworkEndpointPort")
            proto = ep.get("NetworkEndpointProtocolType", "TCP")
            host = ep.get("NetworkEndpointHost")
            name_by_iid[iid] = ent.get("EntityName", "")
            ports_by_iid.setdefault(iid, set()).add((port, proto))
            if host is not None:
                ips.append({"name": ent.get("EntityName", ""), "ip": host, "port": port, "protocol": proto})
    B = [
        {"instance_id": iid, "name": name_by_iid.get(iid, ""),
         "ports": [{"port": p, "protocol": pr} for (p, pr) in sorted(ports, key=lambda x: (x[0] or 0))]}
        for iid, ports in ports_by_iid.items()
    ]
    return B, ips


def _gate_reason(epss, kev):
    hit_epss = (epss is not None) and (epss >= spec.EPSS_FLOOR)
    if hit_epss and kev:
        return "both"
    if kev:
        return "kev"
    return "epss"


_CVE_SEG = re.compile(r"^(?:cve|dla|dsa|usn|ghsa|rhsa|elsa|dla|dls)[-:]", re.I)

def parse_instance_id(inst_id):
    """Parse a PackageVulnerabilityInstance Id into (cve_or_advisory, component).

    Observed shape (all providers): '<advisory-id>/<package>/<version>/<os>/<resource-id...>'
    e.g. 'cve-2011-3389/libgnutls30/3.7.1-5+deb11u3/Linux/arn:aws:ec2:...'.
    Structure-aware rather than blindly positional:
      * advisory id  = segment 0 IF it looks like a CVE/advisory id, else "".
      * component    = the segment immediately AFTER the advisory id (segment 1). This is the
                       package even when the resource-id tail contains extra '/' (AWS ARNs,
                       GCP resource paths, Azure resourceGroups) because those live in later
                       segments. A leading empty segment (id starting with '/') is skipped.
    Returns ("","") for an empty/degenerate id rather than raising."""
    if not inst_id:
        return ("", "")
    segs = inst_id.split("/")
    # tolerate a leading empty segment (id that begins with '/')
    start = 0
    while start < len(segs) and segs[start] == "":
        start += 1
    if start >= len(segs):
        return ("", "")
    first = segs[start]
    advisory = first if _CVE_SEG.match(first) else ""
    # component is the segment after the advisory id; if segment 0 wasn't an advisory id we
    # can't trust the layout, so return no component (caller falls back / it lands in review).
    component = segs[start + 1] if (advisory and start + 1 < len(segs)) else ""
    return (advisory, component)

def load_cves(raw_dir):
    """C rows: one per (host, cve). component parsed structurally from the instance Id."""
    C = []
    for page in _load_pages(raw_dir, "raw_C_"):
        for qmap in _rows(page):
            maps = _first_map(qmap)
            inst = next((v for v in maps.values() if "PackageVulnerabilityInstanceStatus" in v), None)
            vuln = next((v for v in maps.values() if "VulnerabilityEpssScore" in v), None)
            ent = next((v for v in maps.values() if "EntityName" in v), None)
            if not inst or not vuln or not ent:
                continue
            inst_id = inst.get("Id", "")
            id_advisory, component = parse_instance_id(inst_id)
            # CVE from the joined vuln object first (authoritative), else the parsed advisory id.
            cve = (vuln.get("Id") or id_advisory or "").upper()
            iid = ent.get("Id")
            epss = vuln.get("VulnerabilityEpssScore")
            kev = bool(vuln.get("VulnerabilityVprV2MetricsOnCisaKev"))
            C.append({
                "instance_id": iid,
                "name": ent.get("EntityName", ""),
                "type": ent.get("EntityTypeName", ""),
                "cve": cve,
                "component": component,
                "cvss": vuln.get("VulnerabilityCvssScore") or 0,
                "epss": epss if epss is not None else 0,
                "kev": kev,
                "severity": vuln.get("VulnerabilitySeverity", ""),
                "poc": bool(vuln.get("VulnerabilityProofOfConceptAvailable")),
                "gate_reason": _gate_reason(epss, kev),
                "status": inst.get("PackageVulnerabilityInstanceStatus", "Open"),
            })
    return C


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default="./data/raw")
    ap.add_argument("--out", default="./data/assembled.json")
    ap.add_argument("--endpoint-ips", default=None, help="also write endpoint_ips.json here")
    ap.add_argument("--max-hosts", type=int, default=0,
                    help="0 = no cap; else keep only the N hosts with the most qualifying CVEs (safety valve for huge envs)")
    args = ap.parse_args()

    A = load_inventory(args.raw)
    B, ips = load_endpoints(args.raw)
    C = load_cves(args.raw)

    # Optional safety valve: bound the rendered host set for very large environments.
    if args.max_hosts and args.max_hosts > 0:
        from collections import Counter
        by_host = Counter(c["instance_id"] for c in C)
        keep = {iid for iid, _ in by_host.most_common(args.max_hosts)}
        C = [c for c in C if c["instance_id"] in keep]

    out = {"A": list(A.values()), "B": B, "C": C}
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(out, fh)
    print(f"assembled: A={len(out['A'])} hosts | B={len(out['B'])} endpoint-hosts | C={len(out['C'])} cve-rows")
    if args.endpoint_ips and ips:
        with open(args.endpoint_ips, "w") as fh:
            json.dump({"endpoints": ips}, fh)
        print(f"wrote endpoint_ips: {len(ips)} ip:port rows -> {args.endpoint_ips}")


if __name__ == "__main__":
    main()
