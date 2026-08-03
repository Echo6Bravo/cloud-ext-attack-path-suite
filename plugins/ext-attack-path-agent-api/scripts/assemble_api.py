"""
assemble_api.py -- transform headless GraphQL raw pages (from fetch_all.sh) into the
renderer's assembled.json, applying the REDUCED-FIDELITY API-edition gates client-side.

Scales the same way as fetch_all.sh: streams per-page files, dict/set joins, O(n).
See ../skills/ext-attack-path-api/references/graphql-queries.md for the gate mapping and
the fidelity gap this edition documents (no running-state, no observed endpoint, no
AC:Low, no CISA-KEV field, no privilege tier).

Usage:
    python3 assemble_api.py --raw ./data/raw --out ./data/assembled.json

Inputs (from fetch_all.sh):
    gql_vms_*.json     VirtualMachines pages
    gql_vulns_*.json   VulnerabilityInstances pages
"""
from __future__ import annotations
import json, os, glob, argparse

EPSS_FLOOR = 0.30
MATURE = {"Functional", "High"}   # KEV substitute (documented as weaker/different)


def _pages(raw_dir, prefix):
    for f in sorted(glob.glob(os.path.join(raw_dir, prefix + "*.json"))):
        with open(f) as fh:
            yield json.load(fh)


def load_exposed_vms(raw_dir):
    """Gates 2-3: keep VMs with an InternetDirect + Wide/All inbound access."""
    exposed = {}   # name -> {provider, account}
    for page in _pages(raw_dir, "gql_vms_"):
        for n in (((page.get("data") or {}).get("VirtualMachines") or {}).get("nodes") or []):
            accesses = (((n.get("NetworkAccess") or {}).get("Inbound") or {}).get("Accesses") or [])
            if any(a.get("Type") == "InternetDirect" and a.get("Scope") in ("Wide", "All") for a in accesses):
                exposed[n.get("Name")] = {"provider": n.get("Provider", ""), "account": n.get("AccountId", "")}
    return exposed


def load_qualifying_vulns(raw_dir, exposed):
    """Gates 5,6,reduced-9 + reduced-8 component; only on exposed VMs."""
    C = []
    for page in _pages(raw_dir, "gql_vulns_"):
        for n in (((page.get("data") or {}).get("VulnerabilityInstances") or {}).get("nodes") or []):
            res = (n.get("Resource") or {}).get("Name")
            if res not in exposed:
                continue
            v = n.get("Vulnerability") or {}
            if v.get("AttackVector") != "Network":
                continue
            epss = v.get("EpssScore") or 0
            mature = v.get("ExploitMaturity") in MATURE
            if not (epss >= EPSS_FLOOR or mature):
                continue
            sw = n.get("Software") or {}
            C.append({
                "instance_id": res, "name": res, "type": exposed[res]["provider"],
                "cve": (v.get("Id") or "").upper(), "component": sw.get("Name", ""),
                "cvss": v.get("CvssScore") or 0, "epss": epss,
                "kev": bool(mature),   # substitute signal; labeled as maturity in the report note
                "severity": v.get("Severity", ""), "poc": False,
                "gate_reason": "epss" if epss >= EPSS_FLOOR else "kev", "status": "Open",
            })
    return C


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default="./data/raw")
    ap.add_argument("--out", default="./data/assembled.json")
    ap.add_argument("--max-hosts", type=int, default=0)
    args = ap.parse_args()

    exposed = load_exposed_vms(args.raw)
    C = load_qualifying_vulns(args.raw, exposed)

    hosts_with_vulns = {c["instance_id"] for c in C}
    if args.max_hosts and args.max_hosts > 0:
        from collections import Counter
        keep = {h for h, _ in Counter(c["instance_id"] for c in C).most_common(args.max_hosts)}
        C = [c for c in C if c["instance_id"] in keep]
        hosts_with_vulns = keep

    A = [{"instance_id": name, "name": name, "type": exposed[name]["provider"],
          "tenant": exposed[name]["account"], "status": "", "privileged": False, "identity_ids": []}
         for name in hosts_with_vulns]
    # B is intentionally empty: the API has no observed listening endpoint (gate 4 dropped).
    out = {"A": A, "B": [], "C": C}
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(out, fh)
    print(f"assembled (API/reduced-fidelity): A={len(A)} hosts | B=0 (no observed endpoints) | C={len(C)} cve-rows")


if __name__ == "__main__":
    main()
