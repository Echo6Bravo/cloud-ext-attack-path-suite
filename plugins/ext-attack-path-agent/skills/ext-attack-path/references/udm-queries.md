# UDM queries — External Attack-Path Agent (MCP edition)

These four queries are **generated from `attack_path_spec.py`** (the single source of
truth) and copied here verbatim for reference. To regenerate them, run
`python3 scripts/attack_path_spec.py` and read the emitted JSON, or call the spec's
`build_population_query()`, `build_inventory_query()`, `build_endpoints_query()`, and
`build_cve_query()`. The canonical copies also live at the repo root under `queries/`.

Every query encodes the same gate chain (running → internet-direct → wide scope →
observed endpoint → open finding → AV:N → AC:Low → EPSS ≥ 0.30 OR CISA KEV). Gate 8
(component ↔ exposed-port correlation) is **not** in the query — it is applied
deterministically by `attack_path_spec.post_filter()` inside the renderer.

Run each via `mcp__tcs__udm_execute_query` with `skip`/`take` (both required), paginating
fully. Use `mcp__tcs__udm_get_query_results_count` on query 01 for the population total.

> **GUIDs:** each query below carries valid hex GUIDs with matching `queryId`s. If you
> regenerate, the spec mints fresh valid GUIDs each run — either is fine.

---

## Query 01 — Population (count / validate)

Rooted on `IVirtualMachine`. Existence-filters the full gate chain via relation rules so
`VirtualMachineStatus` stays in scope (gate 1). Use with
`udm_get_query_results_count` first to sanity-check the population before pulling rows.

See `queries/01_population.json` in the repo root for the full JSON body (identical gate
structure to query 02 below, with `objectResultHidden` set for counting).

---

## Query 02 — Dataset A: Inventory (one row per host)

Rooted on `IVirtualMachine`. Columns: `EntityName`, `EntityTypeName`, `EntityTenant`,
`VirtualMachineStatus`, `EntityAttributes` (privileged = contains
`SeverePermissionActionPrincipalAttribute`), `OriginatorEntityServiceIdentities`.

```json
{
  "typeName": "UdmQuery",
  "objectTypeName": "IVirtualMachine",
  "id": "7d5ae8e2-eb6a-b61d-ba25-3d31990eddec",
  "collapsed": false, "objectResultHidden": false, "timeZoneId": null, "joins": [],
  "properties": [
    {"identifier": "EntityName", "queryId": "7d5ae8e2-eb6a-b61d-ba25-3d31990eddec", "sort": null, "startOfWeek": null, "transform": null},
    {"identifier": "EntityTypeName", "queryId": "7d5ae8e2-eb6a-b61d-ba25-3d31990eddec", "sort": null, "startOfWeek": null, "transform": null},
    {"identifier": "EntityTenant", "queryId": "7d5ae8e2-eb6a-b61d-ba25-3d31990eddec", "sort": null, "startOfWeek": null, "transform": null},
    {"identifier": "VirtualMachineStatus", "queryId": "7d5ae8e2-eb6a-b61d-ba25-3d31990eddec", "sort": null, "startOfWeek": null, "transform": null},
    {"identifier": "EntityAttributes", "queryId": "7d5ae8e2-eb6a-b61d-ba25-3d31990eddec", "sort": null, "startOfWeek": null, "transform": null},
    {"identifier": "OriginatorEntityServiceIdentities", "queryId": "7d5ae8e2-eb6a-b61d-ba25-3d31990eddec", "sort": null, "startOfWeek": null, "transform": null}
  ],
  "ruleGroup": {
    "typeName": "UdmQueryRuleGroup", "id": "2ec6f556-a7e6-03a4-b11e-4d0e103c3777", "not": false, "ignored": false, "collapsed": false, "name": "", "operator": "And",
    "rules": [
      {"typeName": "UdmQueryRule", "id": "3f561fb9-8983-7fb9-dec2-df1a985aa267", "ignored": false, "not": true, "operator": "In", "propertyIdentifier": "VirtualMachineStatus", "values": ["Stopped"]},
      {"typeName": "UdmQueryRule", "id": "a9b24664-120d-7ffb-83c5-815f093ab913", "ignored": false, "not": false, "operator": "In", "propertyIdentifier": "EntityNetworkAccessType", "values": ["ExternalDirect"]},
      {"typeName": "UdmQueryRule", "id": "50fcd13f-eb79-15f1-fde7-7f2b0f013e9c", "ignored": false, "not": false, "operator": "In", "propertyIdentifier": "EntityNetworkAccessScope", "values": ["Wide", "All"]},
      {"typeName": "UdmQueryRelationRule", "id": "ebaecb12-7812-6932-e400-4d1f40e705b7", "ignored": false, "not": false, "relationPropertyIdentifier": "NetworkDynamicAnalysisResourceNetworkEndpoints",
        "ruleGroup": {"typeName": "UdmQueryRuleGroup", "id": "bd3f1fb1-01a7-a1d5-79bb-0e1f97d99adb", "not": false, "ignored": false, "collapsed": false, "name": "", "operator": "And", "rules": []}},
      {"typeName": "UdmQueryRelationRule", "id": "d2709bb7-d8ab-542e-d950-b88d0edd0c1d", "ignored": false, "not": false, "relationPropertyIdentifier": "EntityPackageVulnerabilityInstances",
        "ruleGroup": {"typeName": "UdmQueryRuleGroup", "id": "571bad08-3c45-93a4-356e-8522659c2386", "not": false, "ignored": false, "collapsed": false, "name": "", "operator": "And",
          "rules": [
            {"typeName": "UdmQueryRule", "id": "fe04dab0-5ead-d233-2911-7613cda24018", "ignored": false, "not": false, "operator": "In", "propertyIdentifier": "PackageVulnerabilityInstanceStatus", "values": ["Open"]},
            {"typeName": "UdmQueryRelationRule", "id": "5a2f5091-4ef8-b991-f0e3-e66d3b1668f5", "ignored": false, "not": false, "relationPropertyIdentifier": "PackageVulnerabilityInstanceVulnerability",
              "ruleGroup": {"typeName": "UdmQueryRuleGroup", "id": "b80ed944-b687-1c0a-0c2e-4f65cfa97bf3", "not": false, "ignored": false, "collapsed": false, "name": "", "operator": "And",
                "rules": [
                  {"typeName": "UdmQueryRule", "id": "93706c09-2464-29af-9c9b-82517d2beb04", "ignored": false, "not": false, "operator": "In", "propertyIdentifier": "VulnerabilityAttackVector", "values": ["Network"]},
                  {"typeName": "UdmQueryRule", "id": "46d9a50d-200f-4a25-1144-caa4c7b52098", "ignored": false, "not": false, "operator": "In", "propertyIdentifier": "VulnerabilityAttackComplexity", "values": ["Low"]},
                  {"typeName": "UdmQueryRuleGroup", "id": "77bba977-dad0-c287-5e8c-0031d8b94cfa", "not": false, "ignored": false, "collapsed": false, "name": "", "operator": "Or",
                    "rules": [
                      {"typeName": "UdmQueryRule", "id": "c7433cc6-f2be-1de5-6541-48cf498f8983", "ignored": false, "not": false, "operator": "Gte", "propertyIdentifier": "VulnerabilityEpssScore", "values": [0.3]},
                      {"typeName": "UdmQueryRule", "id": "81466733-2c7d-17f5-82db-fa7ba9937b6b", "ignored": false, "not": false, "operator": "Equals", "propertyIdentifier": "VulnerabilityVprV2MetricsOnCisaKev", "values": [true]}
                    ]}
                ]}}
          ]}}
    ]}
}
```

> **Privileged flag (tiering):** the query does not filter on privilege. In dataset A,
> set `privileged = true` for a host when its `EntityAttributes` contains
> `SeverePermissionActionPrincipalAttribute`. This drives Tier 1 vs Tier 2 — it never
> excludes a host.

---

## Query 03 — Dataset B: Validated endpoints (IP:port)

Rooted on `NetworkEndpoint`, inner-joined back to the dynamic-analysis resource so only
endpoints on qualifying VMs are returned. Columns: `NetworkEndpointHost`,
`NetworkEndpointPort`, `NetworkEndpointProtocolType`, and the joined `EntityName`.
Dedupe to `[{instance_id, name, ports:[{port, protocol}]}]`; optionally build
`endpoint_ips.json` from host/port/protocol. Full JSON at `queries/03_endpoints.json`.

The endpoint rule group re-applies the exposure + vuln chain (ExternalDirect, Wide/All,
open finding, AV:N, AC:Low, EPSS ≥ 0.30 OR CISA KEV) so the endpoint set matches the
population. **Ports come only from these endpoints — never from a security-group rule.**

---

## Query 04 — Dataset C: Qualifying CVEs (one row per host+CVE)

Rooted on `PackageVulnerabilityInstanceModel`, inner-joined to `...Vulnerability` and
`...Entity`. Columns: `PackageVulnerabilityInstanceStatus`, `VulnerabilityCvssScore`,
`VulnerabilityEpssScore`, `VulnerabilityVprV2MetricsOnCisaKev`, `VulnerabilitySeverity`,
`VulnerabilityProofOfConceptAvailable` (display only), and the joined `EntityName` /
`EntityTypeName`. The rule chain is the full gate set (open → AV:N → AC:Low → EPSS ≥ 0.30
OR CISA KEV) plus the entity being ExternalDirect + Wide/All. Full JSON at
`queries/04_cve.json`.

> **Component parsing (required for gate 8):** parse the package name from the **2nd path
> segment of the instance Id** and carry it as `component` on each dataset-C row. The
> renderer's `attack_path_spec.post_filter()` uses it to confirm the vulnerable package is
> the service on the exposed port (e.g. an `openssh-server` CVE counts on port 22; a
> `libgnutls30` CVE on an SSH-only host does not).

---

## Property value references

- `EntityNetworkAccessType`: `ExternalDirect` (used), `ExternalIndirect`, `Internal`, `None`.
- `EntityNetworkAccessScope`: `All`, `Wide` (both used), `Restricted`, `None`.
- `VulnerabilityAttackVector`: `Network` (used), `Adjacent`, `Local`, `Physical`.
- `VulnerabilityAttackComplexity`: `Low` (used), `High`.
- `PackageVulnerabilityInstanceStatus`: `Open` (used), `Resolved`, etc.
- `VirtualMachineStatus`: `Running`, `Stopped` (excluded), etc.
- Privileged label attribute: `SeverePermissionActionPrincipalAttribute` (tiering only).
