# GraphQL queries — External Attack-Path Agent (API-token edition, reduced fidelity)

These queries are **verified live** against `https://app.tenable.com/api/graph` by schema
introspection and real execution (2026-08). They intentionally enforce only the subset of
the detection contract the GraphQL API can express — see the fidelity table in `SKILL.md`.
Send each via `scripts/tcs_graphql.sh` (query on stdin) and process with `jq`.

If a field ever errors as unknown, the schema changed — re-introspect with
`__type(name:"TypeName"){ fields { name } }` and update this file. **Never invent fields.**

---

## 0. Connectivity

```bash
echo 'query { __typename }' | ./scripts/tcs_graphql.sh
# → {"data":{"__typename":"Query"}}
```

## 1. Exposed VMs (gates 2–3: InternetDirect + Wide/All)

The GraphQL query root is `VirtualMachines` (a cursor connection). Exposure lives under
`NetworkAccess.Inbound.Accesses[]`, each with `Type` (`NetworkInboundAccessType`:
`Internal | InternetDirect | InternetIndirect`) and `Scope` (`NetworkAccessScope`:
`All | None | Restricted | Wide`). There is **no** VM status field (gate 1 cannot be
enforced) and **no** confirmed privileged/severe-permission field (no Tier 1/2 split).

```graphql
query ExposedVMs($after: String) {
  VirtualMachines(first: 100, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      Id
      Name
      Provider
      AccountId
      AccountName
      Region
      NetworkAccess { Inbound { Accesses { Type Scope } } }
    }
  }
}
```

Keep a VM only if it has an access with `Type == "InternetDirect"` and
`Scope in ["Wide","All"]`:

```bash
echo '<query above with $after inlined or paginated>' | ./scripts/tcs_graphql.sh \
 | jq '[.data.VirtualMachines.nodes[]
        | select(any(.NetworkAccess.Inbound.Accesses[]?;
                     .Type=="InternetDirect" and (.Scope=="Wide" or .Scope=="All")))
        | {id:.Id, name:.Name, provider:.Provider, account:.AccountId}]'
```

> **Ports (gate 4):** `Accesses[].Connections[]` exposes only `DestinationPortRange`,
> `ProtocolRange`, `SourceIpAddressRange` — i.e. **security-group rule ranges, not an
> observed listener**. The methodology forbids using SG ranges as endpoint evidence, so
> this edition does **not** populate observed ports. Leave renderer dataset **B** empty.

## 2. Qualifying vulnerabilities (gates 5, 6, reduced-9; component for reduced-8)

Root `VulnerabilityInstances` (cursor connection). Server-side filter narrows to open
findings (and optionally severities); the remaining gates are applied client-side because
the filter input does not expose AV / EPSS / complexity.

Filter input (`VulnerabilityInstancesFilterInput`) supports: `Resolved: Boolean`,
`CvssSeverities/VprSeverities/VulnerabilitySeverities: [Severity]`, `SoftwareNames`,
`SoftwareVersions`, `VulnerabilityIds`, `PluginIds`, `ResourceIds`, `ResourceTypes`.

```graphql
query QualifyingVulns($after: String) {
  VulnerabilityInstances(filter: { Resolved: false }, first: 200, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      Resolved
      Software { Name Version }
      Resource { Name }
      Vulnerability {
        Id
        AttackVector          # enum: Adjacent | Local | Network | Physical
        AttackComplexity?     # DOES NOT EXIST — do not select; gate 7 cannot be enforced
        EpssScore             # Decimal 0..1
        CvssScore             # Decimal (display only)
        ExploitMaturity       # enum: Unproven | Poc | Functional | High  (KEV substitute)
        Severity
      }
    }
  }
}
```

> Remove the `AttackComplexity?` line before sending — it is annotated only to record that
> the field is absent. There is likewise **no** CISA-KEV boolean; `ExploitMaturity ∈
> {Functional, High}` is used as a *weaker, different* real-world-exploitation signal.

Keep a node only if network-exploitable AND publicly-evidenced:

```bash
echo '<QualifyingVulns query>' | ./scripts/tcs_graphql.sh \
 | jq '[.data.VulnerabilityInstances.nodes[]
        | select(.Vulnerability.AttackVector == "Network")
        | select((.Vulnerability.EpssScore // 0) >= 0.30
                 or (.Vulnerability.ExploitMaturity == "Functional")
                 or (.Vulnerability.ExploitMaturity == "High"))
        | {cve: .Vulnerability.Id,
           component: .Software.Name,          # reduced gate 8: name only, no port correlation
           version: .Software.Version,
           resource: .Resource.Name,
           epss: .Vulnerability.EpssScore,
           cvss: .Vulnerability.CvssScore,
           maturity: .Vulnerability.ExploitMaturity,
           severity: .Vulnerability.Severity}]'
```

## 3. Join and assemble

Intersect kept vulnerabilities with the kept exposed-VM set on resource/VM name, then
emit the renderer's `assembled.json`:

- **A (inventory):** one row per exposed VM that also has ≥1 qualifying vuln —
  `{instance_id, name, type: Provider, tenant: AccountId, privileged: false, identity_ids: []}`.
  (`privileged` is always `false` — the API exposes no severe-permission signal, so there
  is no Tier 1.)
- **B (endpoints):** **empty** — the API has no observed listener (gate 4 dropped).
- **C (cve rows):** one row per (VM, qualifying CVE) with `component` = `Software.Name`.

Then render (see `SKILL.md` step 5). **The report must state the fidelity gap.**

---

## Verified schema facts (introspected 2026-08)

- Query root: `Query`. VM root: `VirtualMachines` → `VirtualMachine`. Vuln instances:
  `VulnerabilityInstances` → `VulnerabilityInstance` → `.Vulnerability` (`Vulnerability`).
- `Vulnerability` fields incl.: `AttackVector, CvssScore, CvssSeverity, EpssScore,
  Exploitable, ExploitMaturity, Severity, VprScore, VprSeverity`. **No** `AttackComplexity`,
  **no** CISA-KEV field.
- `NetworkInboundAccessType`: `Internal | InternetDirect | InternetIndirect`.
- `NetworkAccessScope`: `All | None | Restricted | Wide`.
- `ExploitMaturity` (`ExportMaturity` enum): `Unproven | Poc | Functional | High`.
- `Accesses[].Connections[]`: `DestinationPortRange, ProtocolRange, SourceIpAddressRange`
  (rule ranges only — not observed listeners).
- Cursor pagination on every connection: `first`, `after`, `pageInfo{hasNextPage endCursor}`.
- **Max page size is 1000** — `first:` above 1000 is rejected with error `HC0051`
  ("maximum allowed items per page were exceeded"). `fetch_all.sh` defaults `PAGE=1000`.
- **Scope the vuln pull with `ResourceIds`.** `VulnerabilityInstances(filter:{Resolved:false})`
  alone returns *every open vuln in the tenant* (millions of rows at scale). `fetch_all.sh`
  first collects the exposed-VM Ids (phase 1) and passes them as
  `filter:{Resolved:false, ResourceIds:[...]}` (batched), so phase 2 pulls vulns only for
  the qualifying subset — the key scaling decision. Do NOT drop this scoping.
- **Do not server-side filter by severity as a proxy for evidence.** Verified against live
  data: Low/Medium-severity CVEs can have EPSS ≥ 0.30 and must qualify, so a
  `VulnerabilitySeverities:[Critical,High]` pre-filter would silently drop real findings.
  Keep the EPSS/maturity + AV:N test client-side.
