# GraphQL queries — External Attack-Path Agent (API-token edition)

The Tenable Cloud Security GraphQL schema is **environment- and version-specific**, so
this file is a **mapping template with introspection skeletons**, not a set of hard-coded
field names. Introspect the live schema first (Step 2 of the skill), fill in the mapping
table below, then adapt the skeletons. The **detection contract is fixed** (see
`SKILL.md`); only the field names you plug in change.

All queries are sent via `scripts/tcs_graphql.sh` (reads a query on stdin, POSTs it with
the Bearer token). Pipe results through `jq`.

---

## Step 0 — Confirm connectivity

```bash
echo 'query { __typename }' | ./scripts/tcs_graphql.sh
# expect: {"data":{"__typename":"Query"}}  (or the schema's query root name)
```

## Step 1 — Discover the query root and types

```bash
echo 'query { __schema { queryType { name } types { name kind } } }' \
  | ./scripts/tcs_graphql.sh \
  | jq '{root: .data.__schema.queryType.name, types: [.data.__schema.types[] | select(.kind=="OBJECT") | .name]}'
```

## Step 2 — Introspect the fields of the workload and finding types

```bash
# replace <WorkloadType> / <FindingType> with names discovered in Step 1
echo 'query { __type(name:"<WorkloadType>"){ fields { name type { name kind ofType { name } } } } }' \
  | ./scripts/tcs_graphql.sh | jq '.data.__type.fields[] | {name, type: (.type.name // .type.ofType.name)}'
```

---

## Mapping table — fill this in from introspection

Record the concrete GraphQL path for each gate before pulling data. Leave a note in the
report's verification section for any signal the schema cannot express.

| Gate | UDM attribute (MCP edition) | GraphQL field / path (fill in) |
|------|-----------------------------|-------------------------------|
| 1 | `VirtualMachineStatus ≠ Stopped` | `________` |
| 2 | `EntityNetworkAccessType = ExternalDirect` | `________` |
| 3 | `EntityNetworkAccessScope ∈ {Wide, All}` | `________` |
| 4 | network endpoint exists (host/port/protocol) | `________` |
| 5 | `PackageVulnerabilityInstanceStatus = Open` | `________` |
| 6 | `VulnerabilityAttackVector = Network` | `________` |
| 7 | `VulnerabilityAttackComplexity = Low` | `________` |
| 8 | component ↔ port (parse package name) | *(post-filter — parse package id)* |
| 9 | `VulnerabilityEpssScore ≥ 0.30` OR CISA KEV | `________` (EPSS) / `________` (KEV) |
| tier | `SeverePermissionActionPrincipalAttribute` | `________` |

---

## Skeleton A — Inventory (Dataset A)

Fetch qualifying workloads; apply the numeric/boolean gates server-side where the schema
allows, otherwise in `jq`. Paginate on `pageInfo`.

```graphql
query Inventory($after: String) {
  <workloadsRoot>(first: 100, after: $after /* , filter: { ...gates 1-3... } */) {
    pageInfo { hasNextPage endCursor }
    nodes {
      id
      name
      typeName
      account: tenant            # -> EntityTenant
      status                     # -> VirtualMachineStatus  (keep != Stopped)
      networkAccessType          # -> ExternalDirect
      networkAccessScope         # -> Wide|All
      privileged: <severePermFlag>   # -> tiering (SeverePermissionActionPrincipalAttribute)
      identity: <serviceIdentity>    # -> OriginatorEntityServiceIdentities
      endpoints { nodes { host port protocol } }   # gate 4 presence
      # findings { ... } to confirm a qualifying open vuln exists (gates 5-9)
    }
  }
}
```

Assemble each kept node into a Dataset-A row:
`{"name":…, "type":…, "account":…, "status":…, "privileged":true|false, "identity":…}`.

## Skeleton B — Endpoints (Dataset B)

```graphql
query Endpoints($after: String) {
  <workloadsRoot>(first: 100, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes { name endpoints { nodes { host port protocol } } }
  }
}
```

Dedupe to `[{instance_id, name, ports:[{port, protocol}]}]`. Optionally build
`endpoint_ips.json` = `{"endpoints":[{name, ip, port, protocol}]}` from host/port/protocol.
**Ports come only from observed endpoints — never a security-group rule.**

## Skeleton C — Qualifying CVEs (Dataset C)

```graphql
query Findings($after: String) {
  <findingsRoot>(first: 200, after: $after /* , filter: { status: OPEN } */) {
    pageInfo { hasNextPage endCursor }
    nodes {
      workload { name typeName }
      package { name }                 # -> component (for gate 8)
      status                           # -> Open
      vulnerability {
        cveId
        attackVector                   # -> Network
        attackComplexity               # -> Low
        epssScore                      # -> >= 0.30
        cisaKev                        # -> CISA KEV passthrough
        cvssScore                      # display only
        proofOfConceptAvailable        # display only (NOT a gate)
      }
    }
  }
}
```

Keep a node only when: status Open AND attackVector Network AND attackComplexity Low AND
(epssScore ≥ 0.30 OR cisaKev = true) AND the workload is one kept in Dataset A. Emit one
Dataset-C row per (workload, CVE) with `component` set to the parsed package name.

Example client-side gate arithmetic in `jq`:

```bash
jq '[.data.<findingsRoot>.nodes[]
     | select(.status=="Open")
     | select(.vulnerability.attackVector=="Network")
     | select(.vulnerability.attackComplexity=="Low")
     | select((.vulnerability.epssScore // 0) >= 0.30 or (.vulnerability.cisaKev == true))
     | {name: .workload.name, type: .workload.typeName, component: .package.name,
        cve: .vulnerability.cveId, epss: .vulnerability.epssScore,
        kev: .vulnerability.cisaKev, cvss: .vulnerability.cvssScore,
        poc: .vulnerability.proofOfConceptAvailable}]'
```

> **Do not relax a threshold to work around the schema.** If a signal is genuinely not
> queryable, note it in the report's verification section rather than dropping the gate.
> The renderer still applies gate 8 (component↔port) and the stopped-VM safety net.
