# Test-OpenGraphJson.ps1

A PowerShell script that validates, profiles and analyses any **BloodHound OpenGraph** JSON payload before (or after) you ingest it.

It works with the output of any OpenGraph collector, not just one extension. It checks the payload against the published OpenGraph data rules, summarises what is in it, and maps how the data connects into existing graph nodes such as Active Directory and Entra ID. That last part is the usual reason a new OpenGraph upload changes attack paths or findings.

---

## Contents

- [Why use it](#why-use-it)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Parameters](#parameters)
- [What it checks](#what-it-checks)
- [Reading the report](#reading-the-report)
- [Output files](#output-files)
- [Examples](#examples)
- [Limitations](#limitations)
- [References](#references)

---

## Why use it

- **Catch upload failures early.** It finds the things BloodHound rejects or silently drops: bad edge kind names, the reserved `tag_` prefix, `objectid` in properties, broken `match_by` endpoints, nested properties and more.
- **Understand an unfamiliar payload.** You get counts, kind combinations, edge patterns, property coverage and fan-out without opening a multi-megabyte JSON file.
- **Explain changes in attack paths or findings.** It shows which nodes reach the most external (AD / Azure / other) targets, which edge kinds those paths depend on, and the chokepoint nodes and edges.
- **Compare collector runs.** With `-BaselinePath`, it shows what changed and which *new* edges add paths.
- **Check structured-graph readiness.** With an extension schema, it checks the namespace, environment nodes, `environmentid` and `collected`, which BloodHound Enterprise needs before it can produce findings.

---

## Requirements

| | |
|---|---|
| PowerShell | **7.x recommended** (much faster JSON parsing). Windows PowerShell 5.1 is supported. |
| OS | Windows, Linux or macOS (anywhere PowerShell runs) |
| Modules | None. The analysis engine is inline C# compiled at runtime with `Add-Type`. |
| Memory | The file is read fully into memory. Allow roughly **4–6× the JSON file size** in RAM. |
| BloodHound access | Not needed. The script works offline on the JSON file. |

If script execution is blocked:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
# or, for a downloaded file
Unblock-File .\Test-OpenGraphJson.ps1
```

---

## Quick start

```powershell
.\Test-OpenGraphJson.ps1 -Path .\collector_output.json
```

The console shows the full report. The same content, plus CSVs and ready-made Cypher queries, is written to `.\OG-Analysis-<timestamp>\`.

The first lines tell you whether the file is safe to upload:

```
Status        : OK WITH WARNINGS  [0 error types, 3 warning types, 1 info]
```

The **KEY FINDINGS** block at the end summarises the most important points.

---

## Parameters

| Parameter | Required | Description |
|---|---|---|
| `-Path` | Yes | The OpenGraph JSON payload to analyse. |
| `-SchemaPath` | No | The extension definition schema (`schema.json`). Enables structured-graph checks and uses the schema's `is_traversable` flags and `principal_kinds`. Without it, **all edges are assumed traversable** and every node is a possible path origin. |
| `-BaselinePath` | No | An older payload from the same collector. Adds a comparison section and works out which new edges add paths. |
| `-TierZeroFile` | No | A list of external target names to count paths to, one per line (e.g. `ADMINISTRATOR@CORP.LOCAL`, `DC01.CORP.LOCAL`), or a CSV with a `name`, `label` or `objectid` column. Use it to restrict path analysis to Tier Zero objects. |
| `-NonTraversable` | No | Edge kinds to treat as non-traversable when no schema is supplied, e.g. `-NonTraversable Acme_Created,Acme_UsedBy`. |
| `-OutputFolder` | No | Where to write output. Default: `.\OG-Analysis-<yyyyMMdd-HHmmss>`. |
| `-Top` | No | Rows shown in each "top N" table. Default `25`. CSVs always contain everything. |
| `-SkipPathAnalysis` | No | Validation and profiling only. Skips reachability, what-if and chokepoints. |

---

## What it checks

### 1. Validation

Each issue is reported once, with a severity, an occurrence count and an example.

| Severity | Meaning |
|---|---|
| **ERROR** | BloodHound will reject the upload, or ingest will fail or drop data. |
| **WARN** | The upload is accepted, but data may be missing, unresolved, duplicated or excluded from analysis. |
| **INFO** | Worth knowing, but usually intentional. |

**Payload structure and metadata**
- `graph` object with `nodes` and `edges` arrays
- `metadata` must be top-level (not under `graph`) and may contain only `source_kind`
- `source_kind` type, and whether it's present

**Nodes**
- `id` present, a string, unique, not differing from another id only by case, and no `:` or leading/trailing whitespace
- `kinds` is an array of 1–3 strings, the first kind being the primary (icon) kind
- Reserved `tag_` prefix (the whole upload is rejected), and overlap with built-in node kinds such as `User` or `Computer`

**Properties** (nodes and edges)
- Reserved `objectid` (ingest fails), plus `lastseen` (overwritten) and `reconcile` (stripped)
- Values must be string, number, boolean or a homogeneous array of primitives. Nested objects, arrays of objects, mixed-type arrays and nulls are flagged.
- Property names should be lowercase with no spaces or special characters
- The same property having different types across nodes or edges of one kind

**Edges**
- `kind` must match `^[A-Za-z0-9_]+$`, plus the reserved `tag_` prefix
- Post-processed kinds (`AdminTo`, `CanRDP`, `DCSync`, …), which BloodHound deletes and regenerates
- Built-in kinds used directly (fine for deliberate hybrid edges)
- `start` / `end` endpoint rules: `id`, `name` (deprecated) or `property` matching, `value` vs `property_matchers`, and `equals` as the only operator
- Dangling `id` references to nodes not defined in the file, duplicate edges and self-loops

**Naming**
- Custom kinds without a `Namespace_` prefix

**Schema and findings readiness** (with `-SchemaPath`)
- Node and edge kinds not defined in the schema
- Kinds not prefixed with the schema `namespace`
- An environment node is present and has `collected: true`
- Principal-kind nodes without `environmentid` (excluded from findings and metrics)
- `environmentid` values that don't match any node id

### 2–4. Profiling
- Nodes by primary kind, kind combinations and kind prefixes
- Edges by kind: traversability, hybrid count, distinct start and end nodes, and the largest fan-out node
- Edge patterns: `StartKind -[EdgeKind]-> EndKind` counts
- Property coverage and data types for every node and edge kind

### 5. External (hybrid) references
Edges whose start or end is **not defined in the file** resolve against nodes that already exist in BloodHound. These are what tie a new data source to AD, Entra ID or other extensions. The script classifies them:

| Type | Example |
|---|---|
| name match | `"match_by": "name", "value": "SVC_SQL@CORP.LOCAL"` |
| property match | `"match_by": "property", "property_matchers": [...]` |
| id: SID | `S-1-5-21-…-512`, probably an existing AD object |
| id: GUID | probably an existing AD or Entra ID object |
| id: unknown (dangling) | only resolves if a node with that id already exists in the tenant |

References are also grouped by **target group**: the domain from `NAME@DOMAIN` or `HOST.DOMAIN`, the domain part of a SID, or the edge's `domain` property.

### 6. Graph structure
Isolated nodes, connected components, edges per node, environment / `environmentid` coverage, and the highest-degree nodes.

### 7. Reachability into external targets
- **Targets:** external endpoints reached by a traversable edge (narrow these with `-TierZeroFile`)
- **Origins:**
  - schema principal kinds, or every node with outgoing edges if there's no schema
  - external entry points, i.e. existing nodes that point *into* the payload
- **Origin → target pairs:** totals and a per-target-group breakdown
- **Top origins**, including those with **no inbound edges**. Such a node still counts as a principal in BloodHound, so it can create findings even though nothing points at it.
- **What-if:** removes each edge kind in turn and counts the paths that disappear. This shows which kinds the paths depend on.
- **Chokepoints:** nodes and edges ranked by *origins reaching them × targets reachable from them*. On very large graphs this is estimated from the 2,000 origins with the widest reach, and the report says so.

### 8. Baseline comparison (with `-BaselinePath`)
- Node and edge count changes by kind
- New and removed edges, matched on kind + start + end
- Paths lost when only the **new** edges of each kind are removed, i.e. what the new data added

### Key findings
An automatic summary of the errors, the biggest warnings, the largest kinds, isolated nodes, fan-out hotspots, external references, the most exposed target group, no-inbound origins, the edge kinds paths depend on, and the biggest chokepoint.

---

## Reading the report

```
Status : FAIL - errors that will reject the upload or break ingest
```
Fix every **ERROR** before uploading. Section 1 has an example for each one.

```
WARN dangling 120 end id not defined in this file ...
```
These edges only resolve if the referenced node already exists in BloodHound, for example an AD object you collected separately. If it doesn't exist, the edge is dropped at ingest.

```
Origin with no inbound edges reaching 611 external targets: SVC_PROVIDER [Acme_User]
```
A principal can create findings without any inbound path. If this is an infrastructure or service identity that legitimately holds that access, consider classifying it as Tier Zero.

```
Paths into external targets depend most on: Acme_HasAccessTo (95%), Acme_MemberOf (93%)
```
Kinds near 100% sit on almost every path. When you're investigating a *change*, the baseline section (8) is more precise.

---

## Output files

All files are written to `-OutputFolder`.

| File | Contents |
|---|---|
| `Report.txt` | The full console report |
| `validation.csv` | Every validation issue: severity, check, count, detail, example |
| `node_kinds.csv` | Node counts per kind, property counts, missing names, duplicate names, `environmentid` coverage |
| `edge_kinds.csv` | Edge counts per kind, traversability, hybrid count, fan-out |
| `edge_patterns.csv` | `StartKind -[EdgeKind]-> EndKind` counts |
| `properties.csv` | Coverage % and data types for every property of every node and edge kind |
| `hybrid_edges.csv` | External references by edge kind, match type and target group |
| `top_degree_nodes.csv` | Most-connected nodes |
| `target_groups.csv` | Origin → target pairs per target group |
| `origins.csv` | Every origin with the number of targets it reaches and its inbound edge count |
| `targets.csv` | Every external target with the number of origins reaching it |
| `whatif_edge_kinds.csv` | Paths lost when each edge kind is removed, per target group |
| `top_nodes.csv` / `top_edges.csv` | Chokepoint nodes and edges |
| `edge_kinds_vs_baseline.csv` | Edge count changes (with `-BaselinePath`) |
| `new_edges_vs_baseline.csv` | Every new edge (with `-BaselinePath`) |
| `cypher_queries.txt` | Ready-to-run Cypher for the tenant (see below) |

### Cypher queries

`cypher_queries.txt` contains queries tailored to the payload:
- a sample of each edge kind
- isolated nodes per kind
- the largest fan-out nodes
- hybrid edges into existing nodes
- outbound paths from the top origins
- inbound and outbound edges of each chokepoint
- Tier Zero reached from the source kind

All queries return **whole nodes or paths** (`RETURN n` / `RETURN p`), so they run in the BloodHound Enterprise Cypher editor. Read property values in the entity panel.

Things to know when running them:
- BloodHound stores the payload node `id` as the **`objectid`** property, and uppercases `name` and `environmentid` at ingest.
- Newer tenants mark Tier Zero with the `Tag_Tier_Zero` label. On older tenants, use `COALESCE(n.system_tags,'') CONTAINS 'admin_tier_0'` instead.

---

## Examples

**Validate a new collector's output before the first upload**
```powershell
.\Test-OpenGraphJson.ps1 -Path .\acme_output.json -SkipPathAnalysis
```

**Full analysis with the extension schema**
```powershell
.\Test-OpenGraphJson.ps1 -Path .\acme_output.json -SchemaPath .\acme_schema.json
```

**Explain why findings went up after a new collection**
```powershell
.\Test-OpenGraphJson.ps1 -Path .\acme_new.json -BaselinePath .\acme_last_month.json -SchemaPath .\acme_schema.json
```

**Only count paths that land on Tier Zero**
```powershell
# tier0.txt: one name per line, as shown in BloodHound (e.g. DOMAIN ADMINS@CORP.LOCAL)
.\Test-OpenGraphJson.ps1 -Path .\acme_output.json -SchemaPath .\acme_schema.json -TierZeroFile .\tier0.txt
```

**No schema, but some edge kinds are informational only**
```powershell
.\Test-OpenGraphJson.ps1 -Path .\acme_output.json -NonTraversable Acme_CreatedBy,Acme_LastUsed
```

---

## Limitations

- **Offline analysis only.** The script cannot see what already exists in your tenant. It can't tell whether a dangling id or name-matched target actually resolves, whether a target is Tier Zero (unless you pass `-TierZeroFile`), or which extension schemas are installed.
- **Traversability is assumed without a schema.** Without `-SchemaPath`, path counts treat every edge as traversable (except post-processed kinds and `-NonTraversable`). Supply the schema for results that match BloodHound.
- **Path counts are indicators, not findings.** The script counts origin → target pairs through the payload. BloodHound Enterprise findings use their own logic (zones, environments, finding types), so expect the same *direction* and the same *drivers*, not identical numbers.
- **Paths stop at the payload boundary.** Reachability ends at external endpoints. It doesn't follow AD or Entra ID edges beyond the nodes the payload points at.
- **Built-in kind lists are not exhaustive.** Overlap checks use common AD and Entra ID kinds plus the documented post-processed edges.
- **Memory.** Very large payloads (hundreds of MB) need a correspondingly large amount of RAM. Use PowerShell 7.

---

## References

- OpenGraph data payloads: <https://bloodhound.specterops.io/opengraph/developer/graph-data>
- Nodes: <https://bloodhound.specterops.io/opengraph/developer/nodes>
- Edges: <https://bloodhound.specterops.io/opengraph/developer/edges>
- Metadata: <https://bloodhound.specterops.io/opengraph/developer/metadata>
- Extension definition schema: <https://bloodhound.specterops.io/opengraph/developer/graph-definition>
- Graph theory background: <https://bloodhound.specterops.io/opengraph/developer/graph-theory>
