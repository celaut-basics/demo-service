# Celaut Node-Honesty Verifier

This turns the passive `demo-service` into an **active verifier** that checks
whether the nodo node it is running on is *honest*. It reuses the existing
`tiny` / `heavy` / `ping` child scaffolding and the `node_controller` library —
nothing was rewritten from scratch.

An honest node must:

1. **Isolate networks** — a child may only reach the egress it *declared*; an
   undeclared destination must be blocked.
2. **Enforce the memory ceiling it charged for** — a child may use up to the
   `at_most.mem_limit` it declared, and the node must OOM-kill it *at* that
   boundary (not before → shortchanging, not far beyond → the ceiling it billed
   is a lie).
3. **Provision what it billed** — what the manifest declared and the node
   charged (`initial_mu`, `get_mem_limit_at_start()`) must match what the
   container actually gets (cgroup + `/proc/meminfo`).

Each observation becomes an explicit `PASS`/`FAIL` assertion with JSON evidence,
and the results are folded into an attestation **report card** with a
content hash that is ready to be submitted later as an EGO reputation opinion
on-chain (the on-chain submission itself is intentionally *not* implemented yet).

## The four probes

| # | Probe | Child | Asserts |
|---|-------|-------|---------|
| 1 | `network_isolation` | `ping` | declared egress (google) **succeeds** AND an undeclared one (amazon) is **blocked** |
| 2 | `memory_ceiling` | `heavy` | allocation up to just under the declared `at_most` (256 MiB) succeeds; past it the node OOM-kills **at** the declared boundary |
| 3 | `resource_provisioning` | orchestrator (self) | node-reported/charged memory matches the container's real cgroup `memory.max` |
| 4 | `attestation` | orchestrator | per-probe verdict + `sha3_256` content hash, as JSON and HTML |

### 1. Network isolation (`ping/`)

`ping/.service/service.json` declares an egress allow-list of **only** google.
`ping/src/main.rs` also tries amazon, which is **not** declared. The probe reads
the node-provided allow-list from `/__config__` (the `NetworkResolution` entries,
decoded by the existing `dns.rs` parser — now exposed via `dns::resolved_tags()`)
instead of hardcoding it, then emits per target:

```json
{"target":"amazon.com","declared":false,"connected":true,"verdict":"DISHONEST_LEAK"}
```

Verdict matrix: `declared&&connected`→`honest_allowed`,
`!declared&&!connected`→`honest_blocked`, `!declared&&connected`→`DISHONEST_LEAK`,
`declared&&!connected`→`BROKEN_DENIED`.

### 2. Memory ceiling (`heavy/`)

New endpoint `GET /alloc/<mb>` allocates **and touches** `<mb>` MiB (writing one
byte per page defeats lazy/overcommit so the RSS is real), holds briefly, frees.
The orchestrator ramps the request toward and past the declared 256 MiB. The
highest success and the first OOM-kill locate the *observed* ceiling, compared to
the declared one. `GET /introspect` reports the container's real cgroup limits.

### 3. Resource provisioning (orchestrator)

Reads `/sys/fs/cgroup/memory.max` (v2, with a v1 fallback), `cpu.max` and
`/proc/meminfo` and compares them against `get_mem_limit_at_start()` and the
`initial_mu` charged for the heavy child. A ratio `< 0.95` is shortchanging.

### 4. Attestation report card

`GET /attestation.json` runs all probes and returns:

```json
{"summary":{"node_honest":true,"pass":3,"fail":0,"total":3},
 "content_hash":{"alg":"sha3_256","value":"…"}}
```

The hash is taken over the canonical `{probe:verdict}` + summary payload (no
timestamps), so identical observed behaviour always hashes identically. `GET /`
renders the same report as an HTML report card.

## Files changed

- `app.py` — probe battery (`probe_network_isolation`, `probe_memory_ceiling`,
  `probe_resource_provisioning`), `build_attestation()` + content hash, the
  `/attestation.json`, `/probe/*` routes, and a report-card UI replacing the old
  prose HTML. Legacy demo endpoints are preserved.
- `heavy/src/main.rs` — `GET /alloc/<mb>` (touch-to-resident) and
  `GET /introspect`; the classic burst on `/` now returns JSON.
- `ping/src/main.rs` — reworked into the isolation probe; structured JSON
  verdicts derived from the node-provided allow-list.
- `ping/src/dns.rs` — `pub fn resolved_tags()` reusing the existing protobuf
  parser to surface the node-granted egress tags.

## Live validation

Full nodo-orchestrated packing on the test box was blocked by a `bee_rpc`
format skew between the only available packer (`packer-service:10gb`, built
2026-07-18) and the installed nodo (`5a79ec54`): that packer emits single-block
`.celaut.bee` artifacts, while this nodo's importer expects the two-block
`{Metadata, Service}` layout, so `nodo pack`/import fails at
`service_dir = next(it)` — **identically for the unmodified `tiny` service**, so
it is a tooling/version mismatch, not a defect in this change.

Each probe was therefore validated against the **same kernel mechanisms nodo
delegates to** — cgroup memory limits and egress control — by running the packed
child images directly:

- **memory_ceiling** — `heavy` under `--memory=256m --memory-swap=256m`:
  64/128/200/240 MiB → HTTP 200; 256/280/320/400 MiB → OOM-killed (connection
  dropped). Observed ceiling 240 MiB, first kill 256 MiB vs declared 256 MiB →
  **PASS**. `/introspect` reported `cgroup_mem_max = 268435456` (256 MiB).
- **network_isolation** — `ping` with a crafted `/__config__` declaring google:
  - honest node (amazon → `127.0.0.1`): google `honest_allowed`, amazon
    `honest_blocked`, `honest:true` → **PASS**.
  - leaky node (unrestricted egress): google `honest_allowed`, amazon
    `DISHONEST_LEAK`, `honest:false` → correctly **flags the leak**.
- **resource_provisioning** — the container's real `cgroup memory.max` matched
  the declared limit (ratio 1.0) → **PASS**.

Example assembled report card:

```json
{
  "verifier": "celaut-node-honesty-verifier",
  "summary": {"node_honest": true, "pass": 3, "fail": 0, "total": 3},
  "content_hash": {"alg": "sha3_256",
    "value": "b5b22156fcb28125e480e98b7dcd8d3f42f8f5118de4aa70d9a7a9bb62520915"}
}
```
