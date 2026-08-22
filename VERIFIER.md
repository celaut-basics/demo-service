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

Each observation becomes an explicit verdict with JSON evidence, and the results
are folded into an attestation **report card** with a content hash that is ready
to be submitted later as an EGO reputation opinion on-chain (the on-chain
submission itself is intentionally *not* implemented yet).

## Verdict taxonomy — absence of evidence is not evidence of dishonesty

This verifier's output is destined to become a permanent, public, non-retractable
accusation. So the distinction that must never blur is **observed misbehaviour**
vs **failure to observe**. A verifier that cannot measure must declare itself
blind; it must never accuse.

| Verdict | Meaning | Accuses? | Attestable? |
|---|---|---|---|
| `PASS` | behaviour observed and correct | no | yes |
| `DISHONEST` | behaviour observed and incorrect | **yes** | yes |
| `INFRA_ERROR` | could not observe (node/network fault) | no | **no** |
| `NOT_APPLICABLE` | probe does not apply to this environment | no | no |
| `INCONCLUSIVE` | ran, but the result is not decidable | no | **no** |

`FAIL` no longer exists as a verdict: it was ambiguous at exactly the point where
ambiguity is most expensive. Any launch failure, timeout or crash now maps to
`INFRA_ERROR`, never to an accusation.

Two consequences follow:

- `summary.node_honest` is **tri-state** (`true` / `false` / `null`). `null` means
  "could not verify" and is never rendered as guilt.
- The attestation hash is **only minted when every probe reached a conclusive
  verdict** (`summary.attestable`). Otherwise `content_hash.value` is `null` with
  a note explaining which probes were blind. There is no path from an incomplete
  observation to an on-chain opinion.

## The probes

| # | Probe | Child | Asserts |
|---|-------|-------|---------|
| 0 | `gateway_reachability` | orchestrator (self) | **preflight**: TCP + a real RPC round-trip to the node's gRPC gateway. If it fails, every gateway-dependent probe is skipped as `INFRA_ERROR` instead of inventing its own conclusion |
| 1 | `network_isolation` | `ping` | declared egress (google) **succeeds** AND an undeclared one (amazon) is **blocked** |
| 2 | `memory_ceiling` | `heavy` | allocation up to just under the declared `at_most` (256 MiB) succeeds; past it the node OOM-kills **at** the declared boundary |
| 3 | `resource_provisioning` | orchestrator (self) | node-reported/charged memory matches the ceiling the guest really got |
| 4 | `dependency_identity` | all | the dependency requested is the dependency that actually ran |
| 5 | `dependency_observe` | `ping` | the node's `Observe` stream independently corroborates the dependency's connectivity |
| 6 | `mu_accounting` | orchestrator (self) | the node spends MUs in line with the resources it provisions |
| 7 | `attestation` | orchestrator | per-probe verdict + `sha3_256` content hash, as JSON and HTML |

### 0. Gateway reachability (preflight)

Every other probe needs the node's gRPC gateway. When it is unreachable, the
honest answer is "I could not verify this node", said **once** — not six probes
each timing out separately and each writing its own wrong conclusion from the
same silence. The preflight checks L4 (`socket.create_connection`) first, so it
can separate "nothing is listening / packets dropped" from "gateway up but the
RPC misbehaves", then does one real `ModifyServiceSystemResources` round-trip.

`resource_provisioning` is deliberately **not** gateway-dependent: it only reads
`/proc` and `/__config__`, so it stays valid — and can legitimately `PASS` — even
with the gateway down. A report saying *"gateway unreachable; the only thing I
could measure locally is correct"* is exactly what an operator needs.

Exposed as `GET/POST /probe/gateway` and as the MCP tool
`probe_gateway_reachability`.

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

The ladder distinguishes three states per rung: `ok` (the child answered),
`killed` (the child existed and died — genuine ceiling evidence) and
`launch_failed` (the child never existed — evidence of *nothing*). Only the
first two can decide a verdict; if no rung ever produced a running child the
probe returns `INFRA_ERROR`, because a ceiling that was never measured cannot be
called a lie.

### 3. Resource provisioning (orchestrator)

The node runs services either in **containers** (docker) or in **microVMs**
(cloud-hypervisor / qemu). Those enforce a memory ceiling by different
mechanisms, so the probe detects the isolation model and picks the matching
source of truth:

- container → `/sys/fs/cgroup/memory.max` (v2, v1 fallback);
- microVM → `/proc/meminfo` `MemTotal`, because there is **no cgroup at all**:
  the hypervisor sizes the guest's RAM, and that size *is* the ceiling.

The result is compared against `get_mem_limit_at_start()`; a ratio `< 0.95` is
shortchanging. Under a microVM `MemTotal` is always slightly below the assigned
RAM (the guest kernel reserves structures) — the 0.95 threshold already absorbs
that margin. `ceiling_source` in the evidence records which mechanism was read.
The `heavy` child's `/introspect` reports the same pair (`ceiling_bytes`,
`ceiling_source`) so the orchestrator never has to guess.

### 4. Attestation report card

`GET /attestation.json` runs all probes and returns:

```json
{"summary":{"node_honest":true,"observation_complete":true,"attestable":true,
            "pass":7,"dishonest":0,"unobserved":0,"total":7},
 "content_hash":{"alg":"sha3_256","value":"…"}}
```

The hash is taken over the canonical `{probe:verdict}` + summary payload (no
timestamps), so identical observed behaviour always hashes identically. When any
probe is blind, the report degrades instead:

```json
{"summary":{"node_honest":null,"observation_complete":false,"attestable":false,
            "pass":1,"dishonest":0,"unobserved":6,"total":7},
 "content_hash":{"alg":"sha3_256","value":null,
   "note":"NOT ATTESTABLE: 6 of 7 probes could not observe the node …"}}
```

`GET /` renders the same report as an HTML report card, with three states —
`HONEST` / `DISHONEST` / `UNVERIFIED` — and `UNVERIFIED` deliberately **not**
painted in the dishonest colour: an unverified node is not a guilty node.

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

## Reproducibility

`.service/Dockerfile` pins every input: the base image by digest, `requests` and
`Flask` by version, and `celaut-service-libraries` by commit SHA. This service is
content-addressed, so an unpinned `git+…` install (which resolves to whatever
`master` happened to be that day) means two packs of the same source tree produce
different images — and any bug observed in a running instance cannot be traced
back to a specific library revision.

## Live validation

> **Caveat.** The validation below was performed by running the packed child
> images **directly under docker**, not through a nodo node. It therefore
> exercises the container isolation model only. In particular the claim that
> `cgroup memory.max` reflects the node's provisioning **does not hold inside a
> microVM** (`ch` / `qemu`), where no cgroup exists at all — see probe 3 above,
> which is why isolation-model detection was added. The first end-to-end run
> against a real node, and the eight defects it exposed, are documented in
> `FINDINGS-2026-08-22.md` (PR #2).

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
