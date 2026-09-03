# Celaut Node-Honesty Verifier

This turns the passive `demo-service` into an **active verifier** that checks
whether the nodo node it is running on is *honest*. It reuses the existing
`tiny` / `heavy` / `ping` child scaffolding and the `node_controller` library —
nothing was rewritten from scratch.

An honest node must:

1. **Isolate networks** — a child may only reach the egress it *declared*; an
   undeclared destination must be blocked.
2. **Enforce the memory ceiling it charged for** — a child may use up to the
   `at_most.mem_limit` it declared, and past that boundary the allocation must
   fail (not before → shortchanging, not far beyond → the ceiling it billed is a
   lie). *How* it fails depends on the isolation model — see probe 2.
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

### Child readiness — the node's "ready" is not the service's "ready"

Every probe that drives a child waits for that child's port to accept a TCP
connection before it asserts anything.

The node reports an instance ready once the **guest network** answers, which it
learns by pinging the guest IP. Under a microVM the guest kernel brings that IP
up during boot, seconds before the service inside it binds its port; the node's
own log names the gap: `instance registered before the guest could call in`. A
request sent into that gap is refused by a guest that is perfectly healthy, and
the refusal is indistinguishable from a dead child unless someone waits.

`_spin_child` therefore returns only once `_wait_until_ready` has seen the port
open, and raises `ChildNotReadyError` — mapped to `INFRA_ERROR`, never to an
accusation — if it never does. A bare `connect` is the right probe for this: the
port opens exactly when the service binds it, and it costs no application work,
so it cannot perturb what the probe goes on to measure.

That wait is also what makes later failures readable. Once the port is proven
open, a request that dies is a child that died **in flight** — which is the
genuine kill signal the memory-ceiling ladder needs. Without it, the ladder
cannot tell an OOM from a boot.

`CHILD_READY_TIMEOUT_S` (default 120) and `CHILD_READY_POLL_S` (0.5) tune the
wait.

### Children are stopped, not abandoned

Each probe hands every child it spins to `_release_child` in a `finally`.

node_controller's contract is that a taken instance is either returned to its
queue or stopped — its own source says a leaked one "remain[s] as zombies on the
network until the service is removed". Beyond the leak, an abandoned child keeps
drawing MU from *this* service's balance, and that balance is what
`mu_accounting` measures: enough abandoned children swamp the difference its two
windows exist to compare. A verifier that leaks children measures its own litter.

### 0. Gateway reachability (preflight)

Every other probe needs the node's gRPC gateway. When it is unreachable, the
honest answer is "I could not verify this node", said **once** — not six probes
each timing out separately and each writing its own wrong conclusion from the
same silence. The preflight checks L4 (`socket.create_connection`) first, so it
can separate "nothing is listening / packets dropped" from "gateway up but the
RPC misbehaves", then does one real `ModifyServiceSystemResources` round-trip.

A failed round-trip is `INFRA_ERROR` either way, but the report always says
**which side failed**, because the two send an operator to opposite places:

| `fault` | what happened | where to look |
|---|---|---|
| `transport` | nothing answered: no route, closed port, RST, `UNAVAILABLE`, `DEADLINE_EXCEEDED` | the host firewall / the guest → gateway path |
| `node_rpc` | the gateway **answered**, with an error status of its own (any other `StatusCode`) | the node's own log for that RPC — the port is proven reachable |
| `unknown` | no gRPC status in the exception at all | neither side can be blamed from this evidence |

An error reply is proof of reachability: only a reachable gateway can send one.
So a `node_rpc` fault is never reported as an unreachable gateway, and the node's
own `details = "..."` text is surfaced verbatim as `node_detail` — that string
names the RPC path that broke. `classify_rpc_failure` reads the status from a real
`grpc.RpcError` (`.code()`) or from the exception text, so it works with whatever
node_controller re-raises.

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

The ladder distinguishes four states per rung:

| rung state | what it means | decides a verdict? |
|---|---|---|
| `ok` | the child answered | yes |
| `killed` | the child's port was open and the request then died — it died in flight | yes |
| `launch_failed` | the child never existed | no |
| `never_ready` | it launched but never opened its port, so it was never seen allocating anything | no |

Only the first two can decide anything; if no rung ever produced a child that
answered, the probe returns `INFRA_ERROR`, because a ceiling that was never
measured cannot be called a lie. `never_ready` exists because the two failure
modes look identical at the socket: the readiness wait is what separates a guest
still booting from a child the node killed, and only the latter is evidence.

A ladder is also checked for **coherence** before any verdict: a `first_kill`
below a rung that succeeded does not locate a ceiling, since nothing can be
enforced below a request that went through. That combination yields
`INCONCLUSIVE` — the `PASS` branch reads only the highest success, and would
otherwise call an incoherent ladder correct.

#### What "kill" means under a microVM

`enforcement_mechanism` in the evidence records which mechanism was at work,
because the two are not the same event:

- container → `cgroup_oom_kill`: the cgroup's OOM killer reaps the offending
  process and the container survives.
- microVM → `guest_kernel_panic_no_oom_kill`: the child's entrypoint **is PID 1**,
  so the guest kernel has no killable process when an allocation exceeds the RAM
  the hypervisor assigned. It panics — `Attempted to kill init!` — and the whole
  guest goes down.

The ceiling is genuinely enforced either way: the allocation fails, and the child
never gets memory it did not pay for. But "the node OOM-kills the child at the
boundary" describes the container model only, and the evidence should not imply a
mechanism that was not the one at work.

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

### MU accounting (orchestrator)

`controller.modify_resources({min,max})` settles the account and returns this
service's current MU balance, so holding a ceiling across a fixed window and
sampling the balance at both ends measures what the node actually deducted. Two
equal windows are run — one at a LOW ceiling (64 MiB), one at the HIGH ceiling
this service declared — so the spend can be checked against *usage* rather than
merely against zero. An honest node must:

- **charge at all** — a zero spend at both ceilings is a free ride or broken
  metering;
- **charge more when it provisions more** — `spent_high >= spent_low`;
- **not take a funded balance to nothing inside one window**.

Three details keep each of those from misfiring:

**Debt is not overcharging.** The drain test is a *crossing*: `b0 > 0 >= b1`. A
balance that was already at or below zero when the window opened was not spent by
the node during it. Operators run nodes with `costs.ALLOW_DEBT` enabled, where a
negative balance is the configured policy and says nothing about what was
charged; testing only the closing balance accuses every node in debt for a drain
that predates the measurement. `started_in_debt` records the condition so a
reader can see it was considered and dismissed.

**A window too short to read cannot accuse.** `MU_MIN_DECISIVE_WINDOW_SECONDS`
(60) gates *every* accusing branch, not just the zero-spend one: a window too
coarse to tell a real charge from rounding is equally too coarse to price one
ceiling against another. Below it the probe returns `INCONCLUSIVE` and says to
raise `MU_WINDOW_SECONDS`. That default is 60 to match — a shipped window that
cannot decide makes every unconfigured run pay for two windows and then decline
to read them.

**Only this service's own ceiling may vary between the windows.** Which is why
every probe stops its children: each one left running keeps drawing MU from this
same balance, and enough of them swamp the difference the two windows exist to
measure. On the run that motivated this, the parent's balance fell by ~1.2e9 MU
during the suite — 12 abandoned `heavy` children at `initial_mu` 1e8 each, all
of them spun by the verifier itself.

### 4. Attestation report card

A full run drives every probe — including the memory-ceiling ladder and the two
`MU_WINDOW_SECONDS` MU-accounting windows — and can take minutes, so it runs as
a background job rather than inside one HTTP request:

- `POST /attestation.json` schedules a run (a no-op if one is already in
  flight) and returns immediately with the job status.
- `GET /attestation.json` polls that job: `{"status":"idle|running|done|error",
  "started_at":…, "finished_at":…, "result":…, "error":…}`. The report below is
  `result` once `status` is `"done"`:

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
  `probe_resource_provisioning`), child lifecycle (`_spin_child`,
  `_wait_until_ready`, `_release_child`), `build_attestation()` + content hash,
  the `/attestation.json`, `/probe/*` routes, and a report-card UI replacing the
  old prose HTML. Legacy demo endpoints are preserved.
- `heavy/src/main.rs` — `GET /alloc/<mb>` (touch-to-resident) and
  `GET /introspect`; the classic burst on `/` now returns JSON.
- `ping/src/main.rs` — reworked into the isolation probe; structured JSON
  verdicts derived from the node-provided allow-list.
- `ping/src/dns.rs` — `pub fn resolved_tags()` reusing the existing protobuf
  parser to surface the node-granted egress tags.

## Live validation against a real node

The first end-to-end run through a real nodo (`qemu` microVMs, arm64 guests) is
what the readiness wait, the child release, the ladder coherence check and the
debt-crossing rule all come from. Two instances of this service ran on the *same*
node and reported different verdicts — which is by itself proof that what was
being measured was the verifier, since two observers of one node cannot honestly
disagree about it. That run reported:

```json
{"summary": {"node_honest": null, "pass": 3, "dishonest": 1, "unobserved": 3,
             "total": 7, "attestable": false}}
```

Every one of those four non-`PASS` verdicts was the verifier's own:

| probe | reported | what was actually true |
|---|---|---|
| `mu_accounting` | `DISHONEST` | balance was already at −1.317e9 before the window opened (`ALLOW_DEBT`), and both windows were dominated by 20 children the run had abandoned |
| `network_isolation` | `INFRA_ERROR` | the `ping` child was still booting; it answered fine minutes later |
| `dependency_identity` | `INFRA_ERROR` | same, for all three dependencies |
| `dependency_observe` | `INCONCLUSIVE` | same, for `ping` |
| `memory_ceiling` | `PASS` | on self-contradictory evidence: `first_kill 64 MiB` with `observed_ceiling 240 MiB` |

The node's own log recorded no failure at all across the 32 microVMs the run
launched — only `instance registered before the guest could call in`, once per
VM, which is the race in one line.

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
