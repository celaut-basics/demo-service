# Celaut Node-Honesty Verifier

This turns the passive `demo-service` into an **active verifier** that checks
whether the nodo node it is running on is *honest*. It reuses the existing
`tiny` / `heavy` / `ping` / `benchmark` / `sharefs` child scaffolding and the `node_controller` library —
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
4. **Keep the sharing rules** — a directory a service exports is visible to its
   own children, both ways and read-only where they asked for it, and to no one
   else: a child asking for a directory its parent does not export must be
   refused at launch.

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
| 6 | `node_benchmark` | `benchmark` | the node's per-core benchmark runs under its declared architecture and measures every primitive; the scores travel as evidence |
| 7 | `shared_filesystem` | `sharefs`, `sharefs-denied` | the directory this service exports is shared with its child in both directions, a read-only mount refuses a write, and a child asking for a share its parent does not export is refused at launch |
| 8 | `mu_accounting` | orchestrator (self) | the node spends MUs in line with the resources it provisions |
| 9 | `attestation` | orchestrator | per-probe verdict + `sha3_256` content hash, as JSON and HTML |

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

`ping/<arch>/.service/service.json` declares an egress allow-list of **only** google.
`ping/src/main.rs` also tries amazon, which is **not** declared. The probe reads
the node-provided allow-list from `/__config__` (the `NetworkResolution` entries,
decoded by the existing `dns.rs` parser, exposed through `dns::resolved_tags()`)
instead of hardcoding it, then emits per target:

```json
{"target":"amazon.com","declared":false,"method":"tcp_connect","connected":true,"verdict":"DISHONEST_LEAK"}
```

Verdict matrix: `declared&&connected`→`honest_allowed`,
`!declared&&!connected`→`honest_blocked`, `!declared&&connected`→`DISHONEST_LEAK`,
`declared&&!connected`→`BROKEN_DENIED`.

The two targets are tested in two ways, because only google can be reached by name:

- **google (declared)**: an HTTPS request to the name. The in-guest DNS answers it
  with an address the node granted.
- **amazon (undeclared)**: a TCP connection to port 443 of its addresses. The in-guest
  DNS serves only the tags the node granted, so a request to the *name* fails inside
  the guest, before any packet meets the firewall. That "block" would prove nothing.

The verifier declares both google and amazon in its own `service.json`. A child gets
only the networks that every ancestor declares too, and the node resolves the amazon
addresses for the verifier. The verifier passes them to `ping` in the
`UNDECLARED_ADDRS` variable (declared in `ping`'s `envs`). Without an address the
target is `UNTESTED`, never "blocked".

The verifier also opens a connection to both targets itself, as a control. A block
that nothing could pass proves nothing:

| child result | control | verdict |
|---|---|---|
| amazon reachable | any | `DISHONEST` (leak) |
| google denied | verifier reached google | `DISHONEST` (shortchanged) |
| google denied | verifier did not reach it | `INCONCLUSIVE` (target down) |
| amazon blocked, or `UNTESTED` | verifier did not reach amazon | `INCONCLUSIVE` |
| google allowed, amazon blocked | verifier reached amazon | `PASS` |

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
service's current MU balance, so holding a ceiling across a window and sampling
the balance at both ends measures what the node actually deducted. Three windows
are run — LOW (64 MiB), HIGH (the ceiling this service declared), LOW again — so
the spend can be checked against *usage* rather than merely against zero. An
honest node must:

- **charge at all** — a zero spend in every window is a free ride or broken
  metering;
- **charge more when it provisions more** — the HIGH rate must not fall below the
  LOW rate by more than this run's own noise;
- **not take a funded balance to nothing inside one window**.

**Scaling is a weak signal, so it is read as a rate against measured noise.**
Every instance pays for its vCPU at both ceilings, so on a default node memory is
only ~10-15% of the bill. Two single windows compared with `spent_high >=
spent_low` called an honest node `DISHONEST` at startup (216 090 MU low vs
184 932 MU high over 60 s) while every later run of the same node passed
(~145k low vs ~164k high). Now:

- each window's spend is divided by the time it **really** lasted (the settle
  RPCs alone take 0.5-0.7 s, and not the same each time) → `rate_*_mu_per_s`;
- the two LOW windows bracket the HIGH one; their average is the LOW rate and
  their disagreement is the run's noise (`low_window_noise`);
- `HIGH >= LOW` is `PASS`; a shortfall inside `max(MU_SCALING_TOLERANCE,
  2 × noise)` (`accusation_margin`, floor 5%) is `INCONCLUSIVE`; only a shortfall
  beyond it is `DISHONEST`.

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
cannot decide makes every unconfigured run pay for its windows and then decline
to read them.

**Only this service's own ceiling may vary between the windows.** Which is why
every probe stops its children: each one left running keeps drawing MU from this
same balance, and enough of them swamp the difference the windows exist to
measure. On the run that motivated this, the parent's balance fell by ~1.2e9 MU
during the suite — 12 abandoned `heavy` children at `initial_mu` 1e8 each, all
of them spun by the verifier itself.

### Dependency observe (`ping`)

The probe opens the node's `Observe` stream on the `ping` child **before**
driving it, waits up to `OBSERVE_ARM_SECONDS` (5) for the stream's first event,
then calls `ping` and keeps observing `OBSERVE_SECONDS` (12) more.

`ping` only makes traffic while it serves `GET /`. The stream used to be opened
after that request had returned, so it could see at most the tail of a closed
connection: 2 packets on one run, 25 on another — and none on a third, where the
stream's own session event counted as "proof of life" and an honest node was
reported as fabricating connectivity. Silence is now an accusation only when the
stream was demonstrably live **before** the drive (`observe_armed_before_drive`);
a stream that only woke up afterwards is `INCONCLUSIVE`.

Two more rules keep this probe from accusing without evidence:

- **A leak is a packet that comes IN from an undeclared address.** The child tries
  the undeclared target on purpose, so the packet going OUT is the test itself, and
  the capture shows it even when the node drops it. Each packet carries `peer_kind`,
  `peer_host` and `direction` (`ObserveEvent.Packet`).
- **A degraded capture is not a verdict.** When the node cannot capture packets (no
  `AF_PACKET`: the session has a `degraded_reason`, or a notice has `degraded`), an
  empty feed is what the node promised. The result is `INCONCLUSIVE`.

### Node benchmark (`benchmark/`)

`benchmark` is the service a node runs as its `benchmark` core service
(see `benchmark/README.md`); it is packed as a dependency of this demo
(`BENCHMARK` in `<arch>/.service/pack_config.json`) and launched like the other
children, so every run of the suite also runs it. `dependency_identity` checks
it at `/cgi-bin/whoami` (busybox httpd only runs CGIs under `/cgi-bin/`), and
`node_benchmark` calls `/cgi-bin/benchmark` and records the scores as evidence.

There is no declared speed to hold a node against, so the scores never decide
a verdict. What a run *can* prove is which image ran: a guest's `uname -m` is
the architecture of the image it booted, QEMU+TCG included, so a benchmark
declared for this instance's own architecture (`BENCHMARK_DECLARED_ARCH`, read
from `uname -m`: the demo and its children are packed together from one
`arm64/` or `amd64/` tree) that reports another architecture is a substituted
service — `DISHONEST`. A run that never started
or never answered (`BENCHMARK_TIMEOUT_S`, 180 s) is `INFRA_ERROR`; a refused run,
a missing architecture or an unmeasured primitive is `INCONCLUSIVE`.

### Shared filesystem (`sharefs/`, `sharefs-denied/`)

A shared directory is a communication channel between a parent and its direct
children, so a node that lets anyone else reach it breaks the isolation
`Service.Network` otherwise provides. The rules (`docs/SHARED_FILESYSTEMS.md` in
nodo) are: `shared` belongs to the instance whose image contains the directory,
`guest` can only be exercised by that instance's direct children, and a service
that declares an inherited directory it was never granted **cannot run**: the
node must refuse the launch before anything is spent.

This service exports two directories (`shared_filesystems` in its
`service.json`), and the probe has two halves.

| | child | declares | an honest node |
|---|---|---|---|
| **granted** | `sharefs` | `guest` for `demo-share` at `/mnt/from-parent` (rw) and `demo-share-ro` at `/mnt/readonly` (ro) | launches it; both shares work |
| **denied** | `sharefs-denied` | `guest` for `demo-share-not-exported` at `/mnt/not-granted` | **refuses to launch it** |

The children mount the shares at paths different from the parent's
(`/shared`, `/shared-ro`), so what matches the two ends is the tag, never the
location.

**Granted.** Before the child runs, this service writes a random nonce into
`/shared` and another into `/shared-ro`, and clears what an earlier run left.
`sharefs` (`GET /probe?nonce=…`) reads the first, writes its own, and tries to
write to the read-only mount. The child only *reports*: this service holds the
other end of the share, so it checks the claims against what really landed on
disk instead of taking the child's word.

- the child read the parent's nonce → parent → child works;
- the child's nonce shows up in `/shared` (polled for
  `SHARE_PROPAGATION_TIMEOUT_S`, 10 s) → child → parent works;
- the child read the read-only seed → the exporter's content reaches the mount;
- the child's write to `/mnt/readonly` failed **and** its file is absent from
  `/shared-ro` → the read-only mount held. The absence on this side is what
  proves it: a child that says "refused" while its file is there is `DISHONEST`.

**Denied.** `sharefs-denied` is requested on purpose. The pass is the node's own
refusal, which reads `cannot inherit '/mnt/not-granted': …` and is matched on
exactly that path. Any other launch failure — no balance, a timeout, a crash, a
client library that lost the node's text — says nothing about the node's rules
and is `INFRA_ERROR`, never a pass: counting any failure to launch as "the node
said no" would let a broken node pass this half. If the node *does* launch it,
the child reports its mount plan and `/proc/mounts`; a share attached at
`/mnt/not-granted` is `DISHONEST`.

| observation | verdict |
|---|---|
| shared both ways, read-only held, denied child refused | `PASS` |
| the child's mount plan lists the shares but it cannot see the parent's data, the parent cannot see the child's, or the read-only mount shows no seed or accepts a write | `DISHONEST` |
| `sharefs-denied` launched with a share attached at `/mnt/not-granted` | `DISHONEST` |
| this service cannot write its own exported directory, a child never launches or answers, no balance, a transport failure, a launch failure that is not the share's refusal | `INFRA_ERROR` |
| a child launched with **no mount plan** (or one missing a share), the node refused the *granted* share, `sharefs-denied` launched with nothing mounted, or an answer that is not the child's report | `INCONCLUSIVE` |

Observed violations outrank halves that could not be observed, as in
`dependency_identity`.

**What the probe cannot see.** Whether the *packed* specs carry the share
declarations. The packer writes the `shared`/`guest` xattrs from
`service.json → shared_filesystems`; a nodo whose packer does not know the field
drops it **without an error**, and the packed children then launch with nothing
mounted — exactly what they would do on a node that skipped the mount. A guest
cannot tell the two apart, so every such case is `INCONCLUSIVE` (and so not
attestable), never `DISHONEST`, and the reason names the cause. The cost is that
a node that really does drop shares reads `INCONCLUSIVE` rather than
`DISHONEST` until the declarations can be verified from here.

**Requires** a nodo whose packer supports `shared_filesystems`. That is nodo
`dev` from commit `698e658` on
([celaut-project/nodo#475](https://github.com/celaut-project/nodo/pull/475),
which closes [#474](https://github.com/celaut-project/nodo/issues/474)). The
manifests use the field names that #475 accepts: `path`, `role`, `tag` and
`access` (`_SHARED_ENTRY_FIELDS` in `src/packers/zip_with_dockerfile.py`). That
packer refuses an unknown field, and it fails the pack when a declared
directory is not in the image, so each Dockerfile creates its directories.
`tests/test_shared_filesystem.py` holds the manifests, the constants in `app.py`
and the paths in the Rust sources to one another.

**Cost.** `sharefs` is funded like `tiny`. `sharefs-denied` is not in
`CHILD_DECLARED_RESOURCES` (it is never meant to start, and a child that is
never built would be owed to a starved run forever); it is registered at
`CHILD_MIN_INITIAL_MU`, enough for the probe to inspect it if a node does start
it. A share is not durable and lives as long as this instance: a restart gives a
new, empty one, which is why every run writes its own end first.

Exposed as `GET/POST /probe/shared_filesystem` and as the MCP tool
`probe_shared_filesystem`.

### 4. Attestation report card

A full run drives every probe — including the memory-ceiling ladder and the
three `MU_WINDOW_SECONDS` MU-accounting windows — and can take minutes, so it
runs as a background job rather than inside one HTTP request:

- `POST /attestation.json` (MCP `run_attestation`) schedules a run (a no-op if
  one is already queued or running) and returns immediately with the job status.
- `GET /attestation.json` (MCP `get_attestation`) polls that job:
  `{"status":"idle|queued|running|done|error|insufficient_funds|busy",
  "started_at":…, "finished_at":…, "result":…, "error":…, "funding":…}`. The
  report below is `result` once `status` is `"done"`:

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
Opening the page shows the last run; it no longer starts one, since every visit
used to spend MU on a fresh attestation and collide with the startup suite.

**One suite at a time.** Every probe spins children on this instance's balance,
and `mu_accounting` measures that balance, so two runs at once doubled the spend
and fed one run's children into the other's MU windows. Anything that spins a
child or moves this instance's resources takes one lock (`exclusive()`): the
startup suite waits for it, while an attestation, a single probe (HTTP `409`)
or an MCP call gets `busy` and the name of what is running.
`probe_resource_provisioning` only reads local files and may run beside a suite.

## Funding the instance

Every child is paid for out of **this** instance's balance: the node charges the
parent `BUILD_MU` (10 000 000 on a default node) the first time a child is built,
plus the child's `initial_mu`, and refunds whatever the child did not spend when
it is stopped. The node itself funds this instance for
`deposits.INITIAL_RUNTIME_HOURS` of its own resources — about 14e6 MU on a
default node.

The children used to ask for a flat 2e8-5e8 MU each (`HEAVY_INITIAL_MU` etc.):
35× what funds this whole instance for an hour. Every launch of a freshly
executed verifier was refused (`Insufficient balance … needed 0.51 ERG`), its
startup suite reported five `INFRA_ERROR`s, and it never tried again. Now:

1. **Children are funded for minutes, not days.** On the first suite the
   verifier measures the rate the node really charges it (two settled balances,
   `FUNDING_RATE_SAMPLE_SECONDS` apart) and funds each child for
   `CHILD_FUNDED_SECONDS` (600) × `CHILD_BUDGET_MARGIN` (2) of the child's own
   resources, priced from that rate with the node's shipped RAM/vCPU/disk price
   ratios. The largest (`benchmark`, 2 GiB) comes to ~4e6 MU on a default node.
2. **The suite only starts once the balance covers it**: the largest child
   deposit (children run one at a time and are refunded), the suite's own upkeep
   (`SUITE_EXPECTED_SECONDS`), and `MIN_RESERVE_SECONDS` (900) of runtime left
   afterwards. On a node that has built the children before, the default funding
   of a new instance covers that, so the startup suite runs straight away.
3. **While short, it says so.** The startup suite sits in `waiting_for_funds`,
   showing the balance, what is required and the shortfall with the exact
   command; an attestation is refused as `insufficient_funds` instead of running
   into `INFRA_ERROR`s. `GET /status` (MCP `get_service_status`) shows the same.
4. **A refused launch is named.** When the node refuses to charge for a child,
   the probe's `INFRA_ERROR` says `INSUFFICIENT FUNDS` and quotes the node
   (`Launch service error charging …`) instead of a reason cut off at
   `Unable to l`. The rest of that run is skipped (`fault:
   "insufficient_funds"`) rather than launching children the node will refuse
   or spending three MU windows on a run that will be repeated. The startup
   suite then waits for the first builds
   (`BUILD_MU_ESTIMATE` per child not yet launched here) and runs again, up to
   `STARTUP_MAX_ATTEMPTS` (3).

Validated on a real node (`ch`, amd64): a fresh instance with no deposit
measured 3755 MU/s, needed 9.3e6 MU of the 12.3e6 it was given, and passed 8/8
on its first attempt with ~49 minutes of runtime left. The first suite on a node
that has never built the children costs four builds (~4e7 MU) on top, which the
default funding of one instance cannot cover; the verifier then reported
`waiting_for_funds` with the shortfall (3.69e7 MU), resumed by itself after the
top-up and passed 8/8:

```bash
nodo increase_deposit <instance> <amount>   # ui.DISPLAY_UNIT, ERG by default
```

Declaring a much larger `at_init` here to buy more auto-funding was deliberately
rejected: this manifest is also what other nodes and peers read to decide
whether they can host the service, and inflating it past what this Flask
orchestrator actually needs would misrepresent it — the honest lever is the
deposit, not the manifest.

## MCP interface

`POST /mcp` speaks JSON-RPC 2.0 (`initialize`, `tools/list`, `tools/call`). Every
tool returns its result both as text and as `structuredContent`, declares an
`outputSchema`, and is annotated `readOnlyHint` — the `get_*` tools and
`probe_resource_provisioning` are read-only; every other tool spends MU and says
so in its description.

| tool | HTTP route |
|---|---|
| `run_attestation` / `get_attestation` | `POST` / `GET /attestation.json` — the same job the page shows |
| `get_startup_tests` / `rerun_startup_tests` | `GET /startup_tests` / `POST /startup_tests/rerun` |
| `get_service_status` (`refresh`) | `GET /status`, `/current_balance`, `/memory_usage` |
| `probe_*` | `/probe/*` |

`ROUTE_MCP_TOOLS` in `app.py` is that table; `tests/test_mcp.py` fails when a
route has neither a tool nor a reason in `ROUTES_WITHOUT_MCP`, when the page
fetches a route without one, or when the MCP and the route return different
things.

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
- `.service/service.json` — `resources.at_init`/`at_most` raised (1 GiB/5 GiB
  → 2 GiB/8 GiB mem/disk) to give this orchestrator headroom for holding the
  probe suite's working set; see "Funding the instance" for why this is not
  the lever for `heavy`/`ping` launch costs.
- `app.py` — `debug=False` on `app.run()`: the Werkzeug interactive debugger
  is a remote-code-execution risk on a network-reachable service. Also raised
  `HEAVY_INITIAL_MU` and added `PING_INITIAL_MU` so each child survives its
  own probe traffic on its own balance instead of going into debt.

- `app.py` — MCP parity with the UI (`ROUTE_MCP_TOOLS`, `run_attestation` now
  starts the shared background job, `get_attestation`, `rerun_startup_tests`,
  `get_service_status`), one suite at a time (`exclusive()`), children funded
  from the measured rate and a startup suite gated on funds,
  `dependency_observe` arms the stream before driving `ping`, `mu_accounting`
  compares rates across LOW/HIGH/LOW windows against measured noise, launch
  errors quoted from the node's own `details`, `SELF_DECLARED_MEM_BYTES`
  corrected to the 2 GB the manifest declares.
- `tests/harness.py` (stubs shared by the suites), `tests/test_mcp.py`.
- **1.4.0 — shared filesystems.** `sharefs/` and `sharefs-denied/` (Rust, one
  pack root per architecture like the other children), the `shared_filesystem`
  probe in `app.py` (`probe_shared_filesystem`, `/probe/shared_filesystem`, the
  MCP tool, `DEP_IDENTITY` for `sharefs`), `shared_filesystems` and the
  `/shared`, `/shared-ro` directories in both parents' `.service/`, the two new
  `pack_config.json` dependencies, and `tests/test_shared_filesystem.py`.

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

## Packing: one tree per architecture

A Celaut service is one architecture (`service.json → architecture`, which nodo
passes to BuildKit as `--opt platform=`), so every service here is maintained
twice, by hand, and packed from the tree of the architecture wanted:

```sh
nodo pack arm64          # demo + tiny/heavy/ping/benchmark/sharefs/sharefs-denied, all linux/arm64
nodo pack amd64          # the same, all linux/amd64
nodo pack benchmark/amd64   # one service on its own
```

```
arm64/  amd64/                  the demo's pack roots
├── .service/                   Dockerfile, service.json, pack_config.json — per arch
├── app.py      -> ../app.py
└── tiny heavy ping benchmark sharefs sharefs-denied   -> ../<svc>/<arch>
<svc>/                          tiny, heavy, ping, benchmark, sharefs, sharefs-denied
├── src/ Cargo.* | bench.sh serve www/     shared source
└── arm64/  amd64/              the service's pack roots
    ├── .service/               per arch
    └── <sources>  -> ../<sources>
```

The shape follows from what `nodo pack <dir>` does (`src/packers/zip_with_dockerfile.py`): it
reads only `<dir>/.service/` (the name is fixed), copies `<dir>` to its cache **following symlinks**, and resolves each local
dependency as `<copy>/<path>` — so a dependency has to sit inside the pack root
(a `../tiny` would point outside the copy), and the shared sources reach each
root as symlinks that the copy turns into real files. `Dockerfile` and
`pack_config.json` are real files in each `.service/`, edited independently;
only `architecture` differs today. `tests/test_layout.py` checks the shape.

To run the verifier, pack the tree that matches the node, then start the id that
`nodo pack` prints (commands as in nodo's `docs/skill/SKILL.md`):

```sh
nodo pack amd64                     # prints the service id
nodo estimate <service id>          # memory guard limits and the balance it needs
nodo execute <service id>           # starts the verifier
nodo instances                      # shows its API address and balance
nodo increase_deposit <instance id> <amount>   # if the startup suite waits for funds
```

Why every Dockerfile builds for both architectures:

- **Every `FROM` is a multi-arch index** with `linux/amd64` and `linux/arm64`,
  pinned by the digest of that index: `python:3.11@sha256:7bd2bb…`,
  `busybox:1.37.0@sha256:bdf57e…`, `rust:1.86.0-bookworm@sha256:300ec5…`,
  `rust:1.88.0-bookworm@sha256:af306c…` (the two sharefs children: their
  `Cargo.lock` needs rustc 1.88), `gcr.io/distroless/cc-debian12@sha256:e5d81d…` and
  `debian:bookworm-slim@sha256:3783cc…` (checked against the registries on
  2026-10-05). BuildKit picks the entry for the requested platform, so one pin
  serves both.
- **Rust children build natively for the target**: `cargo build` without
  `--target` emits a binary for the builder stage's own platform, which is the
  target one. `ring` (ping's only C/asm crate, via rustls) builds with the gcc
  `rust:bookworm` ships for both. `.cargo/config`'s aarch64 linker is not in any
  `include`, so it never reaches a build.
- **The demo compiles nothing**: its native dependencies, `grpcio==1.56.0`
  (via bee-rpc) and `protobuf`, ship cp311 manylinux wheels for x86_64 and
  aarch64.
- **No source is architecture-specific**: `heavy` touches memory at a 4096-byte
  stride, which reaches every page on both (pages are ≥ 4 KiB), and
  `benchmark/bench.sh` maps `uname -m` to both tags.

Packing an architecture other than the host's needs a binfmt_misc handler for
it on the machine that builds (nodo checks this in `ensure_native_arch`) and
the packer enabled for it (`packer.ARM_PACKER_SUPPORT` / `X86_PACKER_SUPPORT`).

## Reproducibility

`<arch>/.service/Dockerfile` pins every input: the base image by digest, `requests`,
`Flask`, `grpcio`, `protobuf` and each package that Flask and requests pull in by
version, and `bee-rpc` and `celaut-service-libraries` (`node_controller`) by
commit SHA. The Rust children pin their builder and runtime images by digest,
and their crates through `Cargo.lock` (`cargo build --locked`). This service is
content-addressed, so an unpinned `git+…` install (which resolves to whatever
`master` happened to be that day) means two packs of the same source tree produce
different images — and any bug observed in a running instance cannot be traced
back to a specific library revision.

`celaut-service-libraries` requires `bee-rpc` without a pin, so it is installed
with `--no-deps` after the pinned `bee-rpc`. Otherwise pip fetches `bee-rpc`
master again. The `bee-rpc` commit is the one of its `v0.0.1` tag, which nodo
installs too (`bash/requirements.txt`), so both ends speak the same bee-rpc.

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

Each probe was therefore checked against the **same kernel mechanisms nodo
delegates to** — cgroup memory limits and egress control — by running the packed
child images directly. That Docker run is **not** a run on a nodo node, and it
predates the address-based egress probe (see probe 1). A request to a name that
the guest cannot resolve never meets the firewall, so isolation-by-name under
Docker cannot prove the current probe.

- **memory_ceiling** — `heavy` under `--memory=256m --memory-swap=256m`:
  64/128/200/240 MiB → HTTP 200; 256/280/320/400 MiB → OOM-killed (connection
  dropped). Observed ceiling 240 MiB, first kill 256 MiB vs declared 256 MiB →
  **PASS**. `/introspect` reported `cgroup_mem_max = 268435456` (256 MiB).
- **network_isolation** — historical Docker check only. The current probe reads
  `UNDECLARED_ADDRS` and opens TCP to those IPv4 addresses. A real node must
  confirm that path.
- **resource_provisioning** — the container's real `cgroup memory.max` matched
  the declared limit (ratio 1.0) → **PASS**. That cgroup does not exist in a
  microVM.

Example assembled report card (`FAIL` is not a verdict):

```json
{
  "verifier": "celaut-node-honesty-verifier",
  "summary": {"node_honest": true, "pass": 3, "dishonest": 0,
              "unobserved": 0, "total": 3, "attestable": true},
  "content_hash": {"alg": "sha3_256",
    "value": "b5b22156fcb28125e480e98b7dcd8d3f42f8f5118de4aa70d9a7a9bb62520915"}
}
```
