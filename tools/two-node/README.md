# Two-node benchmark (delegation_pricing, MAINTENANCE_OVERCHARGED)

`delegation_pricing` needs a node that delegates a child of the verifier to a peer,
and the score `MAINTENANCE_OVERCHARGED` (nodo #567) is visible only to the operator of
the delegating node. These scripts make two test nodes on one x86_64 Linux host and
run both checks. They use no ledger and spend nothing.

- `ct.sh base|up|down|status`: a `systemd-nspawn` container per node (Ubuntu 22.04,
  `/dev/kvm` bound in, its own network namespace and veth, its own iptables chains).
  Nothing of a node that already runs on the host is read or changed.
- `in-install.sh`: a clean root install of `celaut-project/nodo` `dev` in a container.
  It stops if `dev` is not at the commit in `WANT`.
- `run.sh <step>`: the steps, in order: `up`, `configure`, `verifier <export.bee>`,
  `build-child <tiny id>`, `probe honest`, `overcharge`, `probe overcharged`, `score`,
  `down`.
- `overcharge.py`: the patch that makes B a dishonest peer (step `overcharge`).

## What the steps do

1. `up`: two containers, `nta` (node A, 10.213.101.2) and `ntb` (node B, 10.213.102.2),
   each with a new nodo install (about 16 minutes).
2. `configure`:
   - A: `host_limits.ENABLED=true`, `MAX_CPU_SHARE=0`, and `MAX_RAM_SHARE` at 2.02e9 B
     of the host's memory: room for the verifier (2.0e9 B) and nothing else, so A
     asks its peers for its child. A CPU share does not do it: an instance that
     declares no CPU quota is not counted against it.
   - B: a third of A's prices (`CPU_MU_PER_VCPU_HOUR`, `RAM_MU_PER_GIB_HOUR`,
     `DISK_MU_PER_GIB_HOUR`). A delegates only to a peer that its own price covers
     (`delegated_price.covers`), and B's maximum is its price at the worst
     multiplier of its `MAX_PRICE_VOLATILITY` (2.0): half of A's prices would tie. A
     node that passed B's price on to its client would show a third of its own rates.
   - A connects to B (`nodo connect`). Both nodes register their ERG and BTC payment
     contracts at install, so they share a payment system.
   - B credits A's client with 2e9 MU (`nodo credit_client`). This is free MU, not a
     payment. Both wallets are new and empty, and `AUTOMATIC_REFILL` is off.
3. `verifier <bee>`: A imports the verifier (`nodo export` from the node that packed
   it), executes it with `-e STARTUP_MAX_ATTEMPTS 0` (no startup suite: every child
   would be delegated, and the suite would hold the lock that the probe needs), and
   tops it up from A's own client (`nodo increase_deposit`).
4. `build-child <tiny id>`: B runs `tiny` once, to build it, and stops it. A's own
   price compares the builds too: a node that has built the child itself never
   delegates it to a peer that has not. B fetches the service from A by itself
   (A records it as wanted after a quote that sends hashes only).
5. `probe honest`: `POST /probe/delegation_pricing` on A's verifier.
6. `overcharge`: B becomes a dishonest peer on purpose (`overcharge.py`). Its
   maintenance tick charges 5 times the price, and its quotes stay as they were.
   This patch is for the test only.
7. `probe overcharged`: the probe again. The client must still pay A's own price: A
   absorbs what B overcharges (#567).
8. `score`: A's `reputation_events` and `statement_faults` against B. After the
   overcharged run, A must have scored B `maintenance_overcharged` (-1000), once.
9. `down`: stop the instances, remove both containers.
