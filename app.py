#!/usr/bin/env python3.11
"""
Celaut node-honesty verifier (orchestrator).

This service turns the passive "demo" into an ACTIVE verifier that checks whether
the nodo node it runs on is HONEST. It drives three child services and turns each
observation into an explicit PASS/FAIL assertion, then assembles a signed-ready
attestation report card:

  1. network_isolation   (ping child)   declared egress (google) must succeed and
                                        an UNDECLARED egress (amazon) must be blocked.
  2. memory_ceiling      (heavy child)  allocation up to the declared at_most
                                        (256 MiB) must succeed; past it the node
                                        must OOM-kill AT the declared boundary.
  3. node_benchmark      (benchmark child) the per-core benchmark the node runs as its
                                        `benchmark` core service must run here under
                                        its declared architecture and return a full
                                        set of scores.
  4. resource_provisioning (self)       what the manifest declared / the node
                                        charged must match what the container
                                        actually gets (cgroup + /proc/meminfo).
  5. attestation         report card    per-probe verdict + a content hash of the
                                        result, ready to be submitted later as an
                                        EGO reputation opinion on-chain.
"""

import os, json, logging, hashlib, datetime, re, threading, time, socket, platform, contextlib
import requests
from flask import Flask, jsonify, render_template_string, request
from google.protobuf.json_format import MessageToDict

from node_controller.controller.controller import Controller
from node_controller.gateway.protos import celaut_pb2
from node_controller.gateway.utils import to_amount, from_amount


DIR = "service"
CONFIG_FILE = "/__config__"

if False:  # development mode toggle (unchanged from the original demo)
    DIR = "."
    CONFIG_FILE = "__config__"

VERIFIER_VERSION = "1.3.0"

# ---------------------------------------------------------------------------
# Verdict taxonomy
# ---------------------------------------------------------------------------
# This verifier's output is meant to become an EGO reputation opinion on-chain:
# permanent, public and non-retractable. So the one distinction that must never
# blur is *observed misbehaviour* vs *failure to observe*. Absence of evidence
# is not evidence of dishonesty: a verifier that cannot measure must declare
# itself blind, never accuse.
VERDICT_PASS = "PASS"                      # observed, correct
VERDICT_DISHONEST = "DISHONEST"            # observed, incorrect -> the only accusation
VERDICT_INFRA_ERROR = "INFRA_ERROR"        # could not observe (node/network fault)
VERDICT_NOT_APPLICABLE = "NOT_APPLICABLE"  # probe does not apply to this environment
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"      # ran, undecidable

# Only these two mean "we actually observed the node's behaviour".
CONCLUSIVE_VERDICTS = (VERDICT_PASS, VERDICT_DISHONEST)
# Only these may ever be published as an accusation.
ACCUSING_VERDICTS = (VERDICT_DISHONEST,)

# ---------------------------------------------------------------------------
# Fault attribution for a failed gateway RPC
# ---------------------------------------------------------------------------
# A failed RPC is INFRA_ERROR either way -- it observed nothing, so it may never
# accuse -- but "nobody answered" and "the node answered with an error" are not
# the same finding, and reporting both with one sentence ("the gateway did not
# answer") sent an operator hunting through firewall rules for a bug that was in
# the node's own charging path. The gateway's error reply is itself proof that the
# port is open.
#
#   FAULT_TRANSPORT  nothing answered: no route, closed port, RST, timeout. The
#                    gateway is unreachable and nothing here is observable.
#   FAULT_NODE_RPC   the gateway ANSWERED, with an error status of its own. The
#                    port is reachable; the fault is inside the node.
#   FAULT_UNKNOWN    no gRPC status anywhere in the exception, so which of the two
#                    it was cannot be told. Claim neither.
FAULT_TRANSPORT = "transport"
FAULT_NODE_RPC = "node_rpc"
FAULT_UNKNOWN = "unknown"

# The only statuses gRPC produces when the call never reached a server. Every
# other status travelled back FROM one, which is what makes it evidence of
# reachability.
TRANSPORT_STATUS_CODES = ("UNAVAILABLE", "DEADLINE_EXCEEDED")

_STATUS_CODE_RE = re.compile(r"StatusCode\.([A-Z_]+)")
_STATUS_DETAILS_RE = re.compile(r'details\s*=\s*"(.*?)"', re.DOTALL)


def classify_rpc_failure(exc):
    """Attribute a failed gateway RPC to the transport or to the node.

    Handles both shapes this service actually sees: a real ``grpc.RpcError``
    (which carries ``.code()``) and the exceptions node_controller re-raises,
    where the status survives only in the text -- so the classification never
    depends on grpc being importable here.

    Returns the evidence fields to merge into a probe result, including the
    node's own ``details = "..."`` text when it sent one: that string names the
    failing RPC path, and it is the one thing worth reading first.
    """
    text = str(exc)

    code = None
    code_getter = getattr(exc, "code", None)
    if callable(code_getter):
        try:
            code = getattr(code_getter(), "name", None) or str(code_getter())
        except Exception:
            code = None
    if not code:
        match = _STATUS_CODE_RE.search(text)
        code = match.group(1) if match else None

    detail_match = _STATUS_DETAILS_RE.search(text)

    if not code:
        fault = FAULT_UNKNOWN
    elif code in TRANSPORT_STATUS_CODES:
        fault = FAULT_TRANSPORT
    else:
        fault = FAULT_NODE_RPC

    return {
        "fault": fault,
        "node_answered": fault == FAULT_NODE_RPC,
        "grpc_code": code,
        "node_detail": detail_match.group(1) if detail_match else None,
        "error": f"{type(exc).__name__}: {clip(text)}",
    }


def describe_rpc_failure(failure, rpc, node_url):
    """One sentence that says which side failed, and where to look next."""
    status = f"grpc {failure['grpc_code']}" if failure["grpc_code"] else "no grpc status"
    said = f' It answered: "{failure["node_detail"]}".' if failure["node_detail"] else ""

    if failure["fault"] == FAULT_NODE_RPC:
        return (
            f"the gateway at {node_url} ANSWERED and rejected {rpc} ({status}), so the port IS "
            f"reachable and this is a fault INSIDE THE NODE, not a connectivity problem.{said} "
            f"{failure['error']}",
            f"Do not touch the firewall: the node replied. Look for {rpc} in the node's log "
            "(the node's app.log) -- the text above is the node's own error.",
        )
    if failure["fault"] == FAULT_TRANSPORT:
        return (
            f"TCP connected but {rpc} got no answer from {node_url} ({status}): the gateway is "
            f"not serving this call. {failure['error']}",
            "The port accepts a connection but the gRPC service behind it did not respond; check "
            "that the node process is up and that the guest -> gateway path is not being dropped "
            "mid-stream.",
        )
    return (
        f"{rpc} failed against {node_url} with no gRPC status to attribute it ({status}), so it "
        f"cannot be told whether the node answered. {failure['error']}",
        "Neither the node nor the network can be blamed from this evidence; re-run with the node's "
        "log open to see whether the call ever arrived.",
    )


# Declared resources from the manifests (<svc>/<arch>/.service/service.json
# at_init == at_most; both architectures declare the same resources).
# tests/test_verdicts.py holds these to the manifests, so they cannot drift again:
# SELF_DECLARED_MEM_BYTES said 1 GB for a manifest that declares 2 GB.
HEAVY_DECLARED_MEM_BYTES = 268435456   # 256 MiB
SELF_DECLARED_MEM_BYTES = 2000000000   # 2 GB (this service's own manifest)
SELF_DECLARED_DISK_BYTES = 8000000000  # 8 GB
CHILD_DECLARED_RESOURCES = {           # label -> (mem_limit, disk_space)
    "tiny": (50000000, 200000000),
    "heavy": (HEAVY_DECLARED_MEM_BYTES, 200000000),
    "ping": (50000000, 500000000),
    "benchmark": (2147483648, 200000000),
}


def canonical_arch(machine):
    """Celaut's architecture tag for a `uname -m`, as benchmark/bench.sh maps it."""
    m = (machine or "").lower()
    if m in ("x86_64", "amd64"):
        return "linux/amd64"
    if m in ("aarch64", "arm64"):
        return "linux/arm64"
    return f"linux/{m}"


# The architecture benchmark/<arch>/.service/service.json declares. This service
# and its children are packed together from one arm64/ or amd64/ tree, so the
# benchmark this instance launches was declared for the architecture this
# instance itself runs under.
BENCHMARK_DECLARED_ARCH = canonical_arch(platform.machine())

env_vars = {}
with open(os.path.join(DIR, ".dependencies")) as f:
    for line in f:
        key, value = line.strip().split("=")
        env_vars[key] = value

TINY_SERVICE = env_vars.get("TINY", None)
HEAVY_SERVICE = env_vars.get("HEAVY", None)
PING_SERVICE = env_vars.get("PING", None)
BENCHMARK_SERVICE = env_vars.get("BENCHMARK", None)

logging.basicConfig(filename='app.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

controller = Controller(debug=lambda s: logging.info('Node Controller: %s', s),
                        app_dir=DIR, config_file=CONFIG_FILE)
node_url: str = controller.get_node_url()
mem_limit: int = controller.get_mem_limit_at_start()

resources = {"mem_limit": mem_limit}

# ----------------------------------------------------------------------------
# Funding — what the suite costs, and whether this instance can pay for it
# ----------------------------------------------------------------------------
# Every child is paid for out of THIS instance's balance: the node charges the
# parent BUILD_MU the first time a child is built plus the child's initial_mu,
# and refunds whatever the child did not spend when it is stopped. This
# instance itself is funded by the node for deposits.INITIAL_RUNTIME_HOURS of
# its own resources -- about 14e6 MU on a default node.
#
# The children used to ask for a flat 2e8-5e8 MU each: 35x what funds this
# whole instance for an hour. Every launch was refused for want of balance
# ("needed 0.51 ERG"), so a freshly executed verifier could never run its own
# startup suite. Now each child is funded for CHILD_FUNDED_SECONDS of its own
# resources, priced from the rate the node really charges this instance, and
# the suite only starts once the balance covers it.
#
# Relative price of each resource per unit-hour (GiB of RAM, vCPU, GiB of disk),
# from the node's shipped pricing.RAM/CPU/DISK prices. Only the RATIOS are used:
# the absolute rate is measured, so an operator's prices and scarcity
# surcharges are already in it.
PRICE_WEIGHT_RAM_GIB = 1.0
PRICE_WEIGHT_VCPU = 4.0
PRICE_WEIGHT_DISK_GIB = 0.1
GIB = 1024 ** 3

CHILD_FUNDED_SECONDS = int(os.environ.get("CHILD_FUNDED_SECONDS", "600"))
CHILD_BUDGET_MARGIN = float(os.environ.get("CHILD_BUDGET_MARGIN", "2.0"))
CHILD_MIN_INITIAL_MU = int(os.environ.get("CHILD_MIN_INITIAL_MU", "100000"))
# One full suite: the three MU windows dominate (3 x MU_WINDOW_SECONDS), the
# memory ladder and the benchmark take the rest.
SUITE_EXPECTED_SECONDS = int(os.environ.get("SUITE_EXPECTED_SECONDS", "480"))
# Runtime this instance must still have left AFTER a suite, so that verifying
# the node never leaves the verifier unable to serve the result it produced.
MIN_RESERVE_SECONDS = int(os.environ.get("MIN_RESERVE_SECONDS", "900"))
# pricing.BUILD_MU and pricing.MODIFY_RESOURCES_MU on a default node.
BUILD_MU_ESTIMATE = int(os.environ.get("BUILD_MU_ESTIMATE", "10000000"))
MODIFY_RESOURCES_MU_ESTIMATE = int(os.environ.get("MODIFY_RESOURCES_MU_ESTIMATE", "10000"))
FUNDING_RATE_SAMPLE_SECONDS = int(os.environ.get("FUNDING_RATE_SAMPLE_SECONDS", "20"))
# Each poll settles the account (one MODIFY_RESOURCES charge), so not too often.
FUNDING_POLL_SECONDS = int(os.environ.get("FUNDING_POLL_SECONDS", "30"))
FUNDING_WAIT_TIMEOUT_SECONDS = int(os.environ.get("FUNDING_WAIT_TIMEOUT_SECONDS", "3600"))
# Only for the operator hint: the unit `nodo increase_deposit` reads by default.
MU_PER_ERG = int(os.environ.get("MU_PER_ERG", str(10 ** 9)))

_CHILD_HASHES = {"tiny": TINY_SERVICE, "heavy": HEAVY_SERVICE,
                 "ping": PING_SERVICE, "benchmark": BENCHMARK_SERVICE}

FUNDING = {
    "balance_mu": None,          # last balance the node reported
    "sampled_at": None,
    "self_rate_mu_per_s": None,  # measured; None until two samples exist
    "child_initial_mu": {},      # label -> what each child is funded with
    "built_children": [],        # children this instance has seen launch
}
_funding_lock = threading.Lock()


def price_weight(mem_bytes, disk_bytes, vcpus=1.0):
    """Relative hourly price of holding these resources (1 vCPU unless declared)."""
    return (mem_bytes / GIB * PRICE_WEIGHT_RAM_GIB + vcpus * PRICE_WEIGHT_VCPU
            + disk_bytes / GIB * PRICE_WEIGHT_DISK_GIB)


def child_initial_mu(label, self_rate):
    """MU to fund one child with: CHILD_FUNDED_SECONDS of its own resources."""
    mem, disk = CHILD_DECLARED_RESOURCES[label]
    self_weight = price_weight(mem_limit or SELF_DECLARED_MEM_BYTES, SELF_DECLARED_DISK_BYTES)
    child_rate = self_rate * price_weight(mem, disk) / self_weight
    return max(CHILD_MIN_INITIAL_MU, int(child_rate * CHILD_FUNDED_SECONDS * CHILD_BUDGET_MARGIN))


def _add_child(label, initial_mu=None):
    # No initial_mu: the node funds the child for INITIAL_RUNTIME_HOURS of its own
    # resources, which is sane until this instance has measured its rate.
    config = (celaut_pb2.Configuration(initial_mu=to_amount(initial_mu))
              if initial_mu is not None else None)
    return controller.add_service(service_hash=_CHILD_HASHES[label], config=config)


tiny_service = _add_child("tiny")
heavy_service = _add_child("heavy")
ping_service = _add_child("ping")
benchmark_service = _add_child("benchmark")


def configure_child_budgets(self_rate):
    """Re-register every child funded for CHILD_FUNDED_SECONDS at this rate."""
    global tiny_service, heavy_service, ping_service, benchmark_service
    budgets = {label: child_initial_mu(label, self_rate) for label in CHILD_DECLARED_RESOURCES}
    tiny_service = _add_child("tiny", budgets["tiny"])
    heavy_service = _add_child("heavy", budgets["heavy"])
    ping_service = _add_child("ping", budgets["ping"])
    benchmark_service = _add_child("benchmark", budgets["benchmark"])
    FUNDING["child_initial_mu"] = budgets
    logging.info("Child budgets at %.1f MU/s: %s", self_rate, budgets)
    return budgets


def child_iface(label):
    """The current interface for a child (budgets re-register them)."""
    return {"tiny": tiny_service, "heavy": heavy_service,
            "ping": ping_service, "benchmark": benchmark_service}[label]


def sample_balance():
    """Settle the account at the declared ceiling and record the balance."""
    _, balance = controller.modify_resources(
        {"min": mem_limit or MU_HIGH_CEILING, "max": MU_HIGH_CEILING})
    with _funding_lock:
        FUNDING["balance_mu"] = balance
        FUNDING["sampled_at"] = time.time()
    return balance


def measure_self_rate():
    """MU/s the node charges this instance, from two settled balances.

    The closing sample's own MODIFY_RESOURCES_MU charge is taken out, so the
    rate is the upkeep alone. A top-up between the samples makes the delta
    negative; that is reported as unknown rather than as a free node.
    """
    t0 = time.monotonic()
    b0 = sample_balance()
    time.sleep(FUNDING_RATE_SAMPLE_SECONDS)
    b1 = sample_balance()
    elapsed = time.monotonic() - t0
    spent = b0 - b1 - MODIFY_RESOURCES_MU_ESTIMATE
    if elapsed <= 0 or spent < 0:
        return None
    rate = spent / elapsed
    FUNDING["self_rate_mu_per_s"] = rate
    return rate


def funding_requirement(self_rate, pending_builds=0):
    """MU this instance needs on hand before a suite may start."""
    budgets = FUNDING["child_initial_mu"] or {
        label: child_initial_mu(label, self_rate) for label in CHILD_DECLARED_RESOURCES}
    parts = {
        # Children run one at a time and are refunded on stop, so only the
        # largest deposit is ever held at once.
        "largest_child_deposit_mu": max(budgets.values()),
        "suite_upkeep_mu": int(self_rate * SUITE_EXPECTED_SECONDS),
        "reserve_after_suite_mu": int(self_rate * MIN_RESERVE_SECONDS),
        "pending_builds_mu": pending_builds * BUILD_MU_ESTIMATE,
    }
    parts["required_mu"] = sum(parts.values())
    return parts


def funding_status(required=None):
    """Snapshot for the UI, the MCP and the startup gate (no RPC)."""
    with _funding_lock:
        snap = dict(FUNDING)
    if required is not None:
        balance = snap.get("balance_mu") or 0
        missing = max(0, required["required_mu"] - balance)
        snap.update(required)
        snap["missing_mu"] = missing
        snap["funded"] = missing == 0
        if missing:
            snap["operator_hint"] = (
                f"Top this instance up by at least {missing} MU "
                f"(~{missing / MU_PER_ERG:.4f} ERG on a default node): "
                "`nodo increase_deposit <instance> <amount>` (amount in ui.DISPLAY_UNIT, ERG by default).")
    return snap


# Launch failures in the current suite that the node refused for want of
# balance. A probe reports them as INFRA_ERROR like any launch failure; the
# suite runner reads this to know the run was starved, not blind.
FUNDING_FAILURES = []
_INSUFFICIENT_FUNDS_RE = re.compile(r"error charging|insufficient balance|not enough balance",
                                    re.IGNORECASE)

services = []
logging.info('Gateway main directory: %s', node_url)


# ----------------------------------------------------------------------------
# Low-level helpers
# ----------------------------------------------------------------------------
def _read_first_line(path):
    try:
        with open(path) as fh:
            return fh.readline().strip()
    except Exception:
        return None


def read_container_limits():
    """What the microVM actually gets, straight from the kernel."""
    mem_max = _read_first_line("/sys/fs/cgroup/memory.max")                    # cgroup v2
    if mem_max is None:
        mem_max = _read_first_line("/sys/fs/cgroup/memory/memory.limit_in_bytes")  # v1
    mem_current = _read_first_line("/sys/fs/cgroup/memory.current")
    if mem_current is None:
        mem_current = _read_first_line("/sys/fs/cgroup/memory/memory.usage_in_bytes")
    cpu_max = _read_first_line("/sys/fs/cgroup/cpu.max")

    mem_total_kb = None
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal"):
                    mem_total_kb = int(line.split()[1]); break
    except Exception:
        pass
    return {
        "cgroup_memory_max": mem_max,
        "cgroup_memory_current": mem_current,
        "cgroup_cpu_max": cpu_max,
        "proc_meminfo_memtotal_bytes": (mem_total_kb * 1024) if mem_total_kb else None,
    }


def detect_isolation_model():
    """Which mechanism enforces our memory ceiling: a cgroup, or the VM's own size?

    The node runs services either in containers (docker) or in microVMs
    (cloud-hypervisor / qemu). In a microVM there is no cgroup to read at all:
    the hypervisor sizes the guest's RAM, so /proc/meminfo IS the ceiling.
    Reading only cgroup files makes this probe blind on half the node's
    virtualizers, which is how an honestly-provisioned microVM ends up
    INCONCLUSIVE.
    """
    if os.path.exists("/sys/fs/cgroup/memory.max") or os.path.exists(
            "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        return "container"
    # Sanity-check that we really are in a VM rather than on a host with an
    # exotic cgroup layout, so we never silently rebase the ceiling.
    for path in ("/sys/devices/virtual/dmi/id/product_name", "/sys/hypervisor/type"):
        try:
            with open(path) as fh:
                blob = fh.read().strip().lower()
            if any(k in blob for k in ("cloud hypervisor", "kvm", "qemu", "xen")):
                return "microvm"
        except Exception:
            pass
    if os.path.exists("/dev/vda") or os.path.exists("/sys/class/virtio-ports"):
        return "microvm"
    return "unknown"


class ChildLaunchError(RuntimeError):
    """The node could not give us a child instance.

    This is an INFRASTRUCTURE failure, never evidence of node dishonesty: we did
    not get to observe anything. Probes must map it to INFRA_ERROR, not to an
    accusation.
    """

    def __init__(self, label, original):
        self.label = label
        self.original = original
        self.insufficient_funds = bool(_INSUFFICIENT_FUNDS_RE.search(_full_error_text(original)))
        msg = f"could not launch child '{label}': {_describe_launch_failure(original)}"
        if self.insufficient_funds:
            msg = (f"INSUFFICIENT FUNDS: the node refused to charge this instance for child "
                   f"'{label}' (balance too low for its build + initial deposit). {msg}")
        super().__init__(msg)


def clip(text, limit=400):
    """Shorten for a report without cutting a word in half."""
    text = str(text)
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut + " …"


def _full_error_text(exc):
    last = getattr(exc, "last_error", None)
    return f"{exc} {last}" if last is not None else str(exc)


def _describe_launch_failure(exc):
    """Recover a usable message even when the client library loses the real error.

    node_controller's launch_instance() swallows every grpc.RpcError into debug()
    and then trips over `return instance` with the name unbound, so an
    UnboundLocalError is all that reaches us. Translate that into what it
    actually means instead of propagating a meaningless Python detail.

    A gRPC failure is reduced to the node's own `details = "..."` text: the
    rendezvous wrapper around it used up the whole length budget, so reports
    ended in "Unable to l" and the actual cause was only in the node's log.
    """
    if isinstance(exc, UnboundLocalError) and "instance" in str(exc):
        return (f"every StartService attempt to the node gateway at {node_url} failed; "
                "the client library discarded the gRPC status (see app.log for "
                "'GRPC ERROR LAUNCHING INSTANCE')")
    err = getattr(exc, "last_error", None) or exc
    text = str(err)
    details = _STATUS_DETAILS_RE.search(text)
    if details:
        code = _STATUS_CODE_RE.search(text)
        status = f"grpc {code.group(1)}: " if code else ""
        return clip(f"{status}{details.group(1)}")
    return clip(f"{type(err).__name__}: {text}")


class ChildNotReadyError(Exception):
    """The child launched but never began answering before the deadline.

    Like ChildLaunchError this is an INFRASTRUCTURE failure and never evidence
    of dishonesty: a child that was never reachable was never observed.
    """

    def __init__(self, label, uri, waited, last_error):
        self.label, self.uri, self.waited = label, uri, waited
        self.last_error = last_error
        super().__init__(f"child '{label}' at {uri} did not accept a connection "
                         f"within {waited}s (last error: {last_error})")


# The node calls an instance ready once the GUEST NETWORK answers, which it
# learns from ARP/ping against the guest IP. Under a microVM the guest kernel
# configures that IP during boot, seconds before the service inside it binds its
# port -- the node's own log names the gap: "instance registered before the
# guest could call in". A request sent into that gap is refused by a guest that
# is perfectly healthy, and reading that refusal as a kill turns the node's
# boot latency into an accusation.
#
# So every probe waits for the child's port to accept a connection before it
# asserts anything. That wait is also what makes the later failures readable: a
# request that fails AFTER the port was proven open is a child that died in
# flight, which is the genuine kill signal the memory-ceiling ladder needs.
CHILD_READY_TIMEOUT_S = int(os.environ.get("CHILD_READY_TIMEOUT_S", "120"))
CHILD_READY_POLL_S = float(os.environ.get("CHILD_READY_POLL_S", "0.5"))


def _spin_child(service_iface, label, wait_ready=True):
    """Launch one child instance and return it, ready to take requests.

    Any launch failure is raised as ChildLaunchError, and a child that never
    starts answering as ChildNotReadyError, so callers can tell "the child never
    ran" and "the child never became reachable" apart from "the child ran and
    misbehaved". Only the last of those can support a verdict about the node.

    The caller owns the returned instance and must hand it to _release_child;
    node_controller's own contract is that a taken instance is either returned
    to its queue or stopped, and a verifier that leaks one bills its parent for
    a child it has finished measuring.
    """
    try:
        inst = service_iface.get_instance(max_attempts=2)
    except Exception as e:
        logging.error('Could not spin %s child: %s', label, _describe_launch_failure(e))
        err = ChildLaunchError(label, e)
        if err.insufficient_funds:
            FUNDING_FAILURES.append(label)
        raise err from e
    logging.info('Spun %s child at %s', label, inst.uri)
    base = label.split("(", 1)[0]
    with _funding_lock:
        if base in CHILD_DECLARED_RESOURCES and base not in FUNDING["built_children"]:
            FUNDING["built_children"].append(base)
    if wait_ready:
        _wait_until_ready(inst.uri, label)
    return inst


def _wait_until_ready(uri, label, timeout=None):
    """Block until the child's port accepts a TCP connection.

    A bare connect is the right test: the port opens when the service binds it,
    which is the exact event the node's readiness signal misses. It costs no
    application work, so it cannot itself perturb what the probe goes on to
    measure.
    """
    timeout = CHILD_READY_TIMEOUT_S if timeout is None else timeout
    host, _, port = uri.rpartition(":")
    deadline = time.monotonic() + timeout
    last = None
    while True:
        try:
            with socket.create_connection((host, int(port)), timeout=3):
                logging.info('Child %s at %s is accepting connections', label, uri)
                return
        except OSError as e:
            last = f"{type(e).__name__}: {clip(e)}"
            if time.monotonic() >= deadline:
                raise ChildNotReadyError(label, uri, timeout, last)
            time.sleep(CHILD_READY_POLL_S)


def _release_child(service_iface, inst, label):
    """Stop a child the probe is done with.

    Left running, each child keeps drawing MU from this service's balance for
    the rest of the run. That is not only waste: it is measured by the
    mu_accounting probe, whose windows would otherwise be dominated by the
    upkeep of children the verifier itself abandoned rather than by the resource
    ceiling those windows are meant to compare.
    """
    if inst is None:
        return
    try:
        inst.stop(service_iface.gateway_stub)
        logging.info('Released %s child at %s', label, inst.uri)
    except Exception as e:
        # A child we could not stop is a leak to report, never a verdict.
        logging.warning('Could not release %s child at %s: %s', label, inst.uri, e)


# ----------------------------------------------------------------------------
# Probe 1 — network isolation (ping child asserts declared vs undeclared egress)
# ----------------------------------------------------------------------------
def probe_network_isolation():
    ev = {"probe": "network_isolation"}
    inst = None
    try:
        inst = _spin_child(ping_service, "ping")
        r = requests.get(f"http://{inst.uri}", timeout=45)
        data = r.json()
        ev.update(data)
        honest = bool(data.get("honest", False))
        # Extra guard: even if the child says honest, fail if any target verdict is bad.
        bad = [t for t in data.get("targets", []) if t.get("verdict") in ("DISHONEST_LEAK", "BROKEN_DENIED")]
        verdict = VERDICT_PASS if honest and not bad else VERDICT_DISHONEST
        ev["verdict"] = verdict
        ev["reason"] = ("declared egress reachable and undeclared egress blocked"
                        if verdict == VERDICT_PASS
                        else f"isolation violated: {[t.get('target')+':'+t.get('verdict') for t in bad]}")
    except ChildLaunchError as e:
        # The ping child never ran: we observed nothing about egress isolation.
        ev["verdict"] = VERDICT_INFRA_ERROR
        ev["reason"] = (f"could not observe network isolation: {e}. "
                        "No claim about the node's isolation is made.")
    except ChildNotReadyError as e:
        # It ran but never answered: still nothing observed about egress.
        ev["verdict"] = VERDICT_INFRA_ERROR
        ev["reason"] = (f"could not observe network isolation: {e}. "
                        "No claim about the node's isolation is made.")
    except Exception as e:
        ev["verdict"] = VERDICT_INFRA_ERROR
        ev["reason"] = f"probe could not run: {type(e).__name__}: {clip(e)}"
    finally:
        _release_child(ping_service, inst, "ping")
    return ev


# ----------------------------------------------------------------------------
# Probe 2 — memory ceiling (heavy child ramped toward the declared at_most)
# ----------------------------------------------------------------------------
# Rungs below and above the declared ceiling. One per child, so the length of
# this list is also how many children a full run of this probe spins.
MEMORY_LADDER = [64, 128, 200, 240, 300, 400, 512]


def probe_memory_ceiling():
    declared_mb = HEAVY_DECLARED_MEM_BYTES // (1024 * 1024)  # 256
    ladder = MEMORY_LADDER
    ev = {"probe": "memory_ceiling", "declared_ceiling_mb": declared_mb, "attempts": []}
    highest_ok = 0
    first_kill = None
    launch_failures = []
    observed_rungs = 0  # rungs where the child actually existed and answered (or died)
    for mb in ladder:
        rung = {"requested_mb": mb}
        label = f"heavy({mb}MB)"
        inst = None
        try:
            inst = _spin_child(heavy_service, label)
        except ChildLaunchError as e:
            # The child never ran: this rung observed NOTHING. It is not a kill,
            # and it must never feed first_kill (that is what turned a network
            # fault into a "shortchanged" accusation).
            rung["ok"] = False
            rung["launch_failed"] = True
            rung["error"] = clip(e)
            launch_failures.append(rung)
            ev["attempts"].append(rung)
            continue
        except ChildNotReadyError as e:
            # It ran but never opened its port, so it was never seen allocating
            # anything either. Same rule: a rung that observed nothing cannot
            # decide a ceiling, and must never feed first_kill.
            rung["ok"] = False
            rung["never_ready"] = True
            rung["error"] = clip(e)
            launch_failures.append(rung)
            ev["attempts"].append(rung)
            continue
        try:
            r = requests.get(f"http://{inst.uri}/alloc/{mb}", timeout=60)
            ok = (r.status_code == 200 and r.json().get("ok") is True)
            rung["ok"] = ok
            rung["cgroup_mem_current"] = r.json().get("cgroup_mem_current") if ok else None
            observed_rungs += 1
            if ok:
                highest_ok = max(highest_ok, mb)
            elif first_kill is None:
                first_kill = mb
        except Exception as e:
            # The readiness wait already proved this child's port open, so a
            # request that dies after that is a child that died in flight: the
            # genuine kill signal. Without the wait, this branch also catches a
            # connect refused by a guest still booting and calls it a kill.
            rung["ok"] = False
            rung["killed"] = True
            rung["error"] = clip(e)
            observed_rungs += 1
            if first_kill is None:
                first_kill = mb
        finally:
            _release_child(heavy_service, inst, label)
        ev["attempts"].append(rung)
        # Once we've seen a kill above the ceiling we have enough signal.
        if first_kill is not None and mb >= declared_mb:
            break

    ev["observed_ceiling_mb"] = highest_ok
    ev["first_kill_mb"] = first_kill
    ev["launch_failure_count"] = len(launch_failures)

    # No rung ever produced a running child -> we observed nothing at all.
    # Reporting an accusation here would blame the node for a ceiling we never
    # measured.
    if observed_rungs == 0:
        ev["verdict"] = VERDICT_INFRA_ERROR
        ev["reason"] = (f"could not measure the ceiling: none of the {len(ev['attempts'])} heavy "
                        f"children could be launched "
                        f"({launch_failures[0]['error'] if launch_failures else 'unknown'}). "
                        "No claim about the node's memory enforcement is made.")
        return ev

    # A ceiling cannot both kill at `first_kill` and succeed above it. When the
    # ladder reports that, the two rungs disagree about the same boundary and
    # neither can be trusted to locate it -- whatever produced the low "kill"
    # was not the ceiling. Say so instead of picking the reading that happens to
    # fit: the PASS branch below looks only at highest_ok, and would call an
    # incoherent ladder correct.
    if first_kill is not None and first_kill < highest_ok:
        ev["verdict"] = VERDICT_INCONCLUSIVE
        ev["reason"] = (f"ladder is self-contradictory: reports a kill at {first_kill} MiB yet "
                        f"{highest_ok} MiB succeeded. A ceiling cannot be enforced below a "
                        "request that went through, so these rungs do not locate one. No claim "
                        "about the node's memory enforcement is made.")
        return ev

    # Under a microVM the child's entrypoint is PID 1, so the guest kernel has no
    # killable process when an allocation exceeds the RAM the hypervisor assigned:
    # it panics ("Attempted to kill init!") instead of OOM-killing the offender.
    # The ceiling is still enforced -- the allocation does fail -- but "the node
    # kills the child at the boundary" describes the container model only, and the
    # evidence should not imply a mechanism that was not the one at work.
    ev["enforcement_mechanism"] = ("guest_kernel_panic_no_oom_kill"
                                   if detect_isolation_model() == "microvm"
                                   else "cgroup_oom_kill")

    tol = 0.20  # 20% tolerance around the declared boundary
    low = declared_mb * (1 - tol)
    if first_kill is None:
        # nothing was ever killed, even well above the ceiling
        ev["verdict"] = VERDICT_DISHONEST
        ev["reason"] = (f"ceiling NOT enforced: allocated up to {highest_ok} MiB with no OOM "
                        f"(declared at_most {declared_mb} MiB)")
    elif highest_ok < low:
        ev["verdict"] = VERDICT_DISHONEST
        ev["reason"] = (f"shortchanged: killed at {first_kill} MiB, well below declared {declared_mb} MiB "
                        f"(highest success {highest_ok} MiB)")
    else:
        ev["verdict"] = VERDICT_PASS
        ev["reason"] = (f"enforced near declared boundary: highest success {highest_ok} MiB, "
                        f"first kill {first_kill} MiB vs declared {declared_mb} MiB")
    return ev


# ----------------------------------------------------------------------------
# Probe 3 — resource / MU provisioning honesty (self-introspection)
# ----------------------------------------------------------------------------
def probe_resource_provisioning():
    ev = {"probe": "resource_provisioning"}
    limits = read_container_limits()
    model = detect_isolation_model()
    ev["declared_manifest_mem_bytes"] = SELF_DECLARED_MEM_BYTES
    ev["node_reported_mem_limit_at_start"] = mem_limit
    ev["child_initial_mu"] = dict(FUNDING["child_initial_mu"])
    ev["container_actual"] = limits
    ev["isolation_model"] = model

    # Pick the authority for "what we actually got" from the isolation model.
    actual_bytes, source = None, None
    raw_cgroup = limits.get("cgroup_memory_max")
    if raw_cgroup not in (None, "max"):
        try:
            actual_bytes, source = int(raw_cgroup), "cgroup.memory.max"
        except (TypeError, ValueError):
            actual_bytes = None
    if actual_bytes is None and model in ("microvm", "unknown"):
        # No cgroup: the guest's total RAM is the ceiling the hypervisor imposed.
        # Note: under a microVM MemTotal is always slightly BELOW the assigned
        # RAM (the guest kernel reserves structures). The 0.95 threshold below
        # already absorbs that margin.
        memtotal = limits.get("proc_meminfo_memtotal_bytes")
        if memtotal:
            actual_bytes, source = int(memtotal), "proc.meminfo.MemTotal"
    ev["ceiling_source"] = source

    # The node must deliver at least what it told us it provisioned
    # (get_mem_limit_at_start) and what the manifest declared.
    baseline = max(mem_limit or 0, 0)
    if actual_bytes is None:
        ev["verdict"] = VERDICT_INCONCLUSIVE
        ev["reason"] = (f"no readable memory ceiling under isolation model {model!r} "
                        f"(cgroup={raw_cgroup!r}, MemTotal="
                        f"{limits.get('proc_meminfo_memtotal_bytes')!r})")
    elif baseline == 0:
        ev["verdict"] = VERDICT_INCONCLUSIVE
        ev["reason"] = "node did not report initial_sysresources.mem_limit"
    else:
        ratio = actual_bytes / baseline
        ev["actual_vs_reported_ratio"] = round(ratio, 3)
        if ratio >= 0.95:
            ev["verdict"] = VERDICT_PASS
            ev["reason"] = (f"node delivered {actual_bytes} B (via {source}) >= reported "
                            f"{baseline} B (ratio {ratio:.3f})")
        else:
            ev["verdict"] = VERDICT_DISHONEST
            ev["reason"] = (f"shortchanged: guest sees {actual_bytes} B but node reported/charged "
                            f"{baseline} B via {source} (ratio {ratio:.3f})")
    return ev


# ----------------------------------------------------------------------------
# Probe — MU accounting honesty
# (the node must spend the service's MUs in line with the resources it uses)
# ----------------------------------------------------------------------------
# The node meters usage in MU. `controller.modify_resources({min,max})` settles
# the account and returns the service's *current* MU balance, so we can measure
# how many MU the node actually deducts over a window. To check that the spend
# tracks USAGE (not a flat or arbitrary drain) we hold a LOW resource ceiling,
# then a HIGH one (up to the manifest at_most), then the LOW one again. An honest
# node must (a) actually charge -- the balance must fall while resources are
# held -- (b) charge MORE when it provisions more, and (c) not take a positive
# balance to zero inside a single window.
#
# (b) is a weak signal: every instance pays for its vCPU at both ceilings, so on
# a default node memory is only ~10-15% of the bill. Two single windows compared
# with `>=` called an honest node DISHONEST when one window ran 17% heavy. So:
#   - spend is turned into a RATE over the time each window really lasted (the
#     settle RPCs alone take 0.5-0.7 s and are not the same every time);
#   - the two LOW windows bracket the HIGH one, and how much they disagree is
#     the noise of this node, measured on this run;
#   - only a HIGH rate below the LOW rate by more than that noise (and never by
#     less than MU_SCALING_TOLERANCE) is an accusation. Inside the noise it is
#     INCONCLUSIVE: the run could not tell.
#
# Comparing windows only works if this service's own ceiling is the only thing
# that changed between them. Every probe therefore stops its children (see
# _release_child), and the suite lock keeps any other run from spinning children
# on this balance while the windows are open.
# Defaulted to the decisive length below, because a window shorter than that
# yields readings this probe is not allowed to accuse on.
MU_WINDOW_SECONDS = int(os.environ.get("MU_WINDOW_SECONDS", "60"))
# Below this window length a small charge is indistinguishable from an honest
# node's rounding, so no reading from it can support an accusation.
MU_MIN_DECISIVE_WINDOW_SECONDS = int(os.environ.get("MU_MIN_DECISIVE_WINDOW_SECONDS", "60"))
# Smallest shortfall of the HIGH rate that may ever be called a scaling failure,
# however quiet the two LOW windows were.
MU_SCALING_TOLERANCE = float(os.environ.get("MU_SCALING_TOLERANCE", "0.05"))
MU_LOW_CEILING = 64 * 1024 * 1024                      # 64 MiB
MU_HIGH_CEILING = SELF_DECLARED_MEM_BYTES              # this service's declared at_most


def _sample_mu_balance(min_b, max_b):
    """Settle the account at the given ceiling and return (balance_mu, sysreq)."""
    sysreq, balance = controller.modify_resources({"min": min_b, "max": max_b})
    return balance, sysreq


def _mu_window(ceiling):
    """Hold `ceiling` for MU_WINDOW_SECONDS; return (b_open, b_close, seconds)."""
    b_open, _ = _sample_mu_balance(ceiling, ceiling)
    t_open = time.monotonic()
    time.sleep(MU_WINDOW_SECONDS)
    b_close, _ = _sample_mu_balance(ceiling, ceiling)
    return b_open, b_close, time.monotonic() - t_open


def probe_mu_accounting():
    ev = {"probe": "mu_accounting", "window_seconds": MU_WINDOW_SECONDS,
          "low_ceiling_bytes": MU_LOW_CEILING, "high_ceiling_bytes": MU_HIGH_CEILING}
    try:
        windows = [("low_1", MU_LOW_CEILING), ("high", MU_HIGH_CEILING), ("low_2", MU_LOW_CEILING)]
        readings = {}
        for name, ceiling in windows:
            b_open, b_close, secs = _mu_window(ceiling)
            spent = b_open - b_close
            readings[name] = {"balance": [b_open, b_close], "seconds": round(secs, 3),
                              "spent_mu": spent,
                              # A window measured as 0 s (tests, a frozen clock) still
                              # has a spend to compare; rate it over the nominal length.
                              "rate_mu_per_s": spent / (secs if secs > 0 else max(MU_WINDOW_SECONDS, 1))}
        ev["windows"] = readings
        low1, high, low2 = readings["low_1"], readings["high"], readings["low_2"]
        ev["spent_low_mu"] = low1["spent_mu"] + low2["spent_mu"]
        ev["spent_high_mu"] = high["spent_mu"]

        rate_low = (low1["rate_mu_per_s"] + low2["rate_mu_per_s"]) / 2
        rate_high = high["rate_mu_per_s"]
        noise = abs(low1["rate_mu_per_s"] - low2["rate_mu_per_s"]) / rate_low if rate_low > 0 else 0.0
        margin = max(MU_SCALING_TOLERANCE, 2 * noise)
        ev["rate_low_mu_per_s"] = round(rate_low, 3)
        ev["rate_high_mu_per_s"] = round(rate_high, 3)
        ev["low_window_noise"] = round(noise, 4)
        ev["accusation_margin"] = round(margin, 4)

        opens = [r["balance"][0] for r in readings.values()]
        closes = [r["balance"][1] for r in readings.values()]
        charging = any(r["spent_mu"] > 0 for r in readings.values())
        # "Drained" has to mean the window did the draining. A balance that was
        # already at or below zero when the window opened was not spent by this
        # node during it -- operators run nodes with `costs.ALLOW_DEBT` enabled,
        # where a negative balance is the configured policy and says nothing
        # about how much was charged. Testing only the closing balance accuses
        # every node in debt, for a drain that predates the measurement.
        ev["started_in_debt"] = any(b <= 0 for b in opens)
        drained = any(o > 0 >= c for o, c in zip(opens, closes))
        # One gate for every accusing branch. A window too short to tell a real
        # charge from rounding is too short to price one ceiling against another
        # as well, so the caution the zero-spend branch needs applies to all
        # of them.
        decisive = MU_WINDOW_SECONDS >= MU_MIN_DECISIVE_WINDOW_SECONDS
        too_coarse = (f"a {MU_WINDOW_SECONDS}s window is below the "
                      f"{MU_MIN_DECISIVE_WINDOW_SECONDS}s needed for MU movement to be reliably "
                      "distinguishable from rounding. No accounting claim is made "
                      "(raise MU_WINDOW_SECONDS to decide)")

        if not charging:
            # A zero spend is NOT proof of a free ride: with a short window and a
            # low rate an honest node can legitimately round the charge down to
            # zero.
            if decisive:
                ev["verdict"] = VERDICT_DISHONEST
                ev["reason"] = (f"node deducted 0 MU while holding resources for "
                                f"{MU_WINDOW_SECONDS}s at both ceilings — usage is not being "
                                "accounted (free ride / broken metering)")
            else:
                ev["verdict"] = VERDICT_INCONCLUSIVE
                ev["reason"] = f"no MU movement over {MU_WINDOW_SECONDS}s windows; {too_coarse}."
        elif drained:
            if decisive:
                ev["verdict"] = VERDICT_DISHONEST
                ev["reason"] = ("node took the balance from positive to <= 0 within a single "
                                "window — spending MU far in excess of usage (overcharging)")
            else:
                ev["verdict"] = VERDICT_INCONCLUSIVE
                ev["reason"] = f"balance crossed into debt during a window, but {too_coarse}."
        elif rate_high >= rate_low:
            ev["verdict"] = VERDICT_PASS
            ev["reason"] = (f"node spent MU in line with usage: {rate_low:.1f} MU/s at the low "
                            f"ceiling <= {rate_high:.1f} MU/s at the high ceiling, balance never "
                            "crossed into debt during a window")
        elif rate_high >= rate_low * (1 - margin):
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = (f"high-ceiling rate {rate_high:.1f} MU/s is below the low-ceiling "
                            f"{rate_low:.1f} MU/s, but within this run's noise (the two low "
                            f"windows differ by {noise:.1%}; margin {margin:.1%}). Cannot tell "
                            "scaling from noise; no accounting claim is made.")
        elif decisive:
            ev["verdict"] = VERDICT_DISHONEST
            ev["reason"] = (f"MU spend does not track resource usage: {rate_low:.1f} MU/s at the "
                            f"low ceiling but only {rate_high:.1f} MU/s at the high ceiling, "
                            f"beyond the {margin:.1%} this run's noise allows")
        else:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = (f"spend did not rise with the ceiling ({rate_low:.1f} MU/s low vs "
                            f"{rate_high:.1f} MU/s high), but {too_coarse}.")
    except Exception as e:
        # modify_resources is the one call that propagates the real gRPC status, so
        # an exception here is never an accusation -- but it is not automatically an
        # unreachable node either: the node rejecting the call looks identical from
        # here until the status is read. Attribute it.
        failure = classify_rpc_failure(e)
        ev.update(failure)
        ev["verdict"] = VERDICT_INFRA_ERROR
        reason, ev["operator_hint"] = describe_rpc_failure(
            failure, "ModifyServiceSystemResources", node_url)
        ev["reason"] = f"could not sample MU balances: {reason}"
    finally:
        # Restore the declared ceiling so the probe doesn't leave the service pinned.
        try:
            controller.modify_resources({"min": mem_limit or MU_HIGH_CEILING, "max": MU_HIGH_CEILING})
        except Exception:
            pass
    return ev


# ----------------------------------------------------------------------------
# Probe 4 — dependency execution identity
# (the dependency requested must be the dependency that actually runs)
# ----------------------------------------------------------------------------
# Each child exposes a whoami endpoint returning a fixed, service-specific
# signature (GET /whoami; busybox httpd only runs CGIs under /cgi-bin/, so the
# benchmark's lives at /cgi-bin/whoami).
# We request each dependency by its own service hash and assert that the
# instance that comes back self-identifies as the very service we asked for —
# a node that silently substituted or misrouted a dependency is caught here.
DEP_IDENTITY = [
    ("tiny", "celaut-demo-tiny", "/whoami"),
    ("heavy", "celaut-demo-heavy", "/whoami"),
    ("ping", "celaut-demo-ping", "/whoami"),
    ("benchmark", "celaut-demo-benchmark", "/cgi-bin/whoami"),
]


def probe_dependency_identity():
    ev = {"probe": "dependency_identity", "checks": []}
    mismatches, not_observed, verified = [], [], 0
    for tag, expected_identity, whoami_path in DEP_IDENTITY:
        iface = child_iface(tag)
        c = {"requested": tag, "expected_identity": expected_identity}
        inst = None
        try:
            inst = _spin_child(iface, tag)
            r = requests.get(f"http://{inst.uri}{whoami_path}", timeout=45)
            data = r.json()
            c["executed"] = data.get("service")
            c["identity"] = data.get("identity")
            c["match"] = (data.get("service") == tag and data.get("identity") == expected_identity)
            verified += 1
            if not c["match"]:
                mismatches.append(tag)
        except ChildLaunchError as e:
            # Never ran -> nothing was observed about its identity.
            c["match"] = None
            c["launch_failed"] = True
            c["error"] = clip(e)
            not_observed.append(tag)
        except ChildNotReadyError as e:
            # Ran but never answered -> still nothing observed about identity.
            c["match"] = None
            c["never_ready"] = True
            c["error"] = clip(e)
            not_observed.append(tag)
        except Exception as e:
            # Ran but we could not read its identity: still not a substitution.
            c["match"] = None
            c["unreachable"] = True
            c["error"] = clip(e)
            not_observed.append(tag)
        finally:
            _release_child(iface, inst, tag)
        ev["checks"].append(c)

    ev["verified_count"] = verified
    ev["mismatched"] = mismatches
    ev["not_observed"] = not_observed

    if mismatches:
        # A dependency that DID run and self-identified as something else is real
        # dishonesty, and it outranks a partial infrastructure failure.
        ev["verdict"] = VERDICT_DISHONEST
        ev["reason"] = (f"the node ran a different service than requested for: {mismatches} "
                        "(substituted or misrouted dependency)")
    elif not_observed:
        ev["verdict"] = VERDICT_INFRA_ERROR
        ev["reason"] = (f"could not observe the identity of {not_observed}: the dependencies "
                        "never ran or could not be reached. No substitution claim is made.")
    else:
        ev["verdict"] = VERDICT_PASS
        ev["reason"] = "every requested dependency executed and self-identified correctly"
    return ev


# ----------------------------------------------------------------------------
# Probe — node benchmark (benchmark child, the node's `benchmark` core service)
# ----------------------------------------------------------------------------
# The node files the scores this child returns into its own config.yaml, under
# the architecture the child reports, and admits services against them. So the
# suite runs it like any other dependency and checks the one thing a run can
# prove about the node: that the image it was asked for is the image that ran.
# A guest's `uname -m` is the architecture of the image it booted -- under
# QEMU+TCG too, which emulates the guest's ISA rather than translating it -- so
# a benchmark declared linux/arm64 that reports anything else was not the
# service requested.
#
# The scores themselves are evidence, not a verdict: there is no declared
# number a node's speed could be held against here.
BENCHMARK_SCORE_KEYS = ("int_ops_per_sec", "flt_ops_per_sec",
                        "mem_bandwidth_bytes_per_sec", "sha256_hashes_per_sec")
# A run is ~10 s natively and about as long again under QEMU+TCG; the memory
# primitive is the only one whose duration is not fixed.
BENCHMARK_TIMEOUT_S = int(os.environ.get("BENCHMARK_TIMEOUT_S", "180"))


def probe_node_benchmark():
    ev = {"probe": "node_benchmark", "declared_architecture": BENCHMARK_DECLARED_ARCH}
    inst = None
    try:
        try:
            inst = _spin_child(benchmark_service, "benchmark")
        except (ChildLaunchError, ChildNotReadyError) as e:
            ev["verdict"] = VERDICT_INFRA_ERROR
            ev["reason"] = f"benchmark child never ran: {e}"
            return ev
        try:
            r = requests.get(f"http://{inst.uri}/cgi-bin/benchmark", timeout=BENCHMARK_TIMEOUT_S)
        except Exception as e:
            # Port proven open, then the run never answered: nothing was
            # measured, and a benchmark has no ceiling a kill would be evidence of.
            ev["verdict"] = VERDICT_INFRA_ERROR
            ev["reason"] = (f"benchmark run did not complete within {BENCHMARK_TIMEOUT_S}s: "
                            f"{type(e).__name__}: {clip(e)}")
            return ev
        ev["http_status"] = r.status_code
        try:
            data = r.json()
        except Exception:
            data = None
        if not isinstance(data, dict):
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = f"benchmark answered {r.status_code} with no JSON object: {clip(r.text, 160)!r}"
            return ev
        if r.status_code != 200:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = f"benchmark refused the run ({r.status_code}): {data.get('error')}"
            return ev

        ev["scores"] = data
        arch = data.get("architecture")
        missing = [k for k in BENCHMARK_SCORE_KEYS
                   if not isinstance(data.get(k), int) or data.get(k) <= 0]
        if arch and arch != BENCHMARK_DECLARED_ARCH:
            # Checked before completeness: an observed substitution outranks a
            # partial measurement.
            ev["verdict"] = VERDICT_DISHONEST
            ev["reason"] = (f"benchmark declared {BENCHMARK_DECLARED_ARCH} ran as {arch}: the node "
                            "ran a different image than the one requested")
        elif not arch:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = "benchmark did not report the architecture it ran under"
        elif missing:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = (f"benchmark ran under {arch} but could not measure {missing} "
                            f"(skipped: {data.get('skipped')})")
        else:
            ev["verdict"] = VERDICT_PASS
            ev["reason"] = (f"benchmark ran under its declared {arch} and measured every primitive "
                            f"(mem working set {data.get('mem_bandwidth_working_set_bytes')} B)")
        return ev
    finally:
        _release_child(benchmark_service, inst, "benchmark")


# ----------------------------------------------------------------------------
# Probe — dependency connectivity is not fraudulent (node Observe cross-check)
# ----------------------------------------------------------------------------
# A dishonest node could fabricate a dependency's network behaviour (claim it
# reached a declared peer, or hide a leak). The node exposes an Observe RPC that
# streams a running instance's REAL packets/sessions. We independently Observe
# the dependency's traffic and cross-check it against what the dependency itself
# reports: if the dep claims connectivity the node's Observe stream cannot
# corroborate, or Observe reveals traffic to undeclared peers, the node's
# connectivity picture is fraudulent.
OBSERVE_SECONDS = int(os.environ.get("OBSERVE_SECONDS", "12"))
# How long to wait for the stream's first event before driving the dependency.
OBSERVE_ARM_SECONDS = float(os.environ.get("OBSERVE_ARM_SECONDS", "5"))
OBSERVE_MAX_EVENTS = 60


def _collect_observe_events(instance_id, out, stop_flag):
    try:
        from node_controller.gateway.communication import generate_gateway_stub
        from bee_rpc.client import client_grpc
        stub = generate_gateway_stub(node_url)
        for evt in client_grpc(
            method=stub.Observe,
            input=celaut_pb2.ObserveRequest(instance_id=instance_id, include_packets=True),
            indices_parser=celaut_pb2.ObserveEvent,
            partitions_message_mode_parser=True,
            indices_serializer=celaut_pb2.ObserveRequest,
        ):
            out.append(evt)
            if len(out) >= OBSERVE_MAX_EVENTS or stop_flag[0]:
                break
    except Exception as e:
        out.append(("__error__", clip(e)))


def probe_dependency_observe():
    ev = {"probe": "dependency_observe"}
    inst = None
    try:
        # The network dependency (ping) is where connectivity fraud matters most.
        # Spun through _spin_child so this probe gets the same readiness wait as
        # the others: Observe can only corroborate a connectivity claim the
        # dependency actually got far enough to make.
        inst = _spin_child(ping_service, "ping")
        instance_id = getattr(inst, "token", None)
        ev["dependency"] = "ping"
        ev["instance_id_used"] = instance_id

        # 1) Open the Observe stream FIRST. ping only makes traffic while it is
        #    serving GET /, so a stream opened after that request has returned
        #    can see at most the tail of a closed connection -- 2 packets on one
        #    run, 25 on another, none on a third. That third run, with the
        #    stream's own session event as "proof of life", was reported as
        #    fabricated connectivity on an honest node.
        events, stop_flag = [], [False]
        t = threading.Thread(target=_collect_observe_events,
                             args=(instance_id, events, stop_flag), daemon=True)
        t.start()
        armed_deadline = time.monotonic() + OBSERVE_ARM_SECONDS
        while not events and t.is_alive() and time.monotonic() < armed_deadline:
            time.sleep(0.1)
        # Silence only means something if the stream was demonstrably running
        # BEFORE the traffic it is supposed to see.
        armed_before_drive = bool(events) and not (
            isinstance(events[0], tuple) and events[0] and events[0][0] == "__error__")
        ev["observe_armed_before_drive"] = armed_before_drive

        # 2) Drive the dependency, inside the observed window, and capture its
        #    own account of what it connected to.
        try:
            self_report = requests.get(f"http://{inst.uri}", timeout=30).json()
        except Exception as e:
            self_report = {"error": clip(e)}
        ev["dependency_self_report"] = self_report

        # 3) Keep observing a little past the request, for packets still in flight.
        t.join(timeout=OBSERVE_SECONDS)
        stop_flag[0] = True
        events = list(events)

        packets, sessions, obs_err = [], [], None
        for e in events:
            if isinstance(e, tuple) and e and e[0] == "__error__":
                obs_err = e[1]
                continue
            try:
                if e.HasField("packet"):
                    p = e.packet
                    packets.append({"direction": p.direction, "protocol": p.protocol,
                                    "dst": p.dst, "peer_kind": p.peer_kind,
                                    "peer_tag": p.peer_tag,
                                    "peer_relationship": p.peer_relationship,
                                    "peer_host": p.peer_host})
                elif e.HasField("session"):
                    sessions.append({"instance_id": e.session.instance_id, "tag": e.session.tag})
            except Exception:
                pass

        ev["observe_error"] = obs_err
        ev["packet_count"] = len(packets)
        ev["packets"] = packets[:20]
        ev["sessions"] = sessions[:5]

        # Proof of life for the Observe RPC itself: silence only means something
        # if we know the stream was working. Any event at all (a session record
        # counts) shows the node was really streaming during the window.
        stream_alive = bool(packets or sessions)
        ev["observe_stream_alive"] = stream_alive

        claims_connectivity = isinstance(self_report, dict) and (
            self_report.get("honest") is not None or self_report.get("targets"))
        undeclared = [p for p in packets
                      if str(p.get("peer_relationship", "")).lower() in ("undeclared", "unauthorized", "leak")]

        if obs_err and not packets:
            ev["verdict"] = VERDICT_INFRA_ERROR
            ev["reason"] = f"node Observe RPC unavailable/unsupported: {obs_err}"
        elif undeclared:
            ev["verdict"] = VERDICT_DISHONEST
            ev["reason"] = f"Observe revealed traffic to undeclared/unauthorized peers: {undeclared[:3]}"
        elif not packets and claims_connectivity and stream_alive and armed_before_drive:
            # Only accusable because the stream demonstrably worked BEFORE the
            # dependency made its connection, and still showed nothing for it.
            ev["verdict"] = VERDICT_DISHONEST
            ev["reason"] = ("dependency self-reports connectivity but the node's Observe stream — which "
                            "was demonstrably live before the dependency was driven "
                            f"({len(sessions)} session event(s)) — shows no corresponding traffic; the "
                            "connectivity picture is fabricated")
        elif not packets and claims_connectivity and stream_alive:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = (f"the Observe stream produced its first event only after the dependency "
                            f"had been driven (waited {OBSERVE_ARM_SECONDS}s for it), so it cannot "
                            "show it was watching when the connection happened; no claim is made "
                            "(raise OBSERVE_ARM_SECONDS to decide)")
        elif not packets and claims_connectivity:
            # The stream produced nothing at all, so we cannot tell a fabricated
            # connectivity claim from an Observe window that was simply too short
            # or a stream that never started.
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = (f"dependency claims connectivity but the Observe stream produced no events "
                            f"whatsoever in {OBSERVE_SECONDS}s, so it never proved it was live; "
                            "cannot distinguish fabrication from an unproductive stream "
                            "(raise OBSERVE_SECONDS to decide)")
        elif packets:
            ev["verdict"] = VERDICT_PASS
            ev["reason"] = (f"node exposed {len(packets)} real packet event(s) for the dependency and none to "
                            "undeclared peers — connectivity is independently corroborated, not fabricated")
        else:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = "no packets observed and no connectivity claim to corroborate"
    except (ChildLaunchError, ChildNotReadyError) as e:
        ev["verdict"] = VERDICT_INFRA_ERROR
        ev["reason"] = f"observe probe could not run: {e}"
    except Exception as e:
        ev["verdict"] = VERDICT_INFRA_ERROR
        ev["reason"] = f"observe probe could not run: {type(e).__name__}: {clip(e)}"
    finally:
        _release_child(ping_service, inst, "ping")
    return ev


def _now():
    return datetime.datetime.utcnow().isoformat() + "Z"


# ----------------------------------------------------------------------------
# One suite at a time
# ----------------------------------------------------------------------------
# Every probe spins children on THIS instance's balance, and mu_accounting
# measures that balance. Two runs at once -- the report page auto-starting an
# attestation while the startup suite was still going, or an MCP client calling
# a probe beside the UI's job -- doubled the spend and fed one run's children
# into the other's MU windows. Anything that spins a child or moves this
# instance's resources takes this lock; callers that cannot wait get a BusyError
# naming what is running.
_suite_lock = threading.Lock()
CURRENT_WORK = {"name": None, "since": None}


class BusyError(RuntimeError):
    def __init__(self):
        self.running = dict(CURRENT_WORK)
        super().__init__(f"busy: {self.running['name']} has been running since "
                         f"{self.running['since']}; try again when it finishes")


@contextlib.contextmanager
def exclusive(name, wait=False):
    if not _suite_lock.acquire(blocking=wait):
        raise BusyError()
    CURRENT_WORK.update(name=name, since=_now())
    try:
        yield
    finally:
        CURRENT_WORK.update(name=None, since=None)
        _suite_lock.release()


def ensure_funded(pending_builds=0, timeout=None, on_wait=None):
    """Wait until the balance covers one suite. Returns (funded, funding snapshot).

    The first call measures what the node charges this instance and sizes every
    child from it. When the rate cannot be measured -- the gateway is down, or
    the node charges nothing -- there is nothing to wait for: the suite runs and
    its preflight reports the gateway, or the node is free.
    Call with the suite lock held: sampling settles this instance's resources.
    """
    timeout = FUNDING_WAIT_TIMEOUT_SECONDS if timeout is None else timeout
    deadline = time.monotonic() + timeout
    try:
        rate = FUNDING["self_rate_mu_per_s"]
        if rate is None:
            rate = measure_self_rate()
        if rate is None:
            return True, dict(funding_status(), note="rate unknown (no charge, or a top-up "
                                                     "during sampling); not gating on funds")
        if not FUNDING["child_initial_mu"]:
            configure_child_budgets(rate)
        while True:
            required = funding_requirement(rate, pending_builds)
            sample_balance()
            snap = funding_status(required)
            if snap["funded"] or time.monotonic() >= deadline:
                return snap["funded"], snap
            if on_wait:
                on_wait(snap)
            time.sleep(FUNDING_POLL_SECONDS)
    except Exception as e:
        return True, dict(funding_status(),
                          note=f"could not read the balance ({type(e).__name__}); the "
                               "gateway preflight will report why")


# ----------------------------------------------------------------------------
# Startup automation-test harness
# (runs on boot once funded; executes every dependency and records the verdicts)
# ----------------------------------------------------------------------------
# The suite used to start the instant the service booted, before anyone could
# have topped the instance up, so a freshly executed verifier reported five
# INFRA_ERRORs and never tried again. Now it waits until the balance covers a
# suite, says exactly how much is missing while it waits, and if the node still
# refuses a launch for want of balance (a child's first build costs BUILD_MU)
# it waits for that too and runs again.
STARTUP_MAX_ATTEMPTS = int(os.environ.get("STARTUP_MAX_ATTEMPTS", "3"))
STARTUP_ACTIVE = ("queued", "running", "waiting_for_funds")
STARTUP_TESTS = {"status": "pending", "started_at": None, "finished_at": None,
                 "results": None, "funding": None, "attempt": 0, "error": None}
_startup_lock = threading.Lock()

# ----------------------------------------------------------------------------
# Attestation job — run in the background, polled by the UI and the MCP
# ----------------------------------------------------------------------------
# A full attestation run drives every probe (memory ceiling ladder, three
# MU-accounting windows, several child launches) and can legitimately take
# minutes. Blocking one HTTP request for that long is what a proxy/tunnel
# sitting in front of this service will eventually kill mid-flight, which the
# browser reports as a bare "NetworkError" with no HTTP status to explain it.
# So attestation runs the same way STARTUP_TESTS does: kicked off in a
# background thread, polled from a short-lived request -- by the page and by the
# MCP tools alike, so both read the same run.
ATTESTATION_ACTIVE = ("queued", "running")
ATTESTATION_JOB = {"status": "idle", "started_at": None, "finished_at": None,
                   "result": None, "error": None, "funding": None}
_attestation_lock = threading.Lock()


def run_attestation_job():
    ATTESTATION_JOB["status"] = "running"
    try:
        with exclusive("attestation"):
            funded, snap = ensure_funded(timeout=0)
            ATTESTATION_JOB["funding"] = snap
            if not funded:
                ATTESTATION_JOB["status"] = "insufficient_funds"
                ATTESTATION_JOB["error"] = snap.get("operator_hint")
            else:
                ATTESTATION_JOB["result"] = build_attestation()
                ATTESTATION_JOB["status"] = "done"
    except BusyError as e:
        ATTESTATION_JOB["status"] = "busy"
        ATTESTATION_JOB["error"] = str(e)
    except Exception as e:
        ATTESTATION_JOB["status"] = "error"
        ATTESTATION_JOB["error"] = f"{type(e).__name__}: {clip(e)}"
    ATTESTATION_JOB["finished_at"] = _now()
    logging.info("Attestation job finished: status=%s", ATTESTATION_JOB.get("status"))
    return ATTESTATION_JOB


def start_attestation_async():
    """Schedule one attestation unless one is already queued or running."""
    with _attestation_lock:
        if ATTESTATION_JOB["status"] in ATTESTATION_ACTIVE:
            return False
        ATTESTATION_JOB.update(status="queued", started_at=_now(), finished_at=None,
                               result=None, error=None, funding=None)
    threading.Thread(target=run_attestation_job, name="attestation-run", daemon=True).start()
    return True

# Registry of all probes: (key, callable). Used by the startup harness and the
# attestation so both stay in sync and a single misbehaving probe can never take
# down the whole run.
# ---------------------------------------------------------------------------
# Preflight — can we talk to the node at all?
# ---------------------------------------------------------------------------
# Every probe below needs the node's gRPC gateway. When it is unreachable the
# honest answer is "I could not verify this node", said once — not six probes
# each inventing its own conclusion from the same silence.
def probe_gateway_reachability():
    ev = {"probe": "gateway_reachability", "node_url": node_url}
    host, _, port = node_url.rpartition(":")
    ev["host"], ev["port"] = host, port

    # L4 first: it separates "nothing is listening / packets are dropped" from
    # "the gateway is up but the RPC misbehaves".
    t0 = time.time()
    try:
        with socket.create_connection((host, int(port)), timeout=5):
            ev["tcp_connect"] = "ok"
    except Exception as e:
        ev["tcp_connect"] = f"{type(e).__name__}: {e}"
        ev["verdict"] = VERDICT_INFRA_ERROR
        ev["reason"] = (f"cannot open a TCP connection to the node gateway at {node_url} "
                        f"({type(e).__name__}: {e}). Nothing about this node can be verified; "
                        "this is a node/network fault, NOT evidence of dishonesty.")
        ev["operator_hint"] = ("From the host, check that the gateway port is reachable from the "
                               "guest subnet: the node must allow guest -> gateway traffic on this "
                               "port in whichever firewall layer the host actually enforces.")
        return ev

    # L7: a real RPC round-trip. modify_resources is the cheapest call that both
    # settles the account and echoes state back, and it is the only one that does
    # not go through launch_instance's error-swallowing retry loop.
    try:
        sysreq, balance = controller.modify_resources(
            {"min": mem_limit or MU_HIGH_CEILING, "max": MU_HIGH_CEILING})
        ev["rpc_roundtrip_ms"] = int((time.time() - t0) * 1000)
        ev["balance_mu"] = balance
        with _funding_lock:
            FUNDING["balance_mu"], FUNDING["sampled_at"] = balance, time.time()
        ev["verdict"] = VERDICT_PASS
        ev["reason"] = f"node gateway reachable and answering RPCs at {node_url}"
    except Exception as e:
        # The old message said "the gateway did not answer" for every failure here,
        # including the ones where it demonstrably did. Attribute the fault instead.
        failure = classify_rpc_failure(e)
        ev.update(failure)
        ev["verdict"] = VERDICT_INFRA_ERROR
        ev["reason"], ev["operator_hint"] = describe_rpc_failure(
            failure, "ModifyServiceSystemResources", node_url)
    return ev


PROBES = [
    ("gateway_reachability", probe_gateway_reachability),
    ("resource_provisioning", probe_resource_provisioning),
    ("dependency_identity", probe_dependency_identity),
    ("network_isolation", probe_network_isolation),
    ("dependency_observe", probe_dependency_observe),
    ("memory_ceiling", probe_memory_ceiling),
    ("node_benchmark", probe_node_benchmark),
    ("mu_accounting", probe_mu_accounting),
]

# Probes that cannot produce any observation without the gateway. When the
# preflight fails they are reported as INFRA_ERROR instead of being run, so the
# report says "could not verify" once rather than six times in six dialects.
# resource_provisioning is deliberately NOT here: it only reads /proc and
# /__config__, so it stays valid (and can legitimately PASS) with the gateway down.
GATEWAY_DEPENDENT = ("dependency_identity", "network_isolation",
                     "dependency_observe", "memory_ceiling", "node_benchmark",
                     "mu_accounting")


def _safe_probe(name, fn):
    """Run one probe; never propagate — a crash becomes an INFRA_ERROR verdict so
    the rest of the suite still completes. A crashed probe observed nothing, so
    it must never be counted as an accusation."""
    try:
        return fn()
    except Exception as e:
        return {"probe": name, "verdict": VERDICT_INFRA_ERROR,
                "reason": f"probe crashed: {type(e).__name__}: {clip(e)}"}


def _run_probe_suite():
    """Run the preflight, then every probe, short-circuiting the gateway-dependent
    ones when the node is unreachable. Returns an ordered {name: evidence} dict."""
    del FUNDING_FAILURES[:]
    results = {}
    preflight = _safe_probe("gateway_reachability", probe_gateway_reachability)
    results["gateway_reachability"] = preflight
    gateway_ok = preflight.get("verdict") == VERDICT_PASS
    for name, fn in PROBES:
        if name == "gateway_reachability":
            continue
        if not gateway_ok and name in GATEWAY_DEPENDENT:
            # Say WHY they were skipped. "The node gateway is unreachable" was
            # asserted here regardless of what the preflight actually found, so a
            # node-side error was reported to the operator as a network problem.
            headline = {
                FAULT_NODE_RPC: "the node gateway is reachable but rejected the preflight RPC",
                FAULT_TRANSPORT: "the node gateway is unreachable",
            }.get(preflight.get("fault"), "the node gateway could not be exercised")
            results[name] = {
                "probe": name,
                "verdict": VERDICT_INFRA_ERROR,
                "reason": f"skipped: {headline} ({preflight.get('reason')})",
                "fault": preflight.get("fault"),
                "skipped": True,
            }
            continue
        if FUNDING_FAILURES and name in GATEWAY_DEPENDENT:
            # The node already refused to fund a child: this run is starved and
            # will be re-run once topped up. Launching the rest only collects the
            # same refusal, and mu_accounting's windows would cost minutes of a
            # balance that is already short.
            results[name] = {
                "probe": name,
                "verdict": VERDICT_INFRA_ERROR,
                "reason": (f"skipped: the node refused to fund child(ren) {FUNDING_FAILURES} "
                           "for want of balance earlier in this run (INSUFFICIENT FUNDS)"),
                "fault": "insufficient_funds",
                "skipped": True,
            }
            continue
        results[name] = _safe_probe(name, fn)
    return results


def summarize_suite(results):
    unobserved = [p for p in results.values() if p.get("verdict") not in CONCLUSIVE_VERDICTS]
    summary = {
        "pass": sum(1 for p in results.values() if p.get("verdict") == VERDICT_PASS),
        "dishonest": sum(1 for p in results.values() if p.get("verdict") in ACCUSING_VERDICTS),
        "unobserved": len(unobserved),
        "unobserved_probes": [p.get("probe") for p in unobserved],
        "total": len(results),
    }
    summary["observation_complete"] = not unobserved
    summary["all_passed"] = summary["dishonest"] == 0 and summary["unobserved"] == 0
    return summary


def run_startup_tests():
    def waiting(snap):
        STARTUP_TESTS.update(status="waiting_for_funds", funding=snap)

    try:
        # Waits for an attestation or probe already running instead of colliding.
        with exclusive("startup_tests", wait=True):
            pending_builds = 0
            for attempt in range(1, STARTUP_MAX_ATTEMPTS + 1):
                STARTUP_TESTS["attempt"] = attempt
                funded, snap = ensure_funded(pending_builds, on_wait=waiting)
                STARTUP_TESTS["funding"] = snap
                if not funded:
                    STARTUP_TESTS["status"] = "unfunded"
                    STARTUP_TESTS["error"] = (f"still {snap.get('missing_mu')} MU short after "
                                              f"{FUNDING_WAIT_TIMEOUT_SECONDS}s. "
                                              f"{snap.get('operator_hint', '')}")
                    break
                STARTUP_TESTS.update(status="running", started_at=_now())
                # gateway preflight + resource provisioning + dependency identity +
                # network isolation (real ping child) + observe + memory ceiling +
                # node benchmark + MU.
                results = _run_probe_suite()
                STARTUP_TESTS["results"] = {"summary": summarize_suite(results), "probes": results}
                starved = list(FUNDING_FAILURES)
                STARTUP_TESTS["starved_children"] = starved
                STARTUP_TESTS["status"] = "done"
                if not starved:
                    break
                # The node refused a launch for want of balance: children that have
                # never launched here still owe their first build. Wait for that too.
                pending_builds = max(1, sum(1 for c in CHILD_DECLARED_RESOURCES
                                            if c not in FUNDING["built_children"]))
                logging.info("Startup suite starved of funds (%s); waiting for %d build(s)",
                             starved, pending_builds)
    except Exception as e:
        STARTUP_TESTS["status"] = "error"
        STARTUP_TESTS["error"] = f"{type(e).__name__}: {clip(e)}"
    STARTUP_TESTS["finished_at"] = _now()
    logging.info("Startup automation tests finished: status=%s", STARTUP_TESTS.get("status"))
    return STARTUP_TESTS


def start_startup_tests_async():
    """Schedule the startup suite unless it is already queued, waiting or running.

    The status is claimed under the lock: the rerun route used to write "pending"
    over a running suite, which the running-check then let through, so a rerun
    during a run started a second suite on the same balance.
    """
    with _startup_lock:
        if STARTUP_TESTS["status"] in STARTUP_ACTIVE:
            return False
        STARTUP_TESTS.update(status="queued", started_at=None, finished_at=None, error=None)
    threading.Thread(target=run_startup_tests, name="startup-tests", daemon=True).start()
    return True


# ----------------------------------------------------------------------------
# Probe 5 — attestation report card (JSON + content hash)
# ----------------------------------------------------------------------------
def build_attestation():
    probes = list(_run_probe_suite().values())
    passes = [p for p in probes if p.get("verdict") == VERDICT_PASS]
    dishonest = [p for p in probes if p.get("verdict") in ACCUSING_VERDICTS]
    unobserved = [p for p in probes if p.get("verdict") not in CONCLUSIVE_VERDICTS]

    # An attestation is only mintable when EVERY probe reached a conclusive
    # verdict. Otherwise we did not measure the node — we measured our own
    # inability to reach it — and no opinion may be committed on-chain.
    complete = not unobserved

    summary = {
        # Tri-state on purpose: True / False / None (unknown). Never collapse
        # "proven honest" and "could not verify" into the same boolean.
        "node_honest": (len(dishonest) == 0) if complete else None,
        "observation_complete": complete,
        "attestable": complete,
        "pass": len(passes),
        "dishonest": len(dishonest),
        "unobserved": len(unobserved),
        "unobserved_probes": [p.get("probe") for p in unobserved],
        "total": len(probes),
    }

    if complete:
        # Deterministic content hash over the verdict-bearing payload (no
        # timestamps), so the same observed behaviour always hashes identically
        # — this digest is what an EGO reputation opinion would commit to on-chain.
        hashable = {
            "verifier": "celaut-node-honesty-verifier",
            "version": VERIFIER_VERSION,
            "probes": [{"probe": p.get("probe"), "verdict": p.get("verdict")} for p in probes],
            "summary": {k: summary[k] for k in ("node_honest", "pass", "dishonest", "total")},
        }
        canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
        content_hash = {
            "alg": "sha3_256",
            "value": hashlib.sha3_256(canonical.encode()).hexdigest(),
            "note": "EGO-opinion-ready digest of {probe:verdict} + summary",
        }
    else:
        content_hash = {
            "alg": "sha3_256",
            "value": None,
            "note": ("NOT ATTESTABLE: "
                     f"{len(unobserved)} of {len(probes)} probes could not observe the node "
                     f"({', '.join(p.get('probe') for p in unobserved)}). "
                     "Publishing an opinion from an incomplete observation would accuse a node "
                     "of behaviour that was never measured."),
        }

    return {
        "verifier": "celaut-node-honesty-verifier",
        "version": VERIFIER_VERSION,
        "node_url": node_url,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "probes": probes,
        "summary": summary,
        "content_hash": content_hash,
        # Children the node refused to launch for want of balance: the run was
        # starved, not blind. Evidence only; not part of the hashed payload.
        "starved_children": list(FUNDING_FAILURES),
    }


# ----------------------------------------------------------------------------
# Routes — attestation, probes, startup tests, status
# ----------------------------------------------------------------------------
@app.route('/attestation.json', methods=['GET'])
def attestation_json():
    """Poll the current attestation job."""
    return jsonify(ATTESTATION_JOB)


@app.route('/attestation.json', methods=['POST'])
def attestation_json_run():
    """Schedule an attestation run if one isn't already in flight, and return
    immediately -- the caller polls GET /attestation.json for the result."""
    start_attestation_async()
    return jsonify(ATTESTATION_JOB), 202


# (MCP tool, HTTP route, probe). One table so the routes and the MCP tools
# cannot list different probes.
PROBE_ENDPOINTS = [
    ("probe_gateway_reachability", "/probe/gateway", probe_gateway_reachability),
    ("probe_resource_provisioning", "/probe/resources", probe_resource_provisioning),
    ("probe_dependency_identity", "/probe/dependency_identity", probe_dependency_identity),
    ("probe_network_isolation", "/probe/network", probe_network_isolation),
    ("probe_dependency_observe", "/probe/dependency_observe", probe_dependency_observe),
    ("probe_memory_ceiling", "/probe/memory", probe_memory_ceiling),
    ("probe_node_benchmark", "/probe/benchmark", probe_node_benchmark),
    ("probe_mu_accounting", "/probe/mu_accounting", probe_mu_accounting),
]
# Reads /proc and /__config__ only: it spins nothing and moves nothing, so it
# may run beside a suite.
LOCK_FREE_PROBES = ("probe_resource_provisioning",)


def run_single_probe(tool):
    # Looked up by name at call time, so a patched probe is the one that runs.
    fn = globals()[dict((t, p.__name__) for t, _, p in PROBE_ENDPOINTS)[tool]]
    if tool in LOCK_FREE_PROBES:
        return fn()
    with exclusive(tool):
        return fn()


def _probe_view(tool):
    def view():
        try:
            return jsonify(run_single_probe(tool))
        except BusyError as e:
            return jsonify({"status": "busy", "error": str(e), "running": e.running}), 409
    return view


for _tool, _path, _fn in PROBE_ENDPOINTS:
    app.add_url_rule(_path, endpoint=_tool, view_func=_probe_view(_tool), methods=['GET', 'POST'])


@app.route('/startup_tests', methods=['GET'])
def route_startup_tests():
    return jsonify(STARTUP_TESTS)


@app.route('/startup_tests/rerun', methods=['POST'])
def route_startup_tests_rerun():
    started = start_startup_tests_async()
    return jsonify({"status": "rerun scheduled" if started else "already active",
                    "startup_tests": STARTUP_TESTS}), (202 if started else 409)


def service_status(refresh=False):
    """Balance, funding, and what is running. `refresh` settles the account for a
    live balance -- skipped while a suite runs, because settling moves this
    instance's resources under mu_accounting's windows."""
    note = None
    if refresh:
        try:
            with exclusive("status_refresh"):
                sample_balance()
        except BusyError:
            note = "a suite is running; balance shown is the last one sampled"
        except Exception as e:
            note = f"could not refresh the balance: {type(e).__name__}: {clip(e)}"
    rate = FUNDING["self_rate_mu_per_s"]
    required = funding_requirement(rate) if rate is not None else None
    return {
        "verifier": "celaut-node-honesty-verifier",
        "version": VERIFIER_VERSION,
        "node_url": node_url,
        "mem_limit_bytes": mem_limit,
        "funding": funding_status(required),
        "balance_note": note,
        "running": dict(CURRENT_WORK),
        "startup_tests_status": STARTUP_TESTS["status"],
        "attestation_status": ATTESTATION_JOB["status"],
    }


@app.route('/status', methods=['GET'])
def route_status():
    return jsonify(service_status(refresh=request.args.get("refresh") in ("1", "true")))


# ----------------------------------------------------------------------------
# MCP interface — self-contained JSON-RPC 2.0 over HTTP (Streamable-HTTP style).
# Exposes the verifier's probes/attestation as MCP tools with no extra deps.
# ----------------------------------------------------------------------------
MCP_PROTOCOL_VERSION = "2024-11-05"
_EMPTY_SCHEMA = {"type": "object", "properties": {}}
_OBJECT_SCHEMA = {"type": "object"}
_SPENDS = (" Spends MU from this instance's balance (children are funded from it and "
           "refunded on stop) and waits for the suite lock: returns a busy error while "
           "another run is in progress.")


def _tool(name, description, read_only, input_schema=_EMPTY_SCHEMA):
    return {"name": name, "description": description, "inputSchema": input_schema,
            "outputSchema": _OBJECT_SCHEMA,
            "annotations": {"readOnlyHint": read_only, "destructiveHint": False,
                            "idempotentHint": read_only, "openWorldHint": not read_only}}


MCP_TOOLS = [
    _tool("probe_gateway_reachability",
          "Preflight: check whether this service can reach the node's gRPC gateway at all. Run "
          "this FIRST when other probes report INFRA_ERROR — it distinguishes a node/network "
          "fault from actual node dishonesty. Settles the account (one MODIFY_RESOURCES charge).",
          False),
    _tool("run_attestation",
          "Start a full attestation run (every probe) in the background and return at once with "
          "the job state; poll get_attestation for the report card. This is the same job the web "
          "report shows. Refused with status insufficient_funds when the balance cannot cover a "
          "suite. The content hash is only minted when every probe reached a conclusive verdict."
          + _SPENDS, False),
    _tool("get_attestation",
          "Return the current attestation job (idle / queued / running / done / error / "
          "insufficient_funds / busy) and, once done, its report card — exactly what the web "
          "report renders.", True),
    _tool("get_startup_tests",
          "Return the startup automation suite: its status (queued / waiting_for_funds / running "
          "/ done / unfunded / error), the funding it is waiting for, and its results.", True),
    _tool("rerun_startup_tests",
          "Run the startup automation suite again in the background (it waits for funds first); "
          "poll get_startup_tests. No-op while it is already queued, waiting or running." + _SPENDS,
          False),
    _tool("get_service_status",
          "Balance, measured MU rate, what a suite needs on hand and how much is missing (with "
          "the nodo command to top up), memory, and what is running.",
          True, {"type": "object", "properties": {"refresh": {
              "type": "boolean",
              "description": "settle the account for a live balance (one MODIFY_RESOURCES charge)"}}}),
    _tool("probe_dependency_identity",
          "Execute each dependency and assert the requested dependency is the one that actually ran."
          + _SPENDS, False),
    _tool("probe_network_isolation",
          "Run the ping child and assert declared egress is reachable and undeclared egress is blocked."
          + _SPENDS, False),
    _tool("probe_memory_ceiling",
          "Ramp the heavy child toward/past its declared memory ceiling and check enforcement."
          + _SPENDS, False),
    _tool("probe_resource_provisioning",
          "Compare declared/charged resources against the instance's real memory limits. Reads "
          "only local files; spends nothing and may run beside a suite.", True),
    _tool("probe_mu_accounting",
          "Verify the node spends the service's MUs in line with the resources it provisions "
          "(charges, scales with usage beyond the run's own noise, does not drain). Takes three "
          "MU windows (~3 min)." + _SPENDS, False),
    _tool("probe_dependency_observe",
          "Use the node Observe RPC to independently watch a dependency's real packets and confirm "
          "its connectivity is genuine, not fabricated by the node." + _SPENDS, False),
    _tool("probe_node_benchmark",
          "Run the benchmark child (the node's per-core benchmark core service), return its scores "
          "and check it ran under its declared architecture." + _SPENDS, False),
]

# Every HTTP route an operator can use, and the MCP tool(s) that give a model the
# same thing. tests/test_mcp.py fails when a route has neither an entry here nor
# a reason in ROUTES_WITHOUT_MCP.
ROUTE_MCP_TOOLS = {
    "/attestation.json": ("get_attestation", "run_attestation"),
    "/startup_tests": ("get_startup_tests",),
    "/startup_tests/rerun": ("rerun_startup_tests",),
    "/status": ("get_service_status",),
    "/current_balance": ("get_service_status",),
    "/memory_usage": ("get_service_status",),
    **{path: (tool,) for tool, path, _ in PROBE_ENDPOINTS},
}
ROUTES_WITHOUT_MCP = {
    "/": "the HTML report card; everything it renders comes from routes mapped above",
    "/mcp": "the MCP endpoint itself",
    "/static/<path:filename>": "Flask's built-in static route",
    "/services": "legacy demo endpoint",
    "/generate_service": "legacy demo endpoint",
    "/generate_heavy_service": "legacy demo endpoint",
    "/generate_ping_service": "legacy demo endpoint",
    "/use_services": "legacy demo endpoint",
}


def _mcp_call_tool(name, args):
    if name in dict((t, None) for t, _, _ in PROBE_ENDPOINTS):
        return run_single_probe(name)
    if name == "run_attestation":
        started = start_attestation_async()
        return dict(ATTESTATION_JOB, started=started)
    if name == "get_attestation":
        return ATTESTATION_JOB
    if name == "get_startup_tests":
        return STARTUP_TESTS
    if name == "rerun_startup_tests":
        started = start_startup_tests_async()
        return dict(STARTUP_TESTS, started=started)
    if name == "get_service_status":
        return service_status(refresh=bool(args.get("refresh")))
    raise ValueError(f"unknown tool: {name}")


@app.route('/mcp', methods=['GET', 'POST'])
def mcp_endpoint():
    if request.method == 'GET':
        # Discovery convenience for humans / health checks.
        return jsonify({"service": "celaut-node-honesty-verifier",
                        "mcp": "json-rpc-2.0", "protocolVersion": MCP_PROTOCOL_VERSION,
                        "tools": [t["name"] for t in MCP_TOOLS]})

    req = request.get_json(force=True, silent=True) or {}
    rid = req.get("id")
    method = req.get("method")

    def _result(res):
        return jsonify({"jsonrpc": "2.0", "id": rid, "result": res})

    def _error(code, msg):
        return jsonify({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": msg}})

    def _content(out, is_error):
        return _result({"content": [{"type": "text", "text": json.dumps(out)}],
                        "structuredContent": out, "isError": is_error})

    if method == "initialize":
        return _result({"protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "celaut-node-honesty-verifier",
                                       "version": VERIFIER_VERSION}})
    if method in ("notifications/initialized", "initialized"):
        return ("", 204)
    if method == "tools/list":
        return _result({"tools": MCP_TOOLS})
    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        try:
            return _content(_mcp_call_tool(name, params.get("arguments") or {}), False)
        except BusyError as e:
            return _content({"status": "busy", "error": str(e), "running": e.running}, True)
        except Exception as e:
            return _content({"error": f"{type(e).__name__}: {clip(e)}"}, True)
    return _error(-32601, f"method not found: {method}")


REPORT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Celaut Node-Honesty Verifier</title>
<link rel="stylesheet" href="https://unpkg.com/papercss@1.9.2/dist/paper.min.css">
<style>
 body{font-family:Arial,sans-serif;margin:40px;max-width:1000px}
 .card{padding:16px 20px;margin:14px 0;box-shadow:0 4px 8px rgba(0,0,0,.1);border-radius:6px}
 .PASS{border-left:8px solid #2e7d32}.DISHONEST{border-left:8px solid #c62828}
 .INFRA_ERROR,.INCONCLUSIVE,.NOT_APPLICABLE,.UNVERIFIED{border-left:8px solid #6c7a89}
 .badge{font-weight:bold;padding:2px 10px;border-radius:12px;color:#fff}
 .b-PASS{background:#2e7d32}.b-DISHONEST{background:#c62828}
 .b-INFRA_ERROR,.b-INCONCLUSIVE,.b-NOT_APPLICABLE,.b-UNVERIFIED{background:#6c7a89}
 pre{background:#f6f6f6;padding:10px;border-radius:4px;overflow:auto;font-size:12px}
 .hash{font-family:monospace;word-break:break-all;font-size:12px}
 #overall{font-size:1.3em;font-weight:bold}
</style></head>
<body>
<h1>Celaut Node-Honesty Verifier</h1>
<p>Actively probes the node under test for resource, memory-ceiling and network-isolation honesty, and runs its per-core benchmark.</p>
<p><small>Absence of evidence is not evidence of dishonesty: probes that could not observe the node
report <b>INFRA_ERROR</b>, and no attestation hash is minted unless every probe reached a
conclusive verdict.</small></p>
<div id="funding"></div>
<div id="overall">Loading the last attestation…</div>
<button class="btn btn-primary" onclick="run()">Run attestation</button>
<p><small>A run launches child microVMs paid for from this instance's balance and takes a few minutes.</small></p>
<h3>Startup automation tests</h3>
<div id="startup">Loading startup test results…</div>
<div id="cards"></div>
<h3>Content hash (EGO-opinion-ready)</h3>
<div class="hash" id="hash">—</div>
<h3>Raw report</h3>
<pre id="raw">—</pre>
<script>
function renderAttestation(rep){
  const s=rep.summary;
  // Tri-state: honest / dishonest / unverified. "Unverified" is NOT guilt, so
  // it must never be painted with the dishonest colour.
  const state = (s.node_honest===true) ? 'PASS'
              : (s.dishonest>0) ? 'DISHONEST' : 'UNVERIFIED';
  const label = (state==='PASS') ? 'HONEST'
              : (state==='DISHONEST') ? 'DISHONEST' : 'UNVERIFIED (could not observe)';
  document.getElementById('overall').innerHTML =
    'Node verdict: <span class="badge b-'+state+'">'+label+'</span> &nbsp; ('+
    s.pass+' pass / '+s.dishonest+' dishonest / '+s.unobserved+' unobserved / '+s.total+' probes)';
  const cards=document.getElementById('cards');cards.innerHTML='';
  rep.probes.forEach(p=>{
    const v=p.verdict||'INFRA_ERROR';
    const d=document.createElement('div');d.className='card '+v;
    d.innerHTML='<h3>'+p.probe+' <span class="badge b-'+v+'">'+v+'</span></h3>'+
                '<p>'+(p.reason||'')+'</p><pre>'+JSON.stringify(p,null,2)+'</pre>';
    cards.appendChild(d);
  });
  document.getElementById('hash').innerText = rep.content_hash.value
    ? (rep.content_hash.alg+':'+rep.content_hash.value)
    : rep.content_hash.note;
  document.getElementById('raw').innerText=JSON.stringify(rep,null,2);
}

// A full run drives every probe (memory ladder, MU-accounting windows, several
// child launches) and can take minutes, so the job runs in the background and
// this polls a short-lived status endpoint instead of awaiting one long fetch
// that a proxy/tunnel in front of this service could kill mid-flight.
// Opening the page no longer starts a run: every visit used to spend MU on a
// fresh attestation, and collide with the startup suite while it was running.
const sleep=ms=>new Promise(r=>setTimeout(r,ms));

function fundingHtml(f){
  if(!f) return '';
  if(f.funded===false){
    return '<div class="card UNVERIFIED"><b>Waiting for funds</b>: balance '+f.balance_mu+
      ' MU, a suite needs '+f.required_mu+' MU ('+f.missing_mu+' MU missing).<br>'+
      (f.operator_hint||'')+'</div>';
  }
  return '';
}

async function loadFunding(){
  try{
    const st=await (await fetch('/status')).json();
    const f=st.funding||{};
    document.getElementById('funding').innerHTML = f.balance_mu==null ? '' :
      '<p><small>Balance '+f.balance_mu+' MU'+
      (f.required_mu!=null ? ' · a suite needs '+f.required_mu+' MU' : '')+
      (st.running&&st.running.name ? ' · running: '+st.running.name : '')+'</small></p>'+fundingHtml(f);
  }catch(e){}
}

async function run(){
  document.getElementById('overall').innerText='Starting attestation…';
  try{
    await fetch('/attestation.json',{method:'POST'});
    await pollAttestation();
  }catch(e){document.getElementById('overall').innerText='Error running attestation: '+e;}
}

async function pollAttestation(){
  const el=document.getElementById('overall');
  for(;;){
    const job=await (await fetch('/attestation.json')).json();
    if(job.status==='done'){ renderAttestation(job.result); return; }
    if(job.status==='idle'){ el.innerText='No attestation has been run on this instance yet.'; return; }
    if(job.status==='insufficient_funds'){ el.innerHTML='Not started — insufficient funds.'+fundingHtml(job.funding); return; }
    if(job.status==='busy'){ el.innerText='Not started — '+job.error; return; }
    if(job.status==='error'){ el.innerText='Attestation failed: '+job.error; return; }
    el.innerText='Running probes… ('+job.status+')';
    await sleep(3000);
  }
}

async function loadStartup(){
  const el=document.getElementById('startup');
  for(;;){
    let st;
    try{ st=await (await fetch('/startup_tests')).json(); }
    catch(e){ el.innerText='Error loading startup tests: '+e; return; }
    if(st.status==='waiting_for_funds'){
      el.innerHTML='<em>waiting for funds before running</em>'+fundingHtml(st.funding);
    }else if(st.status==='unfunded' || st.status==='error'){
      el.innerHTML='<div class="card UNVERIFIED"><b>'+st.status+'</b>: '+(st.error||'')+'</div>';
      return;
    }else if(st.status!=='done' || !st.results){
      el.innerHTML='<em>status: '+st.status+'</em>';
    }else{
      const s=st.results.summary;
      const cls = s.all_passed?'PASS':(s.dishonest>0?'DISHONEST':'UNVERIFIED');
      const txt = s.all_passed?'ALL PASSED':(s.dishonest>0?'DISHONESTY OBSERVED':'INCOMPLETE OBSERVATION');
      let h='<div class="card '+cls+'"><b>'+txt+'</b> — '+s.pass+' pass / '+s.dishonest+
        ' dishonest / '+s.unobserved+' unobserved / '+s.total+' tests</div>';
      Object.values(st.results.probes).forEach(p=>{const v=p.verdict||'INFRA_ERROR';
        h+='<div class="card '+v+'"><h4>'+p.probe+' <span class="badge b-'+v+'">'+v+'</span></h4>'+
           '<p>'+(p.reason||'')+'</p><pre>'+JSON.stringify(p,null,2)+'</pre></div>';});
      el.innerHTML=h;
      return;
    }
    await sleep(5000);
    loadFunding();
  }
}
loadFunding();
loadStartup();
pollAttestation();
</script>
</body></html>
"""


@app.route('/')
def home():
    logging.info('Serving the node-honesty report card.')
    return render_template_string(REPORT_HTML)


# ----------------------------------------------------------------------------
# Legacy demo endpoints (kept so the original interaction still works)
# ----------------------------------------------------------------------------
@app.route('/services', methods=['GET'])
def get_services():
    return jsonify([{"ip_port": s[0], "result": s[1]} for s in services])


def _gen(service_iface, label):
    uri = service_iface.get_instance(max_attempts=1).uri
    new_service = (uri, "--")
    services.append(new_service)
    logging.info('Generated new %s service: %s', label, new_service)
    return jsonify({"status": "Service generated", "service": new_service})


@app.route('/generate_service', methods=['POST'])
def generate_service():
    try:
        return _gen(tiny_service, "tiny")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/generate_heavy_service', methods=['POST'])
def generate_heavy_service():
    try:
        return _gen(heavy_service, "heavy")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/generate_ping_service', methods=['POST'])
def generate_ping_service():
    try:
        return _gen(ping_service, "ping")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/use_services', methods=['POST'])
def use_services():
    try:
        for idx, service in enumerate(services):
            ip_port = service[0]
            try:
                result = requests.get(f"http://{ip_port}", timeout=30).text
            except requests.exceptions.RequestException as e:
                logging.error('Error contacting service at %s: %s', ip_port, str(e))
                result = 'Error'
            services[idx] = (ip_port, result)
        return jsonify({"status": "Services used successfully", "services": services})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/current_balance', methods=['GET'])
def current_balance():
    # Used to format a module global that nothing ever updated, so it said 0.00e+00
    # forever. Now the last balance the node reported (see /status for the rest).
    balance = FUNDING["balance_mu"]
    return jsonify({"balance_mu": "{:.2e}".format(balance) if balance is not None else None})


@app.route('/memory_usage', methods=['GET'])
def memory_usage():
    b = resources.get('mem_limit', 0)
    return jsonify({"memory_used": "{:.2f}".format(b / (1024 * 1024) if b else 0)})


if __name__ == '__main__':
    logging.info('Starting the node-honesty verifier.')
    # Kick off the automation test suite as soon as the service starts; it runs
    # in the background so Flask still binds immediately, and waits until the
    # balance covers it. Results are served at /startup_tests, in the report
    # card, and via the MCP get_startup_tests tool.
    start_startup_tests_async()
    # debug=False: the Werkzeug interactive debugger is a remote-code-execution
    # risk on a service that is reachable over the network, PIN or not -- this
    # is an attestation service, not a local dev server.
    # use_reloader=False: the reloader would fork a second process and spin the
    # child services (and the startup tests) twice.
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
