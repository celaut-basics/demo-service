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
  3. resource_provisioning (self)       what the manifest declared / the node
                                        charged must match what the container
                                        actually gets (cgroup + /proc/meminfo).
  4. attestation         report card    per-probe verdict + a content hash of the
                                        result, ready to be submitted later as an
                                        EGO reputation opinion on-chain.
"""

import os, json, logging, hashlib, datetime, re, threading, time, socket
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

VERIFIER_VERSION = "1.1.0"

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
        "error": f"{type(exc).__name__}: {text[:200]}",
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


# Declared ceilings from the child manifests (.service/service.json at_most).
HEAVY_DECLARED_MEM_BYTES = 268435456   # 256 MiB
SELF_DECLARED_MEM_BYTES = 1000000000   # 1 GB (this service's own manifest)

env_vars = {}
with open(os.path.join(DIR, ".dependencies")) as f:
    for line in f:
        key, value = line.strip().split("=")
        env_vars[key] = value

TINY_SERVICE = env_vars.get("TINY", None)
HEAVY_SERVICE = env_vars.get("HEAVY", None)
PING_SERVICE = env_vars.get("PING", None)

logging.basicConfig(filename='app.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

controller = Controller(debug=lambda s: logging.info('Node Controller: %s', s),
                        app_dir=DIR, config_file=CONFIG_FILE)
node_url: str = controller.get_node_url()
mem_limit: int = controller.get_mem_limit_at_start()

# initial_mu the orchestrator asked the node to fund the heavy child with.
HEAVY_INITIAL_MU = pow(10, 8)

resources = {"mem_limit": mem_limit}
balance_mu = 0

tiny_service = controller.add_service(service_hash=TINY_SERVICE)
heavy_service = controller.add_service(
    service_hash=HEAVY_SERVICE,
    config=celaut_pb2.Configuration(initial_mu=to_amount(HEAVY_INITIAL_MU))
)
ping_service = controller.add_service(service_hash=PING_SERVICE)

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
        super().__init__(f"could not launch child '{label}': {_describe_launch_failure(original)}")


def _describe_launch_failure(exc):
    """Recover a usable message even when the client library loses the real error.

    node_controller's launch_instance() swallows every grpc.RpcError into debug()
    and then trips over `return instance` with the name unbound, so an
    UnboundLocalError is all that reaches us. Translate that into what it
    actually means instead of propagating a meaningless Python detail.
    """
    if isinstance(exc, UnboundLocalError) and "instance" in str(exc):
        return (f"every StartService attempt to the node gateway at {node_url} failed; "
                "the client library discarded the gRPC status (see app.log for "
                "'GRPC ERROR LAUNCHING INSTANCE')")
    last = getattr(exc, "last_error", None)
    if last is not None:
        return f"{type(last).__name__}: {str(last)[:200]}"
    return f"{type(exc).__name__}: {str(exc)[:200]}"


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
        raise ChildLaunchError(label, e) from e
    logging.info('Spun %s child at %s', label, inst.uri)
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
            last = f"{type(e).__name__}: {str(e)[:120]}"
            if time.monotonic() >= deadline:
                raise ChildNotReadyError(label, uri, timeout, last)
            time.sleep(CHILD_READY_POLL_S)


def _release_child(service_iface, inst, label):
    """Stop a child the probe is done with.

    Left running, each child keeps drawing MU from this service's balance for
    the rest of the run. That is not only waste: it is measured by the
    mu_accounting probe, whose two windows would otherwise be dominated by the
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
        ev["reason"] = f"probe could not run: {type(e).__name__}: {str(e)[:200]}"
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
            rung["error"] = str(e)[:200]
            launch_failures.append(rung)
            ev["attempts"].append(rung)
            continue
        except ChildNotReadyError as e:
            # It ran but never opened its port, so it was never seen allocating
            # anything either. Same rule: a rung that observed nothing cannot
            # decide a ceiling, and must never feed first_kill.
            rung["ok"] = False
            rung["never_ready"] = True
            rung["error"] = str(e)[:200]
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
            rung["error"] = str(e)[:160]
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
    ev["heavy_child_initial_mu_charged"] = HEAVY_INITIAL_MU
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
# how many MU the node actually deducts over a fixed window. To check that the
# spend tracks USAGE (not a flat or arbitrary drain) we run two equal-length
# windows: one holding a LOW resource ceiling and one holding a HIGH ceiling
# (up to the manifest at_most). An honest node must (a) actually charge — the
# balance must fall while resources are held — (b) charge MORE when it provisions
# more, and (c) not take a positive balance to zero inside a single window.
#
# Comparing the two windows only works if this service's own ceiling is the only
# thing that changed between them. Every probe therefore stops its children (see
# _release_child): each one left running keeps drawing MU from this same balance,
# and enough of them swamp the difference the two windows exist to measure.
# Defaulted to the decisive length below, because a window shorter than that
# yields readings this probe is not allowed to accuse on: a shorter default makes
# every run pay for two windows it cannot read.
MU_WINDOW_SECONDS = int(os.environ.get("MU_WINDOW_SECONDS", "60"))
# Below this window length a small charge is indistinguishable from an honest
# node's rounding, so no reading from it can support an accusation.
MU_MIN_DECISIVE_WINDOW_SECONDS = int(os.environ.get("MU_MIN_DECISIVE_WINDOW_SECONDS", "60"))
MU_LOW_CEILING = 64 * 1024 * 1024                      # 64 MiB
MU_HIGH_CEILING = SELF_DECLARED_MEM_BYTES              # this service's declared at_most


def _sample_mu_balance(min_b, max_b):
    """Settle the account at the given ceiling and return (balance_mu, sysreq)."""
    sysreq, balance = controller.modify_resources({"min": min_b, "max": max_b})
    return balance, sysreq


def probe_mu_accounting():
    ev = {"probe": "mu_accounting", "window_seconds": MU_WINDOW_SECONDS,
          "low_ceiling_bytes": MU_LOW_CEILING, "high_ceiling_bytes": MU_HIGH_CEILING}
    try:
        # Window 1 — hold a LOW ceiling, measure MU spent.
        b0_low, _ = _sample_mu_balance(MU_LOW_CEILING, MU_LOW_CEILING)
        time.sleep(MU_WINDOW_SECONDS)
        b1_low, _ = _sample_mu_balance(MU_LOW_CEILING, MU_LOW_CEILING)
        spent_low = b0_low - b1_low

        # Window 2 — hold a HIGH ceiling, measure MU spent over the same interval.
        b0_high, _ = _sample_mu_balance(MU_HIGH_CEILING, MU_HIGH_CEILING)
        time.sleep(MU_WINDOW_SECONDS)
        b1_high, _ = _sample_mu_balance(MU_HIGH_CEILING, MU_HIGH_CEILING)
        spent_high = b0_high - b1_high

        ev["balance_low"] = [b0_low, b1_low]
        ev["spent_low_mu"] = spent_low
        ev["balance_high"] = [b0_high, b1_high]
        ev["spent_high_mu"] = spent_high

        charging = (spent_low > 0) or (spent_high > 0)
        # "Drained" has to mean the window did the draining. A balance that was
        # already at or below zero when the window opened was not spent by this
        # node during it -- operators run nodes with `costs.ALLOW_DEBT` enabled,
        # where a negative balance is the configured policy and says nothing
        # about how much was charged. Testing only the closing balance accuses
        # every node in debt, for a drain that predates the measurement.
        ev["started_in_debt"] = (b0_low <= 0) or (b0_high <= 0)
        drained = (b0_low > 0 >= b1_low) or (b0_high > 0 >= b1_high)
        scales = spent_high >= spent_low
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
                ev["reason"] = f"no MU movement over a {MU_WINDOW_SECONDS}s window; {too_coarse}."
        elif drained:
            if decisive:
                ev["verdict"] = VERDICT_DISHONEST
                ev["reason"] = ("node took the balance from positive to <= 0 within a single "
                                "window — spending MU far in excess of usage (overcharging)")
            else:
                ev["verdict"] = VERDICT_INCONCLUSIVE
                ev["reason"] = f"balance crossed into debt during the window, but {too_coarse}."
        elif not scales:
            if decisive:
                ev["verdict"] = VERDICT_DISHONEST
                ev["reason"] = (f"MU spend does not track resource usage: low ceiling spent {spent_low} MU "
                                f"but high ceiling spent only {spent_high} MU over {MU_WINDOW_SECONDS}s")
            else:
                ev["verdict"] = VERDICT_INCONCLUSIVE
                ev["reason"] = (f"spend did not rise with the ceiling ({spent_low} MU low vs "
                                f"{spent_high} MU high), but {too_coarse}.")
        else:
            ev["verdict"] = VERDICT_PASS
            ev["reason"] = (f"node spent MU in line with usage: {spent_low} MU at low ceiling <= "
                            f"{spent_high} MU at high ceiling over {MU_WINDOW_SECONDS}s, balance never "
                            "crossed into debt during a window")
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
# Each child exposes GET /whoami returning a fixed, service-specific signature.
# We request each dependency by its own service hash and assert that the
# instance that comes back self-identifies as the very service we asked for —
# a node that silently substituted or misrouted a dependency is caught here.
DEP_IDENTITY = [
    ("tiny", tiny_service, "celaut-demo-tiny"),
    ("heavy", heavy_service, "celaut-demo-heavy"),
    ("ping", ping_service, "celaut-demo-ping"),
]


def probe_dependency_identity():
    ev = {"probe": "dependency_identity", "checks": []}
    mismatches, not_observed, verified = [], [], 0
    for tag, iface, expected_identity in DEP_IDENTITY:
        c = {"requested": tag, "expected_identity": expected_identity}
        inst = None
        try:
            inst = _spin_child(iface, tag)
            r = requests.get(f"http://{inst.uri}/whoami", timeout=45)
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
            c["error"] = str(e)[:200]
            not_observed.append(tag)
        except ChildNotReadyError as e:
            # Ran but never answered -> still nothing observed about identity.
            c["match"] = None
            c["never_ready"] = True
            c["error"] = str(e)[:200]
            not_observed.append(tag)
        except Exception as e:
            # Ran but we could not read its identity: still not a substitution.
            c["match"] = None
            c["unreachable"] = True
            c["error"] = str(e)[:160]
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
        out.append(("__error__", str(e)[:200]))


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

        # 1) Drive the dependency so it produces real traffic and capture its
        #    own account of what it connected to.
        try:
            self_report = requests.get(f"http://{inst.uri}", timeout=30).json()
        except Exception as e:
            self_report = {"error": str(e)[:160]}
        ev["dependency_self_report"] = self_report

        # 2) Independently Observe the dependency's real packets via the node.
        events, stop_flag = [], [False]
        t = threading.Thread(target=_collect_observe_events,
                             args=(instance_id, events, stop_flag), daemon=True)
        t.start()
        t.join(timeout=OBSERVE_SECONDS)
        stop_flag[0] = True

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
        elif not packets and claims_connectivity and stream_alive:
            # Only accusable because the stream demonstrably worked and still
            # showed nothing for a dependency that claims it connected.
            ev["verdict"] = VERDICT_DISHONEST
            ev["reason"] = ("dependency self-reports connectivity but the node's Observe stream — which "
                            f"was demonstrably live ({len(sessions)} session event(s) in the same "
                            "window) — shows no corresponding traffic; the connectivity picture is "
                            "fabricated")
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
        ev["reason"] = f"observe probe could not run: {type(e).__name__}: {str(e)[:180]}"
    finally:
        _release_child(ping_service, inst, "ping")
    return ev


# ----------------------------------------------------------------------------
# Startup automation-test harness
# (runs on boot; executes every dependency and records the verdicts)
# ----------------------------------------------------------------------------
STARTUP_TESTS = {"status": "pending", "started_at": None, "finished_at": None, "results": None}
_startup_lock = threading.Lock()

# ----------------------------------------------------------------------------
# Attestation job — run in the background, polled by the UI
# ----------------------------------------------------------------------------
# A full attestation run drives every probe (memory ceiling ladder, two
# MU-accounting windows, several child launches) and can legitimately take
# minutes. Blocking one HTTP request for that long is what a proxy/tunnel
# sitting in front of this service will eventually kill mid-flight, which the
# browser reports as a bare "NetworkError" with no HTTP status to explain it.
# So attestation runs the same way STARTUP_TESTS already does: kicked off in a
# background thread, polled from a short-lived request.
ATTESTATION_JOB = {"status": "idle", "started_at": None, "finished_at": None,
                    "result": None, "error": None}
_attestation_lock = threading.Lock()


def run_attestation_job():
    with _attestation_lock:
        if ATTESTATION_JOB["status"] == "running":
            return ATTESTATION_JOB
        ATTESTATION_JOB["status"] = "running"
        ATTESTATION_JOB["started_at"] = datetime.datetime.utcnow().isoformat() + "Z"
        ATTESTATION_JOB["finished_at"] = None
        ATTESTATION_JOB["result"] = None
        ATTESTATION_JOB["error"] = None
    try:
        ATTESTATION_JOB["result"] = build_attestation()
        ATTESTATION_JOB["status"] = "done"
    except Exception as e:
        ATTESTATION_JOB["status"] = "error"
        ATTESTATION_JOB["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    ATTESTATION_JOB["finished_at"] = datetime.datetime.utcnow().isoformat() + "Z"
    logging.info("Attestation job finished: status=%s", ATTESTATION_JOB.get("status"))
    return ATTESTATION_JOB


def start_attestation_async():
    threading.Thread(target=run_attestation_job, name="attestation-run", daemon=True).start()

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
    ("mu_accounting", probe_mu_accounting),
]

# Probes that cannot produce any observation without the gateway. When the
# preflight fails they are reported as INFRA_ERROR instead of being run, so the
# report says "could not verify" once rather than six times in six dialects.
# resource_provisioning is deliberately NOT here: it only reads /proc and
# /__config__, so it stays valid (and can legitimately PASS) with the gateway down.
GATEWAY_DEPENDENT = ("dependency_identity", "network_isolation",
                     "dependency_observe", "memory_ceiling", "mu_accounting")


def _safe_probe(name, fn):
    """Run one probe; never propagate — a crash becomes an INFRA_ERROR verdict so
    the rest of the suite still completes. A crashed probe observed nothing, so
    it must never be counted as an accusation."""
    try:
        return fn()
    except Exception as e:
        return {"probe": name, "verdict": VERDICT_INFRA_ERROR,
                "reason": f"probe crashed: {type(e).__name__}: {str(e)[:180]}"}


def _run_probe_suite():
    """Run the preflight, then every probe, short-circuiting the gateway-dependent
    ones when the node is unreachable. Returns an ordered {name: evidence} dict."""
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
        results[name] = _safe_probe(name, fn)
    return results


def run_startup_tests():
    with _startup_lock:
        if STARTUP_TESTS["status"] == "running":
            return STARTUP_TESTS
        STARTUP_TESTS["status"] = "running"
        STARTUP_TESTS["started_at"] = datetime.datetime.utcnow().isoformat() + "Z"
    try:
        # gateway preflight + resource provisioning + dependency identity +
        # network isolation (real ping child) + observe + memory ceiling + MU.
        results = _run_probe_suite()
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
        STARTUP_TESTS["results"] = {"summary": summary, "probes": results}
        STARTUP_TESTS["status"] = "done"
    except Exception as e:
        STARTUP_TESTS["status"] = "error"
        STARTUP_TESTS["error"] = str(e)
    STARTUP_TESTS["finished_at"] = datetime.datetime.utcnow().isoformat() + "Z"
    logging.info("Startup automation tests finished: status=%s", STARTUP_TESTS.get("status"))
    return STARTUP_TESTS


def start_startup_tests_async():
    threading.Thread(target=run_startup_tests, name="startup-tests", daemon=True).start()


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
    }


# ----------------------------------------------------------------------------
# Routes — attestation
# ----------------------------------------------------------------------------
@app.route('/attestation.json', methods=['GET'])
def attestation_json():
    """Poll the current attestation job (idle / running / done / error)."""
    return jsonify(ATTESTATION_JOB)


@app.route('/attestation.json', methods=['POST'])
def attestation_json_run():
    """Schedule an attestation run if one isn't already in flight, and return
    immediately -- the caller polls GET /attestation.json for the result."""
    with _attestation_lock:
        already_running = ATTESTATION_JOB["status"] == "running"
    if not already_running:
        start_attestation_async()
    return jsonify(ATTESTATION_JOB), 202


@app.route('/probe/network', methods=['GET', 'POST'])
def route_probe_network():
    return jsonify(probe_network_isolation())


@app.route('/probe/memory', methods=['GET', 'POST'])
def route_probe_memory():
    return jsonify(probe_memory_ceiling())


@app.route('/probe/resources', methods=['GET', 'POST'])
def route_probe_resources():
    return jsonify(probe_resource_provisioning())


@app.route('/probe/dependency_identity', methods=['GET', 'POST'])
def route_probe_dep_identity():
    return jsonify(probe_dependency_identity())


@app.route('/probe/mu_accounting', methods=['GET', 'POST'])
def route_probe_mu():
    return jsonify(probe_mu_accounting())


@app.route('/probe/dependency_observe', methods=['GET', 'POST'])
def route_probe_observe():
    return jsonify(probe_dependency_observe())


@app.route('/probe/gateway', methods=['GET', 'POST'])
def route_probe_gateway():
    return jsonify(probe_gateway_reachability())


# ----------------------------------------------------------------------------
# Startup automation-test results
# ----------------------------------------------------------------------------
@app.route('/startup_tests', methods=['GET'])
def route_startup_tests():
    return jsonify(STARTUP_TESTS)


@app.route('/startup_tests/rerun', methods=['POST'])
def route_startup_tests_rerun():
    STARTUP_TESTS["status"] = "pending"
    start_startup_tests_async()
    return jsonify({"status": "rerun scheduled"})


# ----------------------------------------------------------------------------
# MCP interface — self-contained JSON-RPC 2.0 over HTTP (Streamable-HTTP style).
# Exposes the verifier's probes/attestation as MCP tools with no extra deps.
# ----------------------------------------------------------------------------
MCP_PROTOCOL_VERSION = "2024-11-05"
_EMPTY_SCHEMA = {"type": "object", "properties": {}}
MCP_TOOLS = [
    {"name": "probe_gateway_reachability",
     "description": ("Preflight: check whether this service can reach the node's gRPC gateway at "
                     "all. Run this FIRST when other probes report INFRA_ERROR — it distinguishes "
                     "a node/network fault from actual node dishonesty."),
     "inputSchema": _EMPTY_SCHEMA},
    {"name": "run_attestation",
     "description": ("Run all node-honesty probes and return the attestation report card. The "
                     "content hash is only minted when every probe reached a conclusive verdict; "
                     "otherwise the report is explicitly NOT attestable."),
     "inputSchema": _EMPTY_SCHEMA},
    {"name": "get_startup_tests",
     "description": "Return the results of the automation tests that run when the service starts.",
     "inputSchema": _EMPTY_SCHEMA},
    {"name": "probe_dependency_identity",
     "description": "Execute each dependency and assert the requested dependency is the one that actually ran.",
     "inputSchema": _EMPTY_SCHEMA},
    {"name": "probe_network_isolation",
     "description": "Run the ping child and assert declared egress is reachable and undeclared egress is blocked.",
     "inputSchema": _EMPTY_SCHEMA},
    {"name": "probe_memory_ceiling",
     "description": "Ramp the heavy child toward/past its declared memory ceiling and check enforcement.",
     "inputSchema": _EMPTY_SCHEMA},
    {"name": "probe_resource_provisioning",
     "description": "Compare declared/charged resources against the container's real cgroup limits.",
     "inputSchema": _EMPTY_SCHEMA},
    {"name": "probe_mu_accounting",
     "description": "Verify the node spends the service's MUs in line with the resources it provisions (charges, scales with usage, does not drain).",
     "inputSchema": _EMPTY_SCHEMA},
    {"name": "probe_dependency_observe",
     "description": "Use the node Observe RPC to independently watch a dependency's real packets and confirm its connectivity is genuine, not fabricated by the node.",
     "inputSchema": _EMPTY_SCHEMA},
]


def _mcp_call_tool(name):
    if name == "probe_gateway_reachability":
        return probe_gateway_reachability()
    if name == "run_attestation":
        return build_attestation()
    if name == "get_startup_tests":
        return STARTUP_TESTS
    if name == "probe_dependency_identity":
        return probe_dependency_identity()
    if name == "probe_network_isolation":
        return probe_network_isolation()
    if name == "probe_memory_ceiling":
        return probe_memory_ceiling()
    if name == "probe_resource_provisioning":
        return probe_resource_provisioning()
    if name == "probe_mu_accounting":
        return probe_mu_accounting()
    if name == "probe_dependency_observe":
        return probe_dependency_observe()
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
            out = _mcp_call_tool(name)
            return _result({"content": [{"type": "text", "text": json.dumps(out)}],
                            "isError": False})
        except Exception as e:
            return _result({"content": [{"type": "text", "text": f"error: {e}"}],
                            "isError": True})
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
<p>Actively probes the node under test for resource, memory-ceiling and network-isolation honesty.</p>
<p><small>Absence of evidence is not evidence of dishonesty: probes that could not observe the node
report <b>INFRA_ERROR</b>, and no attestation hash is minted unless every probe reached a
conclusive verdict.</small></p>
<div id="overall">Running probes… (this launches child microVMs and can take ~1 minute)</div>
<button class="btn btn-primary" onclick="run()">Re-run attestation</button>
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
async function run(){
  document.getElementById('overall').innerText='Running probes… please wait.';
  try{
    await fetch('/attestation.json',{method:'POST'});
    await pollAttestation();
  }catch(e){document.getElementById('overall').innerText='Error running attestation: '+e;}
}

async function pollAttestation(){
  for(;;){
    const res=await fetch('/attestation.json');
    const job=await res.json();
    if(job.status==='done'){ renderAttestation(job.result); return; }
    if(job.status==='error'){ document.getElementById('overall').innerText='Attestation failed: '+job.error; return; }
    document.getElementById('overall').innerText='Running probes… ('+job.status+')';
    await new Promise(r=>setTimeout(r,3000));
  }
}
async function loadStartup(){
  try{
    const res=await fetch('/startup_tests');const st=await res.json();
    const el=document.getElementById('startup');
    if(st.status!=='done'){el.innerHTML='<em>status: '+st.status+'</em> (tests run on boot; refresh in a moment)';return;}
    const s=st.results.summary;
    const cls = s.all_passed?'PASS':(s.dishonest>0?'DISHONEST':'UNVERIFIED');
    const txt = s.all_passed?'ALL PASSED':(s.dishonest>0?'DISHONESTY OBSERVED':'INCOMPLETE OBSERVATION');
    let h='<div class="card '+cls+'"><b>'+txt+'</b> — '+s.pass+' pass / '+s.dishonest+
      ' dishonest / '+s.unobserved+' unobserved / '+s.total+' tests</div>';
    Object.values(st.results.probes).forEach(p=>{const v=p.verdict||'INFRA_ERROR';
      h+='<div class="card '+v+'"><h4>'+p.probe+' <span class="badge b-'+v+'">'+v+'</span></h4>'+
         '<p>'+(p.reason||'')+'</p><pre>'+JSON.stringify(p,null,2)+'</pre></div>';});
    el.innerHTML=h;
  }catch(e){document.getElementById('startup').innerText='Error loading startup tests: '+e;}
}
loadStartup();
run();
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
    return jsonify({"balance_mu": "{:.2e}".format(balance_mu)})


@app.route('/memory_usage', methods=['GET'])
def memory_usage():
    b = resources.get('mem_limit', 0)
    return jsonify({"memory_used": "{:.2f}".format(b / (1024 * 1024) if b else 0)})


if __name__ == '__main__':
    logging.info('Starting the node-honesty verifier.')
    # Kick off the automation test suite as soon as the service starts; it runs
    # in the background so Flask still binds immediately. Results are served at
    # /startup_tests, in the report card, and via the MCP get_startup_tests tool.
    start_startup_tests_async()
    # use_reloader=False: the reloader would fork a second process and spin the
    # child services (and the startup tests) twice.
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
