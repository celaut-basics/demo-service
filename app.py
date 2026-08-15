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

import os, json, logging, hashlib, datetime, threading, time
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

VERIFIER_VERSION = "1.0.0"

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


def _spin_child(service_iface, label):
    """Launch one child instance and return its ip:port uri (or raise)."""
    inst = service_iface.get_instance(max_attempts=2)
    logging.info('Spun %s child at %s', label, inst.uri)
    return inst.uri


# ----------------------------------------------------------------------------
# Probe 1 — network isolation (ping child asserts declared vs undeclared egress)
# ----------------------------------------------------------------------------
def probe_network_isolation():
    ev = {"probe": "network_isolation"}
    try:
        uri = _spin_child(ping_service, "ping")
        r = requests.get(f"http://{uri}", timeout=45)
        data = r.json()
        ev.update(data)
        honest = bool(data.get("honest", False))
        # Extra guard: even if the child says honest, fail if any target verdict is bad.
        bad = [t for t in data.get("targets", []) if t.get("verdict") in ("DISHONEST_LEAK", "BROKEN_DENIED")]
        verdict = "PASS" if honest and not bad else "FAIL"
        ev["verdict"] = verdict
        ev["reason"] = ("declared egress reachable and undeclared egress blocked"
                        if verdict == "PASS"
                        else f"isolation violated: {[t.get('target')+':'+t.get('verdict') for t in bad]}")
    except Exception as e:
        ev["verdict"] = "ERROR"
        ev["reason"] = f"probe could not run: {e}"
    return ev


# ----------------------------------------------------------------------------
# Probe 2 — memory ceiling (heavy child ramped toward the declared at_most)
# ----------------------------------------------------------------------------
def probe_memory_ceiling():
    declared_mb = HEAVY_DECLARED_MEM_BYTES // (1024 * 1024)  # 256
    # rungs below and above the declared ceiling
    ladder = [64, 128, 200, 240, 300, 400, 512]
    ev = {"probe": "memory_ceiling", "declared_ceiling_mb": declared_mb, "attempts": []}
    highest_ok = 0
    first_kill = None
    for mb in ladder:
        rung = {"requested_mb": mb}
        try:
            uri = _spin_child(heavy_service, f"heavy({mb}MB)")
            r = requests.get(f"http://{uri}/alloc/{mb}", timeout=60)
            ok = (r.status_code == 200 and r.json().get("ok") is True)
            rung["ok"] = ok
            rung["cgroup_mem_current"] = r.json().get("cgroup_mem_current") if ok else None
            if ok:
                highest_ok = max(highest_ok, mb)
            elif first_kill is None:
                first_kill = mb
        except Exception as e:
            rung["ok"] = False
            rung["error"] = str(e)[:160]
            if first_kill is None:
                first_kill = mb
        ev["attempts"].append(rung)
        # Once we've seen a kill above the ceiling we have enough signal.
        if first_kill is not None and mb >= declared_mb:
            break

    ev["observed_ceiling_mb"] = highest_ok
    ev["first_kill_mb"] = first_kill
    tol = 0.20  # 20% tolerance around the declared boundary
    low = declared_mb * (1 - tol)
    if first_kill is None:
        # nothing was ever killed, even well above the ceiling
        ev["verdict"] = "FAIL"
        ev["reason"] = (f"ceiling NOT enforced: allocated up to {highest_ok} MiB with no OOM "
                        f"(declared at_most {declared_mb} MiB)")
    elif highest_ok < low:
        ev["verdict"] = "FAIL"
        ev["reason"] = (f"shortchanged: killed at {first_kill} MiB, well below declared {declared_mb} MiB "
                        f"(highest success {highest_ok} MiB)")
    else:
        ev["verdict"] = "PASS"
        ev["reason"] = (f"enforced near declared boundary: highest success {highest_ok} MiB, "
                        f"first kill {first_kill} MiB vs declared {declared_mb} MiB")
    return ev


# ----------------------------------------------------------------------------
# Probe 3 — resource / MU provisioning honesty (self-introspection)
# ----------------------------------------------------------------------------
def probe_resource_provisioning():
    ev = {"probe": "resource_provisioning"}
    limits = read_container_limits()
    ev["declared_manifest_mem_bytes"] = SELF_DECLARED_MEM_BYTES
    ev["node_reported_mem_limit_at_start"] = mem_limit
    ev["heavy_child_initial_mu_charged"] = HEAVY_INITIAL_MU
    ev["container_actual"] = limits

    actual = limits.get("cgroup_memory_max")
    try:
        actual_bytes = int(actual) if actual not in (None, "max") else None
    except Exception:
        actual_bytes = None

    # The node must deliver at least what it told us it provisioned
    # (get_mem_limit_at_start) and what the manifest declared.
    baseline = max(mem_limit or 0, 0)
    if actual_bytes is None:
        ev["verdict"] = "INCONCLUSIVE"
        ev["reason"] = f"could not read a numeric cgroup memory.max (got {actual!r})"
    elif baseline == 0:
        ev["verdict"] = "INCONCLUSIVE"
        ev["reason"] = "node did not report initial_sysresources.mem_limit"
    else:
        ratio = actual_bytes / baseline
        ev["actual_vs_reported_ratio"] = round(ratio, 3)
        if ratio >= 0.95:
            ev["verdict"] = "PASS"
            ev["reason"] = (f"node delivered {actual_bytes} B >= reported {baseline} B "
                            f"(ratio {ratio:.2f})")
        else:
            ev["verdict"] = "FAIL"
            ev["reason"] = (f"shortchanged: container sees {actual_bytes} B but node reported/charged "
                            f"{baseline} B (ratio {ratio:.2f})")
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
# more, and (c) not drain the whole balance in a single window.
MU_WINDOW_SECONDS = int(os.environ.get("MU_WINDOW_SECONDS", "30"))
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
        drained = (b1_low is not None and b1_low <= 0) or (b1_high is not None and b1_high <= 0)
        scales = spent_high >= spent_low

        if not charging:
            ev["verdict"] = "FAIL"
            ev["reason"] = ("node deducted 0 MU while holding resources over the window — "
                            "usage is not being accounted (free ride / broken metering)")
        elif drained:
            ev["verdict"] = "FAIL"
            ev["reason"] = ("node drained the balance to <= 0 within a single window — "
                            "spending MU far in excess of usage (overcharging)")
        elif not scales:
            ev["verdict"] = "FAIL"
            ev["reason"] = (f"MU spend does not track resource usage: low ceiling spent {spent_low} MU "
                            f"but high ceiling spent only {spent_high} MU over {MU_WINDOW_SECONDS}s")
        else:
            ev["verdict"] = "PASS"
            ev["reason"] = (f"node spent MU in line with usage: {spent_low} MU at low ceiling <= "
                            f"{spent_high} MU at high ceiling over {MU_WINDOW_SECONDS}s, balance never drained")
    except Exception as e:
        ev["verdict"] = "INCONCLUSIVE"
        ev["reason"] = f"could not sample MU balances via modify_resources: {str(e)[:180]}"
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
    all_ok = True
    for tag, iface, expected_identity in DEP_IDENTITY:
        c = {"requested": tag, "expected_identity": expected_identity}
        try:
            uri = _spin_child(iface, tag)
            r = requests.get(f"http://{uri}/whoami", timeout=45)
            data = r.json()
            c["executed"] = data.get("service")
            c["identity"] = data.get("identity")
            c["match"] = (data.get("service") == tag and data.get("identity") == expected_identity)
            if not c["match"]:
                all_ok = False
        except Exception as e:
            c["match"] = False
            c["error"] = str(e)[:160]
            all_ok = False
        ev["checks"].append(c)
    ev["verdict"] = "PASS" if all_ok else "FAIL"
    ev["reason"] = ("every requested dependency executed and self-identified correctly"
                    if all_ok else
                    "a requested dependency did not run or returned the wrong identity")
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
    try:
        # The network dependency (ping) is where connectivity fraud matters most.
        inst = ping_service.get_instance(max_attempts=2)
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

        claims_connectivity = isinstance(self_report, dict) and (
            self_report.get("honest") is not None or self_report.get("targets"))
        undeclared = [p for p in packets
                      if str(p.get("peer_relationship", "")).lower() in ("undeclared", "unauthorized", "leak")]

        if obs_err and not packets:
            ev["verdict"] = "INCONCLUSIVE"
            ev["reason"] = f"node Observe RPC unavailable/unsupported: {obs_err}"
        elif undeclared:
            ev["verdict"] = "FAIL"
            ev["reason"] = f"Observe revealed traffic to undeclared/unauthorized peers: {undeclared[:3]}"
        elif not packets and claims_connectivity:
            ev["verdict"] = "FAIL"
            ev["reason"] = ("dependency self-reports connectivity but the node's Observe stream shows no "
                            "corresponding traffic — the connectivity picture may be fabricated")
        elif packets:
            ev["verdict"] = "PASS"
            ev["reason"] = (f"node exposed {len(packets)} real packet event(s) for the dependency and none to "
                            "undeclared peers — connectivity is independently corroborated, not fabricated")
        else:
            ev["verdict"] = "INCONCLUSIVE"
            ev["reason"] = "no packets observed and no connectivity claim to corroborate"
    except Exception as e:
        ev["verdict"] = "INCONCLUSIVE"
        ev["reason"] = f"observe probe could not run: {str(e)[:180]}"
    return ev


# ----------------------------------------------------------------------------
# Startup automation-test harness
# (runs on boot; executes every dependency and records the verdicts)
# ----------------------------------------------------------------------------
STARTUP_TESTS = {"status": "pending", "started_at": None, "finished_at": None, "results": None}
_startup_lock = threading.Lock()


def run_startup_tests():
    with _startup_lock:
        if STARTUP_TESTS["status"] == "running":
            return STARTUP_TESTS
        STARTUP_TESTS["status"] = "running"
        STARTUP_TESTS["started_at"] = datetime.datetime.utcnow().isoformat() + "Z"
    try:
        # resource modification (provisioning) + dependency identity +
        # network isolation (real ping child) + memory ceiling.
        results = {
            "resource_provisioning": probe_resource_provisioning(),
            "dependency_identity": probe_dependency_identity(),
            "network_isolation": probe_network_isolation(),
            "dependency_observe": probe_dependency_observe(),
            "memory_ceiling": probe_memory_ceiling(),
            "mu_accounting": probe_mu_accounting(),
        }
        summary = {
            "pass": sum(1 for p in results.values() if p.get("verdict") == "PASS"),
            "fail": sum(1 for p in results.values() if p.get("verdict") == "FAIL"),
            "other": sum(1 for p in results.values() if p.get("verdict") not in ("PASS", "FAIL")),
            "total": len(results),
        }
        summary["all_passed"] = summary["fail"] == 0 and summary["other"] == 0
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
    probes = [
        probe_resource_provisioning(),
        probe_dependency_identity(),
        probe_network_isolation(),
        probe_dependency_observe(),
        probe_memory_ceiling(),
        probe_mu_accounting(),
    ]
    passes = [p for p in probes if p.get("verdict") == "PASS"]
    fails = [p for p in probes if p.get("verdict") == "FAIL"]
    others = [p for p in probes if p.get("verdict") not in ("PASS", "FAIL")]

    summary = {
        "node_honest": len(fails) == 0 and len(others) == 0,
        "pass": len(passes),
        "fail": len(fails),
        "inconclusive_or_error": len(others),
        "total": len(probes),
    }

    # Deterministic content hash over the verdict-bearing payload (no timestamps),
    # so the same observed behaviour always hashes identically — this digest is
    # what an EGO reputation opinion would commit to on-chain.
    hashable = {
        "verifier": "celaut-node-honesty-verifier",
        "version": VERIFIER_VERSION,
        "probes": [{"probe": p.get("probe"), "verdict": p.get("verdict")} for p in probes],
        "summary": {k: summary[k] for k in ("node_honest", "pass", "fail", "total")},
    }
    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
    content_hash = hashlib.sha3_256(canonical.encode()).hexdigest()

    return {
        "verifier": "celaut-node-honesty-verifier",
        "version": VERIFIER_VERSION,
        "node_url": node_url,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "probes": probes,
        "summary": summary,
        "content_hash": {"alg": "sha3_256", "value": content_hash,
                         "note": "EGO-opinion-ready digest of {probe:verdict} + summary"},
    }


# ----------------------------------------------------------------------------
# Routes — attestation
# ----------------------------------------------------------------------------
@app.route('/attestation.json', methods=['GET', 'POST'])
def attestation_json():
    return jsonify(build_attestation())


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
    {"name": "run_attestation",
     "description": "Run all node-honesty probes and return the attestation report card with content hash.",
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
 .PASS{border-left:8px solid #2e7d32}.FAIL{border-left:8px solid #c62828}
 .ERROR,.INCONCLUSIVE{border-left:8px solid #f9a825}
 .badge{font-weight:bold;padding:2px 10px;border-radius:12px;color:#fff}
 .b-PASS{background:#2e7d32}.b-FAIL{background:#c62828}.b-ERROR,.b-INCONCLUSIVE{background:#f9a825}
 pre{background:#f6f6f6;padding:10px;border-radius:4px;overflow:auto;font-size:12px}
 .hash{font-family:monospace;word-break:break-all;font-size:12px}
 #overall{font-size:1.3em;font-weight:bold}
</style></head>
<body>
<h1>Celaut Node-Honesty Verifier</h1>
<p>Actively probes the node under test for resource, memory-ceiling and network-isolation honesty.</p>
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
async function run(){
  document.getElementById('overall').innerText='Running probes… please wait.';
  try{
    const res=await fetch('/attestation.json',{method:'POST'});
    const rep=await res.json();
    const s=rep.summary;
    document.getElementById('overall').innerHTML =
      'Node verdict: <span class="badge '+(s.node_honest?'b-PASS':'b-FAIL')+'">'+
      (s.node_honest?'HONEST':'DISHONEST / UNVERIFIED')+'</span> &nbsp; ('+
      s.pass+' pass / '+s.fail+' fail / '+s.total+' probes)';
    const cards=document.getElementById('cards');cards.innerHTML='';
    rep.probes.forEach(p=>{
      const v=p.verdict||'ERROR';
      const d=document.createElement('div');d.className='card '+v;
      d.innerHTML='<h3>'+p.probe+' <span class="badge b-'+v+'">'+v+'</span></h3>'+
                  '<p>'+(p.reason||'')+'</p><pre>'+JSON.stringify(p,null,2)+'</pre>';
      cards.appendChild(d);
    });
    document.getElementById('hash').innerText=rep.content_hash.alg+':'+rep.content_hash.value;
    document.getElementById('raw').innerText=JSON.stringify(rep,null,2);
  }catch(e){document.getElementById('overall').innerText='Error running attestation: '+e;}
}
async function loadStartup(){
  try{
    const res=await fetch('/startup_tests');const st=await res.json();
    const el=document.getElementById('startup');
    if(st.status!=='done'){el.innerHTML='<em>status: '+st.status+'</em> (tests run on boot; refresh in a moment)';return;}
    const s=st.results.summary;let h='<div class="card '+(s.all_passed?'PASS':'FAIL')+'">'+
      '<b>'+(s.all_passed?'ALL PASSED':'NOT ALL PASSED')+'</b> — '+s.pass+' pass / '+s.fail+' fail / '+s.total+' tests</div>';
    Object.values(st.results.probes).forEach(p=>{const v=p.verdict||'ERROR';
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
