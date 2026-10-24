#!/usr/bin/env python3.11
"""
Celaut node-honesty verifier (orchestrator).

This service turns the passive "demo" into an ACTIVE verifier that checks whether
the nodo node it runs on is HONEST. It drives the child services and turns each
observation into an explicit PASS / DISHONEST / INFRA_ERROR / INCONCLUSIVE /
NOT_APPLICABLE verdict, then assembles a signed-ready
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
  5. shared_filesystem   (sharefs, sharefs-denied)  the directory this service exports
                                        must be shared with its child both ways and
                                        read-only where asked, and a child asking for a
                                        share its parent does not export must be refused.
  6. attestation         report card    per-probe verdict + a content hash of the
                                        result, ready to be submitted later as an
                                        EGO reputation opinion on-chain.
"""

import os, json, logging, hashlib, datetime, re, threading, time, socket, platform, contextlib, secrets
import ipaddress
import requests
from flask import Flask, jsonify, render_template_string, request
from google.protobuf.json_format import MessageToDict

from bee_rpc.utils import modify_env
from node_controller.controller.controller import Controller
from node_controller.gateway.protos import celaut_pb2
from node_controller.gateway.utils import to_amount, from_amount

import nodo_gateway as gw


DIR = "service"
CONFIG_FILE = "/__config__"

if False:  # development mode toggle (unchanged from the original demo)
    DIR = "."
    CONFIG_FILE = "__config__"

VERIFIER_VERSION = "1.5.0"

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
# A probe that does not apply here (a node that runs for free has no build to fund; a
# node with no peer delegates nothing) left nothing unobserved. It does not block the
# attestation, and it is never counted as a pass.
NEUTRAL_VERDICTS = (VERDICT_NOT_APPLICABLE,)
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
    "sharefs": (50000000, 200000000),
    "netshare": (50000000, 200000000),
}
# sharefs-denied is deliberately NOT in the table above. It declares the same resources
# (tests/test_verdicts.py holds it to its manifest), but it is never meant to start: the
# table drives the budgets and the count of builds a starved run still owes, and a child
# that is never built would be owed forever.
SHARE_DENIED_DECLARED_RESOURCES = (50000000, 200000000)


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
SHAREFS_SERVICE = env_vars.get("SHAREFS", None)
SHAREFS_DENIED_SERVICE = env_vars.get("SHAREFS_DENIED", None)
NETSHARE_SERVICE = env_vars.get("NETSHARE", None)
# The variable that selects the network share of a netshare child: it fills
# ${DEMO_NETSHARE_GROUP} in the formal of its network (netshare/<arch>/.service/service.json).
NETSHARE_GROUP_ENV = "DEMO_NETSHARE_GROUP"

logging.basicConfig(filename='app.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# bee-rpc reads the blocks of a child service from <cwd>/__block__/ by default.
# Under nodo the cwd of this process is /, but the packer puts the blocks in
# service/__block__/ beside __services__. Without this line, a launch that must
# send a child service to the node fails with "gRPCbb: Error reading block".
# node_controller does not set it.
modify_env(block_dir=os.path.join(os.path.abspath(DIR), "__block__") + "/")

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
# One full suite: the three MU windows (3 x MU_WINDOW_SECONDS), the memory ladder
# and the benchmark, and the starts of the newer benchmarks (about 15 of tiny and
# netshare, a 64 MiB tunnel).
SUITE_EXPECTED_SECONDS = int(os.environ.get("SUITE_EXPECTED_SECONDS", "720"))
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
                 "ping": PING_SERVICE, "benchmark": BENCHMARK_SERVICE,
                 "sharefs": SHAREFS_SERVICE, "sharefs_denied": SHAREFS_DENIED_SERVICE,
                 "netshare": NETSHARE_SERVICE}

# Where the packer put the children (pack_config.json): the Service of each one, and
# its Metadata, by service id.
SERVICES_DIR = os.path.join(DIR, "__services__")
METADATA_DIR = os.path.join(DIR, "__metadata__")


def packed(label):
    """A child as this service holds it, for the calls node_controller cannot make."""
    return gw.PackedService(_CHILD_HASHES[label], SERVICES_DIR, METADATA_DIR)


def _read_node_rates():
    """The node's rates (build_mu, net_mu_per_gib, ...) from /__config__, or {}.

    The node writes them in the gateway slot of the configuration file of every
    instance (celaut.proto, ConfigurationFile.gateway). Reading them costs no RPC.
    """
    try:
        return gw.rates_from_config(CONFIG_FILE)
    except Exception as e:
        logging.warning("Could not read the node's rates from %s: %s", CONFIG_FILE, e)
        return {}


NODE_RATES = _read_node_rates()
logging.info("Node rates: %s", NODE_RATES)

FUNDING = {
    "balance_mu": None,          # last balance the node reported
    "sampled_at": None,
    "self_rate_mu_per_s": None,  # measured; None until two samples exist
    "child_initial_mu": {},      # label -> what each child is funded with
    "built_children": [],        # children this instance has seen launch
    # label -> the build that the node quoted for it (GetServiceEstimatedCost): 0 once
    # the node has built it. A label that is absent has no quote, and is funded with
    # the build estimate until this instance has seen it launch.
    "build_quote_mu": {},
    # The build that the node named in a refusal, when it is above the estimate.
    "build_learned_mu": None,
}
_funding_lock = threading.Lock()


def price_weight(mem_bytes, disk_bytes, vcpus=1.0):
    """Relative hourly price of holding these resources (1 vCPU unless declared)."""
    return (mem_bytes / GIB * PRICE_WEIGHT_RAM_GIB + vcpus * PRICE_WEIGHT_VCPU
            + disk_bytes / GIB * PRICE_WEIGHT_DISK_GIB)


def build_mu_estimate():
    """What the node charges for one build: what it named in a refusal, else its rate
    in /__config__, else BUILD_MU_ESTIMATE."""
    learned = FUNDING.get("build_learned_mu")
    rate = NODE_RATES.get("build_mu")
    return max(learned or 0, rate if rate is not None else BUILD_MU_ESTIMATE)


def child_build_mu(label):
    """The build that a start of this child takes out of its initial_mu (#563).

    Since nodo #563 the node takes the build from the initial_mu of the child, not
    from the balance of the parent, and refuses a start whose initial_mu does not
    cover it. The quote of the node is exact. Without one, the build is owed until
    this instance has seen the child launch: after that the node has a built image.
    """
    with _funding_lock:
        quoted = FUNDING["build_quote_mu"].get(label)
        built = label in FUNDING["built_children"]
    if quoted is not None:
        return quoted
    return 0 if built else build_mu_estimate()


def child_runtime_mu(label, self_rate):
    """MU of runtime to fund one child with: CHILD_FUNDED_SECONDS of its own resources."""
    mem, disk = CHILD_DECLARED_RESOURCES[label]
    self_weight = price_weight(mem_limit or SELF_DECLARED_MEM_BYTES, SELF_DECLARED_DISK_BYTES)
    child_rate = self_rate * price_weight(mem, disk) / self_weight
    return max(CHILD_MIN_INITIAL_MU, int(child_rate * CHILD_FUNDED_SECONDS * CHILD_BUDGET_MARGIN))


def child_initial_mu(label, self_rate):
    """MU to fund one child with: its build, if one is owed, and its runtime."""
    return child_build_mu(label) + child_runtime_mu(label, self_rate)


# The balance a build quote asks for. The cost that GetServiceEstimatedCost answers is
# the least initial_mu: the build plus the balance asked for (#563). A request with no
# initial_mu gets the node's default balance filled in (estimated_cost_iterable.py), so
# the quote asks for 1 MU, and the build is the cost less that.
BUILD_QUOTE_BALANCE_MU = 1


# label -> the first request of this instance that carried the child: its bytes and
# seconds. block_skip compares the later starts with it.
FIRST_SENDS = {}


def quote_build(label):
    """(build in MU, EstimatedCost) of one child, as the node quotes it now."""
    measure = {}
    quote = gw.estimated_cost(node_url, packed(label),
                              config=gw.configuration(initial_mu=BUILD_QUOTE_BALANCE_MU),
                              measure=measure)
    if label not in FIRST_SENDS:
        FIRST_SENDS[label] = dict(measure, via="GetServiceEstimatedCost", at=_now())
    return max(0, gw.mu(quote.cost) - BUILD_QUOTE_BALANCE_MU), quote


def quote_child_builds():
    """Ask the node what the build of each child costs (GetServiceEstimatedCost).

    0 for an image the node has built. A child the node does not hold yet goes with
    the request, with the block skip on, and the node keeps it, so the start that
    follows does not send it again. A failed quote leaves that child on the estimate.
    """
    quotes = {}
    for label in CHILD_DECLARED_RESOURCES:
        try:
            quotes[label] = quote_build(label)[0]
        except Exception as e:
            logging.warning("No build quote for %s: %s", label, e)
    with _funding_lock:
        FUNDING["build_quote_mu"].update(quotes)
    return quotes


def _mark_built(label):
    """A child launched here: the node has its image, and the next start owes no build."""
    base = label.split("(", 1)[0]
    with _funding_lock:
        if base not in CHILD_DECLARED_RESOURCES or base in FUNDING["built_children"]:
            return
        FUNDING["built_children"].append(base)
        FUNDING["build_quote_mu"][base] = 0
        rate = FUNDING["self_rate_mu_per_s"]
        refund_build = bool(FUNDING["child_initial_mu"]) and rate is not None
    if refund_build:
        # Fund the next start of this child without the build.
        _register_child_budget(base, child_initial_mu(base, rate))


# ----------------------------------------------------------------------------
# The two egress targets of the network-isolation probe
# ----------------------------------------------------------------------------
# The ping child declares google.com and tries amazon.com, which it does not
# declare. This service declares BOTH (service.json): a child only gets the
# networks every ancestor also declares, so google.com must be here for ping to
# get it at all, and amazon.com is here so that the node resolves its addresses
# for us. The child cannot look amazon.com up itself: its DNS serves only what
# the node granted it, so a request to the name fails inside the guest before
# any packet reaches the firewall under test. It gets the addresses from us
# instead (UNDECLARED_ADDRS) and connects to them directly.
DECLARED_TARGET = ("google.com", "www.google.com")
UNDECLARED_TARGET = ("amazon.com", "www.amazon.com")
UNDECLARED_ADDRS_ENV = "UNDECLARED_ADDRS"
# A bare hostname tag opens 80 and 443; 443 is the port both ends test.
TARGET_PORT = 443
# Matches the bound in ping/src/main.rs: each blocked address costs a timeout.
MAX_TARGET_ADDRESSES = 4
CONTROL_TIMEOUT_S = 3


def granted_addresses(resolutions, tags):
    """Public IPv4 addresses the node resolved for any of `tags`, first ones first.

    `resolutions` are ConfigurationFile.NetworkResolution entries. Only global
    unicast addresses count: a loopback or private address cannot show whether
    the node leaks egress to the internet.
    """
    wanted = set(tags)
    out = []
    for res in resolutions:
        if not wanted & set(res.tags):
            continue
        for inst in res.peer_instances:
            for slot in inst.uri_slot:
                for uri in slot.uri:
                    try:
                        ip = ipaddress.IPv4Address(uri.ip)
                    except ValueError:
                        continue
                    if ip.is_global and str(ip) not in out:
                        out.append(str(ip))
    return out


def _read_own_resolutions():
    """This instance's own NetworkResolution entries, from its __config__."""
    try:
        cfg = celaut_pb2.ConfigurationFile()
        with open(CONFIG_FILE, "rb") as fh:
            cfg.ParseFromString(fh.read())
        return list(cfg.network_resolution)
    except Exception as e:
        logging.warning("Could not read the network resolution from %s: %s", CONFIG_FILE, e)
        return []


def target_addresses(resolutions):
    """{target: [addresses]} for the isolation probe.

    An address that is also one of the declared target is removed from the
    undeclared one: one CDN can serve both names, and reaching an address the
    child was granted is not a leak.
    """
    declared = granted_addresses(resolutions, DECLARED_TARGET)
    undeclared = [ip for ip in granted_addresses(resolutions, UNDECLARED_TARGET)
                  if ip not in declared]
    return {DECLARED_TARGET[0]: declared[:MAX_TARGET_ADDRESSES],
            UNDECLARED_TARGET[0]: undeclared[:MAX_TARGET_ADDRESSES]}


TARGET_ADDRESSES = target_addresses(_read_own_resolutions())
logging.info("Isolation probe targets: %s", TARGET_ADDRESSES)


def control_reach(addresses, port=TARGET_PORT, timeout=CONTROL_TIMEOUT_S):
    """The addresses this service itself can open a TCP connection to.

    This service declared both targets, so the node must let it reach them.
    When it cannot reach a target either, the target is down or the node's
    resolution is stale, and a child that cannot reach it proves nothing.
    """
    reached = []
    for ip in addresses:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                reached.append(ip)
        except OSError:
            pass
    return reached


def _child_config(label, initial_mu=None):
    """The Configuration a child is launched with, or None for the node default."""
    kwargs = {}
    if initial_mu is not None:
        kwargs["initial_mu"] = to_amount(initial_mu)
    undeclared = TARGET_ADDRESSES[UNDECLARED_TARGET[0]]
    if label == "ping" and undeclared:
        kwargs["environment_variables"] = [celaut_pb2.BytesKeyValue(
            key=UNDECLARED_ADDRS_ENV, value=",".join(undeclared).encode())]
    if label == "netshare":
        # The group fills ${DEMO_NETSHARE_GROUP} in netshare's network: without it the
        # node refuses the launch. A group of its own, so dependency_identity never joins
        # the share of network_share.
        kwargs["environment_variables"] = [celaut_pb2.BytesKeyValue(
            key=NETSHARE_GROUP_ENV, value=b"identity")]
    return celaut_pb2.Configuration(**kwargs) if kwargs else None


def _add_child(label, initial_mu=None):
    # No initial_mu: the node funds the child for INITIAL_RUNTIME_HOURS of its own
    # resources, which is sane until this instance has measured its rate.
    return controller.add_service(service_hash=_CHILD_HASHES[label],
                                  config=_child_config(label, initial_mu))


tiny_service = _add_child("tiny")
heavy_service = _add_child("heavy")
ping_service = _add_child("ping")
benchmark_service = _add_child("benchmark")
sharefs_service = _add_child("sharefs")
netshare_service = _add_child("netshare")
# Funded at the floor: an honest node refuses it before anything is spent, and if a node
# does start it the probe still has to be able to inspect it, not be starved of funds.
sharefs_denied_service = _add_child("sharefs_denied", CHILD_MIN_INITIAL_MU)


def _register_child_budget(label, initial_mu):
    """Re-register one child funded with initial_mu (node_controller keeps the config)."""
    global tiny_service, heavy_service, ping_service, benchmark_service, sharefs_service
    global netshare_service
    iface = _add_child(label, initial_mu)
    if label == "tiny":
        tiny_service = iface
    elif label == "heavy":
        heavy_service = iface
    elif label == "ping":
        ping_service = iface
    elif label == "benchmark":
        benchmark_service = iface
    elif label == "sharefs":
        sharefs_service = iface
    elif label == "netshare":
        netshare_service = iface
    with _funding_lock:
        FUNDING["child_initial_mu"] = dict(FUNDING["child_initial_mu"], **{label: initial_mu})
    return iface


def configure_child_budgets(self_rate):
    """Re-register every child funded for CHILD_FUNDED_SECONDS at this rate, plus its build."""
    budgets = {label: child_initial_mu(label, self_rate) for label in CHILD_DECLARED_RESOURCES}
    for label, initial_mu in budgets.items():
        _register_child_budget(label, initial_mu)
    with _funding_lock:
        FUNDING["child_initial_mu"] = dict(budgets)
    logging.info("Child budgets at %.1f MU/s: %s", self_rate, budgets)
    return budgets


def child_iface(label):
    """The current interface for a child (budgets re-register them)."""
    return {"tiny": tiny_service, "heavy": heavy_service,
            "ping": ping_service, "benchmark": benchmark_service,
            "sharefs": sharefs_service, "sharefs_denied": sharefs_denied_service,
            "netshare": netshare_service}[label]


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


def funding_requirement(self_rate):
    """MU this instance needs on hand before a suite may start.

    Each child is funded with its build and its runtime (#563). The runtime comes back
    when the child stops; the build does not. So the balance must hold the largest
    deposit at once, plus the builds of the other children that the node has not
    built yet.
    """
    budgets = FUNDING["child_initial_mu"] or {
        label: child_initial_mu(label, self_rate) for label in CHILD_DECLARED_RESOURCES}
    builds = {label: child_build_mu(label) for label in budgets}
    largest = max(budgets, key=lambda label: budgets[label])
    parts = {
        # Children run one at a time and are refunded on stop, so only the
        # largest deposit is ever held at once. (network_share holds three members,
        # and splits one child's runtime between them.)
        "largest_child_deposit_mu": budgets[largest],
        "builds_owed_mu": sum(b for label, b in builds.items() if label != largest),
        "suite_upkeep_mu": int(self_rate * SUITE_EXPECTED_SECONDS),
        "reserve_after_suite_mu": int(self_rate * MIN_RESERVE_SECONDS),
    }
    parts["required_mu"] = sum(parts.values())
    parts["builds_owed"] = sorted(label for label, b in builds.items() if b)
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
# The last three are the refusals of nodo #563: the initial_mu of a child does not
# cover its build, or leaves less than one maintenance period after it
# (src/utils/cost_functions/start_funding.py). Both mean the child was funded too
# low, which is a shortage like the others: nothing was observed about the node.
_INSUFFICIENT_FUNDS_RE = re.compile(
    r"error charging|insufficient balance|not enough balance"
    r"|does not cover the build|after the build of|least initial_mu",
    re.IGNORECASE)
# "initial_mu 2000000 MU does not cover the build of the service, 10000000 MU."
_BUILD_REFUSAL_RE = re.compile(r"does not cover the build of (?:the service|this node), (\d+) MU")


def learn_from_refusal(label, text):
    """Take the build that a #563 refusal names as the build of that child.

    The node names the figure it wanted, so the next start of the child is funded with
    it instead of the estimate. Returns the build, or None.
    """
    match = _BUILD_REFUSAL_RE.search(text or "")
    if not match:
        return None
    build = int(match.group(1))
    base = label.split("(", 1)[0]
    with _funding_lock:
        FUNDING["build_learned_mu"] = max(FUNDING.get("build_learned_mu") or 0, build)
        if base in CHILD_DECLARED_RESOURCES:
            FUNDING["build_quote_mu"][base] = build
    return build

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
        if self.insufficient_funds:
            learn_from_refusal(label, _full_error_text(original))
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
    _mark_built(label)
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
        # Control first, from this service, which declared both targets: a
        # target that nobody can reach cannot show whether the child's egress
        # is blocked or open.
        control = {target: {"addresses": addrs, "reached": control_reach(addrs)}
                   for target, addrs in TARGET_ADDRESSES.items()}
        ev["control"] = control
        inst = _spin_child(ping_service, "ping")
        r = requests.get(f"http://{inst.uri}", timeout=45)
        data = r.json()
        ev.update(data)
        targets = data.get("targets", [])
        leaks = [t for t in targets if t.get("verdict") == "DISHONEST_LEAK"]
        denied = [t for t in targets if t.get("verdict") == "BROKEN_DENIED"]
        untested = [t.get("target") for t in targets if t.get("verdict") == "UNTESTED"]
        # A declared target the child could not reach is only the node's fault
        # when this service could reach it at the same time.
        denied_seen = [t for t in denied if control.get(t.get("target"), {}).get("reached")]
        blocked = [t for t in targets if t.get("verdict") == "honest_blocked"]
        blocked_unproven = [t.get("target") for t in blocked
                            if not control.get(t.get("target"), {}).get("reached")]
        if leaks or denied_seen:
            ev["verdict"] = VERDICT_DISHONEST
            ev["reason"] = ("isolation violated: "
                            f"{[t.get('target') + ':' + t.get('verdict') for t in leaks + denied_seen]}")
        elif denied:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = (f"the child could not reach the declared {[t.get('target') for t in denied]}, "
                            "but neither could this service, which declared it too: the target is "
                            "down or its addresses are stale. No claim about the node's isolation "
                            "is made.")
        elif untested or blocked_unproven or not blocked:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = ("undeclared egress was not tested against the node's firewall "
                            f"(untested: {untested}, not reachable even from this service: "
                            f"{blocked_unproven}). A block that nothing could have passed proves "
                            "nothing. No claim about the node's isolation is made.")
        elif data.get("honest") is True:
            ev["verdict"] = VERDICT_PASS
            ev["reason"] = ("declared egress reachable and undeclared egress blocked, while this "
                            "service reached the undeclared target itself")
        else:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = f"the ping child gave no usable assertion: {clip(data)}"
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
    ("sharefs", "celaut-demo-sharefs", "/whoami"),
    ("netshare", "celaut-demo-netshare", "/whoami"),
]
# sharefs-denied is absent on purpose: a node that honours the share rules never starts it,
# so there is no identity to read. shared_filesystem is what asks for it.


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
# Probe — shared filesystem (sharefs child is granted a share, sharefs-denied is not)
# ----------------------------------------------------------------------------
# This service exports two directories to its children (service.json, shared_filesystems):
#
#   /shared     tag demo-share     read-write, mounted by sharefs at /mnt/from-parent
#   /shared-ro  tag demo-share-ro  mounted by sharefs with access=ro at /mnt/readonly
#
# The invariant a node must keep: only the exporter's direct children can attach to
# what it exports, a child declaring a directory its parent does not export cannot run
# at all, and nothing else can reach the directory. So the probe has two halves.
#
#   granted -- sharefs must SEE what this service wrote, this service must SEE what
#              sharefs wrote, and the read-only mount must refuse a write. This service
#              holds the other end of the share, so it checks the child's claims against
#              what really landed on disk instead of trusting them.
#   denied  -- sharefs-denied declares a directory under a tag this service does NOT
#              export. The node must refuse to launch it.
#
# The same discipline as every other probe applies: only an OBSERVED violation accuses.
# Two things the probe cannot see from here are reported as INCONCLUSIVE, never as
# DISHONEST: whether the packed child specs really carry the share declarations (a
# packer that does not know the `shared_filesystems` field silently drops it, and then a
# child launches with nothing mounted exactly as it would on a node that skipped the
# mount), and why a node refused a launch other than by the text of its refusal.
SHARE_DIR = os.environ.get("SHARE_DIR", "/shared")
SHARE_RO_DIR = os.environ.get("SHARE_RO_DIR", "/shared-ro")
# Files each side writes. They live under the share, so the other end can read them.
SHARE_PARENT_NONCE_FILE = "parent_nonce"
SHARE_RO_SEED_FILE = "ro_seed"
SHARE_CHILD_NONCE_FILE = "child_nonce"
SHARE_RO_ATTEMPT_FILE = "child_write_attempt"
# Where sharefs mounts them. They must match sharefs/.service/service.json and its main.rs.
SHARE_GUEST_RW_MOUNT = "/mnt/from-parent"
SHARE_GUEST_RO_MOUNT = "/mnt/readonly"
# The directory sharefs-denied declares for a tag nobody exports. The node's refusal names
# it ("cannot inherit '/mnt/not-granted': ..."), which is how that refusal is told apart
# from any other launch failure. Must match sharefs-denied/.service/service.json.
SHARE_DENIED_MOUNT = "/mnt/not-granted"
# A write by the guest reaches the host's directory at once, but a reader may see it a
# moment later; wait this long before concluding it never arrived.
SHARE_PROPAGATION_TIMEOUT_S = float(os.environ.get("SHARE_PROPAGATION_TIMEOUT_S", "10"))
SHARE_PROPAGATION_POLL_S = float(os.environ.get("SHARE_PROPAGATION_POLL_S", "0.5"))

_SHARE_OK = "ok"
_SHARE_DISHONEST = "dishonest"
_SHARE_INFRA = "infra"
_SHARE_INCONCLUSIVE = "inconclusive"

_PACKAGING_HINT = ("If the packed services do not carry their shared_filesystems declarations "
                   "(a nodo packer older than the one that supports the field drops it without "
                   "an error), this is what a child looks like; repack with a nodo whose packer "
                   "supports shared_filesystems (celaut-project/nodo#475).")


def _share_refused(exc, guest_path):
    """Whether the node refused this launch because the share at `guest_path` was not granted.

    The node's own refusal reads "Unable to launch service <id>: cannot inherit
    '<path>': <why>" (src/manager/shares.py). The path is the one the manifest declares,
    so the match is on that exact text and nothing looser: a launch that failed for want
    of balance, a timeout or a crash is not a refusal of a share, and counting it as one
    would let a broken node pass the denied half.
    """
    return re.search(r"cannot inherit '" + re.escape(guest_path) + r"'", _full_error_text(exc)) is not None


def _share_write(path, text):
    with open(path, "w") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())


def _share_read(path):
    """The file's text, or None when it does not exist (any other error propagates)."""
    try:
        with open(path) as fh:
            return fh.read().strip()
    except FileNotFoundError:
        return None


def _share_remove(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def _share_wait_for(path, expected, timeout=None):
    """Poll `path` until it holds `expected`; return what it last held (None if absent)."""
    timeout = SHARE_PROPAGATION_TIMEOUT_S if timeout is None else timeout
    deadline = time.monotonic() + timeout
    seen = None
    while True:
        seen = _share_read(path)
        if seen == expected or time.monotonic() >= deadline:
            return seen
        time.sleep(SHARE_PROPAGATION_POLL_S)


def _share_part(status, reason, **evidence):
    return {"status": status, "reason": reason, "evidence": evidence}


def _judge_granted_share(data, nonces):
    """Decide what the sharefs child reported, against what is on this side of the share."""
    plan = data.get("mount_plan") or {}
    shared = data.get("shared") or {}
    readonly = data.get("readonly") or {}
    raw_plan = plan.get("raw") or ""
    evidence = {"child_report": data}

    # The node injects a mount plan into a guest that inherits shares. Without one, the
    # node was never asked to mount anything for this instance: that is a package that
    # does not declare the share, or a node that skipped it, and a guest cannot tell the
    # two apart. Not an accusation.
    missing = [p for p in (SHARE_GUEST_RW_MOUNT, SHARE_GUEST_RO_MOUNT) if p not in raw_plan]
    if not plan.get("present") or missing:
        return _share_part(
            _SHARE_INCONCLUSIVE,
            "the child launched without a guest mount plan for "
            f"{missing or [SHARE_GUEST_RW_MOUNT, SHARE_GUEST_RO_MOUNT]}, so it was not asked "
            f"to mount the shares it declares. {_PACKAGING_HINT}",
            **evidence)

    failures = []

    # parent -> child, through the read-write share
    seen_by_child = shared.get("parent_nonce") or {}
    if not (seen_by_child.get("ok") and seen_by_child.get("content") == nonces["parent"]):
        failures.append(
            f"the child could not read what this service wrote to {SHARE_DIR}/"
            f"{SHARE_PARENT_NONCE_FILE} (child saw {seen_by_child})")

    # child -> parent, through the same share. Checked on this side's own disk.
    child_write = shared.get("child_write") or {}
    seen_by_parent = _share_wait_for(
        os.path.join(SHARE_DIR, SHARE_CHILD_NONCE_FILE), nonces["child"])
    evidence["parent_saw_child_nonce"] = seen_by_parent
    if not child_write.get("ok"):
        failures.append(f"the read-write share refused the child's write ({child_write})")
    elif seen_by_parent != nonces["child"]:
        failures.append(
            f"what the child wrote to {SHARE_GUEST_RW_MOUNT} never appeared in {SHARE_DIR} "
            f"(this service saw {seen_by_parent!r})")

    # the exporter's content reaches the read-only mount
    seed_seen = readonly.get("seed") or {}
    if not (seed_seen.get("ok") and seed_seen.get("content") == nonces["seed"]):
        failures.append(
            f"the read-only mount did not show what this service put in {SHARE_RO_DIR}/"
            f"{SHARE_RO_SEED_FILE} (child saw {seed_seen})")

    # ...and refuses a write. The child's own report is not enough: the file's absence
    # on this side is what proves the write did not land.
    attempt = readonly.get("write_attempt") or {}
    landed = _share_read(os.path.join(SHARE_RO_DIR, SHARE_RO_ATTEMPT_FILE))
    evidence["ro_attempt_landed"] = landed is not None
    if attempt.get("succeeded") is not False or landed is not None:
        failures.append(
            f"the read-only mount accepted a write (child reported {attempt}; "
            f"{'the file is present' if landed is not None else 'the file is absent'} in {SHARE_RO_DIR})")

    if failures:
        return _share_part(_SHARE_DISHONEST, "; ".join(failures), **evidence)
    return _share_part(
        _SHARE_OK,
        "the child saw the parent's data, the parent saw the child's, and the read-only "
        "mount refused a write",
        **evidence)


def _probe_granted_share():
    nonces = {"parent": secrets.token_hex(8), "child": secrets.token_hex(8),
              "seed": secrets.token_hex(8)}
    # Seed this side of the share first, and clear anything a previous run left, so that
    # what the child finds -- and what this service finds afterwards -- is this run's.
    try:
        _share_remove(os.path.join(SHARE_DIR, SHARE_CHILD_NONCE_FILE))
        _share_remove(os.path.join(SHARE_RO_DIR, SHARE_RO_ATTEMPT_FILE))
        _share_write(os.path.join(SHARE_DIR, SHARE_PARENT_NONCE_FILE), nonces["parent"])
        _share_write(os.path.join(SHARE_RO_DIR, SHARE_RO_SEED_FILE), nonces["seed"])
    except OSError as e:
        # Our own exported directory is unusable: nothing was observed about the node.
        return _share_part(
            _SHARE_INFRA,
            f"this service could not write its own exported directories "
            f"({SHARE_DIR}, {SHARE_RO_DIR}): {type(e).__name__}: {clip(e)}")

    iface = child_iface("sharefs")
    inst = None
    try:
        inst = _spin_child(iface, "sharefs")
        r = requests.get(f"http://{inst.uri}/probe", params={"nonce": nonces["child"]}, timeout=45)
        data = r.json()
        if not isinstance(data, dict) or data.get("probe") != "shared_filesystem":
            return _share_part(_SHARE_INCONCLUSIVE,
                               f"the sharefs child answered with something that is not its report: "
                               f"{clip(r.text)}")
        return _judge_granted_share(data, nonces)
    except ChildLaunchError as e:
        if _share_refused(e.original, SHARE_GUEST_RW_MOUNT):
            # The node refused a share this service does export. Either the node refused a
            # grant it owed, or the packed parent never exported it; from here, both look
            # the same.
            return _share_part(
                _SHARE_INCONCLUSIVE,
                f"the node refused to launch sharefs for the share at {SHARE_GUEST_RW_MOUNT}: "
                f"{clip(e)}. This service exports it in its manifest, so either the node "
                f"refused a grant it owed or the packed parent never exported it. "
                f"{_PACKAGING_HINT}")
        return _share_part(_SHARE_INFRA,
                           f"could not observe the granted share: {e}. No claim is made.")
    except ChildNotReadyError as e:
        return _share_part(_SHARE_INFRA,
                           f"could not observe the granted share: {e}. No claim is made.")
    except ValueError as e:
        # requests' JSONDecodeError is a ValueError AND a RequestException; it must be
        # caught here, as an answer we could not read, before the transport clause.
        return _share_part(_SHARE_INCONCLUSIVE,
                           f"the sharefs child's answer was not JSON: {clip(e)}")
    except requests.RequestException as e:
        return _share_part(_SHARE_INFRA,
                           f"could not reach the sharefs child: {type(e).__name__}: {clip(e)}")
    finally:
        _release_child(iface, inst, "sharefs")


def _probe_denied_share():
    iface = child_iface("sharefs_denied")
    inst = None
    try:
        # Not waiting for it to come up: an honest node never starts it.
        inst = _spin_child(iface, "sharefs-denied", wait_ready=False)
    except ChildLaunchError as e:
        if _share_refused(e.original, SHARE_DENIED_MOUNT):
            return _share_part(
                _SHARE_OK,
                f"the node refused to launch a service asking for {SHARE_DENIED_MOUNT}, "
                "a share its parent does not export",
                refusal=clip(_full_error_text(e.original), 600))
        # Failing to launch is not the same as refusing the share. A launch that fails
        # for want of balance, a timeout or a crash says nothing about the node's rules.
        return _share_part(
            _SHARE_INFRA,
            f"the denied child did not launch, but not because of its share: {e}. "
            "No claim is made.")

    # It launched. Say what the node did about the share it was never granted.
    try:
        _wait_until_ready(inst.uri, "sharefs-denied")
        r = requests.get(f"http://{inst.uri}/plan", timeout=45)
        data = r.json()
        if data.get("mounted") is True:
            return _share_part(
                _SHARE_DISHONEST,
                f"the node launched sharefs-denied and attached a share at {SHARE_DENIED_MOUNT}, "
                "which its parent never exported: only the exporter's children may attach",
                child_report=data)
        return _share_part(
            _SHARE_INCONCLUSIVE,
            f"the node launched sharefs-denied instead of refusing it, but mounted nothing "
            f"at {SHARE_DENIED_MOUNT}. A node that honours the invariant refuses the launch; "
            f"this one did not, though the child's package may simply lack the declaration. "
            f"{_PACKAGING_HINT}",
            child_report=data)
    except (ChildNotReadyError, requests.RequestException, ValueError) as e:
        return _share_part(
            _SHARE_INCONCLUSIVE,
            f"the node launched sharefs-denied instead of refusing it, and it could not be "
            f"inspected afterwards: {type(e).__name__}: {clip(e)}. {_PACKAGING_HINT}")
    finally:
        _release_child(iface, inst, "sharefs-denied")


def _run_share_half(name, fn):
    try:
        return fn()
    except Exception as e:
        return _share_part(_SHARE_INFRA, f"the {name} half could not run: {type(e).__name__}: {clip(e)}")


def probe_shared_filesystem():
    ev = {"probe": "shared_filesystem"}
    ev["granted"] = _run_share_half("granted", _probe_granted_share)
    ev["denied"] = _run_share_half("denied", _probe_denied_share)
    parts = {"granted": ev["granted"], "denied": ev["denied"]}

    # Observed violations outrank halves that could not be observed, as in
    # dependency_identity: one half proving the node broke the rule is not undone by the
    # other half being blind.
    dishonest = {k: p for k, p in parts.items() if p["status"] == _SHARE_DISHONEST}
    infra = {k: p for k, p in parts.items() if p["status"] == _SHARE_INFRA}
    inconclusive = {k: p for k, p in parts.items() if p["status"] == _SHARE_INCONCLUSIVE}
    if dishonest:
        ev["verdict"] = VERDICT_DISHONEST
        ev["reason"] = "shared-filesystem rules broken: " + " | ".join(
            f"{k}: {p['reason']}" for k, p in dishonest.items())
    elif infra:
        ev["verdict"] = VERDICT_INFRA_ERROR
        ev["reason"] = "could not observe shared-filesystem behaviour: " + " | ".join(
            f"{k}: {p['reason']}" for k, p in infra.items())
    elif inconclusive:
        ev["verdict"] = VERDICT_INCONCLUSIVE
        ev["reason"] = "shared-filesystem behaviour is not decidable: " + " | ".join(
            f"{k}: {p['reason']}" for k, p in inconclusive.items())
    else:
        ev["verdict"] = VERDICT_PASS
        ev["reason"] = ("the granted child shared data both ways and the read-only mount held; "
                        "the child asking for an ungranted share was refused")
    return ev


# ----------------------------------------------------------------------------
# The newer benchmarks: children started over nodo_gateway
# ----------------------------------------------------------------------------
# node_controller starts a child with its own copy of an older celaut.proto. The
# benchmarks below need what it cannot send -- an initial_mu per start, a
# StartReference, env vars per instance, the block skip -- or read what it cannot
# read (quotes, statements, tunnels), so they start their children with nodo_gateway.
# They keep the rules of the other probes: every child is stopped in a `finally`, a
# start the node refuses for want of funds is recorded in FUNDING_FAILURES, and only an
# observed violation accuses.
CHILD_PORT = 3030  # every demo child serves http on 3030 (its service.json)


def _instance_uri(instance, port=CHILD_PORT):
    """host:port of a slot of a ServiceInstance, the declared port first."""
    slots = list(instance.instance.uri_slot)
    for slot in sorted(slots, key=lambda s: s.internal_port != port):
        for uri in slot.uri:
            return f"{uri.ip}:{uri.port}"
    return None


def _child_budget(label):
    with _funding_lock:
        return FUNDING["child_initial_mu"].get(label)


def _gw_start(label, *, initial_mu="budget", envs=None, start_ref=None, send_service=True,
              block_skip=True, wait_ready=True, count_funding=True, **kwargs):
    """Start one child over nodo_gateway; the gw.StartResult, with ``uri``.

    ``initial_mu`` "budget" is what the funding gate sized the child at (its build and
    its runtime), and None leaves it to the node. A refusal for funds is recorded in
    FUNDING_FAILURES unless ``count_funding`` is off: build_funding asks for refusals.
    """
    if initial_mu == "budget":
        initial_mu = _child_budget(label)
    config = gw.configuration(initial_mu=initial_mu, envs=envs) \
        if (initial_mu is not None or envs) else None
    try:
        result = gw.start_service(node_url, packed(label), config=config, start_ref=start_ref,
                                  send_service=send_service, block_skip=block_skip, **kwargs)
    except gw.GatewayError as e:
        if count_funding and _INSUFFICIENT_FUNDS_RE.search(str(e)):
            learn_from_refusal(label, str(e))
            FUNDING_FAILURES.append(label)
        raise
    _mark_built(label)
    result.uri = _instance_uri(result.instance)
    logging.info("Started %s at %s (%d request bytes)", label, result.uri, result.request_bytes)
    if wait_ready and result.uri:
        _wait_until_ready(result.uri, label)
    return result


def _gw_stop(token, label):
    """Stop a child started over nodo_gateway; its refund, or None when it failed."""
    if not token:
        return None
    try:
        refund = gw.stop_service(node_url, token)
        logging.info("Stopped %s (refund %s MU)", label, refund)
        return refund
    except Exception as e:
        # A child we could not stop is a leak to report, never a verdict.
        logging.warning("Could not stop %s: %s", label, e)
        return None


def _own_head():
    """The seq of the last movement of this instance's account (a statement with no row)."""
    return int(gw.balance_statement(node_url, from_seq=0).head_seq)


def _own_rows_after(seq):
    """Every movement of this instance's account after ``seq``, from signed statements."""
    return [mv for page in gw.full_statement(node_url, from_seq=seq + 1) for mv in page.movements]


def _child_rows(token):
    return [mv for page in gw.full_statement(node_url, token=token, from_seq=1)
            for mv in page.movements]


def _rows_for_ref(rows, ref):
    """The child_start movements that carry a StartReference, in hex (#578)."""
    return [mv for mv in rows
            if mv.kind == "child_start" and gw.detail_of(mv).get("start_ref") == ref.hex()]


def _movement_view(mv):
    return {"seq": int(mv.seq), "kind": mv.kind, "amount": int(mv.amount.n),
            "balance_after": int(mv.balance_after.n), "detail": gw.detail_of(mv)}


def _infra(ev, what, e):
    """INFRA_ERROR for an exception: an RPC that failed observed nothing."""
    ev["verdict"] = VERDICT_INFRA_ERROR
    if isinstance(e, gw.GatewayError):
        ev["grpc_code"] = e.code
        ev["node_detail"] = e.details
    ev["reason"] = f"could not observe {what}: {type(e).__name__}: {clip(e)}. No claim is made."
    if FUNDING_FAILURES:
        ev["fault"] = "insufficient_funds"
    return ev


# ----------------------------------------------------------------------------
# Probe — build funding (nodo #563)
# ----------------------------------------------------------------------------
# Since nodo #563 the caller pays Configuration.initial_mu and nothing else. The node
# takes the build of the service out of it, and refuses a start when the build does not
# fit, or when what is left does not pay one maintenance period. A refused start
# charges nothing (src/utils/cost_functions/start_funding.py). So:
#
#   below the build       -> refused, "does not cover the build of the service, <b> MU"
#   below one period      -> refused, "leaves <x> MU after the build of <b> MU. One
#                            maintenance period costs <p> MU."
#   enough                -> started; this account pays exactly initial_mu, and the build
#                            shows on the child's account, never on this one.
#
# The build is the node's own quote (quote_build: the cost of a quote that asks for a
# balance of 1 MU, less that MU), and it is 0 once the node has built the image: then
# only the second rule can be exercised. Each start carries a StartReference, so its child_start (if
# any) is found in this account's statement by its reference, not by amount or time.
BUILD_FUNDING_CHILD = "tiny"
# The funded start: the build plus the runtime the child is funded with anyway, and never
# less than this many periods. A few periods are a balance that runs out in seconds
# (MANAGER_ITERATION_TIME is 10 s on a default node), before the child has even booted.
BUILD_FUNDING_MIN_PERIODS = 60
_BUILD_RULE_RE = re.compile(r"does not cover the build of the service, (\d+) MU")
_PERIOD_RULE_RE = re.compile(r"leaves (-?\d+) MU after the build of (\d+) MU\. "
                             r"One maintenance period costs (\d+) MU")


def _judge_build_funding(ev, rows, build, period):
    """The verdict of build_funding, from its attempts and this account's movements."""
    ev["build_rows_on_this_account"] = [_movement_view(mv) for mv in rows if mv.kind == "build"]
    violations, unexpected = [], []
    for attempt in ev["attempts"]:
        starts = _rows_for_ref(rows, bytes.fromhex(attempt["start_ref"]))
        attempt["child_start_rows"] = [_movement_view(mv) for mv in starts]
        start_seqs = {str(int(mv.seq)) for mv in starts}
        refunds = [mv for mv in rows if mv.kind == "refund"
                   and str(gw.detail_of(mv).get("refunds_seq")) in start_seqs]
        net = sum(int(mv.amount.n) for mv in starts + refunds)
        attempt["net_charge_mu"] = -net
        if -net > attempt["initial_mu"]:
            violations.append(f"{attempt['attempt']}: charged {-net} MU for an initial_mu of "
                              f"{attempt['initial_mu']} MU")
        if attempt["expect"] == "start":
            amounts = [int(mv.amount.n) for mv in starts]
            if amounts != [-attempt["initial_mu"]]:
                violations.append(f"funded: the child_start of its reference is {amounts}, "
                                  f"not [-{attempt['initial_mu']}]")
            child_rows = attempt.get("child_rows") or []
            opened = [r["amount"] for r in child_rows if r["kind"] == "start"]
            attempt["child_build_mu"] = -sum(r["amount"] for r in child_rows if r["kind"] == "build")
            if opened and opened[0] != attempt["initial_mu"]:
                violations.append(f"funded: the child's account opened with {opened[0]} MU, not "
                                  f"the initial_mu {attempt['initial_mu']} MU")
            if attempt["child_build_mu"] > build:
                violations.append(f"funded: the child paid a build of {attempt['child_build_mu']} "
                                  f"MU, above the quote of {build} MU")
            continue
        if attempt["outcome"] == "started":
            unexpected.append(f"{attempt['attempt']}: the node started a child with an initial_mu "
                              f"of {attempt['initial_mu']} MU (build {build} MU, one period "
                              f"{period} MU) instead of refusing it")
            continue
        if net != 0:
            violations.append(f"{attempt['attempt']}: the node refused the start and kept "
                              f"{-net} MU of it")
        text = attempt.get("node_detail") or ""
        if attempt["expect"] == "build":
            m = _BUILD_RULE_RE.search(text)
            attempt["named_build_mu"] = int(m.group(1)) if m else None
            if not m:
                unexpected.append(f"below_build was refused, but not by the build rule: {text}")
        else:
            m = _PERIOD_RULE_RE.search(text)
            if m:
                attempt["named_build_mu"] = int(m.group(2))
                attempt["named_period_mu"] = int(m.group(3))
            else:
                unexpected.append(f"below_one_period was refused, but not by the period rule: {text}")
    if ev["build_rows_on_this_account"]:
        violations.append(f"a build was charged to this account, the caller's: "
                          f"{ev['build_rows_on_this_account']}")

    if violations:
        ev["verdict"] = VERDICT_DISHONEST
        ev["reason"] = "the node broke the start-funding rules of #563: " + "; ".join(violations)
    elif unexpected:
        ev["verdict"] = VERDICT_INCONCLUSIVE
        ev["reason"] = ("the node did not refuse an under-funded start the way #563 says, but it "
                        "charged nothing beyond initial_mu: " + "; ".join(unexpected))
    else:
        rules = [a["attempt"] for a in ev["attempts"] if a["expect"] != "start"]
        ev["verdict"] = VERDICT_PASS
        ev["reason"] = (f"refused {rules} with the #563 messages and charged nothing for them; "
                        f"the funded start (build {build} MU) charged this account exactly its "
                        f"initial_mu, and the build was paid from the child's account")
    return ev


def probe_build_funding():
    label = BUILD_FUNDING_CHILD
    ev = {"probe": "build_funding", "child": label, "attempts": []}
    tokens = []
    try:
        build, quote = quote_build(label)
        period = gw.mu(quote.max_maintenance_cost)
        ev["quote"] = {"build_mu": build, "max_maintenance_cost_mu": period,
                       "init_maintenance_cost_mu": gw.mu(quote.init_maintenance_cost),
                       "maintenance_seconds_loop": int(quote.maintenance_seconds_loop)}
        if build == 0 and period == 0:
            ev["verdict"] = VERDICT_NOT_APPLICABLE
            ev["reason"] = ("the node quotes no build and no maintenance for the child: it runs "
                            "for free (free tier), so a start cannot be under-funded")
            return ev
        head = _own_head()

        plan = []
        if build > 0:
            plan.append(("below_build", build - 1, "build"))
        plan.append(("below_one_period", build + max(1, period // 2), "period"))
        rate = FUNDING["self_rate_mu_per_s"]
        runtime = child_runtime_mu(label, rate) if rate is not None else 0
        plan.append(("funded", build + max(runtime, BUILD_FUNDING_MIN_PERIODS * max(period, 1)), None))
        for name, amount, rule in plan:
            ref = secrets.token_bytes(16)
            attempt = {"attempt": name, "initial_mu": amount, "expect": rule or "start",
                       "start_ref": ref.hex()}
            ev["attempts"].append(attempt)
            try:
                r = _gw_start(label, initial_mu=amount, start_ref=ref,
                              count_funding=(rule is None), wait_ready=(rule is None))
            except gw.GatewayError as e:
                attempt["outcome"] = "refused"
                attempt["grpc_code"] = e.code
                attempt["node_detail"] = clip(e.details or str(e), 500)
                if rule is None:
                    raise
                continue
            tokens.append(r.instance.token)
            attempt["outcome"] = "started"
            if rule is None:
                attempt["child_balance_mu"] = gw.metrics_balance(node_url, r.instance.token)
                attempt["child_rows"] = [_movement_view(mv) for mv in _child_rows(r.instance.token)]
        return _judge_build_funding(ev, _own_rows_after(head), build, period)
    except Exception as e:
        return _infra(ev, "the start-funding rules", e)
    finally:
        for token in tokens:
            _gw_stop(token, label)


def _node_claims(feature):
    """Whether the node's signed Peer names ``feature``, or None when it cannot be read.

    The celaut-gateway layer of each address the node announces lists the message
    type at each index of each RPC (src/identity/transport_stack.py), so a node whose
    StartService takes a StartReference names it there. A node that does not name a
    feature makes no promise about it, and is not accused of breaking it.
    """
    try:
        return feature.encode() in gw.peer_info(node_url).SerializeToString()
    except Exception as e:
        logging.warning("Could not read the node's Peer: %s", e)
        return None


# ----------------------------------------------------------------------------
# Probe — idempotent StartService (nodo #578, PR #585)
# ----------------------------------------------------------------------------
# A StartService with a StartReference chosen by the caller is idempotent: the node keys
# the reference by the caller (a local instance, here), and a second request with the
# same reference starts nothing and charges nothing. It answers the same
# ServiceInstance, and needs no service: the reference alone is enough. The child_start
# that paid the start carries the reference in detail.start_ref, so this account's
# statement shows how many starts the reference paid for.
IDEMPOTENT_CHILD = "tiny"
IDEMPOTENT_ASKS = 3            # the first start and two more requests with its reference
IDEMPOTENT_RETRY_ABORTED = 5   # ABORTED: the first start is still running; ask again
IDEMPOTENT_RETRY_SECONDS = 2


def _ask_again(label, ref, initial_mu):
    """A request with the reference and the hashes only. ABORTED is asked again."""
    for _ in range(IDEMPOTENT_RETRY_ABORTED):
        try:
            config = gw.configuration(initial_mu=initial_mu) if initial_mu is not None else None
            return gw.start_service(node_url, packed(label), start_ref=ref, config=config,
                                    send_service=False)
        except gw.GatewayError as e:
            if e.code != "ABORTED":
                raise
            time.sleep(IDEMPOTENT_RETRY_SECONDS)
    raise RuntimeError(f"the start of the reference was still in progress after "
                       f"{IDEMPOTENT_RETRY_ABORTED} requests")


def probe_idempotent_start():
    label = IDEMPOTENT_CHILD
    ev = {"probe": "idempotent_start", "child": label, "asks": []}
    tokens = []
    try:
        head = _own_head()
        ref = secrets.token_bytes(16)
        ev["start_ref"] = ref.hex()
        first = _gw_start(label, start_ref=ref)
        tokens.append(first.instance.token)
        ev["first"] = {"uri": first.uri, "seconds_to_instance": first.seconds_to_instance}
        budget = _child_budget(label)
        errors = []
        for i in range(1, IDEMPOTENT_ASKS):
            # The second request carries no Configuration, the third one another
            # initial_mu: neither may change what the reference already started.
            other_mu = None if i == 1 else (budget or 0) + 12345
            ask = {"ask": i + 1, "initial_mu": other_mu}
            try:
                r = _ask_again(label, ref, other_mu)
                ask.update(token_is_first=(r.instance.token == first.instance.token),
                           uri=_instance_uri(r.instance), seconds_to_instance=r.seconds_to_instance)
                if r.instance.token not in tokens:
                    tokens.append(r.instance.token)
            except Exception as e:
                ask["error"] = clip(e)
                errors.append(f"request {i + 1}: {clip(e)}")
            ev["asks"].append(ask)

        starts = _rows_for_ref(_own_rows_after(head), ref)
        ev["child_start_rows"] = [_movement_view(mv) for mv in starts]
        ev["instances"] = len(tokens)
        claims = _node_claims("StartReference")
        ev["node_announces_start_reference"] = claims
        repeated = len(starts) > 1 or len(tokens) > 1
        if repeated and claims:
            ev["verdict"] = VERDICT_DISHONEST
            ev["reason"] = (f"one StartReference gave {len(tokens)} instance(s) and "
                            f"{len(starts)} child_start charge(s); the node announces "
                            "StartReference, and a second request with it must start and "
                            "charge nothing")
        elif repeated:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = (f"one StartReference gave {len(tokens)} instance(s) and "
                            f"{len(starts)} charge(s), but the node does not announce "
                            "StartReference (#578), so it made no promise to break")
        elif errors:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = ("a request with the reference of a start that succeeded did not "
                            "get its instance back: " + "; ".join(errors))
        elif len(starts) != 1:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = (f"the statement shows {len(starts)} child_start with the reference; "
                            "the start that it paid for cannot be found")
        else:
            ev["verdict"] = VERDICT_PASS
            ev["reason"] = (f"{IDEMPOTENT_ASKS} requests with one StartReference gave one "
                            f"instance and one charge of {-int(starts[0].amount.n)} MU; the "
                            "requests after the first sent no service and got the same instance")
        return ev
    except Exception as e:
        return _infra(ev, "an idempotent start", e)
    finally:
        for token in tokens:
            _gw_stop(token, label)


# ----------------------------------------------------------------------------
# Probe — block skip on StartService (nodo #371, commit 7375f37)
# ----------------------------------------------------------------------------
# A StartService carries the Service, and the Service carries its blocks: tiny's image
# is one block of tens of MB. A node that already holds what arrives stops the sender:
# for a service it holds, at the first hash (bee-rpc's signal), and since #371 also for
# each block it holds of a service it does not hold yet (a skip request in the response
# direction, honoured by a sender with bee-rpc `block_skip`). Before #371 the node read
# every block of such a service from the wire and dropped the ones it held.
#
# What a client sees is the first request that carries a service and the requests after
# it. The first one is this instance's first send of tiny (quote_child_builds asks for
# a quote with the service before any start): it carries the blocks the node does not
# hold. The probe then starts tiny again, with the skip off and on, and counts the bytes
# of each request the way nodo's own test does (the Buffers handed to gRPC), with the
# time to the instance. A node that makes a client send blocks it holds costs bandwidth,
# not money: that is never an accusation.
BLOCK_SKIP_CHILD = "tiny"
BLOCK_SKIP_ROUNDS = 2  # pairs of (skip off, skip on)
# A start that sends less than this share of the blocks did not send them.
BLOCK_SKIP_MAX_SHARE = 0.05


def _packed_block_bytes(label):
    """Bytes of the blocks of a packed child: what a request that carries them sends."""
    p = packed(label)
    try:
        with open(os.path.join(p.service_path, "_.json")) as fh:
            layout = json.load(fh)
    except Exception:
        return None
    total = 0
    block_dir = os.path.join(DIR, "__block__")
    for entry in layout:
        if isinstance(entry, list) and entry and isinstance(entry[0], str):
            path = os.path.join(block_dir, entry[0])
            if os.path.isfile(path):
                total += os.path.getsize(path)
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    total += sum(os.path.getsize(os.path.join(root, f)) for f in files)
    return total


def _median(values):
    values = sorted(values)
    if not values:
        return None
    mid = len(values) // 2
    return values[mid] if len(values) % 2 else (values[mid - 1] + values[mid]) / 2


def _timed_start(label, block_skip):
    r = _gw_start(label, block_skip=block_skip, wait_ready=False)
    try:
        return {"block_skip": block_skip, "request_bytes": r.request_bytes,
                "seconds_to_instance": r.seconds_to_instance,
                "seconds_to_request_sent": r.seconds_to_complete}
    finally:
        _gw_stop(r.instance.token, label)


def probe_block_skip():
    label = BLOCK_SKIP_CHILD
    ev = {"probe": "block_skip", "child": label, "starts": []}
    try:
        blocks = _packed_block_bytes(label)
        first = FIRST_SENDS.get(label)
        ev["packed_block_bytes"] = blocks
        ev["first_send"] = first
        off, on = [], []
        for _ in range(BLOCK_SKIP_ROUNDS):
            off.append(_timed_start(label, False))
            on.append(_timed_start(label, True))
        ev["starts"] = off + on
        sent_on, sent_off = _median([s["request_bytes"] for s in on]), _median([s["request_bytes"] for s in off])
        i_on, i_off = _median([s["seconds_to_instance"] for s in on]), _median([s["seconds_to_instance"] for s in off])
        first_carried = bool(first and blocks and first.get("request_bytes", 0) >= blocks / 2)
        ev.update({
            "request_bytes_with_skip": sent_on,
            "request_bytes_without_skip": sent_off,
            "seconds_to_instance_with_skip": i_on,
            "seconds_to_instance_without_skip": i_off,
            "first_send_carried_the_blocks": first_carried,
            "bytes_saved_against_first_send": (round(1 - sent_on / first["request_bytes"], 4)
                                               if first_carried else None),
        })
        if not blocks:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = "the blocks of the packed child could not be sized"
        elif sent_on > blocks * BLOCK_SKIP_MAX_SHARE:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = (f"a start of a child the node holds sent {sent_on} bytes of {blocks} "
                            "bytes of blocks: the node did not stop the sender. It costs "
                            "bandwidth, not money; no claim is made")
        else:
            compare = (f"; the first send of this child carried {first['request_bytes']} bytes "
                       f"in {first['seconds']}s" if first_carried else
                       "; the node already held the child at this instance's first send, so "
                       "there is no full send to compare with")
            ev["verdict"] = VERDICT_PASS
            ev["reason"] = (f"a StartService for a child whose blocks the node holds sent "
                            f"{sent_on} bytes of {blocks} bytes of blocks with the skip "
                            f"({sent_off} without), and got its instance in {i_on}s "
                            f"({i_off}s without){compare}")
        return ev
    except Exception as e:
        return _infra(ev, "the block skip", e)


# ----------------------------------------------------------------------------
# Probe — environment variables (nodo #574, #582)
# ----------------------------------------------------------------------------
# A service declares the names of its environment variables (`envs` in service.json).
# Since #582 the packer embeds them in Service.Container.environment_variables, so the
# spec says what the service asks for; since #574 the node asks the caller for every
# one and marks none required. At launch the values come from
# Configuration.environment_variables, and the node gives them to the service on two
# paths: always in /__config__ (config.environment_variables, the exact bytes), and
# also as Linux env vars of the entrypoint when the name and value pass
# src/utils/guest_env.py. The node gives no value of its own: a declared variable the
# caller leaves out is absent, and the service uses its own default.
#
# `tiny` declares three: one the probe gives a random value, one it gives an empty
# value, one it leaves out. tiny's /env reports both paths, with the values in hex.
ENV_CHILD = "tiny"
TINY_DECLARED_ENVS = ("DEMO_ENV_GIVEN", "DEMO_ENV_EMPTY", "DEMO_ENV_UNSET")


def _packed_env_names(label):
    """The env names the packer embedded in a child's spec (#582)."""
    return [kv.key for kv in packed(label).spec().container.environment_variables]


def _judge_env_report(report, sent, unset):
    """(violations, gaps) between what was sent and what the child received."""
    violations, gaps = [], []
    process = report.get("process_env") or {}
    config = report.get("config_env") or {}
    if not report.get("config_readable"):
        gaps.append("the child could not read its /__config__")
    for name, value in sent.items():
        want = value.hex()
        got = config.get(name)
        if report.get("config_readable"):
            if got is None:
                violations.append(f"{name} is not in /__config__, but the caller gave it")
            elif got != want:
                violations.append(f"{name} in /__config__ is {got}, the caller gave {want}")
        env = process.get(name)
        if env is None:
            gaps.append(f"{name} is not in the process environment (the second path is "
                        "additive and a guest may lack it)")
        elif env != want:
            violations.append(f"{name} in the process environment is {env}, the caller gave {want}")
    for name in unset:
        if process.get(name) is not None or config.get(name) is not None:
            violations.append(f"{name} has a value ({process.get(name) or config.get(name)}) "
                              "that nobody gave")
    return violations, gaps


def probe_env_vars():
    label = ENV_CHILD
    ev = {"probe": "env_vars", "child": label, "declared": list(TINY_DECLARED_ENVS)}
    token = None
    try:
        try:
            ev["packed_names"] = _packed_env_names(label)
        except Exception as e:
            ev["packed_names"] = None
            ev["packed_error"] = clip(e)
        given = "v-" + secrets.token_hex(8)
        sent = {"DEMO_ENV_GIVEN": given.encode(), "DEMO_ENV_EMPTY": b""}
        unset = ("DEMO_ENV_UNSET",)
        ev["sent"] = {k: v.decode() for k, v in sent.items()}
        ev["left_out"] = list(unset)
        r = _gw_start(label, envs=sent)
        token = r.instance.token
        report = requests.get(f"http://{r.uri}/env", timeout=30).json()
        ev["child_report"] = report
        violations, gaps = _judge_env_report(report, sent, unset)
        if ev["packed_names"] is None:
            gaps.append(f"the packed spec of the child could not be read: {ev.get('packed_error')}")
        elif sorted(ev["packed_names"]) != sorted(TINY_DECLARED_ENVS):
            # The packer keeps the names as a sorted key-value list, so only the set counts.
            gaps.append(f"the packed spec names {ev['packed_names']}, the manifest declares "
                        f"{list(TINY_DECLARED_ENVS)}: the packer that packed this service drops "
                        "envs (before nodo #582)")
        if violations:
            ev["verdict"] = VERDICT_DISHONEST
            ev["reason"] = "the child did not get the configuration it was started with: " + \
                           "; ".join(violations)
        elif gaps:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = "the values that arrived are right, but: " + "; ".join(gaps)
        else:
            ev["verdict"] = VERDICT_PASS
            ev["reason"] = ("the packed spec names the three declared variables; the given and "
                            "the empty value arrived exactly in /__config__ and in the process "
                            "environment, and the variable left out has no value (the service's "
                            "own default applies)")
        return ev
    except ValueError as e:
        ev["verdict"] = VERDICT_INCONCLUSIVE
        ev["reason"] = f"the child's /env answer was not JSON: {clip(e)}"
        return ev
    except (ChildNotReadyError, requests.RequestException) as e:
        return _infra(ev, "the env vars", e)
    except Exception as e:
        return _infra(ev, "the env vars", e)
    finally:
        _gw_stop(token, label)


# ----------------------------------------------------------------------------
# Probe — network share (nodo #268)
# ----------------------------------------------------------------------------
# A network share is a directory that instances with no common parent share because they
# declare the same network and the same share (docs/SHARED_FILESYSTEMS.md, "Network
# shares"). netshare declares the network `celaut-demo-netshare` with the selection key
# group=${DEMO_NETSHARE_GROUP}, and /netshare as a share of it. The share id includes the
# formal after substitution, so each group is its own share.
#
# The probe starts three netshare instances as siblings: two of one group, one of
# another. This service is the parent of each, but it does not export /netshare and is
# not a member: it only declares the network, because a child gets only the networks
# every ancestor declares. Member A writes, member B (same group) must read it, B writes
# back and A must read that, and member C (other group) must not see A's file.
NETSHARE_CHILD = "netshare"
NETSHARE_MOUNT = "/netshare"
NETSHARE_TIMEOUT_S = 30
NETSHARE_MEMBERS = 3  # held at once: they share the runtime budget of one child


def _netshare_member_mu():
    """The initial_mu of one member: the build (if still owed) and a third of the runtime.

    Three members run at once, for seconds. One child's runtime split between them keeps
    what the suite holds at once at the largest single deposit, which is what the
    funding gate counts on.
    """
    rate = FUNDING["self_rate_mu_per_s"]
    if rate is None:
        return None
    runtime = child_runtime_mu(NETSHARE_CHILD, rate) // NETSHARE_MEMBERS
    return child_build_mu(NETSHARE_CHILD) + max(CHILD_MIN_INITIAL_MU, runtime)


def _netshare(uri, action, **params):
    return requests.get(f"http://{uri}/{action}", params=params, timeout=NETSHARE_TIMEOUT_S).json()


def _netshare_wait(uri, name, expected):
    """Read ``name`` on a member until it holds ``expected``; the last answer."""
    deadline = time.monotonic() + SHARE_PROPAGATION_TIMEOUT_S
    while True:
        answer = _netshare(uri, "read", name=name)
        if answer.get("content") == expected or time.monotonic() >= deadline:
            return answer
        time.sleep(SHARE_PROPAGATION_POLL_S)


def _plan_has_share(answer):
    plan = (answer or {}).get("mount_plan") or {}
    return bool(plan.get("present")) and NETSHARE_MOUNT in (plan.get("raw") or "")


def probe_network_share():
    label = NETSHARE_CHILD
    ev = {"probe": "network_share", "child": label}
    tokens = []
    try:
        groups = {"same": "g" + secrets.token_hex(4), "other": "g" + secrets.token_hex(4)}
        uris = {}
        for member, group in (("a", groups["same"]), ("b", groups["same"]), ("c", groups["other"])):
            r = _gw_start(label, initial_mu=_netshare_member_mu(),
                          envs={NETSHARE_GROUP_ENV: group.encode()})
            tokens.append(r.instance.token)
            uris[member] = r.uri
        ev["groups"] = {"a": groups["same"], "b": groups["same"], "c": groups["other"]}
        n1, n2 = secrets.token_hex(8), secrets.token_hex(8)
        answers = {
            "a_write": _netshare(uris["a"], "write", name="from_a", nonce=n1),
        }
        answers["b_read"] = _netshare_wait(uris["b"], "from_a", n1)
        answers["b_write"] = _netshare(uris["b"], "write", name="from_b", nonce=n2)
        answers["a_read"] = _netshare_wait(uris["a"], "from_b", n2)
        answers["c_read"] = _netshare(uris["c"], "read", name="from_a")
        ev["answers"] = answers
        plans = {m: _plan_has_share(answers[k]) for m, k in
                 (("a", "a_write"), ("b", "b_write"), ("c", "c_read"))}
        ev["mount_plans"] = plans

        if answers["c_read"].get("content") == n1:
            ev["verdict"] = VERDICT_DISHONEST
            ev["reason"] = ("a member of another group read what a member of the first group "
                            "wrote: the node put two shares with different ids in one directory")
        elif not all(plans.values()):
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = (f"a member launched with no mount plan for {NETSHARE_MOUNT} "
                            f"({plans}): it was not asked to mount the share. {_PACKAGING_HINT}")
        elif not (answers["a_write"].get("ok") and answers["b_write"].get("ok")):
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = (f"a member could not write to the share it mounts read-write: "
                            f"{answers['a_write']}, {answers['b_write']}")
        elif answers["b_read"].get("content") != n1 or answers["a_read"].get("content") != n2:
            ev["verdict"] = VERDICT_DISHONEST
            ev["reason"] = ("two members of one group did not see each other's files: the node "
                            "gave one network share two directories (B saw "
                            f"{answers['b_read'].get('content')!r} for {n1!r}, A saw "
                            f"{answers['a_read'].get('content')!r} for {n2!r})")
        else:
            ev["verdict"] = VERDICT_PASS
            ev["reason"] = ("two members of one group with no common exporter shared /netshare "
                            "both ways, and a member of another group did not see it")
        return ev
    except ValueError as e:
        ev["verdict"] = VERDICT_INCONCLUSIVE
        ev["reason"] = f"a member's answer was not JSON: {clip(e)}"
        return ev
    except Exception as e:
        return _infra(ev, "the network share", e)
    finally:
        for token in tokens:
            _gw_stop(token, label)


# ----------------------------------------------------------------------------
# Probe — service tunnel: throughput and price
# ----------------------------------------------------------------------------
# Gateway.ServiceTunnel opens a byte stream to a declared slot of a local instance. The
# node charges the instance tunnel_open_mu to open it, then net_mu_per_gib for the bytes
# it relays in either direction, billed per costs.TUNNEL_CHARGE_INTERVAL_KB and the rest
# when the tunnel closes (src/tunneling/rpc_tunnel.py). The charge is per volume, with no
# scarcity surcharge: amount = net_mu_per_gib * bytes // GiB. Each charge is a "tunnel"
# movement of the instance, with the bytes it billed in its detail.
#
# The probe reads TUNNEL_TEST_BYTES from tiny's /bytes/<n>, once directly (the control)
# and once over a ServiceTunnel, and then reads tiny's statement: the bytes billed must
# be the bytes relayed, and each charge at most the advertised rate (from /__config__).
TUNNEL_CHILD = "tiny"
TUNNEL_TEST_BYTES = int(os.environ.get("TUNNEL_TEST_BYTES", str(64 * 1024 * 1024)))
TUNNEL_SETTLE_S = float(os.environ.get("TUNNEL_SETTLE_S", "15"))
# Bytes billed beyond what was relayed that can still be framing, not an overcharge.
TUNNEL_BILL_SLACK = 4096


def _direct_download(uri, n):
    t0 = time.monotonic()
    with requests.get(f"http://{uri}/bytes/{n}", stream=True, timeout=300) as r:
        got = sum(len(chunk) for chunk in r.iter_content(64 * 1024))
    return got, time.monotonic() - t0


def _tunnel_rows(token, relayed):
    """The tunnel movements of the child, once the bill of the closed tunnel is in."""
    deadline = time.monotonic() + TUNNEL_SETTLE_S
    while True:
        rows = [mv for mv in _child_rows(token) if mv.kind == "tunnel"]
        billed = sum(int(gw.detail_of(mv).get("bytes", 0)) for mv in rows)
        # The last part of a megabyte may cost 0 MU, and a charge of 0 writes no row.
        if billed >= relayed - TUNNEL_BILL_SLACK or time.monotonic() >= deadline:
            return rows
        time.sleep(1)


def _judge_tunnel_bill(rows, relayed, rates):
    """(evidence, violations, notes) for the tunnel movements of the child."""
    net_rate, open_rate = rates.get("net_mu_per_gib"), rates.get("tunnel_open_mu")
    opens, traffic, violations, notes = [], [], [], []
    for mv in rows:
        detail = gw.detail_of(mv)
        charged = -int(mv.amount.n)
        if detail.get("open"):
            opens.append(charged)
            if open_rate is not None and charged > open_rate:
                violations.append(f"the opening cost {charged} MU, the node advertises "
                                  f"{open_rate} MU")
            continue
        n = int(detail.get("bytes", 0))
        expected = net_rate * n // GIB if net_rate is not None else None
        traffic.append({"bytes": n, "charged_mu": charged, "advertised_mu": expected})
        if expected is not None and charged > expected:
            violations.append(f"{n} bytes cost {charged} MU, the advertised rate gives {expected} MU")
    billed = sum(t["bytes"] for t in traffic)
    charged = sum(t["charged_mu"] for t in traffic)
    if billed > relayed + TUNNEL_BILL_SLACK:
        violations.append(f"{billed} bytes billed for {relayed} bytes relayed")
    elif billed < relayed - TUNNEL_BILL_SLACK and net_rate:
        notes.append(f"{billed} bytes billed for {relayed} relayed: the node charged less")
    if net_rate is None or open_rate is None:
        notes.append("the node's rates are not in /__config__: the prices were not compared")
    evidence = {"open_charges_mu": opens, "traffic_rows": traffic, "billed_bytes": billed,
                "relayed_bytes": relayed, "traffic_charged_mu": charged,
                "advertised_net_mu_per_gib": net_rate, "advertised_tunnel_open_mu": open_rate,
                "effective_mu_per_gib": round(charged * GIB / billed, 1) if billed else None}
    return evidence, violations, notes


def probe_tunnel():
    label = TUNNEL_CHILD
    n = TUNNEL_TEST_BYTES
    ev = {"probe": "tunnel", "child": label, "bytes_asked": n}
    token = None
    try:
        r = _gw_start(label)
        token = r.instance.token
        got, direct_s = _direct_download(r.uri, n)
        ev["direct"] = {"bytes": got, "seconds": round(direct_s, 3),
                        "mib_per_s": round(got / direct_s / 2 ** 20, 1) if direct_s else None}
        t = gw.tunnel_http_get(node_url, token, CHILD_PORT, f"/bytes/{n}")
        relayed = t.sent_bytes + t.received_bytes
        ev["tunnel"] = {"status": t.status, "body_bytes": t.body_bytes, "sent_bytes": t.sent_bytes,
                        "received_bytes": t.received_bytes, "seconds": round(t.seconds, 3),
                        "mib_per_s": round(t.body_bytes / t.seconds / 2 ** 20, 1) if t.seconds else None}
        if t.status != 200 or t.body_bytes != n:
            ev["verdict"] = VERDICT_INFRA_ERROR
            ev["reason"] = (f"the tunnel answered {t.status} with {t.body_bytes} of {n} bytes: the "
                            "transfer did not complete, so there is no bill to check")
            return ev
        evidence, violations, notes = _judge_tunnel_bill(_tunnel_rows(token, relayed), relayed,
                                                          NODE_RATES)
        ev["bill"] = evidence
        ev["notes"] = notes
        if violations:
            ev["verdict"] = VERDICT_DISHONEST
            ev["reason"] = "the node charged the tunnel above what it advertises: " + "; ".join(violations)
        elif not evidence["traffic_rows"] and NODE_RATES.get("net_mu_per_gib"):
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = (f"the node relayed {relayed} bytes and the statement of the child shows "
                            f"no traffic charge after {TUNNEL_SETTLE_S}s")
        elif NODE_RATES.get("net_mu_per_gib") is None:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = "the tunnel worked, but the node's rates are not in /__config__ to compare"
        else:
            ev["verdict"] = VERDICT_PASS
            ev["reason"] = (f"{n} bytes over the tunnel at {ev['tunnel']['mib_per_s']} MiB/s "
                            f"(direct {ev['direct']['mib_per_s']} MiB/s); {evidence['billed_bytes']} "
                            f"bytes billed for {relayed} relayed, at "
                            f"{evidence['effective_mu_per_gib']} MU/GiB against the advertised "
                            f"{evidence['advertised_net_mu_per_gib']}")
        return ev
    except Exception as e:
        return _infra(ev, "the tunnel", e)
    finally:
        _gw_stop(token, label)


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
            self_report = requests.get(f"http://{inst.uri}", timeout=45).json()
        except Exception as e:
            self_report = {"error": clip(e)}
        ev["dependency_self_report"] = self_report

        # 3) Keep observing a little past the request, for packets still in flight.
        t.join(timeout=OBSERVE_SECONDS)
        stop_flag[0] = True
        events = list(events)

        packets, sessions, degraded, obs_err = [], [], [], None
        for e in events:
            if isinstance(e, tuple) and e and e[0] == "__error__":
                obs_err = e[1]
                continue
            try:
                if e.HasField("packet"):
                    p = e.packet
                    packets.append({"direction": p.direction, "protocol": p.protocol,
                                    "src": p.src, "dst": p.dst, "peer_kind": p.peer_kind,
                                    "peer_tag": p.peer_tag,
                                    "peer_relationship": p.peer_relationship,
                                    "peer_host": p.peer_host, "source": p.source})
                elif e.HasField("session"):
                    sessions.append({"instance_id": e.session.instance_id, "tag": e.session.tag,
                                     "capture_mode": e.session.capture_mode,
                                     "degraded_reason": e.session.degraded_reason})
                    if e.session.degraded_reason:
                        degraded.append(e.session.degraded_reason)
                elif e.HasField("notice"):
                    if e.notice.degraded:
                        degraded.append(e.notice.message)
            except Exception:
                pass

        ev["observe_error"] = obs_err
        ev["packet_count"] = len(packets)
        ev["packets"] = packets[:20]
        ev["sessions"] = sessions[:5]
        # The node says so when it cannot capture the instance's packets (no
        # AF_PACKET, no conntrack). No packet is then what it promised, not a
        # fabrication.
        ev["observe_degraded"] = degraded[:3]

        # Proof of life for the Observe RPC itself: silence only means something
        # if we know the stream was working. Any event at all (a session record
        # counts) shows the node was really streaming during the window.
        stream_alive = bool(packets or sessions)
        ev["observe_stream_alive"] = stream_alive

        claims_connectivity = isinstance(self_report, dict) and (
            self_report.get("honest") is not None or self_report.get("targets"))
        # The node tags a packet with the peer it belongs to: "instance" with a
        # relationship (parent, child, peer), or "external" with the host. A
        # packet that came IN from an address of the undeclared target can only
        # reach the guest if the node let that flow through.
        undeclared_addrs = set(TARGET_ADDRESSES[UNDECLARED_TARGET[0]])
        ev["undeclared_addresses"] = sorted(undeclared_addrs)
        undeclared = [p for p in packets
                      if p.get("peer_kind") == "external" and p.get("direction") == "IN"
                      and p.get("peer_host") in undeclared_addrs]

        if obs_err and not packets:
            ev["verdict"] = VERDICT_INFRA_ERROR
            ev["reason"] = f"node Observe RPC unavailable/unsupported: {obs_err}"
        elif undeclared:
            ev["verdict"] = VERDICT_DISHONEST
            ev["reason"] = ("Observe shows traffic coming in from an undeclared destination, so the "
                            f"node let that flow through: {undeclared[:3]}")
        elif not packets and claims_connectivity and degraded:
            ev["verdict"] = VERDICT_INCONCLUSIVE
            ev["reason"] = ("the node reported that its observation of the dependency is degraded "
                            f"({clip('; '.join(degraded), 200)}), so no packet is what it promised; "
                            "no claim is made")
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


def ensure_funded(timeout=None, on_wait=None, requote=False):
    """Wait until the balance covers one suite. Returns (funded, funding snapshot).

    The first call measures what the node charges this instance, asks the node what
    the build of each child costs, and sizes every child from both. ``requote`` asks
    again (after the node refused a start for funds). When the rate cannot be
    measured -- the gateway is down, or the node charges nothing -- there is nothing
    to wait for: the suite runs and its preflight reports the gateway, or the node is
    free.
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
        if not FUNDING["child_initial_mu"] or requote:
            quote_child_builds()
            configure_child_budgets(rate)
        while True:
            required = funding_requirement(rate)
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
    # First of the probes that start children: on a node that has not built `tiny`
    # yet, this is the start that pays its build, so both #563 rules are exercised.
    ("build_funding", probe_build_funding),
    ("dependency_identity", probe_dependency_identity),
    ("network_isolation", probe_network_isolation),
    ("dependency_observe", probe_dependency_observe),
    ("memory_ceiling", probe_memory_ceiling),
    ("node_benchmark", probe_node_benchmark),
    ("shared_filesystem", probe_shared_filesystem),
    ("idempotent_start", probe_idempotent_start),
    ("block_skip", probe_block_skip),
    ("env_vars", probe_env_vars),
    ("network_share", probe_network_share),
    ("tunnel", probe_tunnel),
    ("mu_accounting", probe_mu_accounting),
]

# Probes that cannot produce any observation without the gateway. When the
# preflight fails they are reported as INFRA_ERROR instead of being run, so the
# report says "could not verify" once rather than six times in six dialects.
# resource_provisioning is deliberately NOT here: it only reads /proc and
# /__config__, so it stays valid (and can legitimately PASS) with the gateway down.
GATEWAY_DEPENDENT = ("build_funding", "dependency_identity", "network_isolation",
                     "dependency_observe", "memory_ceiling", "node_benchmark",
                     "shared_filesystem", "mu_accounting",
                     "idempotent_start",
                     "block_skip",
                     "env_vars",
                     "network_share",
                     "tunnel")


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
    unobserved = [p for p in results.values()
                  if p.get("verdict") not in CONCLUSIVE_VERDICTS + NEUTRAL_VERDICTS]
    not_applicable = [p.get("probe") for p in results.values()
                      if p.get("verdict") in NEUTRAL_VERDICTS]
    summary = {
        "pass": sum(1 for p in results.values() if p.get("verdict") == VERDICT_PASS),
        "dishonest": sum(1 for p in results.values() if p.get("verdict") in ACCUSING_VERDICTS),
        "unobserved": len(unobserved),
        "unobserved_probes": [p.get("probe") for p in unobserved],
        "not_applicable": len(not_applicable),
        "not_applicable_probes": not_applicable,
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
            starved = []
            for attempt in range(1, STARTUP_MAX_ATTEMPTS + 1):
                STARTUP_TESTS["attempt"] = attempt
                funded, snap = ensure_funded(on_wait=waiting, requote=bool(starved))
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
                # node benchmark + shared filesystem + MU.
                results = _run_probe_suite()
                STARTUP_TESTS["results"] = {"summary": summarize_suite(results), "probes": results}
                starved = list(FUNDING_FAILURES)
                STARTUP_TESTS["starved_children"] = starved
                STARTUP_TESTS["status"] = "done"
                if not starved:
                    break
                # The node refused a launch for want of balance, or because a child's
                # initial_mu did not cover its build. Ask for the builds again (a
                # refusal that named its build already raised that child's) and wait
                # until the balance covers them.
                logging.info("Startup suite starved of funds (%s); quoting the builds again",
                             starved)
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
    unobserved = [p for p in probes
                  if p.get("verdict") not in CONCLUSIVE_VERDICTS + NEUTRAL_VERDICTS]
    not_applicable = [p.get("probe") for p in probes if p.get("verdict") in NEUTRAL_VERDICTS]

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
        "not_applicable": len(not_applicable),
        "not_applicable_probes": not_applicable,
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
    ("probe_build_funding", "/probe/build_funding", probe_build_funding),
    ("probe_dependency_identity", "/probe/dependency_identity", probe_dependency_identity),
    ("probe_network_isolation", "/probe/network", probe_network_isolation),
    ("probe_dependency_observe", "/probe/dependency_observe", probe_dependency_observe),
    ("probe_memory_ceiling", "/probe/memory", probe_memory_ceiling),
    ("probe_node_benchmark", "/probe/benchmark", probe_node_benchmark),
    ("probe_shared_filesystem", "/probe/shared_filesystem", probe_shared_filesystem),
    ("probe_idempotent_start", "/probe/idempotent_start", probe_idempotent_start),
    ("probe_block_skip", "/probe/block_skip", probe_block_skip),
    ("probe_env_vars", "/probe/env_vars", probe_env_vars),
    ("probe_network_share", "/probe/network_share", probe_network_share),
    ("probe_tunnel", "/probe/tunnel", probe_tunnel),
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
        "node_rates": dict(NODE_RATES),
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
    _tool("probe_build_funding",
          "Check the start-funding rules of nodo #563: a child funded below its build, or below "
          "one maintenance period after it, must be refused with the node's message and charge "
          "nothing; a child funded with enough must start, charge this account exactly its "
          "initial_mu, and pay the build from its own account." + _SPENDS, False),
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
    _tool("probe_shared_filesystem",
          "Check the node's shared-filesystem rules: the sharefs child must see what this service "
          "wrote to the directory it exports and this service what the child wrote back, a "
          "read-only mount must refuse a write, and sharefs-denied (which asks for a share this "
          "service does not export) must be refused at launch. A package that does not carry the "
          "share declarations reports INCONCLUSIVE, never DISHONEST." + _SPENDS, False),
    _tool("probe_idempotent_start",
          "Check that StartService with a StartReference is idempotent (nodo #578): the same "
          "reference twice gives one instance and one charge, and the second request gets the "
          "same instance back without sending the service."
          + _SPENDS, False),
    _tool("probe_block_skip",
          "Measure the block skip of nodo #371: start the tiny child with the skip off and on, "
          "after the node holds its block, and report the request bytes, the time to the instance"
          " and the time until the request was sent. PASS when the skip saves at least half of "
          "the bytes; a node that does not skip is never accused."
          + _SPENDS, False),
    _tool("probe_env_vars",
          "Check the env vars of nodo #574/#582: the packed spec of the tiny child names its "
          "declared variables, and a child started with one value given, one empty and one left "
          "out gets exactly those, in /__config__ and in its process environment, with no value "
          "for the one left out."
          + _SPENDS, False),
    _tool("probe_network_share",
          "Check the network shares of nodo #268: two netshare children of one group (no common "
          "exporter) must share /netshare both ways, and a member of another group must not see "
          "it."
          + _SPENDS, False),
    _tool("probe_tunnel",
          "Measure a ServiceTunnel to the tiny child: its throughput (against a direct download),"
          " and the bill on the child's statement: the bytes billed must be the bytes relayed, "
          "and each charge at most the advertised net_mu_per_gib and tunnel_open_mu."
          + _SPENDS, False),
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
<p>Actively probes the node under test for resource, memory-ceiling, network-isolation and shared-filesystem honesty, and runs its per-core benchmark.</p>
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
