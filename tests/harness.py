"""Shared test harness: stubs node_controller/bee_rpc and imports app.py.

No node, no network and no node_controller install required: the client
library, the gateway and the child services are all stubbed at import time.
Importing this module once per process gives every test file the same app.
"""
import os
import socket
import sys
import threading
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


# Every probe waits for a child's port to accept a connection before it asserts
# anything, so the stubs need real ports to answer that wait: one that listens
# and one that refuses. Stubbing the wait away would leave untested the very
# distinction it exists to draw -- a child that never came up (observed nothing)
# versus one that died mid-request (a genuine kill).
_LISTENER = socket.socket()
_LISTENER.bind(("127.0.0.1", 0))
_LISTENER.listen(64)
LISTENING_URI = "127.0.0.1:%d" % _LISTENER.getsockname()[1]


def _drain_ready_listener():
    """Drop every connection so the accept queue cannot fill.

    `_wait_until_ready` only needs the TCP handshake. Without accept(), each
    handshake stays in the listen backlog until the process exits. After 64
    waits, later waits hang for CHILD_READY_TIMEOUT_S (120s) and
    `unittest discover` never finishes.
    """
    while True:
        try:
            conn, _ = _LISTENER.accept()
        except OSError:
            return
        try:
            conn.close()
        except OSError:
            pass


threading.Thread(
    target=_drain_ready_listener, name="harness-accept", daemon=True
).start()

_closed = socket.socket()
_closed.bind(("127.0.0.1", 0))
_CLOSED_PORT = _closed.getsockname()[1]
_closed.close()
CLOSED_URI = "127.0.0.1:%d" % _CLOSED_PORT


# ---------------------------------------------------------------------------
# Stub out everything app.py touches at import time.
# ---------------------------------------------------------------------------
def _install_stubs(tmpdir):
    """Fake node_controller + bee_rpc so app.py imports with no node present."""

    class _Instance:
        def __init__(self, uri=None, token="inst-token"):
            self.uri = uri or LISTENING_URI
            self.token = token

        def stop(self, gateway_stub):
            FakeServiceInterface.stopped.append(self.uri)

    class FakeServiceInterface:
        """Mimics node_controller's ServiceInterface.

        launch_mode:
          "unbound_local" -> reproduce the observed library bug verbatim
          "ok"            -> hand back a live instance, on a port that answers
          "never_ready"   -> hand back an instance whose port never opens: the
                             shape of a microVM the node reports ready before the
                             service inside it has bound anything
        """
        launch_mode = "unbound_local"
        # Every uri handed to stop(), so tests can assert children are released.
        stopped = []

        def __init__(self, service_hash=None, config=None):
            self.service_hash = service_hash
            # Real ServiceInterfaces carry the stub _release_child stops through.
            self.gateway_stub = object()

        def get_instance(self, max_attempts=1):
            if FakeServiceInterface.launch_mode == "ok":
                return _Instance()
            if FakeServiceInterface.launch_mode == "never_ready":
                return _Instance(uri=CLOSED_URI)
            # Verbatim shape of the real failure: node_controller's
            # launch_instance() swallows every grpc.RpcError into debug() and
            # then executes `return instance` with the name never assigned.
            raise UnboundLocalError(
                "cannot access local variable 'instance' where it is not "
                "associated with a value")

    class FakeController:
        rpc_mode = "unavailable"  # or "ok"

        def __init__(self, *a, **kw):
            pass

        def get_node_url(self):
            return "192.168.200.1:58443"

        def get_mem_limit_at_start(self):
            return 1000000000

        def add_service(self, service_hash=None, config=None):
            return FakeServiceInterface(service_hash, config)

        def modify_resources(self, spec):
            if FakeController.rpc_mode == "ok":
                return ({"mem_limit": 1000000000}, 10 ** 8)
            if FakeController.rpc_mode == "node_error":
                # Verbatim shape of the live failure the node returns when it
                # cannot charge the caller: the gateway ANSWERED, with a status
                # and its own details string. Reachability is not in question.
                raise RuntimeError(
                    "_MultiThreadedRendezvous: <_MultiThreadedRendezvous of RPC that "
                    "terminated with:\n\tstatus = StatusCode.UNKNOWN\n\tdetails = "
                    '"Exception iterating responses: Error charging for the resource '
                    'change of ipv4:192.168.200.38:49254"\n>')
            raise RuntimeError(
                "StatusCode.UNAVAILABLE failed to connect to all addresses; "
                "last error: UNKNOWN: ipv4:192.168.200.1:58443: Failed to connect")

    nc = types.ModuleType("node_controller")
    nc_controller = types.ModuleType("node_controller.controller")
    nc_controller_controller = types.ModuleType("node_controller.controller.controller")
    nc_controller_controller.Controller = FakeController

    nc_gateway = types.ModuleType("node_controller.gateway")
    nc_protos = types.ModuleType("node_controller.gateway.protos")
    celaut_pb2 = types.ModuleType("node_controller.gateway.protos.celaut_pb2")
    celaut_pb2.Configuration = lambda **kw: {"config": kw}
    celaut_pb2.BytesKeyValue = lambda **kw: dict(kw)
    celaut_pb2.ObserveRequest = lambda **kw: {"observe": kw}
    celaut_pb2.ObserveEvent = object
    nc_protos.celaut_pb2 = celaut_pb2

    nc_utils = types.ModuleType("node_controller.gateway.utils")
    nc_utils.to_amount = lambda v: v
    nc_utils.from_amount = lambda v: v

    nc_comm = types.ModuleType("node_controller.gateway.communication")
    nc_comm.generate_gateway_stub = lambda url: object()

    bee = types.ModuleType("bee_rpc")
    bee_client = types.ModuleType("bee_rpc.client")
    bee_client.client_grpc = lambda **kw: iter(())
    bee.client = bee_client
    bee_utils = types.ModuleType("bee_rpc.utils")
    bee_utils.env_calls = []
    bee_utils.modify_env = lambda **kw: bee_utils.env_calls.append(kw)
    bee.utils = bee_utils

    for name, mod in [
        ("node_controller", nc),
        ("node_controller.controller", nc_controller),
        ("node_controller.controller.controller", nc_controller_controller),
        ("node_controller.gateway", nc_gateway),
        ("node_controller.gateway.protos", nc_protos),
        ("node_controller.gateway.protos.celaut_pb2", celaut_pb2),
        ("node_controller.gateway.utils", nc_utils),
        ("node_controller.gateway.communication", nc_comm),
        ("bee_rpc", bee),
        ("bee_rpc.client", bee_client),
        ("bee_rpc.utils", bee_utils),
    ]:
        sys.modules[name] = mod

    # app.py reads "<DIR>/.dependencies" at import time.
    svc = os.path.join(tmpdir, "service")
    os.makedirs(svc, exist_ok=True)
    with open(os.path.join(svc, ".dependencies"), "w") as fh:
        fh.write("TINY=tinyhash\nHEAVY=heavyhash\nPING=pinghash\nBENCHMARK=benchmarkhash\n"
                 "SHAREFS=sharefshash\nSHAREFS_DENIED=sharefsdeniedhash\n")

    return FakeServiceInterface, FakeController


import tempfile  # noqa: E402

_TMP = tempfile.mkdtemp(prefix="verifier-tests-")
FakeServiceInterface, FakeController = _install_stubs(_TMP)

os.chdir(_TMP)
sys.path.insert(0, ROOT)
# The funding gate samples the balance twice and polls while short; no waiting
# in tests.
os.environ.setdefault("FUNDING_RATE_SAMPLE_SECONDS", "0")
os.environ.setdefault("FUNDING_POLL_SECONDS", "0")
import app  # noqa: E402
