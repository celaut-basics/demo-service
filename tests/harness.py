"""Shared test harness: stubs celaut_pool/bee_rpc and imports app.py.

No node, no network and no `celaut` binary required: the client
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
    """Fake celaut_pool + bee_rpc so app.py imports with no node present."""

    class _Instance:
        def __init__(self, uri=None, lease=1):
            self.uri = uri or LISTENING_URI
            self.lease = lease

        def stop(self, gateway_stub):
            FakeServiceInterface.stopped.append(self.uri)

    class FakeServiceInterface:
        """Mimics celaut_pool.ServiceInterface.

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
            # The real ServiceInterface has no gateway stub: `celaut` holds the connection.
            self.gateway_stub = None

        def get_instance(self, max_attempts=1):
            if FakeServiceInterface.launch_mode == "ok":
                return _Instance()
            if FakeServiceInterface.launch_mode == "never_ready":
                return _Instance(uri=CLOSED_URI)
            # Verbatim shape of a failure that the old node_controller library gave:
            # launch_instance() swallowed every grpc.RpcError and then executed
            # `return instance` with the name never assigned. app.py still translates it.
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

    # app.py gets its pool from celaut_pool, which runs the `celaut` command.
    pool = types.ModuleType("celaut_pool")
    pool.Controller = FakeController

    bee = types.ModuleType("bee_rpc")
    bee_client = types.ModuleType("bee_rpc.client")
    bee_client.client_grpc = lambda **kw: iter(())
    bee.client = bee_client
    bee_utils = types.ModuleType("bee_rpc.utils")
    bee_utils.env_calls = []
    bee_utils.modify_env = lambda **kw: bee_utils.env_calls.append(kw)
    bee.utils = bee_utils

    for name, mod in [
        ("celaut_pool", pool),
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
                 "SHAREFS=sharefshash\nSHAREFS_DENIED=sharefsdeniedhash\n"
                 "NETSHARE=netsharehash\n")

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
