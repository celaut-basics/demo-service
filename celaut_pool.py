"""The children of this service, through the ``celaut`` command.

``celaut`` is the library of a Celaut service (celaut-project/service-library, in Rust) as a
static binary. This module is the only place that runs it. It gives the verifier what it needs
from the pool of its dependencies:

* ``Controller.get_node_url()`` and ``get_mem_limit_at_start()``: the gateway and the memory
  limit that the node wrote in ``/__config__``.
* ``Controller.add_service(service_hash, config)``: a child that this service can launch. It
  starts nothing: ``ServiceInterface.get_instance()`` starts one (``celaut acquire``) and
  ``Instance.stop()`` stops it (``celaut stop``).
* ``Controller.modify_resources({"min", "max"})``: settle the account at a memory ceiling
  (``celaut resize``). The answer is ``(resources, balance_mu)``.
* ``Controller.observe(lease)``: the events of the node's ``Observe`` of a child, as dicts.

The tokens of the children never reach this process: ``celaut`` keeps them in its pool file, and
this service only sees lease numbers. That is by design: a token stops an instance and reads its
balance. It is also why a child is named by its ``instance_ref`` in a report (see
``nodo_gateway.instance_ref``) and never by its token.

An error of ``celaut`` is a ``CelautError`` whose text has the gRPC status in the form that
``app.classify_rpc_failure`` reads: ``StatusCode.UNAVAILABLE`` when the node did not answer (exit
code 3 of ``celaut``) and ``StatusCode.UNKNOWN`` with the node's own text as ``details = "..."``
when it answered with an error. So a refusal is never taken for a dead gateway.

Each call is one process that lives as long as the call. ``celaut`` locks its pool file, so the
threads of this service can call it at the same time.
"""
import json
import logging
import os
import subprocess
import threading
from contextlib import contextmanager
from types import SimpleNamespace

# Where the binary is. The Dockerfile puts it in /usr/local/bin.
CELAUT_BIN = os.environ.get("CELAUT_BIN", "celaut")

# A start can take minutes: the node may have to build the child and boot its microVM. The
# time is for all the attempts of one ``acquire``.
ACQUIRE_TIMEOUT_S = int(os.environ.get("CELAUT_ACQUIRE_TIMEOUT_S", "1800"))
# Every other command is one call to the gateway.
COMMAND_TIMEOUT_S = int(os.environ.get("CELAUT_COMMAND_TIMEOUT_S", "180"))


class CelautError(RuntimeError):
    """A ``celaut`` command failed.

    ``kind`` and ``unreachable`` are the ones of the JSON that ``celaut`` writes on stderr.
    ``unreachable`` is true when the node did not answer, which is never a fault of the node.
    """

    def __init__(self, command, text, *, kind=None, unreachable=False, exit_code=None):
        self.command = command
        self.kind = kind
        self.unreachable = unreachable
        self.exit_code = exit_code
        self.detail = text
        if unreachable:
            shown = f"StatusCode.UNAVAILABLE celaut {command}: {text}"
        elif kind == "gateway":
            # The node answered with an error. Its text goes where the verifier reads the
            # node's own words; a double quote would end that text early.
            shown = f'StatusCode.UNKNOWN celaut {command}: details = "{text.replace(chr(34), chr(39))}"'
        else:
            shown = f"celaut {command}: {text}"
        super().__init__(shown)


def _run(args, *, global_args=(), timeout=COMMAND_TIMEOUT_S):
    """Run ``celaut`` and give the JSON of its stdout (``None`` if it wrote nothing)."""
    command = args[0]
    try:
        done = subprocess.run([CELAUT_BIN, *global_args, *args], capture_output=True, text=True,
                              timeout=timeout)
    except FileNotFoundError as e:
        raise CelautError(command, f"the celaut binary was not found ({CELAUT_BIN}): {e}",
                          kind="config", exit_code=127)
    except subprocess.TimeoutExpired:
        raise CelautError(command, f"no answer within {timeout}s", kind="timeout",
                          unreachable=True, exit_code=None)
    if done.returncode == 0:
        text = done.stdout.strip()
        return json.loads(text) if text else None
    try:
        info = json.loads(done.stderr.strip().splitlines()[-1])
        raise CelautError(command, str(info.get("error", done.stderr.strip())),
                          kind=info.get("kind"), unreachable=bool(info.get("unreachable")),
                          exit_code=done.returncode)
    except (ValueError, IndexError):
        raise CelautError(command, done.stderr.strip() or f"exit code {done.returncode}",
                          exit_code=done.returncode)


class Instance:
    """A child that this service started. ``lease`` is what ``celaut`` calls it."""

    def __init__(self, controller, lease, uri):
        self._controller = controller
        self.lease = lease
        self.uri = uri

    def stop(self, _stub=None):
        """Stop the child. Gives the MU that the node gave back."""
        out = _run(["stop", str(self.lease)], global_args=self._controller.global_args)
        return int(out["refund_mu"]) if out and "refund_mu" in out else 0


class ServiceInterface:
    """A child that can be launched, with its configuration."""

    # There is no gateway stub in this process: ``celaut`` holds the connection. The attribute
    # stays so that a caller that passes it to ``Instance.stop`` keeps working.
    gateway_stub = None

    def __init__(self, controller, service_hash, config):
        self._controller = controller
        self.service_hash = service_hash
        self.config = config

    def _dependency_args(self):
        root = self._controller.app_dir
        args = ["--service", self.service_hash, "--root", root,
                "--block-dir", os.path.join(root, "__block__")]
        config = self.config or {}
        for item in config.get("environment_variables", ()):
            value = item["value"]
            if isinstance(value, bytes):
                value = value.decode()
            args += ["--env", f"{item['key']}={value}"]
        if config.get("initial_mu") is not None:
            args += ["--initial-mu", str(int(config["initial_mu"]))]
        return args

    def get_instance(self, max_attempts=1):
        """Start a child and give it. Always a new one: a probe measures a fresh child."""
        out = _run(["acquire", "--new", "--attempts", str(max(1, int(max_attempts))),
                    *self._dependency_args()],
                   global_args=self._controller.global_args, timeout=ACQUIRE_TIMEOUT_S)
        return Instance(self._controller, int(out["lease"]), out["uri"])


class Controller:
    """The node of this service, as ``celaut`` shows it."""

    def __init__(self, debug=None, app_dir=".", config_file="/__config__", **_ignored):
        self._debug = debug or (lambda text: logging.debug(text))
        self.app_dir = os.path.abspath(app_dir)
        self.config_file = config_file
        self.global_args = ("--config", config_file)
        self._config = None
        self._lock = threading.Lock()

    def _node_config(self):
        with self._lock:
            if self._config is None:
                self._config = _run(["config"], global_args=self.global_args)
            return self._config

    def get_node_url(self):
        return self._node_config()["gateway"]

    def get_mem_limit_at_start(self):
        return self._node_config().get("mem_limit")

    def add_service(self, service_hash=None, config=None):
        return ServiceInterface(self, service_hash, config)

    def modify_resources(self, spec):
        """Settle the account at the memory ceiling ``spec["max"]``. The node reads only the
        maximum (its ``min_sysreq`` is not used), so ``spec["min"]`` is not sent."""
        out = _run(["resize", "--mem", str(int(spec["max"]))], global_args=self.global_args)
        return SimpleNamespace(mem_limit=out.get("mem_limit")), int(out["balance_mu"])

    @contextmanager
    def observe(self, lease, packets=True):
        """The events of the ``Observe`` stream of the child ``lease``, one dict each:
        ``{"time", "kind", "data"}``. The stream is closed when the block ends."""
        args = [CELAUT_BIN, *self.global_args, "observe", str(lease)]
        if packets:
            args.append("--packets")
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        def events():
            for line in proc.stdout:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except ValueError:
                        continue
            code = proc.wait()
            if code != 0:
                try:
                    info = json.loads(proc.stderr.read().strip().splitlines()[-1])
                    raise CelautError("observe", str(info.get("error")), kind=info.get("kind"),
                                      unreachable=bool(info.get("unreachable")), exit_code=code)
                except (ValueError, IndexError):
                    raise CelautError("observe", f"exit code {code}", exit_code=code)

        try:
            yield events()
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            for stream in (proc.stdout, proc.stderr):
                try:
                    stream.close()
                except Exception:
                    pass
