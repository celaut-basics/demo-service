#!/usr/bin/env python3
"""Regression tests for the verdict taxonomy (PR #2 / FINDINGS-2026-08-22).

The invariant under test is the one that motivated the whole change:

    a probe that could not OBSERVE the node must never ACCUSE it.

These tests reproduce the exact failure mode seen live against the `witty-panda`
instance -- the node's gRPC gateway was unreachable, so `launch_instance()` fell
off the end of its retry loop and raised `UnboundLocalError` -- and assert the
suite now degrades to INFRA_ERROR with no attestation hash, instead of emitting
two DISHONEST verdicts and minting an EGO-opinion-ready digest over them.

Run with:  python3 tests/test_verdicts.py
No node, no network and no node_controller install required: the client library,
the gateway and the child services are all stubbed at import time.
"""
import json
import os
import sys
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


# ---------------------------------------------------------------------------
# Stub out everything app.py touches at import time.
# ---------------------------------------------------------------------------
def _install_stubs(tmpdir):
    """Fake node_controller + bee_rpc so app.py imports with no node present."""

    class _Instance:
        def __init__(self, uri="127.0.0.1:3030", token="inst-token"):
            self.uri = uri
            self.token = token

    class FakeServiceInterface:
        """Mimics node_controller's ServiceInterface.

        launch_mode:
          "unbound_local" -> reproduce the observed library bug verbatim
          "ok"            -> hand back a live instance
        """
        launch_mode = "unbound_local"

        def __init__(self, service_hash=None, config=None):
            self.service_hash = service_hash

        def get_instance(self, max_attempts=1):
            if FakeServiceInterface.launch_mode == "ok":
                return _Instance()
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
    ]:
        sys.modules[name] = mod

    # app.py reads "<DIR>/.dependencies" at import time.
    svc = os.path.join(tmpdir, "service")
    os.makedirs(svc, exist_ok=True)
    with open(os.path.join(svc, ".dependencies"), "w") as fh:
        fh.write("TINY=tinyhash\nHEAVY=heavyhash\nPING=pinghash\n")

    return FakeServiceInterface, FakeController


import tempfile  # noqa: E402

_TMP = tempfile.mkdtemp(prefix="verifier-tests-")
FakeServiceInterface, FakeController = _install_stubs(_TMP)

os.chdir(_TMP)
sys.path.insert(0, ROOT)
import app  # noqa: E402


class BlindNodeTests(unittest.TestCase):
    """The observed scenario: the gateway is unreachable, so nothing is observable."""

    def setUp(self):
        FakeServiceInterface.launch_mode = "unbound_local"
        FakeController.rpc_mode = "unavailable"

    # -- D1 ------------------------------------------------------------------
    def test_launch_failure_is_typed_and_explains_the_real_cause(self):
        with self.assertRaises(app.ChildLaunchError) as ctx:
            app._spin_child(app.heavy_service, "heavy")
        msg = str(ctx.exception)
        self.assertIn("StartService", msg)
        self.assertIn(app.node_url, msg)
        # The meaningless Python detail must not be the whole story.
        self.assertNotEqual(msg.strip(), "cannot access local variable 'instance'")

    # -- D2 ------------------------------------------------------------------
    def test_memory_ceiling_does_not_accuse_when_no_child_ever_ran(self):
        ev = app.probe_memory_ceiling()
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)
        self.assertNotIn(ev["verdict"], app.ACCUSING_VERDICTS)
        self.assertIsNone(ev["first_kill_mb"], "a launch failure is not an OOM-kill")
        self.assertTrue(all(a.get("launch_failed") for a in ev["attempts"]))
        self.assertNotIn("shortchanged", ev["reason"])

    # -- D3 ------------------------------------------------------------------
    def test_dependency_identity_does_not_accuse_when_no_dependency_ran(self):
        ev = app.probe_dependency_identity()
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)
        self.assertEqual(ev["verified_count"], 0)
        self.assertEqual(sorted(ev["not_observed"]), ["heavy", "ping", "tiny"])
        self.assertEqual(ev["mismatched"], [])
        for check in ev["checks"]:
            self.assertIsNone(check["match"], "unobserved must be None, not False")

    def test_network_isolation_degrades_to_infra_error(self):
        ev = app.probe_network_isolation()
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)

    def test_mu_accounting_reports_infra_error_not_inconclusive(self):
        ev = app.probe_mu_accounting()
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)
        self.assertIn("UNAVAILABLE", ev["reason"])

    # -- D6 ------------------------------------------------------------------
    def test_gateway_preflight_fails_closed_and_names_the_fault(self):
        ev = app.probe_gateway_reachability()
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)
        self.assertIn("NOT evidence of dishonesty", ev["reason"])
        self.assertIn("operator_hint", ev)

    def test_suite_short_circuits_gateway_dependent_probes(self):
        results = app._run_probe_suite()
        self.assertEqual(results["gateway_reachability"]["verdict"], app.VERDICT_INFRA_ERROR)
        for name in app.GATEWAY_DEPENDENT:
            self.assertTrue(results[name].get("skipped"), f"{name} should be skipped")
            self.assertEqual(results[name]["verdict"], app.VERDICT_INFRA_ERROR)
        # resource_provisioning is local-only: it must still run.
        self.assertFalse(results["resource_provisioning"].get("skipped"))

    # -- D5: the whole point -------------------------------------------------
    def test_blind_run_mints_no_attestation_hash_and_makes_no_accusation(self):
        rep = app.build_attestation()
        s = rep["summary"]
        self.assertEqual(s["dishonest"], 0, "a blind run must accuse nobody")
        self.assertIsNone(s["node_honest"], "unknown must be null, not false")
        self.assertFalse(s["attestable"])
        self.assertFalse(s["observation_complete"])
        self.assertIsNone(rep["content_hash"]["value"],
                          "no EGO-opinion digest may be minted from an unobserved run")
        self.assertIn("NOT ATTESTABLE", rep["content_hash"]["note"])
        # And the report must be free of the strings that were published live.
        blob = json.dumps(rep)
        self.assertNotIn("shortchanged", blob)
        self.assertNotIn("did not run or returned the wrong identity", blob)

    def test_acceptance_criteria_from_the_findings_document(self):
        """FINDINGS-2026-08-22.md, 'Criterio de aceptacion'.

        With the node in the observed state (gateway unreachable) the battery
        must report 1 PASS + 6 INFRA_ERROR, attestable: false, content_hash: null.
        The guest's real /proc/meminfo figures are injected because the test host
        is not the microVM.
        """
        guest_limits = {"cgroup_memory_max": None, "cgroup_memory_current": None,
                        "cgroup_cpu_max": None,
                        "proc_meminfo_memtotal_bytes": 961429504}
        with mock.patch.object(app, "read_container_limits", return_value=guest_limits), \
             mock.patch.object(app, "detect_isolation_model", return_value="microvm"):
            rep = app.build_attestation()
        verdicts = {p["probe"]: p["verdict"] for p in rep["probes"]}
        self.assertEqual(verdicts["resource_provisioning"], app.VERDICT_PASS)
        for name in ("gateway_reachability",) + app.GATEWAY_DEPENDENT:
            self.assertEqual(verdicts[name], app.VERDICT_INFRA_ERROR)
        self.assertEqual(rep["summary"]["pass"], 1)
        self.assertEqual(rep["summary"]["dishonest"], 0)
        self.assertEqual(rep["summary"]["unobserved"], 6)
        self.assertEqual(rep["summary"]["total"], 7)
        self.assertFalse(rep["summary"]["attestable"])
        self.assertIsNone(rep["content_hash"]["value"])


class MicroVmProvisioningTests(unittest.TestCase):
    """D4: under a microVM there is no cgroup, so /proc/meminfo IS the ceiling."""

    def test_microvm_without_cgroup_yields_pass_not_inconclusive(self):
        limits = {"cgroup_memory_max": None, "cgroup_memory_current": None,
                  "cgroup_cpu_max": None,
                  # exactly what the live `witty-panda` guest reported
                  "proc_meminfo_memtotal_bytes": 961429504}
        with mock.patch.object(app, "read_container_limits", return_value=limits), \
             mock.patch.object(app, "detect_isolation_model", return_value="microvm"):
            ev = app.probe_resource_provisioning()
        self.assertEqual(ev["verdict"], app.VERDICT_PASS)
        self.assertEqual(ev["ceiling_source"], "proc.meminfo.MemTotal")
        self.assertAlmostEqual(ev["actual_vs_reported_ratio"], 0.961, places=3)

    def test_container_still_prefers_the_cgroup(self):
        limits = {"cgroup_memory_max": "1000000000", "cgroup_memory_current": "1000",
                  "cgroup_cpu_max": "max", "proc_meminfo_memtotal_bytes": 8000000000}
        with mock.patch.object(app, "read_container_limits", return_value=limits), \
             mock.patch.object(app, "detect_isolation_model", return_value="container"):
            ev = app.probe_resource_provisioning()
        self.assertEqual(ev["verdict"], app.VERDICT_PASS)
        self.assertEqual(ev["ceiling_source"], "cgroup.memory.max")

    def test_real_shortchanging_is_still_called_dishonest(self):
        limits = {"cgroup_memory_max": "500000000", "cgroup_memory_current": "1000",
                  "cgroup_cpu_max": "max", "proc_meminfo_memtotal_bytes": 500000000}
        with mock.patch.object(app, "read_container_limits", return_value=limits), \
             mock.patch.object(app, "detect_isolation_model", return_value="container"):
            ev = app.probe_resource_provisioning()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn("shortchanged", ev["reason"])


class RealDishonestyStillDetectedTests(unittest.TestCase):
    """The fix must not blunt the verifier: observed misbehaviour still accuses."""

    def setUp(self):
        FakeServiceInterface.launch_mode = "ok"
        FakeController.rpc_mode = "ok"

    def test_substituted_dependency_is_dishonest(self):
        def fake_get(url, timeout=None):
            r = mock.Mock()
            # The node runs 'tiny' when 'heavy' was requested.
            r.json.return_value = {"service": "tiny", "identity": "celaut-demo-tiny"}
            r.status_code = 200
            return r
        with mock.patch.object(app.requests, "get", side_effect=fake_get):
            ev = app.probe_dependency_identity()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn("heavy", ev["mismatched"])

    def test_mismatch_outranks_a_partial_launch_failure(self):
        calls = {"n": 0}
        original = FakeServiceInterface.get_instance

        def flaky(self, max_attempts=1):
            calls["n"] += 1
            if calls["n"] == 1:  # tiny never launches
                raise UnboundLocalError(
                    "cannot access local variable 'instance' where it is not "
                    "associated with a value")
            return original(self, max_attempts)

        def fake_get(url, timeout=None):
            r = mock.Mock()
            r.json.return_value = {"service": "ping", "identity": "celaut-demo-ping"}
            r.status_code = 200
            return r

        with mock.patch.object(FakeServiceInterface, "get_instance", flaky), \
             mock.patch.object(app.requests, "get", side_effect=fake_get):
            ev = app.probe_dependency_identity()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST,
                         "observed substitution must outrank a partial infra failure")
        self.assertIn("tiny", ev["not_observed"])
        self.assertIn("heavy", ev["mismatched"])

    def test_unenforced_memory_ceiling_is_dishonest(self):
        def fake_get(url, timeout=None):
            r = mock.Mock()
            r.status_code = 200
            r.json.return_value = {"ok": True, "cgroup_mem_current": "1"}
            return r
        with mock.patch.object(app.requests, "get", side_effect=fake_get):
            ev = app.probe_memory_ceiling()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn("NOT enforced", ev["reason"])

    def test_ceiling_enforced_at_the_declared_boundary_passes(self):
        def fake_get(url, timeout=None):
            mb = int(url.rsplit("/", 1)[1])
            if mb > 256:
                raise ConnectionError("connection dropped (OOM-killed)")
            r = mock.Mock()
            r.status_code = 200
            r.json.return_value = {"ok": True, "cgroup_mem_current": str(mb << 20)}
            return r
        with mock.patch.object(app.requests, "get", side_effect=fake_get):
            ev = app.probe_memory_ceiling()
        self.assertEqual(ev["verdict"], app.VERDICT_PASS)
        self.assertEqual(ev["observed_ceiling_mb"], 240)
        self.assertEqual(ev["first_kill_mb"], 300)
        self.assertTrue(any(a.get("killed") for a in ev["attempts"]))

    def test_fully_observed_honest_run_mints_a_hash(self):
        good = {"probe": "x", "verdict": app.VERDICT_PASS, "reason": "ok"}
        with mock.patch.object(app, "_run_probe_suite",
                               return_value={n: dict(good, probe=n) for n, _ in app.PROBES}):
            rep = app.build_attestation()
        self.assertTrue(rep["summary"]["attestable"])
        self.assertTrue(rep["summary"]["node_honest"])
        self.assertIsNotNone(rep["content_hash"]["value"])
        self.assertEqual(len(rep["content_hash"]["value"]), 64)

    def test_hash_is_deterministic_across_runs(self):
        good = {"probe": "x", "verdict": app.VERDICT_PASS, "reason": "ok"}
        with mock.patch.object(app, "_run_probe_suite",
                               return_value={n: dict(good, probe=n) for n, _ in app.PROBES}):
            a = app.build_attestation()["content_hash"]["value"]
            b = app.build_attestation()["content_hash"]["value"]
        self.assertEqual(a, b)

    def test_observed_dishonesty_is_attestable(self):
        probes = {n: {"probe": n, "verdict": app.VERDICT_PASS, "reason": "ok"}
                  for n, _ in app.PROBES}
        probes["memory_ceiling"]["verdict"] = app.VERDICT_DISHONEST
        with mock.patch.object(app, "_run_probe_suite", return_value=probes):
            rep = app.build_attestation()
        self.assertTrue(rep["summary"]["attestable"],
                        "fully observed dishonesty MUST be publishable")
        self.assertFalse(rep["summary"]["node_honest"])
        self.assertIsNotNone(rep["content_hash"]["value"])


class MuAccountingRoundingTests(unittest.TestCase):
    """D8: a zero MU delta over a short window is rounding, not proof of a free ride."""

    def setUp(self):
        FakeController.rpc_mode = "ok"

    def test_short_window_with_zero_spend_is_inconclusive(self):
        with mock.patch.object(app, "MU_WINDOW_SECONDS", 0), \
             mock.patch.object(app, "MU_MIN_DECISIVE_WINDOW_SECONDS", 60), \
             mock.patch.object(app, "_sample_mu_balance", return_value=(10 ** 8, {})):
            ev = app.probe_mu_accounting()
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)
        self.assertNotIn(ev["verdict"], app.ACCUSING_VERDICTS)

    def test_long_window_with_zero_spend_is_dishonest(self):
        with mock.patch.object(app, "MU_WINDOW_SECONDS", 0), \
             mock.patch.object(app, "MU_MIN_DECISIVE_WINDOW_SECONDS", 0), \
             mock.patch.object(app, "_sample_mu_balance", return_value=(10 ** 8, {})):
            ev = app.probe_mu_accounting()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn("free ride", ev["reason"])


class ObserveCorroborationTests(unittest.TestCase):
    """D8: only accuse of fabricated connectivity if the Observe stream proved it was live."""

    def setUp(self):
        FakeServiceInterface.launch_mode = "ok"

    def _run(self, events):
        def fake_collect(instance_id, out, stop_flag):
            out.extend(events)

        def fake_get(url, timeout=None):
            r = mock.Mock()
            r.json.return_value = {"honest": True, "targets": [{"target": "google.com"}]}
            return r

        with mock.patch.object(app, "_collect_observe_events", side_effect=fake_collect), \
             mock.patch.object(app.requests, "get", side_effect=fake_get):
            return app.probe_dependency_observe()

    def test_silent_stream_is_inconclusive_not_an_accusation(self):
        ev = self._run([])
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)
        self.assertFalse(ev["observe_stream_alive"])

    def test_live_stream_with_no_packets_is_dishonest(self):
        session_evt = mock.Mock()
        session_evt.HasField.side_effect = lambda f: f == "session"
        session_evt.session.instance_id = "abc"
        session_evt.session.tag = "ping"
        ev = self._run([session_evt])
        self.assertTrue(ev["observe_stream_alive"])
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)


class TaxonomyInvariantTests(unittest.TestCase):
    def test_fail_verdict_is_gone_from_the_source(self):
        with open(os.path.join(ROOT, "app.py")) as fh:
            src = fh.read()
        self.assertNotIn('"FAIL"', src,
                         "FAIL is ambiguous; use DISHONEST or INFRA_ERROR")

    def test_only_dishonest_accuses(self):
        self.assertEqual(app.ACCUSING_VERDICTS, (app.VERDICT_DISHONEST,))
        self.assertNotIn(app.VERDICT_INFRA_ERROR, app.CONCLUSIVE_VERDICTS)
        self.assertNotIn(app.VERDICT_INCONCLUSIVE, app.CONCLUSIVE_VERDICTS)
        self.assertNotIn(app.VERDICT_NOT_APPLICABLE, app.CONCLUSIVE_VERDICTS)

    def test_crashed_probe_never_accuses(self):
        def boom():
            raise ValueError("kaboom")
        ev = app._safe_probe("x", boom)
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)

    def test_preflight_is_exposed_over_mcp(self):
        names = [t["name"] for t in app.MCP_TOOLS]
        self.assertIn("probe_gateway_reachability", names)


class FaultAttributionTests(unittest.TestCase):
    """An error reply from the gateway must never be reported as unreachability.

    The live confusion this pins down: the node rejected
    ModifyServiceSystemResources with `StatusCode.UNKNOWN ... Error charging for
    the resource change of ...`, and the preflight reported "the node gateway is
    unreachable", which sent the operator into the host firewall. The gateway had
    answered -- an answer only a reachable gateway can send.
    """

    def setUp(self):
        FakeController.rpc_mode = "node_error"
        # Let the L4 leg pass so the L7 leg is the one under test.
        self._tcp = mock.patch.object(app.socket, "create_connection")
        self._tcp.start()

    def tearDown(self):
        self._tcp.stop()
        FakeController.rpc_mode = "unavailable"

    def test_a_status_reply_is_attributed_to_the_node_not_the_network(self):
        ev = app.probe_gateway_reachability()
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)
        self.assertEqual(ev["fault"], app.FAULT_NODE_RPC)
        self.assertTrue(ev["node_answered"])
        self.assertEqual(ev["grpc_code"], "UNKNOWN")
        self.assertIn("Error charging for the resource change", ev["node_detail"])
        self.assertIn("INSIDE THE NODE", ev["reason"])
        self.assertNotIn("unreachable", ev["reason"])
        self.assertNotIn("did not answer", ev["reason"])
        self.assertNotIn(ev["verdict"], app.ACCUSING_VERDICTS)

    def test_the_firewall_is_not_suggested_when_the_node_replied(self):
        ev = app.probe_gateway_reachability()
        self.assertIn("Do not touch the firewall", ev["operator_hint"])

    def test_skipped_probes_say_the_gateway_was_reachable(self):
        results = app._run_probe_suite()
        for name in app.GATEWAY_DEPENDENT:
            reason = results[name]["reason"]
            self.assertTrue(results[name]["skipped"])
            self.assertIn("reachable but rejected the preflight RPC", reason)
            self.assertNotIn("gateway is unreachable", reason)

    def test_a_transport_failure_is_still_called_unreachable(self):
        FakeController.rpc_mode = "unavailable"
        ev = app.probe_gateway_reachability()
        self.assertEqual(ev["fault"], app.FAULT_TRANSPORT)
        self.assertFalse(ev["node_answered"])
        self.assertEqual(ev["grpc_code"], "UNAVAILABLE")
        results = app._run_probe_suite()
        self.assertIn("gateway is unreachable", results["mu_accounting"]["reason"])

    def test_an_exception_with_no_status_blames_neither_side(self):
        class _Blank(Exception):
            pass

        failure = app.classify_rpc_failure(_Blank("connection died mid-stream"))
        self.assertEqual(failure["fault"], app.FAULT_UNKNOWN)
        self.assertFalse(failure["node_answered"])
        reason, _hint = app.describe_rpc_failure(failure, "SomeRpc", "1.2.3.4:5000")
        self.assertIn("cannot be told whether the node answered", reason)

    def test_a_real_grpc_error_is_read_from_its_status_code(self):
        class _RpcError(Exception):
            def code(self):
                class _Code:
                    name = "RESOURCE_EXHAUSTED"
                return _Code()

        failure = app.classify_rpc_failure(_RpcError("no text status here"))
        self.assertEqual(failure["grpc_code"], "RESOURCE_EXHAUSTED")
        self.assertEqual(failure["fault"], app.FAULT_NODE_RPC)


if __name__ == "__main__":
    unittest.main(verbosity=2)
