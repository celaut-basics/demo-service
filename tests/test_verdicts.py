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
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from harness import (  # noqa: E402
    ROOT, LISTENING_URI, CLOSED_URI, FakeServiceInterface, FakeController, app)


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
        self.assertEqual(sorted(ev["not_observed"]), ["benchmark", "heavy", "ping", "tiny"])
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
        must report 1 PASS + 6 INFRA_ERROR, attestable: false, content_hash: null --
        7 INFRA_ERROR now that node_benchmark joined the gateway-dependent probes.
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
        self.assertEqual(rep["summary"]["unobserved"], 7)
        self.assertEqual(rep["summary"]["total"], 8)
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


class DebtIsNotOverchargingTests(unittest.TestCase):
    """The live false positive: an operator's node was called DISHONEST for a
    balance that was already negative before the measurement began.

    Numbers are the ones the `eager-jungle` instance reported. `costs.ALLOW_DEBT`
    is a supported node setting, so a balance below zero is that node's configured
    policy -- not evidence about what it charged during the window.
    """

    def setUp(self):
        FakeController.rpc_mode = "ok"

    @staticmethod
    def _samples(seq):
        """_sample_mu_balance returns the next balance on each call."""
        it = iter(seq)
        return lambda min_b, max_b: (next(it), {})

    def test_a_balance_already_in_debt_is_not_an_accusation(self):
        balances = [-1316921755, -1317120138, -1317130138, -1317256207,
                    -1317266207, -1317464590]
        with mock.patch.object(app, "MU_WINDOW_SECONDS", 0), \
             mock.patch.object(app, "MU_MIN_DECISIVE_WINDOW_SECONDS", 0), \
             mock.patch.object(app, "_sample_mu_balance", self._samples(balances)):
            ev = app.probe_mu_accounting()
        self.assertTrue(ev["started_in_debt"])
        # It spent more at the low ceiling than the high one, so this run is not
        # a PASS either -- but the claim it makes must be about that, never about
        # a drain that happened before anyone was watching.
        self.assertNotIn("drained", ev["reason"])
        self.assertNotIn("<= 0", ev["reason"])

    def test_crossing_from_positive_into_debt_is_still_dishonest(self):
        # 10^8 down to -1 in one window: the node really did take a funded
        # balance to nothing while holding resources.
        balances = [10 ** 8, -1, 10 ** 8, 10 ** 8 - 1, 10 ** 8, 10 ** 8 - 1]
        with mock.patch.object(app, "MU_WINDOW_SECONDS", 0), \
             mock.patch.object(app, "MU_MIN_DECISIVE_WINDOW_SECONDS", 0), \
             mock.patch.object(app, "_sample_mu_balance", self._samples(balances)):
            ev = app.probe_mu_accounting()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn("positive", ev["reason"])

    def test_a_short_window_cannot_accuse_on_scaling_either(self):
        # Spend that does not rise with the ceiling is the other accusing branch.
        # Below the decisive length it must degrade, exactly as zero spend does.
        balances = [10 ** 8, 10 ** 8 - 500, 10 ** 8, 10 ** 8 - 10, 10 ** 8, 10 ** 8 - 500]
        with mock.patch.object(app, "MU_WINDOW_SECONDS", 0), \
             mock.patch.object(app, "MU_MIN_DECISIVE_WINDOW_SECONDS", 60), \
             mock.patch.object(app, "_sample_mu_balance", self._samples(balances)):
            ev = app.probe_mu_accounting()
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)
        self.assertNotIn(ev["verdict"], app.ACCUSING_VERDICTS)

    def test_the_shipped_window_is_long_enough_to_decide(self):
        # A default that cannot decide makes every unconfigured run pay for the
        # windows and then declare itself unable to read them.
        self.assertGreaterEqual(app.MU_WINDOW_SECONDS, app.MU_MIN_DECISIVE_WINDOW_SECONDS)


class MuScalingNoiseTests(unittest.TestCase):
    """The live false positive at startup: low 216090 MU vs high 184932 MU over
    60 s was called DISHONEST, on a node every later run found honest. Memory is
    ~10-15% of the bill, so one heavy window outweighs the whole signal."""

    def setUp(self):
        FakeController.rpc_mode = "ok"

    @staticmethod
    def _windows(*spends, seconds=60.0):
        """_mu_window returns (open, close, secs) for each window in order."""
        it = iter(spends)
        return lambda ceiling: (10 ** 8, 10 ** 8 - next(it), seconds)

    def _run(self, *spends, **kw):
        with mock.patch.object(app, "MU_MIN_DECISIVE_WINDOW_SECONDS", 0), \
             mock.patch.object(app, "_mu_window", side_effect=self._windows(*spends, **kw)):
            return app.probe_mu_accounting()

    def test_the_startup_reading_is_inside_the_noise(self):
        # Same first two windows as the live run; the second low window shows how
        # far this node's low-ceiling spend wanders on its own (24% here), so a
        # high window 4% under the low average says nothing either way.
        ev = self._run(216090, 184932, 170000)
        self.assertNotIn(ev["verdict"], app.ACCUSING_VERDICTS)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])
        self.assertIn("noise", ev["reason"])

    def test_a_steady_node_that_charges_less_for_more_is_dishonest(self):
        ev = self._run(150000, 100000, 150500)
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)

    def test_a_small_dip_within_the_floor_tolerance_accuses_nobody(self):
        ev = self._run(150000, 148000, 150000)  # 1.3% under, floor is 5%
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)

    def test_the_honest_shape_passes(self):
        ev = self._run(145004, 164523, 146000)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])

    def test_spend_is_compared_as_a_rate_over_the_real_window(self):
        # The high window lasted twice as long: 200 MU over 120 s is a LOWER rate
        # than 150 MU over 60 s, whatever the raw totals say.
        durations = iter([60.0, 120.0, 60.0])
        spends = iter([150, 200, 150])
        with mock.patch.object(app, "MU_MIN_DECISIVE_WINDOW_SECONDS", 0), \
             mock.patch.object(app, "_mu_window",
                               side_effect=lambda c: (10 ** 8, 10 ** 8 - next(spends), next(durations))):
            ev = app.probe_mu_accounting()
        self.assertLess(ev["rate_high_mu_per_s"], ev["rate_low_mu_per_s"])
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)


class ChildReadinessTests(unittest.TestCase):
    """The node calls a microVM ready when its guest network answers, seconds
    before the service inside it binds a port. Probes must wait for the port,
    and must never read the gap as the child being killed.
    """

    def setUp(self):
        FakeController.rpc_mode = "ok"
        FakeServiceInterface.stopped = []

    def tearDown(self):
        FakeServiceInterface.launch_mode = "ok"

    def test_a_child_that_never_opens_its_port_raises_not_ready(self):
        FakeServiceInterface.launch_mode = "never_ready"
        with mock.patch.object(app, "CHILD_READY_TIMEOUT_S", 0), \
             mock.patch.object(app, "CHILD_READY_POLL_S", 0):
            with self.assertRaises(app.ChildNotReadyError):
                app._spin_child(app.heavy_service, "heavy")

    def test_a_booting_child_is_not_recorded_as_a_kill(self):
        FakeServiceInterface.launch_mode = "never_ready"
        with mock.patch.object(app, "CHILD_READY_TIMEOUT_S", 0), \
             mock.patch.object(app, "CHILD_READY_POLL_S", 0):
            ev = app.probe_memory_ceiling()
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)
        self.assertIsNone(ev["first_kill_mb"])
        self.assertTrue(all(r.get("never_ready") for r in ev["attempts"]))
        self.assertNotIn(ev["verdict"], app.ACCUSING_VERDICTS)

    def test_probes_stop_the_children_they_spin(self):
        # A child left running keeps billing this service's balance -- which is
        # what mu_accounting measures -- and node_controller's own contract is
        # that a taken instance is returned to its queue or stopped.
        FakeServiceInterface.launch_mode = "ok"

        def fake_get(url, timeout=None):
            r = mock.Mock()
            r.status_code = 200
            r.json.return_value = {"ok": True, "cgroup_mem_current": 1}
            return r

        with mock.patch.object(app.requests, "get", fake_get):
            app.probe_memory_ceiling()
        self.assertEqual(len(FakeServiceInterface.stopped), len(app.MEMORY_LADDER))

    def test_a_self_contradictory_ladder_decides_nothing(self):
        # A kill below a request that succeeded does not locate a ceiling. The
        # PASS branch reads only the highest success, so it would call this run
        # correct on evidence that cannot hold together.
        FakeServiceInterface.launch_mode = "ok"
        answers = {64: None, 128: True, 200: True, 240: True, 300: None}

        def fake_get(url, timeout=None):
            mb = int(url.rsplit("/", 1)[1])
            if answers.get(mb) is None:
                raise ConnectionError("connection aborted")
            r = mock.Mock()
            r.status_code = 200
            r.json.return_value = {"ok": True, "cgroup_mem_current": 1}
            return r

        with mock.patch.object(app.requests, "get", fake_get):
            ev = app.probe_memory_ceiling()
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)
        self.assertNotIn(ev["verdict"], app.ACCUSING_VERDICTS)
        self.assertIn("self-contradictory", ev["reason"])


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


    def test_the_stream_is_opened_before_the_dependency_is_driven(self):
        # ping only makes traffic while serving GET /; a stream opened after that
        # can see the tail of the connection at best, nothing at worst.
        order = []

        def fake_collect(instance_id, out, stop_flag):
            order.append("observe")
            out.append(self._session_evt())

        def fake_get(url, timeout=None):
            order.append("drive")
            r = mock.Mock()
            r.json.return_value = {"honest": True, "targets": [{"target": "google.com"}]}
            return r

        with mock.patch.object(app, "_collect_observe_events", side_effect=fake_collect), \
             mock.patch.object(app.requests, "get", side_effect=fake_get):
            ev = app.probe_dependency_observe()
        self.assertEqual(order, ["observe", "drive"])
        self.assertTrue(ev["observe_armed_before_drive"])

    def test_a_stream_that_only_wakes_after_the_drive_cannot_accuse(self):
        # The first event (a session record) arrives only once the dependency was
        # already driven: the stream never showed it was watching at the time.
        driven = []

        def fake_collect(instance_id, out, stop_flag):
            while not driven:
                time.sleep(0.01)
            out.append(self._session_evt())

        def fake_get(url, timeout=None):
            driven.append(True)
            r = mock.Mock()
            r.json.return_value = {"honest": True, "targets": [{"target": "google.com"}]}
            return r

        with mock.patch.object(app, "OBSERVE_ARM_SECONDS", 0.2), \
             mock.patch.object(app, "OBSERVE_SECONDS", 2), \
             mock.patch.object(app, "_collect_observe_events", side_effect=fake_collect), \
             mock.patch.object(app.requests, "get", side_effect=fake_get):
            ev = app.probe_dependency_observe()
        self.assertTrue(ev["observe_stream_alive"])
        self.assertFalse(ev["observe_armed_before_drive"])
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)

    @staticmethod
    def _session_evt():
        evt = mock.Mock()
        evt.HasField.side_effect = lambda f: f == "session"
        evt.session.instance_id = "abc"
        evt.session.tag = "ping"
        return evt


class FundingTests(unittest.TestCase):
    """A freshly executed verifier could never run its own suite: each child asked
    for 2e8-5e8 MU out of an instance the node funds with ~14e6."""

    def setUp(self):
        FakeController.rpc_mode = "ok"
        FakeServiceInterface.launch_mode = "ok"
        del app.FUNDING_FAILURES[:]

    def tearDown(self):
        app.FUNDING.update(self_rate_mu_per_s=None, child_initial_mu={}, balance_mu=None)

    def test_children_are_funded_for_minutes_not_days(self):
        # A default node charges a 2 GB / 8 GB instance ~3950 MU/s (14.2e6 per hour).
        budgets = {label: app.child_initial_mu(label, 3950.0) for label in app.CHILD_DECLARED_RESOURCES}
        self.assertLess(max(budgets.values()), 14_000_000 // 2,
                        "the largest child must fit well inside one hour of this instance")
        self.assertEqual(max(budgets, key=budgets.get), "benchmark")
        self.assertGreater(budgets["benchmark"], budgets["tiny"])

    def test_one_suite_fits_in_the_funding_the_node_gives_a_new_instance(self):
        rate = 3950.0
        app.FUNDING["child_initial_mu"] = {}
        need = app.funding_requirement(rate)
        self.assertLess(need["required_mu"], int(rate * 3600) * 0.9)

    def test_first_builds_are_charged_when_the_node_refused_for_funds(self):
        need = app.funding_requirement(3950.0, pending_builds=4)
        self.assertEqual(need["pending_builds_mu"], 4 * app.BUILD_MU_ESTIMATE)

    def test_a_short_balance_reports_what_is_missing_and_how_to_top_up(self):
        required = app.funding_requirement(3950.0)
        app.FUNDING["balance_mu"] = 1000
        snap = app.funding_status(required)
        self.assertFalse(snap["funded"])
        self.assertEqual(snap["missing_mu"], required["required_mu"] - 1000)
        self.assertIn("nodo increase_deposit", snap["operator_hint"])

    def test_the_gate_waits_until_the_balance_covers_a_suite(self):
        # 20 MU/s measured, then the balance is short twice before a top-up lands.
        balances = iter([10 ** 6 + 20 + app.MODIFY_RESOURCES_MU_ESTIMATE, 10 ** 6,
                         1000, 1000, 10 ** 9])
        waits = []
        with mock.patch.object(app.controller, "modify_resources",
                               side_effect=lambda spec: ({}, next(balances))), \
             mock.patch.object(app.time, "monotonic", side_effect=[0.0, 1.0] + [2.0] * 20):
            funded, snap = app.ensure_funded(timeout=60, on_wait=waits.append)
        self.assertTrue(funded)
        self.assertEqual(len(waits), 2)
        self.assertTrue(all(w["missing_mu"] > 0 for w in waits))
        self.assertTrue(app.FUNDING["child_initial_mu"], "children must be sized from the rate")

    def test_a_refused_charge_is_classified_as_insufficient_funds(self):
        # Verbatim shape of the live refusal.
        exc = RuntimeError(
            "_MultiThreadedRendezvous: <_MultiThreadedRendezvous of RPC that terminated with:\n"
            "\tstatus = StatusCode.UNKNOWN\n\tdetails = \"Exception iterating responses: Unable "
            "to launch service 5de95f70. Attempt details: local: Exception: Launch service error "
            "charging 93399e98\"\n>")
        err = app.ChildLaunchError("ping", exc)
        self.assertTrue(err.insufficient_funds)
        self.assertIn("INSUFFICIENT FUNDS", str(err))
        # The node's own words survive instead of being cut at "Unable to l".
        self.assertIn("error charging", str(err))

    def test_a_starved_launch_is_recorded_for_the_suite(self):
        exc = RuntimeError('details = "Launch service error charging abc"')
        with mock.patch.object(app.heavy_service, "get_instance", side_effect=exc):
            with self.assertRaises(app.ChildLaunchError):
                app._spin_child(app.heavy_service, "heavy(64MB)")
        self.assertEqual(app.FUNDING_FAILURES, ["heavy(64MB)"])

    def test_a_starved_run_stops_launching_and_skips_the_mu_windows(self):
        # The first child the node refuses ends the spending: every later
        # gateway-dependent probe is skipped as INFRA_ERROR, naming the cause.
        exc = RuntimeError('details = "Launch service error charging abc"')
        mu = mock.Mock(side_effect=AssertionError("mu_accounting must not run"))
        preflight = {"probe": "gateway_reachability", "verdict": app.VERDICT_PASS}
        with mock.patch.object(FakeServiceInterface, "get_instance", side_effect=exc), \
             mock.patch.object(app, "probe_gateway_reachability", return_value=preflight), \
             mock.patch.object(app, "PROBES", [(n, mu if n == "mu_accounting" else f)
                                              for n, f in app.PROBES]):
            results = app._run_probe_suite()
        self.assertEqual(results["dependency_identity"]["verdict"], app.VERDICT_INFRA_ERROR)
        for name in ("network_isolation", "dependency_observe", "memory_ceiling",
                     "node_benchmark", "mu_accounting"):
            self.assertEqual(results[name].get("fault"), "insufficient_funds", name)
        self.assertEqual(results["resource_provisioning"]["verdict"], app.VERDICT_PASS)
        mu.assert_not_called()

    def test_clip_never_cuts_a_word(self):
        self.assertEqual(app.clip("alpha beta gamma", 12), "alpha beta …")
        self.assertEqual(app.clip("short", 12), "short")


class ManifestConstantsTests(unittest.TestCase):
    """app.py prices and measures against these numbers; a manifest edit that
    leaves them behind (SELF_DECLARED_MEM_BYTES said 1 GB for a 2 GB manifest)
    silently skews resource_provisioning, mu_accounting and every child budget."""

    @staticmethod
    def _resources(arch, label):
        sub = "" if label == "demo" else label
        with open(os.path.join(ROOT, arch, sub, ".service", "service.json")) as fh:
            res = json.load(fh)["resources"]
        return res["at_init"], res["at_most"]

    def test_self_constants_match_the_manifest(self):
        for arch in ("amd64", "arm64"):
            at_init, at_most = self._resources(arch, "demo")
            self.assertEqual(at_most["mem_limit"], app.SELF_DECLARED_MEM_BYTES, arch)
            self.assertEqual(at_init["disk_space"], app.SELF_DECLARED_DISK_BYTES, arch)

    def test_child_constants_match_their_manifests(self):
        for arch in ("amd64", "arm64"):
            for label, (mem, disk) in app.CHILD_DECLARED_RESOURCES.items():
                at_init, at_most = self._resources(arch, label)
                self.assertEqual((at_init["mem_limit"], at_init["disk_space"]), (mem, disk),
                                 f"{arch}/{label}")
        self.assertEqual(app.CHILD_DECLARED_RESOURCES["heavy"][0], app.HEAVY_DECLARED_MEM_BYTES)


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


class NodeBenchmarkTests(unittest.TestCase):
    """benchmark is launched like every other dependency and runs in the suite."""

    SCORES = {"architecture": app.BENCHMARK_DECLARED_ARCH, "int_ops_per_sec": 78500,
              "flt_ops_per_sec": 250000, "mem_bandwidth_bytes_per_sec": 14810232055,
              "mem_bandwidth_working_set_bytes": 1073741824,
              "sha256_hashes_per_sec": 17024, "skipped": []}

    def setUp(self):
        FakeServiceInterface.launch_mode = "ok"
        FakeController.rpc_mode = "ok"
        FakeServiceInterface.stopped = []

    def _run(self, payload, status=200):
        urls = []

        def fake_get(url, timeout=None):
            urls.append(url)
            r = mock.Mock()
            r.status_code = status
            r.json.return_value = payload
            return r
        with mock.patch.object(app.requests, "get", side_effect=fake_get):
            ev = app.probe_node_benchmark()
        return ev, urls

    def test_the_demo_packs_benchmark_as_a_dependency(self):
        # The layout itself is checked by tests/test_layout.py.
        for arch in ("arm64", "amd64"):
            with open(os.path.join(ROOT, arch, ".service", "pack_config.json")) as fh:
                self.assertEqual(json.load(fh)["dependencies"].get("BENCHMARK"), "benchmark")
        self.assertEqual(app.benchmark_service.service_hash, "benchmarkhash")

    def test_the_expected_architecture_is_this_instance_own(self):
        self.assertEqual(app.canonical_arch("x86_64"), "linux/amd64")
        self.assertEqual(app.canonical_arch("aarch64"), "linux/arm64")
        self.assertEqual(app.canonical_arch("riscv64"), "linux/riscv64")
        self.assertEqual(app.BENCHMARK_DECLARED_ARCH, app.canonical_arch(app.platform.machine()))

    def test_benchmark_is_part_of_the_suite_and_needs_the_gateway(self):
        self.assertIn("node_benchmark", dict(app.PROBES))
        self.assertIn("node_benchmark", app.GATEWAY_DEPENDENT)
        self.assertIn("probe_node_benchmark", [t["name"] for t in app.MCP_TOOLS])
        self.assertIn("benchmark", [d[0] for d in app.DEP_IDENTITY])

    def test_a_full_run_under_the_declared_architecture_passes(self):
        ev, urls = self._run(dict(self.SCORES))
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual(ev["scores"]["int_ops_per_sec"], 78500)
        self.assertTrue(urls[0].endswith("/cgi-bin/benchmark"))
        self.assertEqual(FakeServiceInterface.stopped, [LISTENING_URI])

    def test_another_architecture_is_a_substitution(self):
        other = "linux/amd64" if app.BENCHMARK_DECLARED_ARCH != "linux/amd64" else "linux/arm64"
        ev, _ = self._run(dict(self.SCORES, architecture=other))
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)

    def test_an_unmeasured_primitive_is_inconclusive(self):
        scores = dict(self.SCORES, skipped=["sha256_hashes_per_sec: sha256sum failed"])
        del scores["sha256_hashes_per_sec"]
        ev, _ = self._run(scores)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)
        self.assertIn("sha256_hashes_per_sec", ev["reason"])

    def test_a_refused_run_does_not_accuse(self):
        ev, _ = self._run({"error": "a benchmark is already running"}, status=409)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)

    def test_a_child_that_never_ran_is_infra_error(self):
        FakeServiceInterface.launch_mode = "unbound_local"
        ev, urls = self._run(dict(self.SCORES))
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)
        self.assertEqual(urls, [])

    def test_a_run_that_never_answers_is_infra_error(self):
        with mock.patch.object(app.requests, "get", side_effect=TimeoutError("read timed out")):
            ev = app.probe_node_benchmark()
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)
        self.assertEqual(FakeServiceInterface.stopped, [LISTENING_URI])

    def test_identity_is_read_from_the_cgi_whoami(self):
        # The probe visits DEP_IDENTITY in order; each child answers as itself,
        # but only on the path its own server actually serves.
        expected = iter(app.DEP_IDENTITY)

        def fake_get(url, timeout=None):
            tag, identity, path = next(expected)
            r = mock.Mock()
            r.status_code = 200
            r.json.return_value = ({"service": tag, "identity": identity}
                                   if url.endswith(path) else {})
            return r
        with mock.patch.object(app.requests, "get", side_effect=fake_get):
            ev = app.probe_dependency_identity()
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual(ev["verified_count"], 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
