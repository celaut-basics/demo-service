#!/usr/bin/env python3
"""The shared-filesystem probe: what it concludes, and what it refuses to conclude.

The probe has two halves. `granted`: the sharefs child must see what this service
wrote to the directory it exports, this service must see what the child wrote back,
and a read-only mount must refuse a write. `denied`: sharefs-denied asks for a share
this service does not export, and the node must refuse to launch it.

Two rules from the verdict taxonomy are held here, because a verdict is destined to
become a permanent public accusation:

* only an OBSERVED violation is DISHONEST. A child that launched without any mount plan
  looks the same on a node that skipped the mount as on a package that never declared
  the share, so it is INCONCLUSIVE;
* the denied half passes only on the node's own refusal of THAT share. Any other launch
  failure -- no balance, a timeout, a crash -- proves nothing, and counting it as a
  refusal would let a broken node pass.

No node and no children are needed: the fake child below reads and writes real
temporary directories, shaped like the report sharefs/src/main.rs returns.

Run with:  python3 tests/test_shared_filesystem.py
"""
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from harness import (  # noqa: E402
    ROOT, LISTENING_URI, CLOSED_URI, FakeServiceInterface, FakeController, app)

ARCHES = ("amd64", "arm64")

REFUSAL_TEMPLATE = ("Unable to launch service {sid}: cannot inherit '{path}': its parent does "
                    "not export 'demo-share-not-exported' at all (it exports demo-share, "
                    "demo-share-ro). This is a composition error.")


def refusal(path):
    return RuntimeError('details = "' + REFUSAL_TEMPLATE.format(sid="abc", path=path) + '"')


def _json(path):
    with open(path) as fh:
        return json.load(fh)


class _Response:
    def __init__(self, payload=None, text=None):
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload)
        self.status_code = 200

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class Harness(unittest.TestCase):
    """A fake node for the two children, and real directories for the two shares."""

    def setUp(self):
        FakeController.rpc_mode = "ok"
        FakeServiceInterface.launch_mode = "ok"
        FakeServiceInterface.stopped = []
        del app.FUNDING_FAILURES[:]

        self.tmp = tempfile.mkdtemp(prefix="share-probe-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.shared = os.path.join(self.tmp, "shared")
        self.shared_ro = os.path.join(self.tmp, "shared-ro")
        os.makedirs(self.shared)
        os.makedirs(self.shared_ro)
        for name, value in (("SHARE_DIR", self.shared), ("SHARE_RO_DIR", self.shared_ro),
                            ("SHARE_PROPAGATION_TIMEOUT_S", 0.2),
                            ("SHARE_PROPAGATION_POLL_S", 0.02)):
            patcher = mock.patch.object(app, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        # -- knobs for the granted child ------------------------------------
        self.granted_launch = None          # an exception to raise instead of launching
        self.granted_uri = LISTENING_URI
        self.plan_present = True
        self.plan_paths = [app.SHARE_GUEST_RW_MOUNT, app.SHARE_GUEST_RO_MOUNT]
        self.child_sees_parent = True
        self.child_write_lands = True       # does the child's write reach this side?
        self.child_write_ok = True          # does the child say it wrote?
        self.ro_shows_seed = True
        self.ro_write_succeeds = False      # what the child reports about the ro write
        self.ro_write_lands = False         # does that write reach this side?
        self.granted_answer = None          # override the whole /probe response
        self.granted_transport_error = None
        # -- knobs for the denied child -------------------------------------
        self.denied_launch = refusal(app.SHARE_DENIED_MOUNT)   # None = it launches
        self.denied_mounted = False
        self.denied_uri = LISTENING_URI
        self.denied_answer = None
        self.launched = []

        harness = self

        def get_instance(iface, max_attempts=1):
            harness.launched.append(iface.service_hash)
            if iface.service_hash == "sharefshash":
                if harness.granted_launch is not None:
                    raise harness.granted_launch
                return FakeServiceInterface_Instance(harness.granted_uri)
            if iface.service_hash == "sharefsdeniedhash":
                if harness.denied_launch is not None:
                    raise harness.denied_launch
                return FakeServiceInterface_Instance(harness.denied_uri)
            raise AssertionError(f"unexpected child {iface.service_hash}")

        def fake_get(url, params=None, timeout=None):
            if url.endswith("/probe"):
                if harness.granted_transport_error:
                    raise harness.granted_transport_error
                if harness.granted_answer is not None:
                    return harness.granted_answer
                return _Response(harness.child_report((params or {}).get("nonce")))
            if url.endswith("/plan"):
                if harness.denied_answer is not None:
                    return harness.denied_answer
                return _Response({"probe": "shared_filesystem_denied", "service": "sharefs-denied",
                                  "mounted": harness.denied_mounted})
            raise AssertionError(f"unexpected url {url}")

        for patcher in (mock.patch.object(FakeServiceInterface, "get_instance", get_instance),
                        mock.patch.object(app.requests, "get", side_effect=fake_get)):
            patcher.start()
            self.addCleanup(patcher.stop)

    # -- the sharefs child, shaped like sharefs/src/main.rs's report ---------
    def child_report(self, nonce):
        def read(path):
            try:
                with open(path) as fh:
                    return {"ok": True, "content": fh.read().strip()}
            except FileNotFoundError:
                return {"ok": False, "missing": True, "error": "NotFound", "os_error": 2}

        parent = (read(os.path.join(self.shared, app.SHARE_PARENT_NONCE_FILE))
                  if self.child_sees_parent
                  else {"ok": False, "missing": True, "error": "NotFound", "os_error": 2})
        if self.child_write_ok and self.child_write_lands:
            with open(os.path.join(self.shared, app.SHARE_CHILD_NONCE_FILE), "w") as fh:
                fh.write(nonce)
        child_write = {"ok": True} if self.child_write_ok else {
            "ok": False, "error": "PermissionDenied", "os_error": 13}
        seed = (read(os.path.join(self.shared_ro, app.SHARE_RO_SEED_FILE))
                if self.ro_shows_seed
                else {"ok": False, "missing": True, "error": "NotFound", "os_error": 2})
        if self.ro_write_lands:
            with open(os.path.join(self.shared_ro, app.SHARE_RO_ATTEMPT_FILE), "w") as fh:
                fh.write(nonce)
        attempt = ({"succeeded": True, "error": None, "os_error": None}
                   if self.ro_write_succeeds
                   else {"succeeded": False, "error": "ReadOnly", "os_error": 30})
        plan = ({"present": True, "raw": json.dumps([{"tag": "t", "path": p, "ro": False}
                                                      for p in self.plan_paths])}
                if self.plan_present else {"present": False, "raw": None})
        return {"probe": "shared_filesystem", "service": "sharefs", "mount_plan": plan,
                "shared": {"path": app.SHARE_GUEST_RW_MOUNT, "mount": None,
                           "parent_nonce": parent, "child_write": child_write},
                "readonly": {"path": app.SHARE_GUEST_RO_MOUNT, "mount": None,
                             "seed": seed, "write_attempt": attempt}}


def FakeServiceInterface_Instance(uri):
    # harness.py keeps its _Instance class private to its stub installer; an instance
    # from get_instance() only needs `uri` and a stop() that records the release.
    class _Instance:
        token = "inst-token"

        def __init__(self, u):
            self.uri = u

        def stop(self, gateway_stub):
            FakeServiceInterface.stopped.append(self.uri)
    return _Instance(uri)


class GrantedShareTests(Harness):
    def test_an_honest_node_passes_both_halves(self):
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual(ev["granted"]["status"], "ok")
        self.assertEqual(ev["denied"]["status"], "ok")
        # The granted child ran and was released; the denied one never started.
        self.assertEqual(FakeServiceInterface.stopped, [LISTENING_URI])
        self.assertEqual(self.launched, ["sharefshash", "sharefsdeniedhash"])

    def test_the_parent_writes_its_own_end_before_the_child_runs(self):
        seen = {}
        real = self.child_report

        def spy(nonce):
            with open(os.path.join(self.shared, app.SHARE_PARENT_NONCE_FILE)) as fh:
                seen["parent"] = fh.read()
            with open(os.path.join(self.shared_ro, app.SHARE_RO_SEED_FILE)) as fh:
                seen["seed"] = fh.read()
            return real(nonce)
        self.child_report = spy
        app.probe_shared_filesystem()
        self.assertTrue(seen["parent"] and seen["seed"])
        self.assertNotEqual(seen["parent"], seen["seed"])

    def test_leftovers_from_an_earlier_run_do_not_count(self):
        # A previous run's child nonce and read-only attempt are still on disk. Neither may
        # satisfy, or accuse, this run.
        with open(os.path.join(self.shared, app.SHARE_CHILD_NONCE_FILE), "w") as fh:
            fh.write("stale")
        with open(os.path.join(self.shared_ro, app.SHARE_RO_ATTEMPT_FILE), "w") as fh:
            fh.write("stale")
        self.child_write_lands = False       # this run's child write never arrives
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn("never appeared", ev["granted"]["reason"])
        self.assertFalse(ev["granted"]["evidence"]["ro_attempt_landed"],
                         "the stale attempt must have been cleared, not read as this run's")

    def test_a_child_that_cannot_see_the_parents_data_is_dishonest(self):
        self.child_sees_parent = False
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn(app.SHARE_PARENT_NONCE_FILE, ev["granted"]["reason"])

    def test_a_child_that_sees_somebody_elses_data_is_dishonest(self):
        # Readable, but not what this run wrote: not the share this service exported.
        real = self.child_report

        def other(nonce):
            data = real(nonce)
            data["shared"]["parent_nonce"] = {"ok": True, "content": "not-ours"}
            return data
        self.child_report = other
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)

    def test_a_child_write_that_never_reaches_the_parent_is_dishonest(self):
        self.child_write_lands = False
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn("never appeared", ev["granted"]["reason"])

    def test_a_read_write_share_that_refuses_the_child_is_dishonest(self):
        self.child_write_ok = False
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn("refused the child's write", ev["granted"]["reason"])

    def test_a_read_only_mount_that_hides_the_exporters_data_is_dishonest(self):
        self.ro_shows_seed = False
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn(app.SHARE_RO_SEED_FILE, ev["granted"]["reason"])

    def test_a_read_only_mount_that_accepts_a_write_is_dishonest(self):
        self.ro_write_succeeds = True
        self.ro_write_lands = True
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn("accepted a write", ev["granted"]["reason"])

    def test_the_child_reporting_a_refused_write_is_not_taken_on_its_word(self):
        # The child says the write failed, yet the file is on this side of the share.
        self.ro_write_succeeds = False
        self.ro_write_lands = True
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertTrue(ev["granted"]["evidence"]["ro_attempt_landed"])

    def test_every_failure_is_reported_not_just_the_first(self):
        self.child_sees_parent = False
        self.ro_shows_seed = False
        ev = app.probe_shared_filesystem()
        self.assertIn(app.SHARE_PARENT_NONCE_FILE, ev["granted"]["reason"])
        self.assertIn(app.SHARE_RO_SEED_FILE, ev["granted"]["reason"])


class WhatTheProbeCannotSeeTests(Harness):
    """A child with nothing mounted is the same to the probe whether the node skipped
    the mount or the package never declared it. It must not accuse."""

    def assertNotAccusing(self, ev):
        self.assertNotIn(ev["verdict"], app.ACCUSING_VERDICTS)
        self.assertNotIn(ev["verdict"], app.CONCLUSIVE_VERDICTS)

    def test_no_mount_plan_is_inconclusive_and_points_at_the_packer(self):
        self.plan_present = False
        self.child_sees_parent = False
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)
        self.assertNotAccusing(ev)
        self.assertIn("nodo#475", ev["reason"])

    def test_a_plan_missing_one_of_the_shares_is_inconclusive(self):
        self.plan_paths = [app.SHARE_GUEST_RW_MOUNT]
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)
        self.assertIn(app.SHARE_GUEST_RO_MOUNT, ev["granted"]["reason"])

    def test_the_node_refusing_the_granted_share_is_inconclusive(self):
        # This service exports it, so either the node refused a grant it owed or the packed
        # parent never exported it. From here those look the same.
        self.granted_launch = refusal(app.SHARE_GUEST_RW_MOUNT)
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["granted"]["status"], "inconclusive")
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)
        self.assertNotAccusing(ev)

    def test_a_denied_child_that_launches_with_nothing_mounted_is_inconclusive(self):
        self.denied_launch = None
        self.denied_mounted = False
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["denied"]["status"], "inconclusive")
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)
        self.assertIn("nodo#475", ev["denied"]["reason"])
        self.assertIn(LISTENING_URI, FakeServiceInterface.stopped, "it must still be released")

    def test_a_denied_child_that_launches_and_cannot_be_inspected_is_inconclusive(self):
        self.denied_launch = None
        self.denied_answer = _Response(text="<html>")
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["denied"]["status"], "inconclusive")

    def test_an_unreadable_answer_is_inconclusive_not_an_accusation(self):
        self.granted_answer = _Response(text="<html>oops</html>")
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["granted"]["status"], "inconclusive")
        self.assertNotAccusing(ev)

    def test_an_answer_that_is_not_the_childs_report_is_inconclusive(self):
        self.granted_answer = _Response({"something": "else"})
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["granted"]["status"], "inconclusive")


class NothingObservedTests(Harness):
    def test_the_parents_own_directory_being_unusable_is_infra_error(self):
        shutil.rmtree(self.shared)
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["granted"]["status"], "infra")
        self.assertNotIn("sharefshash", self.launched, "no child may run on a broken own end")

    def test_a_launch_failure_for_want_of_balance_is_infra_error_and_marks_the_run_starved(self):
        self.granted_launch = RuntimeError('details = "Launch service error charging abc"')
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["granted"]["status"], "infra")
        self.assertIn("sharefs", app.FUNDING_FAILURES)

    def test_a_child_that_never_answers_is_infra_error(self):
        self.granted_uri = CLOSED_URI
        with mock.patch.object(app, "CHILD_READY_TIMEOUT_S", 0.2):
            ev = app.probe_shared_filesystem()
        self.assertEqual(ev["granted"]["status"], "infra")
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)

    def test_a_transport_failure_is_infra_error(self):
        self.granted_transport_error = app.requests.ConnectionError("reset")
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["granted"]["status"], "infra")

    def test_the_node_being_blind_is_not_an_accusation(self):
        FakeServiceInterface.launch_mode = "unbound_local"
        self.granted_launch = UnboundLocalError("cannot access local variable 'instance'")
        self.denied_launch = UnboundLocalError("cannot access local variable 'instance'")
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)
        self.assertNotIn(ev["verdict"], app.ACCUSING_VERDICTS)

    def test_a_crashed_half_degrades_to_infra_error(self):
        with mock.patch.object(app, "_probe_granted_share", side_effect=OSError("boom")):
            ev = app.probe_shared_filesystem()
        self.assertEqual(ev["granted"]["status"], "infra")
        self.assertIn("boom", ev["granted"]["reason"])


class DeniedShareTests(Harness):
    def test_the_nodes_refusal_of_that_share_is_the_pass(self):
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["denied"]["status"], "ok")
        self.assertIn("cannot inherit", ev["denied"]["evidence"]["refusal"])

    def test_a_launch_failure_for_want_of_balance_is_not_a_refusal(self):
        # The easy way to get this wrong: any failure to launch looks like "the node said no".
        self.denied_launch = RuntimeError('details = "Launch service error charging abc"')
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["denied"]["status"], "infra")
        self.assertNotEqual(ev["verdict"], app.VERDICT_PASS)

    def test_a_refusal_of_some_other_share_is_not_this_refusal(self):
        self.denied_launch = refusal("/mnt/some-other-share")
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["denied"]["status"], "infra")
        self.assertNotEqual(ev["verdict"], app.VERDICT_PASS)

    def test_a_blind_launch_failure_is_not_a_refusal(self):
        # The client library often loses the node's text and raises only this.
        self.denied_launch = UnboundLocalError("cannot access local variable 'instance'")
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["denied"]["status"], "infra")
        self.assertNotEqual(ev["verdict"], app.VERDICT_PASS)

    def test_the_refusal_is_read_from_the_clients_last_error_too(self):
        # node_controller wraps the real error; the text may live on `last_error`.
        wrapper = RuntimeError("could not start")
        wrapper.last_error = refusal(app.SHARE_DENIED_MOUNT)
        self.denied_launch = wrapper
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["denied"]["status"], "ok")

    def test_a_denied_child_that_gets_a_share_mounted_is_dishonest(self):
        self.denied_launch = None
        self.denied_mounted = True
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["denied"]["status"], "dishonest")
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn("never exported", ev["reason"])
        self.assertIn(LISTENING_URI, FakeServiceInterface.stopped, "it must still be released")

    def test_the_denied_child_is_not_waited_for_when_the_node_refuses_it(self):
        # An honest node never starts it; the probe must not sit out a readiness timeout.
        with mock.patch.object(app, "_wait_until_ready",
                               side_effect=AssertionError("must not wait for a refused child")):
            ev = app.probe_shared_filesystem()
        self.assertEqual(ev["denied"]["status"], "ok")


class CombinedVerdictTests(Harness):
    def test_an_observed_violation_outranks_a_half_that_could_not_observe(self):
        self.granted_launch = RuntimeError('details = "Launch service error charging abc"')
        self.denied_launch = None
        self.denied_mounted = True
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["granted"]["status"], "infra")
        self.assertEqual(ev["denied"]["status"], "dishonest")
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)

    def test_infra_outranks_inconclusive(self):
        self.plan_present = False                                  # granted: inconclusive
        self.denied_launch = RuntimeError('details = "error charging"')   # denied: infra
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)

    def test_both_halves_must_be_ok_to_pass(self):
        self.denied_launch = RuntimeError('details = "error charging"')
        ev = app.probe_shared_filesystem()
        self.assertEqual(ev["granted"]["status"], "ok")
        self.assertNotEqual(ev["verdict"], app.VERDICT_PASS)

    def test_the_verdict_is_attestable_only_when_conclusive(self):
        self.plan_present = False
        ev = app.probe_shared_filesystem()
        self.assertNotIn(ev["verdict"], app.CONCLUSIVE_VERDICTS)


class WiringTests(unittest.TestCase):
    def test_the_probe_is_in_the_suite_and_needs_the_gateway(self):
        self.assertIn("shared_filesystem", dict(app.PROBES))
        self.assertIn("shared_filesystem", app.GATEWAY_DEPENDENT)

    def test_it_runs_before_the_long_mu_windows(self):
        names = [n for n, _ in app.PROBES]
        self.assertLess(names.index("shared_filesystem"), names.index("mu_accounting"))

    def test_it_is_reachable_over_http_and_mcp(self):
        self.assertIn("probe_shared_filesystem", [t["name"] for t in app.MCP_TOOLS])
        self.assertIn("/probe/shared_filesystem", app.ROUTE_MCP_TOOLS)
        self.assertEqual(app.ROUTE_MCP_TOOLS["/probe/shared_filesystem"], ("probe_shared_filesystem",))

    def test_the_granted_child_is_identity_checked_and_the_denied_one_is_not(self):
        tags = [d[0] for d in app.DEP_IDENTITY]
        self.assertIn("sharefs", tags)
        self.assertNotIn("sharefs_denied", tags)
        self.assertNotIn("sharefs-denied", tags)

    def test_the_denied_child_does_not_make_a_starved_run_wait_for_a_build_it_will_never_do(self):
        self.assertIn("sharefs", app.CHILD_DECLARED_RESOURCES)
        self.assertNotIn("sharefs_denied", app.CHILD_DECLARED_RESOURCES)
        self.assertNotIn("sharefs-denied", app.CHILD_DECLARED_RESOURCES)

    def test_both_children_are_registered_with_their_own_hashes(self):
        self.assertEqual(app.child_iface("sharefs").service_hash, "sharefshash")
        self.assertEqual(app.child_iface("sharefs_denied").service_hash, "sharefsdeniedhash")

    def test_the_verifier_version_moved(self):
        self.assertEqual(app.VERIFIER_VERSION, "1.4.0")


class ManifestAgreementTests(unittest.TestCase):
    """The declarations in the manifests, the constants in app.py and the paths in the Rust
    sources are three copies of the same names. A mismatch only shows up on a node, as a
    child that mounts nothing -- which the probe then has to call INCONCLUSIVE."""

    @staticmethod
    def shares(arch, service):
        sub = "" if service == "demo" else service
        return _json(os.path.join(ROOT, arch, sub, ".service", "service.json")).get(
            "shared_filesystems", [])

    def test_every_architecture_declares_the_same_shares(self):
        for service in ("demo", "sharefs", "sharefs-denied"):
            self.assertEqual(self.shares("amd64", service), self.shares("arm64", service), service)

    def test_the_parent_exports_what_the_granted_child_inherits(self):
        for arch in ARCHES:
            exported = {s["tag"]: s for s in self.shares(arch, "demo") if s["role"] == "shared"}
            inherited = [s for s in self.shares(arch, "sharefs") if s["role"] == "guest"]
            self.assertEqual({s["tag"] for s in inherited}, set(exported), arch)
            self.assertEqual(len(inherited), 2, arch)
            self.assertEqual(exported["demo-share"]["path"], app.SHARE_DIR, arch)
            self.assertEqual(exported["demo-share-ro"]["path"], app.SHARE_RO_DIR, arch)
            by_tag = {s["tag"]: s for s in inherited}
            self.assertEqual(by_tag["demo-share"]["path"], app.SHARE_GUEST_RW_MOUNT, arch)
            self.assertEqual(by_tag["demo-share"]["access"], "rw", arch)
            self.assertEqual(by_tag["demo-share-ro"]["path"], app.SHARE_GUEST_RO_MOUNT, arch)
            self.assertEqual(by_tag["demo-share-ro"]["access"], "ro", arch)

    def test_the_guest_mounts_differ_from_the_parents_paths(self):
        # What matches the two ends is the tag; sharing the path would prove nothing.
        for arch in ARCHES:
            parent = {s["path"] for s in self.shares(arch, "demo")}
            child = {s["path"] for s in self.shares(arch, "sharefs")}
            self.assertFalse(parent & child, arch)

    def test_the_denied_child_asks_for_a_tag_the_parent_does_not_export(self):
        for arch in ARCHES:
            exported = {s["tag"] for s in self.shares(arch, "demo") if s["role"] == "shared"}
            asked = self.shares(arch, "sharefs-denied")
            self.assertEqual(len(asked), 1, arch)
            self.assertEqual(asked[0]["role"], "guest", arch)
            self.assertNotIn(asked[0]["tag"], exported, arch)
            self.assertEqual(asked[0]["path"], app.SHARE_DENIED_MOUNT, arch)

    def test_the_denied_child_declares_the_resources_app_py_assumes(self):
        for arch in ARCHES:
            res = _json(os.path.join(ROOT, arch, "sharefs-denied", ".service", "service.json"))["resources"]
            self.assertEqual((res["at_init"]["mem_limit"], res["at_init"]["disk_space"]),
                             app.SHARE_DENIED_DECLARED_RESOURCES, arch)

    def test_the_rust_sources_use_the_manifest_paths(self):
        def consts(path):
            with open(os.path.join(ROOT, path, "src", "main.rs")) as fh:
                return dict(re.findall(r'^const (\w+): &str = "([^"]*)";', fh.read(), re.M))
        granted = consts("sharefs")
        self.assertEqual(granted["SHARED_MOUNT"], app.SHARE_GUEST_RW_MOUNT)
        self.assertEqual(granted["READONLY_MOUNT"], app.SHARE_GUEST_RO_MOUNT)
        self.assertEqual(granted["PARENT_NONCE_FILE"], app.SHARE_PARENT_NONCE_FILE)
        self.assertEqual(granted["READONLY_SEED_FILE"], app.SHARE_RO_SEED_FILE)
        self.assertEqual(granted["CHILD_NONCE_FILE"], app.SHARE_CHILD_NONCE_FILE)
        self.assertEqual(granted["READONLY_ATTEMPT_FILE"], app.SHARE_RO_ATTEMPT_FILE)
        self.assertEqual(consts("sharefs-denied")["DENIED_MOUNT"], app.SHARE_DENIED_MOUNT)

    def test_the_images_contain_every_directory_a_share_is_declared_on(self):
        # The packer marks a directory that already exists; it does not create it.
        for arch in ARCHES:
            for service in ("demo", "sharefs", "sharefs-denied"):
                sub = "" if service == "demo" else service
                with open(os.path.join(ROOT, arch, sub, ".service", "Dockerfile")) as fh:
                    mkdirs = " ".join(line for line in fh if "mkdir" in line)
                for share in self.shares(arch, service):
                    self.assertIn(share["path"], mkdirs, f"{arch}/{service}: {share['path']}")

    def test_no_directory_is_declared_both_ways_or_twice(self):
        for arch in ARCHES:
            for service in ("demo", "sharefs", "sharefs-denied"):
                shares = self.shares(arch, service)
                self.assertEqual(len({s["path"] for s in shares}), len(shares), f"{arch}/{service}")
                self.assertEqual(len({s["tag"] for s in shares}), len(shares), f"{arch}/{service}")
                self.assertTrue(all(s["role"] in ("shared", "guest") for s in shares))

    def test_the_parent_never_inherits(self):
        # A share declared inside another is the re-export the invariant forbids.
        for arch in ARCHES:
            self.assertTrue(all(s["role"] == "shared" for s in self.shares(arch, "demo")), arch)


if __name__ == "__main__":
    unittest.main(verbosity=2)
