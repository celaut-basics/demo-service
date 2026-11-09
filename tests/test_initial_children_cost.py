#!/usr/bin/env python3
"""initial_children_cost (nodo #538): the probe, the manifests and tools/pack/stamp.py.

Since nodo#635 at 8fcaf618 the quote has no separate field for the initial children:
EstimatedCost.cost holds their starts. The probe is driven against a fake node that keeps
the #538 rule, and against ones that break it. A node that keeps the rule passes, a node
seen keeping MU of a refused start is DISHONEST, and a figure that is only off (or a node
whose cost holds no children) is INCONCLUSIVE, never an accusation.

Run with:  python3 tests/test_initial_children_cost.py
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from harness import LISTENING_URI, app  # noqa: E402
from test_new_benchmarks import FakeAccount, amount, movement, refusal, run_with  # noqa: E402

gw = app.gw
TINY_RESOURCES = {"mem_limit": 50000000, "disk_space": 200000000}


class FakeNode538:
    """A node with #538: the cost of a parent holds the starts of its initial children,
    and it refuses a parent whose initial_mu cannot pay them and one period."""

    def __init__(self, *, build_f=10_000_000, balance_f=180_000, tiny_start=180_000,
                 period=500, predates=False, start_underfunded=False, keep_refused=False,
                 refuse_funded=False, child_starts=1, child_rc="0", charged=None,
                 children_in_cost=None):
        self.build_f, self.balance_f = build_f, balance_f
        self.tiny_start, self.period = tiny_start, period
        self.predates = predates
        self.start_underfunded = start_underfunded
        self.keep_refused = keep_refused
        self.refuse_funded = refuse_funded
        self.child_starts, self.child_rc = child_starts, child_rc
        self.charged = tiny_start if charged is None else charged
        if children_in_cost is None:
            children_in_cost = 0 if predates else tiny_start
        self.children_in_cost = children_in_cost
        self.account = FakeAccount()
        self.children = {}
        self.stopped = []

    def quote(self, node_url, packed, config=None, **kw):
        asked = config["initial_mu"] if config else None
        if packed == "tiny":
            cost = self.tiny_start if asked is None else asked
        else:
            cost = (self.build_f + (self.balance_f if asked is None else asked)
                    + self.children_in_cost)
        return SimpleNamespace(cost=amount(cost), max_maintenance_cost=amount(self.period),
                               init_maintenance_cost=amount(self.period),
                               maintenance_seconds_loop=10)

    least_children = None  # the children as the check prices them; None: as quoted

    @property
    def least(self):
        children = self.tiny_start if self.least_children is None else self.least_children
        return self.build_f + (0 if self.predates else children) + self.period

    def start(self, label, *, initial_mu, start_ref=None, **kw):
        detail = {"start_ref": start_ref.hex()} if start_ref else None
        funded = initial_mu >= self.least
        if (not funded and not self.start_underfunded) or (funded and self.refuse_funded):
            if self.keep_refused:
                self.account.move("child_start", -initial_mu, detail)
            children = "" if self.predates else (
                f"The initial children of the service cost {self.tiny_start} MU and one ")
            raise refusal(
                f"Unable to launch service x: initial_mu {initial_mu} MU leaves "
                f"{initial_mu - self.build_f} MU after the build of {self.build_f} MU. "
                f"{children or 'One '}maintenance period costs {self.period} MU. "
                f"The least initial_mu is {self.least} MU.")
        start = self.account.move("child_start", -initial_mu, detail)
        token = f"family{len(self.children)}"
        rows = [movement(1, "start", initial_mu, initial_mu),
                movement(2, "build", -self.build_f, initial_mu - self.build_f)]
        balance = initial_mu - self.build_f
        for i in range(self.child_starts):
            balance -= self.charged
            rows.append(movement(len(rows) + 1, "child_start", -self.charged, balance))
            rows.append(movement(len(rows) + 1, "child_bound", 0, balance,
                                 {"starts_seq": str(len(rows)), "service_id": app.TINY_SERVICE}))
        self.children[token] = rows
        del start
        return SimpleNamespace(instance=SimpleNamespace(token=token), uri=LISTENING_URI)

    def patches(self):
        status = {"state": "done", "rc": self.child_rc, "attempts": "1"}
        return [mock.patch.object(gw, "estimated_cost",
                                  side_effect=lambda url, packed, **kw: self.quote(url, packed, **kw)),
                mock.patch.object(app, "packed", side_effect=lambda label: label),
                mock.patch.object(gw, "configuration", side_effect=lambda **kw: kw),
                mock.patch.object(gw, "config_initial_mu", return_value=123),
                mock.patch.object(app, "_gw_start", side_effect=self.start),
                mock.patch.object(app, "_gw_stop", side_effect=lambda t, l: self.stopped.append(t)),
                mock.patch.object(app, "_own_head", side_effect=self.account.head),
                mock.patch.object(app, "_own_rows_after", side_effect=self.account.after),
                mock.patch.object(app, "_child_rows", side_effect=lambda t: self.children[t]),
                mock.patch.object(app, "_family_wait", return_value=status),
                mock.patch.object(app, "_family_stop_child", return_value='{"refund_mu": 1}'),
                mock.patch.object(app, "_wait_until_ready", return_value=None),
                mock.patch.object(app, "FAMILY_SETTLE_S", 0)]


class InitialChildrenCostProbeTests(unittest.TestCase):
    def setUp(self):
        del app.FUNDING_FAILURES[:]

    def test_a_node_that_keeps_the_rule_passes(self):
        node = FakeNode538()
        ev = run_with(node, app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        # The cost of family holds the start of tiny: no separate field.
        self.assertEqual(ev["quote"]["children_in_cost_mu"], 180_000)
        self.assertEqual(ev["quote"]["cost_mu"], 10_000_000 + 180_000 + 180_000)
        self.assertEqual(ev["underfunded"]["outcome"], "refused")
        # The build and one period, without the children: below the least.
        self.assertEqual(ev["underfunded"]["initial_mu"], 10_000_000 + 500)
        self.assertEqual(ev["underfunded"]["named_least_mu"], node.least)
        self.assertEqual(ev["underfunded"]["net_charge_mu"], 0)
        self.assertEqual(ev["funded"]["child_start_mu"], 180_000)
        # The client formula: cost + maintenance * (periods + 1), nothing for the children.
        self.assertEqual(ev["funded"]["initial_mu"],
                         10_360_000 + 500 * (app.CHILDREN_COST_PERIODS + 1))
        self.assertEqual(ev["own_initial_mu"], 123)
        self.assertEqual(sorted(node.stopped), ["family0"])

    def test_a_node_that_keeps_mu_of_a_refused_start_is_dishonest(self):
        ev = run_with(FakeNode538(keep_refused=True), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST, ev["reason"])

    def test_a_node_whose_cost_holds_no_children_is_reported(self):
        ev = run_with(FakeNode538(predates=True), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])
        self.assertIn("predates nodo #538", ev["reason"])

    def test_a_free_node_is_not_applicable(self):
        node = FakeNode538(build_f=0, balance_f=0, tiny_start=0, period=0)
        ev = run_with(node, app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_NOT_APPLICABLE, ev["reason"])

    def test_an_underfunded_parent_that_starts_is_not_an_accusation(self):
        # ON_UNDERFUNDED=warn is the operator's choice.
        node = FakeNode538(start_underfunded=True)
        ev = run_with(node, app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])
        self.assertIn("ON_UNDERFUNDED", ev["reason"])
        self.assertEqual(len(node.stopped), 2)

    def test_a_quote_at_a_higher_load_than_the_check_is_not_under_funded(self):
        # Seen on n538e: the node's least prices the children at its base load, so the
        # quote of family for a short balance passed. The probe's under-funded amount
        # leaves the children out, which no honest node starts.
        node = FakeNode538(tiny_start=180_000)
        node.least_children = 120_000  # the base-load figure of the check
        ev = run_with(node, app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertLess(ev["underfunded"]["initial_mu"], node.least)

    def test_a_refused_start_funded_by_the_quote_is_reported(self):
        ev = run_with(FakeNode538(refuse_funded=True), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])
        self.assertIn("funded with the cost of its quote", ev["reason"])

    def test_a_retry_of_the_child_is_reported(self):
        ev = run_with(FakeNode538(child_starts=2), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])
        self.assertIn("retry", ev["reason"])

    def test_a_child_that_could_not_start_is_reported(self):
        ev = run_with(FakeNode538(child_starts=0, child_rc="1"), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])
        self.assertIn("one attempt", ev["reason"])

    def test_a_charge_that_the_cost_does_not_cover_is_reported(self):
        ev = run_with(FakeNode538(charged=400_000), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])
        self.assertIn("held 180000 MU", ev["reason"])

    def test_a_charge_priced_at_a_later_load_passes(self):
        # Seen on nodo #635: the start of the child cost 34 % more than the quote.
        ev = run_with(FakeNode538(charged=241_200), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual(ev["funded"]["child_start_vs_quote"], 0.34)

    def test_a_charge_below_the_quote_passes(self):
        ev = run_with(FakeNode538(charged=165_600), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual(ev["funded"]["child_start_vs_quote"], -0.08)

    def test_a_cost_that_does_not_hold_the_start_of_the_child_is_reported(self):
        ev = run_with(FakeNode538(children_in_cost=1), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])

    def test_the_probe_runs_in_the_suite(self):
        self.assertIn("initial_children_cost", dict(app.PROBES))
        self.assertIn("initial_children_cost", app.GATEWAY_DEPENDENT)
        self.assertNotIn("children_initial_cost", dict(app.PROBES))


class ChildFundingTests(unittest.TestCase):
    """A child's runtime is the node's default balance for it."""

    def tearDown(self):
        app.FUNDING["default_balance_mu"].clear()
        app.FUNDING["build_quote_mu"].clear()

    def test_the_default_balance_of_the_node_funds_the_child(self):
        def quote(url, packed, config=None, **kw):
            asked = config["initial_mu"] if config else 70_000
            return SimpleNamespace(cost=amount(10_000_000 + asked),
                                   max_maintenance_cost=amount(1), init_maintenance_cost=amount(1),
                                   maintenance_seconds_loop=10)
        with mock.patch.object(gw, "estimated_cost", side_effect=quote), \
                mock.patch.object(app, "packed", side_effect=lambda label: label), \
                mock.patch.object(gw, "configuration", side_effect=lambda **kw: kw):
            app.quote_child_builds()
        self.assertEqual(app.FUNDING["build_quote_mu"]["tiny"], 10_000_000)
        self.assertEqual(app.FUNDING["default_balance_mu"]["tiny"], 70_000)
        self.assertEqual(app.child_runtime_mu("tiny", 1000.0), 70_000)
        self.assertEqual(app.child_initial_mu("tiny", 1000.0), 10_070_000)

    def test_a_node_that_gives_no_default_balance_keeps_the_measured_rate(self):
        def quote(url, packed, config=None, **kw):
            # A default start that gives the child nothing above its build.
            asked = config["initial_mu"] if config else 0
            return SimpleNamespace(cost=amount(10_000_000 + asked), max_maintenance_cost=amount(1),
                                   init_maintenance_cost=amount(1), maintenance_seconds_loop=10)
        with mock.patch.object(gw, "estimated_cost", side_effect=quote), \
                mock.patch.object(app, "packed", side_effect=lambda label: label), \
                mock.patch.object(gw, "configuration", side_effect=lambda **kw: kw):
            app.quote_child_builds()
        self.assertFalse(any(app.FUNDING["default_balance_mu"].values()))
        self.assertEqual(app.child_runtime_mu("tiny", 1000.0),
                         max(app.CHILD_MIN_INITIAL_MU, int(
                             1000.0 * app.price_weight(*app.CHILD_DECLARED_RESOURCES["tiny"])
                             / app.price_weight(app.mem_limit or app.SELF_DECLARED_MEM_BYTES,
                                                app.SELF_DECLARED_DISK_BYTES)
                             * app.CHILD_FUNDED_SECONDS * app.CHILD_BUDGET_MARGIN)))


def _json(path):
    with open(path) as fh:
        return json.load(fh)


def _workloads(field):
    for clause in field:
        for group in clause["any_of"]:
            yield group["workloads"]


class ManifestTests(unittest.TestCase):
    def test_the_verifier_declares_each_child_of_its_suite_as_initial(self):
        expected = [app.CHILD_DECLARED_RESOURCES[label] for label in
                    ("tiny", "heavy", "ping", "benchmark", "sharefs", "netshare")]
        for arch in ("amd64", "arm64"):
            manifest = _json(os.path.join(ROOT, arch, ".service", "service.json"))
            initial = manifest["initial_environment_workload"]
            self.assertEqual(len(initial), len(expected), arch)
            for workloads, (mem, disk) in zip(_workloads(initial), expected):
                self.assertEqual(len(workloads), 1, arch)
                res = workloads[0]["dependency"]["service"]["container"]["resources"]
                self.assertEqual(res["at_init"], {"mem_limit": mem, "disk_space": disk}, arch)
                self.assertEqual(res["at_most"], res["at_init"], arch)
            counts = [w[0]["count"] for w in _workloads(initial)]
            self.assertEqual(counts, [1, 1, 1, 1, 1, app.NETSHARE_MEMBERS], arch)

    def test_no_workload_has_the_old_resources_field(self):
        # #538 removed Workload.resources; the packer refuses it.
        for arch in ("amd64", "arm64"):
            for root in (arch, os.path.join("family", arch)):
                manifest = _json(os.path.join(ROOT, root, ".service", "service.json"))
                for field in ("initial_environment_workload", "possible_environment_workload"):
                    for workloads in _workloads(manifest.get(field, [])):
                        for w in workloads:
                            self.assertEqual(set(w), {"count", "dependency"}, root)
                            arch_tags = w["dependency"]["service"]["container"]["architecture"]["tags"]
                            self.assertEqual(arch_tags, [f"linux/{arch}"], root)

    def test_family_declares_the_tiny_that_it_starts(self):
        for arch in ("amd64", "arm64"):
            manifest = _json(os.path.join(ROOT, "family", arch, ".service", "service.json"))
            (workloads,) = list(_workloads(manifest["initial_environment_workload"]))
            self.assertEqual(workloads[0]["count"], 1)
            res = workloads[0]["dependency"]["service"]["container"]["resources"]
            tiny = _json(os.path.join(ROOT, "tiny", arch, ".service", "service.json"))["resources"]
            self.assertEqual(res, tiny)
            pack_config = _json(os.path.join(ROOT, "family", arch, ".service", "pack_config.json"))
            self.assertEqual(pack_config["dependencies"], {"TINY": "tiny"})


class StampTests(unittest.TestCase):
    def test_stamp_names_every_workload_and_dependency_by_id(self):
        names = ["TINY", "HEAVY", "PING", "BENCHMARK", "SHAREFS", "SHAREFS_DENIED", "NETSHARE",
                 "FAMILY"]
        ids = {name: f"{i:064x}" for i, name in enumerate(names, 1)}
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "verifier")
            subprocess.run([sys.executable, os.path.join(ROOT, "tools", "pack", "stamp.py"),
                            os.path.join(ROOT, "amd64"), "verifier", out,
                            *[f"{k}={v}" for k, v in ids.items()]],
                           check=True, capture_output=True)
            pack_config = _json(os.path.join(out, ".service", "pack_config.json"))
            self.assertEqual(pack_config["dependencies"], ids)
            for name in names:
                self.assertFalse(os.path.exists(os.path.join(out, name.lower().replace("_", "-"))))
            manifest = _json(os.path.join(out, ".service", "service.json"))
            initial = [w[0]["dependency"]["hash"] for w in
                       _workloads(manifest["initial_environment_workload"])]
            self.assertEqual(initial, [[ids[n]] for n in
                                       ("TINY", "HEAVY", "PING", "BENCHMARK", "SHAREFS", "NETSHARE")])
            possible = [[w["dependency"]["hash"] for w in ws] for ws in
                        _workloads(manifest["possible_environment_workload"])]
            self.assertEqual(possible, [[[ids["FAMILY"]], [ids["TINY"]]], [[ids["SHAREFS_DENIED"]]]])
            self.assertTrue(os.path.isfile(os.path.join(out, "app.py")))


if __name__ == "__main__":
    unittest.main()
