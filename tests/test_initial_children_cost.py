#!/usr/bin/env python3
"""initial_children_cost (nodo #538, #636): the probe, the manifests and tools/pack/stamp.py.

Since nodo #636 EstimatedCost.cost is what the start spends: the build, and the builds of
the initial children, with no balance. Each child gets its balance in its own start. The
probe is driven against a fake node that keeps the #538 rule with the #636 cost, and
against ones that break it. A node that keeps the rule passes, a node seen keeping MU of a
refused start is DISHONEST, and a figure that is only off (or a node whose cost still holds
a balance) is INCONCLUSIVE, never an accusation.

Run with:  python3 tests/test_initial_children_cost.py
"""
import json
import math
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
PERIOD, LOOP, V, T = 500, 10, 0.10, 86400
ONE = math.ceil(PERIOD * 1.1)          # the funding sum of one period: 550


def quote_of(cost, period=PERIOD, bounded=True):
    return SimpleNamespace(cost=amount(cost), max_maintenance_cost=amount(period),
                           init_maintenance_cost=amount(period), maintenance_seconds_loop=LOOP,
                           price_bounded=bounded, price_volatility=V if bounded else 0.0,
                           volatility_period_seconds=T if bounded else 0)


class FakeNode636:
    """A node with #538 and #636: the cost of a parent holds the builds of its initial
    children and no balance, and it refuses a parent whose initial_mu cannot pay those
    builds and one period. A child started with no initial_mu gets the default of the
    node: its cost + the sum of 360 periods."""

    def __init__(self, *, build_f=10_000_000, build_t=10_000_000, period=PERIOD,
                 predates=False, start_underfunded=False, keep_refused=False,
                 refuse_funded=False, child_starts=1, child_rc="0", charged=None,
                 children_in_cost=None):
        self.build_f, self.build_t, self.period = build_f, build_t, period
        self.predates = predates
        self.start_underfunded = start_underfunded
        self.keep_refused = keep_refused
        self.refuse_funded = refuse_funded
        self.child_starts, self.child_rc = child_starts, child_rc
        self.one = math.ceil(period * 1.1) if period else 0
        self.tiny_default = build_t + 360 * self.one
        self.charged = self.tiny_default if charged is None else charged
        if children_in_cost is None:
            # Before #636 the cost held a balance for the parent and the children.
            children_in_cost = build_t + (500_000 if predates else 0)
        self.children_in_cost = children_in_cost
        self.account = FakeAccount()
        self.children = {}
        self.stopped = []
        self.asked = []

    def quote(self, node_url, packed, config=None, **kw):
        self.asked.append(config)
        if packed == "tiny":
            return quote_of(self.build_t, self.period)
        return quote_of(self.build_f + self.children_in_cost, self.period)

    @property
    def least(self):
        return self.build_f + self.build_t + self.one

    def start(self, label, *, initial_mu, start_ref=None, **kw):
        detail = {"start_ref": start_ref.hex()} if start_ref else None
        funded = initial_mu >= self.least
        if (not funded and not self.start_underfunded) or (funded and self.refuse_funded):
            if self.keep_refused:
                self.account.move("child_start", -initial_mu, detail)
            raise refusal(
                f"Unable to launch service x: initial_mu {initial_mu} MU leaves "
                f"{initial_mu - self.build_f} MU after the build of {self.build_f} MU. "
                f"The builds of the initial children cost {self.build_t} MU and one "
                f"maintenance period costs {self.one} MU. "
                f"The least initial_mu is {self.least} MU.")
        self.account.move("child_start", -initial_mu, detail)
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


class FundingSumTests(unittest.TestCase):
    """gw.funding_sum_mu: the formula of EstimatedCost.cost in celaut.proto (#636)."""

    def test_each_period_uses_its_k(self):
        # Periods of 6 h with T = 24 h: k(i) = floor(i * 6 / 24) + 1, so the tick that
        # ends at hour 24 is already in the second period.
        q = SimpleNamespace(init_maintenance_cost=amount(1000), maintenance_seconds_loop=6 * 3600,
                            price_bounded=True, price_volatility=0.1, volatility_period_seconds=86400)
        self.assertEqual(gw.funding_sum_mu(q, 3), 3 * 1100)
        self.assertEqual(gw.funding_sum_mu(q, 4), 3 * 1100 + 1210)

    def test_one_period_for_the_whole_life_and_no_bound(self):
        self.assertEqual(gw.funding_sum_mu(quote_of(0), 7), 7 * ONE)
        q = quote_of(0)
        q.volatility_period_seconds = 0
        self.assertEqual(gw.funding_sum_mu(q, 7), 7 * ONE)
        self.assertEqual(gw.funding_sum_mu(quote_of(0, bounded=False), 7), 7 * PERIOD)

    def test_a_float32_volatility_is_read_as_written(self):
        # 0.1 arrives as 0.10000000149011612.
        q = quote_of(0)
        q.price_volatility = 0.10000000149011612
        self.assertEqual(gw.funding_sum_mu(q, 360), 360 * ONE)

    def test_a_bad_volatility_is_read_as_zero(self):
        for bad in (float("nan"), float("inf"), -0.5):
            q = quote_of(0)
            q.price_volatility = bad
            self.assertEqual(gw.funding_sum_mu(q, 2), 2 * PERIOD)


class InitialChildrenCostProbeTests(unittest.TestCase):
    def setUp(self):
        del app.FUNDING_FAILURES[:]

    def test_a_node_that_keeps_the_rule_passes(self):
        node = FakeNode636()
        ev = run_with(node, app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        # The cost of family holds the build of tiny, and no balance.
        self.assertEqual(ev["quote"]["children_in_cost_mu"], 10_000_000)
        self.assertEqual(ev["quote"]["cost_mu"], 20_000_000)
        self.assertEqual(ev["quote"]["one_period_sum_mu"], ONE)
        self.assertEqual(ev["underfunded"]["outcome"], "refused")
        # The build of family and one period, without the build of tiny.
        self.assertEqual(ev["underfunded"]["initial_mu"], 10_000_000 + ONE)
        self.assertEqual(ev["underfunded"]["named_least_mu"], node.least)
        self.assertEqual(ev["underfunded"]["net_charge_mu"], 0)
        # The client formula: cost + the sum of N periods + a default start of tiny.
        self.assertEqual(ev["tiny_default_start_mu"], 10_000_000 + 360 * ONE)
        # family carries the default start of tiny with the headroom of the judge.
        self.assertEqual(ev["funded"]["initial_mu"], 20_000_000 + app.CHILDREN_COST_PERIODS * ONE
                         + math.ceil((10_000_000 + 360 * ONE) * (1 + app.CHILDREN_CHARGE_TOLERANCE)))
        self.assertEqual(ev["funded"]["child_start_mu"], node.tiny_default)
        self.assertEqual(ev["own_initial_mu"], 123)
        self.assertEqual(sorted(node.stopped), ["family0"])
        # The quotes ask for no balance: initial_mu does not change a quote.
        self.assertEqual(node.asked, [None, None])

    def test_a_built_tiny_has_no_build_to_check(self):
        node = FakeNode636(build_t=0)
        ev = run_with(node, app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual(ev["underfunded"]["outcome"], "not_attempted")
        self.assertIn("tiny is built here", ev["reason"])
        self.assertEqual(ev["quote"]["children_in_cost_mu"], 0)

    def test_a_node_that_keeps_mu_of_a_refused_start_is_dishonest(self):
        ev = run_with(FakeNode636(keep_refused=True), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST, ev["reason"])

    def test_a_node_whose_cost_holds_a_balance_is_reported(self):
        ev = run_with(FakeNode636(predates=True), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])
        self.assertIn("predates nodo #636", ev["reason"])

    def test_a_free_node_is_not_applicable(self):
        node = FakeNode636(build_f=0, build_t=0, period=0)
        ev = run_with(node, app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_NOT_APPLICABLE, ev["reason"])

    def test_an_underfunded_parent_that_starts_is_not_an_accusation(self):
        # ON_UNDERFUNDED=warn is the operator's choice.
        node = FakeNode636(start_underfunded=True)
        ev = run_with(node, app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])
        self.assertIn("ON_UNDERFUNDED", ev["reason"])
        self.assertEqual(len(node.stopped), 2)

    def test_a_refused_start_funded_by_the_quote_is_reported(self):
        ev = run_with(FakeNode636(refuse_funded=True), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])
        self.assertIn("funded with the cost of its quote", ev["reason"])

    def test_a_retry_of_the_child_is_reported(self):
        ev = run_with(FakeNode636(child_starts=2), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])
        self.assertIn("retry", ev["reason"])

    def test_a_child_that_could_not_start_is_reported(self):
        ev = run_with(FakeNode636(child_starts=0, child_rc="1"), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])
        self.assertIn("one attempt", ev["reason"])

    def test_a_charge_far_above_the_default_start_is_reported(self):
        node = FakeNode636()
        node.charged = node.tiny_default * 3
        ev = run_with(node, app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])
        self.assertIn("a default start of tiny was quoted", ev["reason"])

    def test_a_charge_priced_at_a_later_load_passes(self):
        node = FakeNode636()
        node.charged = round(node.tiny_default * 1.34)
        ev = run_with(node, app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual(ev["funded"]["child_start_vs_quote"], 0.34)

    def test_a_cost_that_does_not_hold_the_build_of_the_child_is_reported(self):
        ev = run_with(FakeNode636(children_in_cost=1), app.probe_initial_children_cost)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE, ev["reason"])

    def test_the_probe_runs_in_the_suite(self):
        self.assertIn("initial_children_cost", dict(app.PROBES))
        self.assertIn("initial_children_cost", app.GATEWAY_DEPENDENT)
        self.assertNotIn("children_initial_cost", dict(app.PROBES))


class ChildFundingTests(unittest.TestCase):
    """A child's runtime is the funding sum of its quote for the periods the verifier chooses."""

    def tearDown(self):
        app.FUNDING["runtime_quote_mu"].clear()
        app.FUNDING["build_quote_mu"].clear()

    def _quote_children(self, quote):
        asked = []

        def estimated_cost(url, packed, config=None, **kw):
            asked.append(config)
            return quote
        with mock.patch.object(gw, "estimated_cost", side_effect=estimated_cost), \
                mock.patch.object(app, "packed", side_effect=lambda label: label), \
                mock.patch.object(gw, "configuration", side_effect=lambda **kw: kw):
            app.quote_child_builds()
        return asked

    def test_the_funding_sum_of_the_quote_funds_the_child(self):
        asked = self._quote_children(quote_of(10_000_000))
        # The quote asks for no balance: cost is the build (#636).
        self.assertTrue(asked and all(config is None for config in asked))
        periods = app.CHILD_RUNTIME_PERIODS(LOOP)
        self.assertEqual(periods, math.ceil(app.CHILD_FUNDED_SECONDS * app.CHILD_BUDGET_MARGIN / LOOP))
        self.assertEqual(app.FUNDING["build_quote_mu"]["tiny"], 10_000_000)
        self.assertEqual(app.FUNDING["runtime_quote_mu"]["tiny"], periods * ONE)
        self.assertEqual(app.child_runtime_mu("tiny", 1000.0), periods * ONE)
        self.assertEqual(app.child_initial_mu("tiny", 1000.0), 10_000_000 + periods * ONE)

    def test_a_quote_with_no_maintenance_keeps_the_measured_rate(self):
        self._quote_children(quote_of(10_000_000, period=0))
        self.assertFalse(any(app.FUNDING["runtime_quote_mu"].values()))
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
