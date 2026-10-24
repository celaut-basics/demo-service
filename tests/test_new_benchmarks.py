#!/usr/bin/env python3
"""The benchmarks of the nodo features after v3 (#563, #578, #371, #574/#582, #570/#571,
#268, tunnels, #577/#586, #567).

Each probe is driven against a fake node that keeps the rule under test, and against
one that breaks it, and the verdicts are checked: a node that keeps the rule passes, a
node seen breaking it is DISHONEST, and a node that could not be observed is never
accused.

Run with:  python3 tests/test_new_benchmarks.py
"""
import json
import os
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from harness import LISTENING_URI, FakeController, FakeServiceInterface, app  # noqa: E402

gw = app.gw


def amount(n):
    return SimpleNamespace(n=str(int(n)))


def movement(seq, kind, amt, balance, detail=None, ref=""):
    return SimpleNamespace(
        seq=seq, ts=1000 + seq, amount=amount(amt), balance_after=amount(balance), kind=kind,
        instance_ref=ref, prev_hash="",
        detail=json.dumps(detail, sort_keys=True, separators=(",", ":")) if detail else "")


class FakeRpcError(Exception):
    def __init__(self, code, details):
        super().__init__(details)
        self._code, self._details = code, details

    def code(self):
        return SimpleNamespace(name=self._code)

    def details(self):
        return self._details


def refusal(text, code="UNKNOWN"):
    return gw.GatewayError("StartService", FakeRpcError(code, text))


class FakeAccount:
    """This instance's account on a fake node: rows appended as the node would."""

    def __init__(self, balance=10 ** 9):
        self.rows = []
        self.balance = balance

    def move(self, kind, amt, detail=None, ref=""):
        self.balance += amt
        self.rows.append(movement(len(self.rows) + 1, kind, amt, self.balance, detail, ref))
        return self.rows[-1]

    def head(self):
        return len(self.rows)

    def after(self, seq):
        return [r for r in self.rows if r.seq > seq]


def started(token, uri=LISTENING_URI, request_bytes=0):
    return SimpleNamespace(instance=SimpleNamespace(token=token), uri=uri,
                           request_bytes=request_bytes, seconds_to_instance=0.1,
                           seconds_to_complete=0.2, request_complete=True)


class FakeNode563:
    """A node with the start-funding rules of #563, or one that breaks them."""

    def __init__(self, build, period, *, start_underfunded=False, keep_refused=False,
                 build_to_caller=False):
        self.build, self.period = build, period
        self.start_underfunded = start_underfunded
        self.keep_refused = keep_refused
        self.build_to_caller = build_to_caller
        self.account = FakeAccount()
        self.children = {}
        self.stopped = []

    def quote(self, *a, config=None, **kw):
        # The cost of a quote is the build plus the balance it asks for (#563).
        asked = config["initial_mu"] if config else 0
        return SimpleNamespace(cost=amount(self.build + asked), max_maintenance_cost=amount(self.period),
                               init_maintenance_cost=amount(self.period),
                               maintenance_seconds_loop=60)

    def start(self, label, *, initial_mu, start_ref=None, **kw):
        detail = {"start_ref": start_ref.hex()} if start_ref else None
        if not self.start_underfunded:
            if initial_mu < self.build:
                if self.keep_refused:
                    self.account.move("child_start", -initial_mu, detail)
                raise refusal(f"Unable to launch service x. Attempt details: local: "
                              f"StartAmountTooSmall: initial_mu {initial_mu} MU does not cover "
                              f"the build of the service, {self.build} MU.")
            if initial_mu - self.build < self.period:
                raise refusal(f"initial_mu {initial_mu} MU leaves {initial_mu - self.build} MU "
                              f"after the build of {self.build} MU. One maintenance period costs "
                              f"{self.period} MU. The least initial_mu is "
                              f"{self.build + self.period} MU.")
        self.account.move("child_start", -initial_mu, detail)
        if self.build_to_caller:
            self.account.move("build", -self.build)
        token = f"child{len(self.children)}"
        self.children[token] = [movement(1, "start", initial_mu, initial_mu),
                                movement(2, "build", -self.build, initial_mu - self.build)]
        return started(token)

    def patches(self):
        return [mock.patch.object(gw, "estimated_cost", side_effect=self.quote),
                mock.patch.object(gw, "configuration", side_effect=lambda **kw: kw),
                mock.patch.object(app, "_gw_start", side_effect=self.start),
                mock.patch.object(app, "_gw_stop", side_effect=lambda t, l: self.stopped.append(t)),
                mock.patch.object(app, "_own_head", side_effect=self.account.head),
                mock.patch.object(app, "_own_rows_after", side_effect=self.account.after),
                mock.patch.object(app, "_child_rows", side_effect=lambda t: self.children[t]),
                mock.patch.object(gw, "metrics_balance", return_value=1)]


def run_with(node, probe):
    patches = node.patches()
    for p in patches:
        p.start()
    try:
        return probe()
    finally:
        for p in patches:
            p.stop()


class BuildFundingTests(unittest.TestCase):
    def setUp(self):
        del app.FUNDING_FAILURES[:]

    def test_a_node_that_keeps_both_rules_passes(self):
        node = FakeNode563(build=10_000_000, period=200_000)
        ev = run_with(node, app.probe_build_funding)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual([a["attempt"] for a in ev["attempts"]],
                         ["below_build", "below_one_period", "funded"])
        self.assertEqual(ev["attempts"][0]["named_build_mu"], 10_000_000)
        self.assertEqual(ev["attempts"][2]["child_build_mu"], 10_000_000)
        self.assertEqual(node.stopped, ["child0"], "the funded child must be stopped")
        self.assertEqual(app.FUNDING_FAILURES, [], "asked-for refusals are not a shortage")

    def test_the_build_is_the_cost_less_the_balance_the_quote_asks_for(self):
        # With no initial_mu the node fills in its default balance, and the cost would be
        # the build plus that: the quote asks for 1 MU instead.
        node = FakeNode563(build=10_000_000, period=200_000)
        with mock.patch.object(gw, "estimated_cost", side_effect=node.quote) as quote, \
             mock.patch.object(gw, "configuration", side_effect=lambda **kw: kw):
            build, _ = app.quote_build("tiny")
        self.assertEqual(build, 10_000_000)
        self.assertEqual(quote.call_args.kwargs["config"], {"initial_mu": app.BUILD_QUOTE_BALANCE_MU})

    def test_a_built_image_exercises_the_period_rule_only(self):
        ev = run_with(FakeNode563(build=0, period=200_000), app.probe_build_funding)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual([a["attempt"] for a in ev["attempts"]], ["below_one_period", "funded"])

    def test_a_build_charged_to_the_caller_is_dishonest(self):
        ev = run_with(FakeNode563(build=10_000_000, period=200_000, build_to_caller=True),
                      app.probe_build_funding)
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn("charged to this account", ev["reason"])

    def test_a_refused_start_that_keeps_the_money_is_dishonest(self):
        ev = run_with(FakeNode563(build=10_000_000, period=200_000, keep_refused=True),
                      app.probe_build_funding)
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn("refused the start and kept", ev["reason"])

    def test_a_node_that_starts_an_underfunded_child_is_not_accused(self):
        node = FakeNode563(build=10_000_000, period=200_000, start_underfunded=True)
        ev = run_with(node, app.probe_build_funding)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)
        self.assertEqual(sorted(node.stopped), ["child0", "child1", "child2"])

    def test_a_free_node_is_not_applicable_and_does_not_block_the_attestation(self):
        ev = run_with(FakeNode563(build=0, period=0), app.probe_build_funding)
        self.assertEqual(ev["verdict"], app.VERDICT_NOT_APPLICABLE)
        summary = app.summarize_suite({"a": {"probe": "a", "verdict": app.VERDICT_PASS},
                                       "b": ev})
        self.assertTrue(summary["observation_complete"])
        self.assertEqual(summary["not_applicable_probes"], ["build_funding"])
        self.assertEqual(summary["pass"], 1)

    def test_a_quote_that_fails_is_infra_error(self):
        with mock.patch.object(gw, "estimated_cost",
                               side_effect=refusal("connection refused", "UNAVAILABLE")), \
             mock.patch.object(gw, "configuration", side_effect=lambda **kw: kw):
            ev = app.probe_build_funding()
        self.assertEqual(ev["verdict"], app.VERDICT_INFRA_ERROR)
        self.assertEqual(ev["grpc_code"], "UNAVAILABLE")


class FakeNode578:
    """A node that keys StartReference by the caller (#578), or one that ignores it."""

    def __init__(self, idempotent=True, announces=True):
        self.idempotent, self.announces = idempotent, announces
        self.account = FakeAccount()
        self.by_ref = {}
        self.stopped = []
        self.service_sent = []

    def _start(self, ref, initial_mu, send_service=True):
        if self.idempotent and ref in self.by_ref:
            return started(self.by_ref[ref])
        token = f"child{len(self.service_sent)}"
        self.service_sent.append(send_service)
        self.account.move("child_start", -(initial_mu or 1000), {"start_ref": ref.hex()})
        self.by_ref.setdefault(ref, token)
        return started(token)

    def gw_start(self, label, *, start_ref=None, initial_mu="budget", **kw):
        return self._start(start_ref, 5000)

    def again(self, node_url, packed, *, start_ref=None, config=None, send_service=True, **kw):
        result = self._start(start_ref, 7000, send_service)
        result.instance = SimpleNamespace(token=result.instance.token, instance=None)
        return result

    def patches(self):
        peer = SimpleNamespace(SerializeToString=lambda: b"x celaut.StartReference y"
                               if self.announces else b"x")
        return [mock.patch.object(app, "_gw_start", side_effect=self.gw_start),
                mock.patch.object(gw, "start_service", side_effect=self.again),
                mock.patch.object(gw, "configuration", side_effect=lambda **kw: kw),
                mock.patch.object(gw, "peer_info", return_value=peer),
                mock.patch.object(app, "_instance_uri", return_value=LISTENING_URI),
                mock.patch.object(app, "_gw_stop", side_effect=lambda t, l: self.stopped.append(t)),
                mock.patch.object(app, "_own_head", side_effect=self.account.head),
                mock.patch.object(app, "_own_rows_after", side_effect=self.account.after)]


class IdempotentStartTests(unittest.TestCase):
    def test_one_reference_gives_one_instance_and_one_charge(self):
        node = FakeNode578()
        ev = run_with(node, app.probe_idempotent_start)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual(len(ev["child_start_rows"]), 1)
        self.assertTrue(all(a["token_is_first"] for a in ev["asks"]))
        self.assertEqual(node.stopped, ["child0"])

    def test_a_second_start_for_an_announced_reference_is_dishonest(self):
        node = FakeNode578(idempotent=False)
        ev = run_with(node, app.probe_idempotent_start)
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertEqual(len(ev["child_start_rows"]), 3)
        self.assertEqual(sorted(node.stopped), ["child0", "child1", "child2"],
                         "every instance it started must be stopped")

    def test_a_node_that_does_not_announce_the_reference_is_not_accused(self):
        ev = run_with(FakeNode578(idempotent=False, announces=False), app.probe_idempotent_start)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)


class FakeNode371:
    """A node that holds tiny: it stops the sender (signal or #371 skip), or does not."""

    BLOCK = 27_000_000

    def __init__(self, stops=True):
        self.stops = stops
        self.n = 0

    def gw_start(self, label, *, block_skip=True, **kw):
        self.n += 1
        sent = 600 if self.stops else self.BLOCK + 900
        r = started(f"child{self.n}", request_bytes=sent)
        r.seconds_to_instance = 0.9 if self.stops else 1.6
        return r

    def patches(self, first=None):
        return [mock.patch.object(app, "_gw_start", side_effect=self.gw_start),
                mock.patch.object(app, "_gw_stop"),
                mock.patch.dict(app.FIRST_SENDS, first or {}, clear=True),
                mock.patch.object(app, "_packed_block_bytes", return_value=self.BLOCK)]


class BlockSkipTests(unittest.TestCase):
    def run_probe(self, node, first=None):
        patches = node.patches(first)
        for p in patches:
            p.start()
        try:
            return app.probe_block_skip()
        finally:
            for p in patches:
                p.stop()

    def test_later_starts_without_the_blocks_pass_and_compare_with_the_first_send(self):
        first = {"tiny": {"request_bytes": FakeNode371.BLOCK + 2000, "seconds": 4.2}}
        ev = self.run_probe(FakeNode371(), first)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual(ev["request_bytes_with_skip"], 600)
        self.assertTrue(ev["first_send_carried_the_blocks"])
        self.assertGreater(ev["bytes_saved_against_first_send"], 0.99)
        self.assertIn("first send", ev["reason"])

    def test_a_node_that_held_the_child_before_still_passes_and_says_so(self):
        ev = self.run_probe(FakeNode371(), {"tiny": {"request_bytes": 700, "seconds": 0.5}})
        self.assertEqual(ev["verdict"], app.VERDICT_PASS)
        self.assertFalse(ev["first_send_carried_the_blocks"])
        self.assertIn("already held", ev["reason"])

    def test_a_node_that_makes_the_client_send_the_blocks_is_never_accused(self):
        ev = self.run_probe(FakeNode371(stops=False))
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)


class EnvVarsTests(unittest.TestCase):
    def _run(self, report, names=None):
        names = list(app.TINY_DECLARED_ENVS) if names is None else names
        response = mock.Mock()
        response.json.side_effect = lambda: report(self.sent)
        captured = {}

        def start(label, *, envs=None, **kw):
            self.sent = envs
            captured["envs"] = envs
            return started("child0")

        with mock.patch.object(app, "_gw_start", side_effect=start), \
             mock.patch.object(app, "_gw_stop") as stop, \
             mock.patch.object(app, "_packed_env_names", return_value=names), \
             mock.patch.object(app.requests, "get", return_value=response):
            ev = app.probe_env_vars()
        stop.assert_called_once_with("child0", "tiny")
        return ev, captured["envs"]

    @staticmethod
    def honest(sent):
        values = {k: v.hex() for k, v in sent.items()}
        return {"config_readable": True, "config_env": dict(values),
                "process_env": dict(values, DEMO_ENV_UNSET=None)}

    def test_exact_values_on_both_paths_pass(self):
        # The packer stores the names sorted (keyvalue.from_dict).
        ev, envs = self._run(self.honest, names=sorted(app.TINY_DECLARED_ENVS))
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual(set(envs), {"DEMO_ENV_GIVEN", "DEMO_ENV_EMPTY"})
        self.assertEqual(envs["DEMO_ENV_EMPTY"], b"")

    def test_a_changed_value_is_dishonest(self):
        def tampered(sent):
            r = self.honest(sent)
            r["config_env"]["DEMO_ENV_GIVEN"] = b"other".hex()
            return r
        self.assertEqual(self._run(tampered)[0]["verdict"], app.VERDICT_DISHONEST)

    def test_a_value_nobody_gave_is_dishonest(self):
        def invented(sent):
            r = self.honest(sent)
            r["process_env"]["DEMO_ENV_UNSET"] = b"x".hex()
            return r
        self.assertEqual(self._run(invented)[0]["verdict"], app.VERDICT_DISHONEST)

    def test_a_missing_second_path_is_not_an_accusation(self):
        def first_path_only(sent):
            r = self.honest(sent)
            r["process_env"] = {k: None for k in app.TINY_DECLARED_ENVS}
            return r
        self.assertEqual(self._run(first_path_only)[0]["verdict"], app.VERDICT_INCONCLUSIVE)

    def test_a_spec_without_the_names_blames_the_packer_not_the_node(self):
        ev, _ = self._run(self.honest, names=[])
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)
        self.assertIn("#582", ev["reason"])


class TinyManifestTests(unittest.TestCase):
    def test_the_declared_envs_match_the_manifests_and_the_source(self):
        for arch in ("amd64", "arm64"):
            with open(os.path.join(app.os.path.dirname(app.__file__), "tiny", arch,
                                   ".service", "service.json")) as fh:
                self.assertEqual(json.load(fh)["envs"], list(app.TINY_DECLARED_ENVS), arch)
        with open(os.path.join(os.path.dirname(app.__file__), "tiny", "src", "main.rs")) as fh:
            source = fh.read()
        for name in app.TINY_DECLARED_ENVS:
            self.assertIn(f'"{name}"', source)


class NeutralVerdictTests(unittest.TestCase):
    def test_not_applicable_probes_are_hashed_but_do_not_block_the_hash(self):
        results = {"x": {"probe": "x", "verdict": app.VERDICT_PASS},
                   "y": {"probe": "y", "verdict": app.VERDICT_NOT_APPLICABLE}}
        with mock.patch.object(app, "_run_probe_suite", return_value=results):
            rep = app.build_attestation()
        self.assertTrue(rep["summary"]["attestable"])
        self.assertIsNotNone(rep["content_hash"]["value"])
        self.assertEqual(rep["summary"]["not_applicable_probes"], ["y"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
