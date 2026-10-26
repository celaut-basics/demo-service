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


class FakeNode268:
    """Members of network shares: one directory per group, or a node that breaks that."""

    def __init__(self, mode="honest"):
        self.mode = mode
        self.dirs = {}
        self.members = {}
        self.stopped = []

    def gw_start(self, label, *, envs=None, **kw):
        group = envs[app.NETSHARE_GROUP_ENV].decode()
        uri = f"m{len(self.members)}:3030"
        key = {"honest": group, "one_dir": "all",
               "split": f"{group}-{len(self.members)}"}[self.mode]
        self.members[uri] = key
        return started(f"t{len(self.members)}", uri=uri)

    def call(self, uri, action, **params):
        d = self.dirs.setdefault(self.members[uri], {})
        plan = {"present": True, "raw": '[{"path":"/netshare"}]'}
        if action == "write":
            d[params["name"]] = params["nonce"]
            return {"ok": True, "mount_plan": plan}
        return {"present": params["name"] in d, "content": d.get(params["name"]), "mount_plan": plan}

    def patches(self):
        return [mock.patch.object(app, "_gw_start", side_effect=self.gw_start),
                mock.patch.object(app, "_netshare", side_effect=self.call),
                mock.patch.object(app, "SHARE_PROPAGATION_TIMEOUT_S", 0),
                mock.patch.object(app, "_gw_stop", side_effect=lambda t, l: self.stopped.append(t))]


class NetworkShareTests(unittest.TestCase):
    def test_one_share_per_group_passes(self):
        node = FakeNode268()
        ev = run_with(node, app.probe_network_share)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual(sorted(node.stopped), ["t1", "t2", "t3"])

    def test_another_group_seeing_the_share_is_dishonest(self):
        ev = run_with(FakeNode268("one_dir"), app.probe_network_share)
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)
        self.assertIn("another group", ev["reason"])

    def test_two_members_of_one_group_apart_is_dishonest(self):
        ev = run_with(FakeNode268("split"), app.probe_network_share)
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)

    def test_a_member_with_no_mount_plan_is_a_packaging_question(self):
        node = FakeNode268("split")
        real = node.call

        def no_plan(uri, action, **p):
            out = real(uri, action, **p)
            out["mount_plan"] = {"present": False, "raw": None}
            return out
        node.call = no_plan
        self.assertEqual(run_with(node, app.probe_network_share)["verdict"], app.VERDICT_INCONCLUSIVE)


class NetshareManifestTests(unittest.TestCase):
    ROOT = os.path.dirname(HERE)

    def manifest(self, arch, sub=""):
        with open(os.path.join(self.ROOT, arch, sub, ".service", "service.json")) as fh:
            return json.load(fh)

    def test_the_share_is_a_share_of_a_network_the_child_and_the_parent_declare(self):
        for arch in ("amd64", "arm64"):
            child = self.manifest(arch, "netshare")
            share, = child["shared_filesystems"]
            self.assertEqual((share["role"], share["path"]), ("network", app.NETSHARE_MOUNT))
            network, = [n for n in child["network"] if share["network"] in n["tags"]]
            self.assertEqual(network["formal"], {"group": "${%s}" % app.NETSHARE_GROUP_ENV})
            self.assertEqual(child["envs"], [app.NETSHARE_GROUP_ENV])
            parent_tags = {t for n in self.manifest(arch)["network"] for t in n["tags"]}
            self.assertIn(share["network"], parent_tags, "a child gets only its ancestors' networks")
            with open(os.path.join(self.ROOT, arch, "netshare", ".service", "Dockerfile")) as fh:
                self.assertIn("mkdir -p " + app.NETSHARE_MOUNT, fh.read())


class TunnelTests(unittest.TestCase):
    RATES = {"net_mu_per_gib": 2_000_000, "tunnel_open_mu": 10_000}

    def rows(self, relayed, rate=2_000_000, open_mu=10_000, extra_bytes=0):
        mib = 1024 * 1024
        rows = [movement(1, "tunnel", -open_mu, 0, {"open": True})]
        left, seq = relayed + extra_bytes, 2
        while left > 0:
            n = min(mib, left)
            rows.append(movement(seq, "tunnel", -(rate * n // app.GIB), 0, {"bytes": n}))
            left -= n
            seq += 1
        return rows

    def judge(self, rows, relayed):
        return app._judge_tunnel_bill(rows, relayed, self.RATES)

    def test_a_bill_at_the_advertised_rate_has_no_violation(self):
        relayed = 64 * 1024 * 1024 + 300
        evidence, violations, notes = self.judge(self.rows(relayed), relayed)
        self.assertEqual(violations, [])
        self.assertEqual(evidence["billed_bytes"], relayed)
        self.assertLessEqual(evidence["effective_mu_per_gib"], 2_000_000)

    def test_a_dearer_rate_is_a_violation(self):
        relayed = 8 * 1024 * 1024
        _, violations, _ = self.judge(self.rows(relayed, rate=3_000_000), relayed)
        self.assertTrue(violations)

    def test_bytes_billed_that_were_not_relayed_are_a_violation(self):
        relayed = 8 * 1024 * 1024
        _, violations, _ = self.judge(self.rows(relayed, extra_bytes=2 * 1024 * 1024), relayed)
        self.assertTrue(any("billed for" in v for v in violations))

    def test_a_dearer_opening_is_a_violation(self):
        relayed = 1024
        _, violations, _ = self.judge(self.rows(relayed, open_mu=50_000), relayed)
        self.assertTrue(any("opening" in v for v in violations))

    def test_the_probe_reports_throughput_and_stops_the_child(self):
        n = 4 * 1024 * 1024
        sent, received = 60, n + 200
        tunnel = SimpleNamespace(status=200, body_bytes=n, sent_bytes=sent, received_bytes=received,
                                 seconds=0.5)
        with mock.patch.object(app, "_gw_start", return_value=started("c0")), \
             mock.patch.object(app, "_gw_stop") as stop, \
             mock.patch.object(app, "_direct_download", return_value=(n, 0.25)), \
             mock.patch.object(gw, "tunnel_http_get", return_value=tunnel), \
             mock.patch.object(app, "NODE_RATES", self.RATES), \
             mock.patch.object(app, "TUNNEL_TEST_BYTES", n), \
             mock.patch.object(app, "_child_rows", return_value=self.rows(sent + received)):
            ev = app.probe_tunnel()
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual(ev["tunnel"]["mib_per_s"], 8.0)
        self.assertEqual(ev["direct"]["mib_per_s"], 16.0)
        stop.assert_called_once_with("c0", "tiny")


def signed_chain(kinds_amounts, account="client-or-token", key=None, pages=1, sign=True,
                 tamper=None):
    """A statement of ``account`` as nodo builds it: chained rows, head, signature."""
    ref = gw.account_ref(account)
    prev, balance, mvs = gw.genesis_hash_of_ref(ref), 0, []
    for i, (kind, amt, detail) in enumerate(kinds_amounts, start=1):
        balance += amt
        mv = movement(i, kind, amt, balance, detail)
        mv.prev_hash = prev
        prev = gw.movement_hash(mv)
        mvs.append(mv)
    if tamper:
        tamper(mvs)
    head_seq, head_hash = len(mvs), (gw.movement_hash(mvs[-1]) if mvs else prev)
    out, size = [], -(-len(mvs) // pages)
    for p in range(pages):
        chunk = mvs[p * size:(p + 1) * size]
        st = SimpleNamespace(account_ref=ref, from_seq=chunk[0].seq if chunk else 1, to_seq=0,
                             movements=chunk, balance=amount(balance), head_seq=head_seq,
                             head_hash=head_hash, oldest_seq=1, retention_days=30,
                             ts=int(app.time.time()), signature="")
        if sign and key is not None:
            st.signature = key.sign(gw.statement_payload(
                public_hex(key), gw.statement_digest(st)).encode()).hex()
        out.append(st)
    return out


def public_hex(key):
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw).hex()


try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    HAVE_ED25519 = True
except ImportError:  # pragma: no cover
    HAVE_ED25519 = False

RUN = [("start", 14_000_000, None), ("maintenance", -3000, {"seconds": 60}),
       ("child_start", -2_000_000, {"start_ref": "ab"}), ("refund", 1_900_000, {"refunds_seq": "3"}),
       ("statement_query", -103, {"rows": "2"})]


@unittest.skipUnless(HAVE_ED25519, "cryptography is not installed")
class StatementReaderTests(unittest.TestCase):
    def setUp(self):
        self.key = ed25519.Ed25519PrivateKey.generate()

    def test_a_chain_as_nodo_signs_it_verifies_and_adds_up(self):
        out = gw.verify_statement(signed_chain(RUN, key=self.key), public_hex(self.key))
        self.assertEqual(out["problems"], [])
        self.assertTrue(out["signatures_ok"])
        self.assertTrue(out["adds_up"])
        self.assertEqual(out["sum_mu"], out["balance_mu"])

    def test_pages_must_continue_one_another(self):
        out = gw.verify_statement(signed_chain(RUN, key=self.key, pages=2), public_hex(self.key))
        self.assertEqual(out["problems"], [])
        self.assertEqual(out["movements"], len(RUN))

    def test_a_row_changed_after_it_was_chained_breaks_the_chain(self):
        def bump(mvs):
            mvs[1].amount = amount(-2000)
        out = gw.verify_statement(signed_chain(RUN, key=self.key, tamper=bump), public_hex(self.key))
        self.assertTrue(out["problems"])

    def test_another_key_does_not_verify(self):
        other = ed25519.Ed25519PrivateKey.generate()
        out = gw.verify_statement(signed_chain(RUN, key=other), public_hex(self.key))
        self.assertFalse(out["signatures_ok"])


@unittest.skipUnless(HAVE_ED25519, "cryptography is not installed")
class BalanceStatementProbeTests(unittest.TestCase):
    RATES = {"statement_query_mu": 100, "statement_row_mu": 1}

    def run_probe(self, pages, reported, after_balance):
        key = self.key
        after = [movement(99, "resource_change", -10000, after_balance)]
        peer = SimpleNamespace(public_key=public_hex(key), mu_per_call=[])
        with mock.patch.object(gw, "peer_info", return_value=peer), \
             mock.patch.object(gw, "full_statement", return_value=pages), \
             mock.patch.object(app.controller, "modify_resources", return_value=({}, reported)), \
             mock.patch.object(app, "_own_rows_after", return_value=after), \
             mock.patch.object(app, "NODE_RATES", self.RATES):
            return app.probe_balance_statement()

    def setUp(self):
        self.key = ed25519.Ed25519PrivateKey.generate()

    def test_a_true_statement_passes(self):
        pages = signed_chain(RUN, key=self.key)
        ev = self.run_probe(pages, 5_000, 5_000)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertEqual(ev["kinds"]["statement_query"], 1)

    def test_the_rates_of_the_peer_are_used_when_the_config_lacks_them(self):
        run = RUN[:-1] + [("statement_query", -5000, {"rows": "2"})]
        pages = signed_chain(run, key=self.key)
        peer = SimpleNamespace(public_key=public_hex(self.key), mu_per_call=[
            SimpleNamespace(key="statement_query_mu", value=amount(100)),
            SimpleNamespace(key="statement_row_mu", value=amount(1))])
        after = [movement(99, "resource_change", -10000, 5_000)]
        with mock.patch.object(gw, "peer_info", return_value=peer), \
             mock.patch.object(gw, "full_statement", return_value=pages), \
             mock.patch.object(app.controller, "modify_resources", return_value=({}, 5_000)), \
             mock.patch.object(app, "_own_rows_after", return_value=after), \
             mock.patch.object(app, "NODE_RATES", {}):
            ev = app.probe_balance_statement()
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)

    def test_a_query_charged_above_its_price_is_dishonest(self):
        run = RUN[:-1] + [("statement_query", -5000, {"rows": "2"})]
        ev = self.run_probe(signed_chain(run, key=self.key), 5_000, 5_000)
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)

    def test_a_balance_that_is_not_in_the_chain_is_dishonest(self):
        ev = self.run_probe(signed_chain(RUN, key=self.key), 5_000, 4_000)
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)

    def test_an_unsigned_statement_cannot_accuse(self):
        def bump(mvs):
            mvs[1].amount = amount(-2000)
        ev = self.run_probe(signed_chain(RUN, key=self.key, sign=False, tamper=bump), 5_000, 5_000)
        self.assertEqual(ev["verdict"], app.VERDICT_INCONCLUSIVE)


class DelegationPricingTests(unittest.TestCase):
    # A default node: 1111 MU/s per vCPU, 277 per GiB of RAM, 27 per GiB of disk. tiny
    # (1 vCPU, 50 MB, 200 MB) has a base of about 1129 MU/s, and at most 10x that with
    # the memory at 512 MiB.
    RATES = {"cpu_mu_per_vcpu_second": 1111, "ram_mu_per_gib_second": 277,
             "disk_mu_per_gib_second": 27, "scarcity_max_multiplier": 10}

    def run_probe(self, delegated_code, mu_per_s, paid=None):
        account = FakeAccount()
        budget = 3_000_000

        def start(label, *, start_ref=None, **kw):
            account.move("child_start", -(paid or budget), {"start_ref": start_ref.hex()})
            return started("d0")

        def statement(node_url, token="", **kw):
            if delegated_code:
                raise refusal("This node gives no statement of that instance.", delegated_code)
            return SimpleNamespace(head_seq=0)

        quote = SimpleNamespace(cost=amount(budget), init_maintenance_cost=amount(17824),
                                max_maintenance_cost=amount(17824), maintenance_seconds_loop=10)
        with mock.patch.object(app, "_child_budget", return_value=budget), \
             mock.patch.object(gw, "configuration", side_effect=lambda **kw: kw), \
             mock.patch.object(gw, "estimated_cost", return_value=quote), \
             mock.patch.object(app, "_gw_start", side_effect=start), \
             mock.patch.object(app, "_gw_stop", return_value=123) as stop, \
             mock.patch.object(gw, "balance_statement", side_effect=statement), \
             mock.patch.object(gw, "metrics_balance", return_value=2_000_000), \
             mock.patch.object(app, "_burn", return_value=[(0, 2_000_000),
                                                           (120, 2_000_000 - 120 * mu_per_s)]), \
             mock.patch.object(app, "NODE_RATES", self.RATES), \
             mock.patch.object(app, "_own_head", side_effect=account.head), \
             mock.patch.object(app, "_own_rows_after", side_effect=account.after):
            ev = app.probe_delegation_pricing()
        stop.assert_called_once_with("d0", "tiny")
        return ev

    def test_a_child_the_node_runs_itself_is_not_applicable(self):
        self.assertEqual(self.run_probe(None, 1341)["verdict"], app.VERDICT_NOT_APPLICABLE)

    def test_the_node_own_price_at_a_launch_multiplier_passes(self):
        # Measured on the two-node run: 1341 MU/s, the node's rates at its launch scarcity.
        ev = self.run_probe("UNIMPLEMENTED", 1341)
        self.assertEqual(ev["verdict"], app.VERDICT_PASS, ev["reason"])
        self.assertTrue(ev["delegated"])
        self.assertAlmostEqual(ev["burn"]["ratio_to_quote"], 0.752, places=2)

    def test_the_peer_price_passed_on_is_not_the_node_price(self):
        # A third of the node's rates (the peer of tools/two-node/).
        self.assertEqual(self.run_probe("UNIMPLEMENTED", 384)["verdict"], app.VERDICT_INCONCLUSIVE)

    def test_a_charge_above_the_largest_multiplier_is_dishonest(self):
        self.assertEqual(self.run_probe("UNIMPLEMENTED", 20000)["verdict"], app.VERDICT_DISHONEST)

    def test_a_father_charged_beyond_initial_mu_is_dishonest(self):
        ev = self.run_probe("UNIMPLEMENTED", 1341, paid=3_500_000)
        self.assertEqual(ev["verdict"], app.VERDICT_DISHONEST)

    def test_another_error_does_not_say_whether_it_was_delegated(self):
        self.assertEqual(self.run_probe("UNAVAILABLE", 1341)["verdict"], app.VERDICT_INCONCLUSIVE)


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
