"""celaut_pool: the children of this service through the `celaut` command.

No node and no real binary: a script stands in for `celaut`. It writes the arguments that it got
to a file and answers what the test says, as JSON on stdout, or as the JSON error and the exit
code that `celaut` uses (1 refused, 3 the node did not answer).

harness.py replaces the module `celaut_pool` with a fake for the other tests, so this file loads
the real one from its path.
"""
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import harness  # noqa: E402,F401  (the app is imported once per process, as in the other tests)
from harness import app  # noqa: E402


def _load_real():
    spec = importlib.util.spec_from_file_location("celaut_pool_real", os.path.join(ROOT, "celaut_pool.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pool = _load_real()

FAKE = """#!{python}
import json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "calls"), "a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\\n")
args = sys.argv[1:]
command = next(a for a in args if a in ("config", "acquire", "stop", "resize", "observe"))
with open(os.path.join(here, command + ".json")) as fh:
    answer = json.load(fh)
if "exit" in answer:
    print(json.dumps(answer["error"]), file=sys.stderr)
    sys.exit(answer["exit"])
if command == "observe":
    for line in answer["lines"]:
        print(json.dumps(line), flush=True)
else:
    print(json.dumps(answer))
"""


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="celaut-fake-")
        script = os.path.join(self.dir, "celaut")
        with open(script, "w") as fh:
            fh.write(FAKE.format(python=sys.executable))
        os.chmod(script, os.stat(script).st_mode | stat.S_IEXEC)
        self._bin = pool.CELAUT_BIN
        pool.CELAUT_BIN = script
        self.controller = pool.Controller(app_dir="service", config_file="/__config__")

    def tearDown(self):
        pool.CELAUT_BIN = self._bin

    def answer(self, command, value):
        with open(os.path.join(self.dir, command + ".json"), "w") as fh:
            json.dump(value, fh)

    def calls(self):
        with open(os.path.join(self.dir, "calls")) as fh:
            return [json.loads(line) for line in fh]

    # -- the node ------------------------------------------------------------

    def test_the_gateway_and_the_memory_limit_come_from_celaut_config(self):
        self.answer("config", {"gateway": "192.168.200.1:58443", "mem_limit": 1000000000})
        self.assertEqual(self.controller.get_node_url(), "192.168.200.1:58443")
        self.assertEqual(self.controller.get_mem_limit_at_start(), 1000000000)
        self.assertEqual(len(self.calls()), 1, "the config is asked once")
        self.assertEqual(self.calls()[0], ["--config", "/__config__", "config"])

    def test_resize_settles_at_the_maximum_and_gives_the_balance(self):
        self.answer("resize", {"mem_limit": 5, "balance_mu": "123456789"})
        sysreq, balance = self.controller.modify_resources({"min": 1, "max": 5})
        self.assertEqual((sysreq.mem_limit, balance), (5, 123456789))
        self.assertEqual(self.calls()[0][-3:], ["resize", "--mem", "5"])

    # -- a child -------------------------------------------------------------

    def test_a_child_is_started_with_its_service_its_root_its_variables_and_its_funds(self):
        self.answer("acquire", {"lease": 7, "uri": "10.0.0.9:8080", "new": True})
        child = self.controller.add_service("ab" * 32, {
            "initial_mu": 2500000,
            "environment_variables": [{"key": "UNDECLARED_ADDRS", "value": b"1.2.3.4,5.6.7.8"}]})

        instance = child.get_instance(max_attempts=2)

        self.assertEqual((instance.uri, instance.lease), ("10.0.0.9:8080", 7))
        args = self.calls()[0]
        root = os.path.abspath("service")
        self.assertEqual(args[:3], ["--config", "/__config__", "acquire"])
        self.assertIn("--new", args, "a probe measures a fresh child")
        self.assertEqual(args[args.index("--attempts") + 1], "2")
        self.assertEqual(args[args.index("--service") + 1], "ab" * 32)
        self.assertEqual(args[args.index("--root") + 1], root)
        self.assertEqual(args[args.index("--block-dir") + 1], os.path.join(root, "__block__"))
        self.assertEqual(args[args.index("--env") + 1], "UNDECLARED_ADDRS=1.2.3.4,5.6.7.8")
        self.assertEqual(args[args.index("--initial-mu") + 1], "2500000")

    def test_a_child_with_no_configuration_has_no_funds_and_no_variables(self):
        self.answer("acquire", {"lease": 1, "uri": "10.0.0.9:1", "new": True})
        self.controller.add_service("cd" * 32, None).get_instance()
        args = self.calls()[0]
        self.assertNotIn("--initial-mu", args)
        self.assertNotIn("--env", args)

    def test_stopping_a_child_gives_the_refund(self):
        self.answer("acquire", {"lease": 3, "uri": "10.0.0.9:1", "new": True})
        self.answer("stop", {"refund_mu": 777})
        instance = self.controller.add_service("cd" * 32, None).get_instance()
        self.assertEqual(instance.stop(), 777)
        self.assertEqual(self.calls()[-1][-2:], ["stop", "3"])

    def test_the_token_of_a_child_never_reaches_this_process(self):
        self.answer("acquire", {"lease": 3, "uri": "10.0.0.9:1", "new": True})
        instance = self.controller.add_service("cd" * 32, None).get_instance()
        self.assertFalse(hasattr(instance, "token"))

    # -- errors, in the shapes that the verifier classifies ------------------

    def test_a_node_that_does_not_answer_is_a_transport_failure(self):
        self.answer("resize", {"exit": 3, "error": {
            "error": "reading failed after 1 attempt(s): transport error",
            "kind": "gateway", "unreachable": True}})
        with self.assertRaises(pool.CelautError) as caught:
            self.controller.modify_resources({"min": 1, "max": 5})
        self.assertTrue(caught.exception.unreachable)
        failure = app.classify_rpc_failure(caught.exception)
        self.assertEqual(failure["fault"], app.FAULT_TRANSPORT)
        self.assertFalse(failure["node_answered"])

    def test_a_refusal_of_the_node_is_a_fault_inside_the_node_with_its_own_text(self):
        self.answer("resize", {"exit": 1, "error": {
            "error": 'Error charging for the resource change of "ipv4:1.2.3.4"',
            "kind": "gateway", "unreachable": False}})
        with self.assertRaises(pool.CelautError) as caught:
            self.controller.modify_resources({"min": 1, "max": 5})
        failure = app.classify_rpc_failure(caught.exception)
        self.assertEqual(failure["fault"], app.FAULT_NODE_RPC)
        self.assertTrue(failure["node_answered"])
        self.assertIn("Error charging for the resource change", failure["node_detail"])

    def test_a_start_that_the_node_refuses_for_want_of_funds_is_known_as_such(self):
        self.answer("acquire", {"exit": 1, "error": {
            "error": "starting a service failed after 1 attempt(s): initial_mu 2000000 MU does "
                     "not cover the build of the service, 10000000 MU.",
            "kind": "gateway", "unreachable": False}})
        child = self.controller.add_service("ab" * 32, {"initial_mu": 2000000})
        with self.assertRaises(pool.CelautError) as caught:
            child.get_instance()
        error = app.ChildLaunchError("tiny", caught.exception)
        self.assertTrue(error.insufficient_funds)

    def test_a_missing_binary_is_a_config_error(self):
        pool.CELAUT_BIN = os.path.join(self.dir, "nope")
        with self.assertRaises(pool.CelautError) as caught:
            self.controller.add_service("ab" * 32, None).get_instance()
        self.assertEqual(caught.exception.kind, "config")

    # -- observe ---------------------------------------------------------------

    def test_observe_gives_the_events_as_dicts_and_stops_with_the_stream(self):
        lines = [
            {"time": "10:00:00", "kind": "session", "data": {"tag": "ping", "capture_mode": "pcap"}},
            {"time": "10:00:01", "kind": "packet", "data": {"direction": "IN", "peer_host": "1.2.3.4"}},
        ]
        self.answer("observe", {"lines": lines})
        with self.controller.observe(5, packets=True) as events:
            got = list(events)
        self.assertEqual(got, lines)
        self.assertEqual(self.calls()[0], ["--config", "/__config__", "observe", "5", "--packets"])

    def test_observe_ends_the_process_when_the_reader_leaves_early(self):
        lines = [{"time": "t", "kind": "packet", "data": {}} for _ in range(3)]
        self.answer("observe", {"lines": lines})
        with self.controller.observe(5) as events:
            first = next(events)
        self.assertEqual(first["kind"], "packet")

    def test_observe_that_fails_raises_the_error_of_celaut(self):
        self.answer("observe", {"exit": 1, "error": {"error": "no such lease", "kind": "failed",
                                                      "unreachable": False}})
        with self.assertRaises(pool.CelautError):
            with self.controller.observe(9) as events:
                list(events)


if __name__ == "__main__":
    unittest.main()
