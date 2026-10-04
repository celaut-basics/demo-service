#!/usr/bin/env python3
"""The MCP interface must give a model everything the web report gives a person.

It did not: run_attestation started a second, synchronous, unlocked run instead
of reading the one the page showed, the startup suite could not be re-run, and
the balance was not exposed at all -- so the only way to get fresh startup
results was to kill the instance and execute it again.

These tests hold the routes and the tools together, and check that both read
the same jobs, under the same lock.

Run with:  python3 tests/test_mcp.py
"""
import json
import os
import sys
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from harness import FakeController, FakeServiceInterface, app  # noqa: E402

client = app.app.test_client()


def rpc(method, params=None, rid=1):
    body = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        body["params"] = params
    return client.post("/mcp", data=json.dumps(body), content_type="application/json")


def call(name, arguments=None):
    res = rpc("tools/call", {"name": name, "arguments": arguments or {}}).get_json()["result"]
    # Text and structured content must say the same thing.
    assert json.loads(res["content"][0]["text"]) == res["structuredContent"]
    return res


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def reset_jobs():
    wait_for(lambda: not app._suite_lock.locked())
    app.ATTESTATION_JOB.update(status="idle", started_at=None, finished_at=None,
                               result=None, error=None, funding=None)
    app.STARTUP_TESTS.update(status="pending", started_at=None, finished_at=None,
                             results=None, funding=None, attempt=0, error=None)


FUNDED = (True, {"funded": True})


class RouteToolParityTests(unittest.TestCase):
    def test_every_route_has_an_mcp_tool_or_a_reason(self):
        routes = {rule.rule for rule in app.app.url_map.iter_rules()}
        unmapped = routes - set(app.ROUTE_MCP_TOOLS) - set(app.ROUTES_WITHOUT_MCP)
        self.assertEqual(unmapped, set(),
                         "add the route to ROUTE_MCP_TOOLS (with its tool) or ROUTES_WITHOUT_MCP")

    def test_the_map_names_no_route_that_does_not_exist(self):
        routes = {rule.rule for rule in app.app.url_map.iter_rules()}
        self.assertEqual(set(app.ROUTE_MCP_TOOLS) - routes, set())
        self.assertEqual(set(app.ROUTES_WITHOUT_MCP) - routes - {"/static/<path:filename>"}, set())

    def test_every_mapped_tool_is_listed_and_dispatchable(self):
        listed = {t["name"] for t in app.MCP_TOOLS}
        for route, tools in app.ROUTE_MCP_TOOLS.items():
            for tool in tools:
                self.assertIn(tool, listed, f"{route} -> {tool}")

    def test_every_listed_tool_is_reachable_from_a_route(self):
        # The reverse: a tool with no route is something a person cannot see.
        mapped = {t for tools in app.ROUTE_MCP_TOOLS.values() for t in tools}
        self.assertEqual({t["name"] for t in app.MCP_TOOLS} - mapped, set())

    def test_the_report_page_reads_only_mapped_routes(self):
        html = client.get("/").get_data(as_text=True)
        fetched = {u.split("?")[0] for u in __import__("re").findall(r"fetch\('([^']+)'", html)}
        self.assertTrue(fetched)
        self.assertEqual(fetched - set(app.ROUTE_MCP_TOOLS), set())


class ProtocolTests(unittest.TestCase):
    def test_initialize(self):
        res = rpc("initialize", {}).get_json()["result"]
        self.assertEqual(res["serverInfo"]["name"], "celaut-node-honesty-verifier")
        self.assertIn("tools", res["capabilities"])

    def test_initialized_notification_has_no_body(self):
        self.assertEqual(rpc("notifications/initialized").status_code, 204)

    def test_tools_are_fully_described(self):
        for tool in rpc("tools/list").get_json()["result"]["tools"]:
            for key in ("name", "description", "inputSchema", "outputSchema", "annotations"):
                self.assertIn(key, tool, tool["name"])
            self.assertIn("readOnlyHint", tool["annotations"])

    def test_tools_that_spend_say_so_and_readers_are_read_only(self):
        for tool in app.MCP_TOOLS:
            if tool["annotations"]["readOnlyHint"]:
                self.assertTrue(tool["name"].startswith("get_")
                                or tool["name"] == "probe_resource_provisioning", tool["name"])
            elif tool["name"] != "probe_gateway_reachability":
                self.assertIn("MU", tool["description"], tool["name"])

    def test_unknown_method_is_a_jsonrpc_error(self):
        self.assertEqual(rpc("nope").get_json()["error"]["code"], -32601)

    def test_unknown_tool_is_a_tool_error(self):
        self.assertTrue(call("nope")["isError"])


class SameJobTests(unittest.TestCase):
    """The page and the model read one attestation job, not one each."""

    def setUp(self):
        reset_jobs()
        self.release = threading.Event()

        def slow_attestation():
            self.release.wait(5)
            return {"summary": {"node_honest": True}, "probes": [], "content_hash": {"value": "h"}}

        self.patches = [mock.patch.object(app, "build_attestation", side_effect=slow_attestation),
                        mock.patch.object(app, "ensure_funded", return_value=FUNDED)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        self.release.set()
        wait_for(lambda: app.ATTESTATION_JOB["status"] not in app.ATTESTATION_ACTIVE)
        for p in self.patches:
            p.stop()

    def test_run_attestation_returns_at_once_and_reads_back_what_the_page_reads(self):
        t0 = time.monotonic()
        started = call("run_attestation")["structuredContent"]
        self.assertLess(time.monotonic() - t0, 1.0, "must not block for the whole run")
        self.assertTrue(started["started"])
        self.assertIn(started["status"], app.ATTESTATION_ACTIVE)

        self.release.set()
        self.assertTrue(wait_for(lambda: app.ATTESTATION_JOB["status"] == "done"))
        via_mcp = call("get_attestation")["structuredContent"]
        via_http = client.get("/attestation.json").get_json()
        self.assertEqual(via_mcp, via_http)
        self.assertEqual(via_mcp["result"]["content_hash"]["value"], "h")

    def test_a_second_start_joins_the_running_job(self):
        self.assertTrue(call("run_attestation")["structuredContent"]["started"])
        self.assertFalse(call("run_attestation")["structuredContent"]["started"])
        self.assertEqual(client.post("/attestation.json").status_code, 202)
        self.release.set()
        self.assertTrue(wait_for(lambda: app.ATTESTATION_JOB["status"] == "done"))
        self.assertEqual(app.build_attestation.call_count, 1)

    def test_probes_are_refused_while_a_run_holds_the_balance(self):
        call("run_attestation")
        self.assertTrue(wait_for(lambda: app._suite_lock.locked()))
        res = call("probe_network_isolation")
        self.assertTrue(res["isError"])
        self.assertEqual(res["structuredContent"]["status"], "busy")
        self.assertEqual(res["structuredContent"]["running"]["name"], "attestation")
        self.assertEqual(client.post("/probe/network").status_code, 409)
        # Reading local files spends nothing and is allowed beside a run.
        self.assertFalse(call("probe_resource_provisioning")["isError"])

    def test_opening_the_page_does_not_start_a_run(self):
        client.get("/")
        self.assertEqual(app.ATTESTATION_JOB["status"], "idle")
        self.assertNotIn("\nrun();", client.get("/").get_data(as_text=True))


class StartupTestsOverMcpTests(unittest.TestCase):
    def setUp(self):
        reset_jobs()
        self.release = threading.Event()

        def slow_suite():
            self.release.wait(5)
            return {"gateway_reachability": {"probe": "gateway_reachability", "verdict": "PASS"}}

        self.patches = [mock.patch.object(app, "_run_probe_suite", side_effect=slow_suite),
                        mock.patch.object(app, "ensure_funded", return_value=FUNDED)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        self.release.set()
        wait_for(lambda: app.STARTUP_TESTS["status"] not in app.STARTUP_ACTIVE)
        for p in self.patches:
            p.stop()

    def test_rerun_is_available_and_does_not_double_start(self):
        first = call("rerun_startup_tests")["structuredContent"]
        self.assertTrue(first["started"])
        self.assertFalse(call("rerun_startup_tests")["structuredContent"]["started"])
        self.assertEqual(client.post("/startup_tests/rerun").status_code, 409)

        self.release.set()
        self.assertTrue(wait_for(lambda: app.STARTUP_TESTS["status"] == "done"))
        self.assertEqual(app._run_probe_suite.call_count, 1)
        self.assertEqual(call("get_startup_tests")["structuredContent"],
                         client.get("/startup_tests").get_json())
        self.assertTrue(app.STARTUP_TESTS["results"]["summary"]["all_passed"])


class FundingOverMcpTests(unittest.TestCase):
    def setUp(self):
        reset_jobs()
        FakeController.rpc_mode = "ok"

    def tearDown(self):
        app.FUNDING.update(self_rate_mu_per_s=None, child_initial_mu={}, balance_mu=None)

    def test_an_underfunded_attestation_is_refused_with_the_missing_amount(self):
        short = (False, {"funded": False, "missing_mu": 123,
                         "operator_hint": "nodo increase_deposit <instance> <amount>"})
        with mock.patch.object(app, "ensure_funded", return_value=short), \
             mock.patch.object(app, "build_attestation") as build:
            call("run_attestation")
            self.assertTrue(wait_for(lambda: app.ATTESTATION_JOB["status"] == "insufficient_funds"))
        build.assert_not_called()
        job = call("get_attestation")["structuredContent"]
        self.assertEqual(job["funding"]["missing_mu"], 123)
        self.assertIn("increase_deposit", job["error"])

    def test_the_startup_suite_waits_for_funds_and_says_so(self):
        seen = []

        def gate(pending_builds=0, timeout=None, on_wait=None):
            on_wait({"funded": False, "missing_mu": 5})
            seen.append(call("get_startup_tests")["structuredContent"]["status"])
            return True, {"funded": True}

        with mock.patch.object(app, "ensure_funded", side_effect=gate), \
             mock.patch.object(app, "_run_probe_suite", return_value={}):
            app.start_startup_tests_async()
            self.assertTrue(wait_for(lambda: app.STARTUP_TESTS["status"] == "done"))
        self.assertEqual(seen, ["waiting_for_funds"])

    def test_a_starved_suite_waits_for_the_builds_and_runs_again(self):
        gates = []

        def gate(pending_builds=0, timeout=None, on_wait=None):
            gates.append(pending_builds)
            return True, {"funded": True}

        runs = iter([["heavy"], []])

        def suite():
            del app.FUNDING_FAILURES[:]
            app.FUNDING_FAILURES.extend(next(runs))
            return {}

        with mock.patch.object(app, "ensure_funded", side_effect=gate), \
             mock.patch.object(app, "_run_probe_suite", side_effect=suite):
            app.start_startup_tests_async()
            self.assertTrue(wait_for(lambda: app.STARTUP_TESTS["status"] in ("done", "error")
                                     and not app._suite_lock.locked()))
        self.assertEqual(len(gates), 2)
        self.assertEqual(gates[0], 0)
        self.assertGreaterEqual(gates[1], 1, "the second wait must include the first builds")
        self.assertEqual(app.STARTUP_TESTS["starved_children"], [])

    def test_service_status_matches_the_route_and_reports_funding(self):
        app.FUNDING.update(self_rate_mu_per_s=3950.0, balance_mu=1000)
        via_mcp = call("get_service_status")["structuredContent"]
        via_http = client.get("/status").get_json()
        self.assertEqual(via_mcp, via_http)
        self.assertFalse(via_mcp["funding"]["funded"])
        self.assertGreater(via_mcp["funding"]["missing_mu"], 0)

    def test_refresh_does_not_settle_the_account_under_a_running_suite(self):
        with app.exclusive("attestation"), \
             mock.patch.object(app, "sample_balance") as sample:
            status = call("get_service_status", {"refresh": True})["structuredContent"]
        sample.assert_not_called()
        self.assertIn("suite is running", status["balance_note"])

    def test_current_balance_reports_the_real_balance(self):
        app.FUNDING["balance_mu"] = 14241077
        self.assertEqual(client.get("/current_balance").get_json()["balance_mu"], "1.42e+07")


if __name__ == "__main__":
    FakeServiceInterface.launch_mode = "ok"
    unittest.main(verbosity=2)
