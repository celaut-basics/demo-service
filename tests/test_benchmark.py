#!/usr/bin/env python3
"""Tests for the `benchmark/` variant (celaut-project/nodo#459).

Two layers:

* The pure parts of `bench.sh` -- reading the clock, validating the working set,
  rendering JSON -- and the CGI's refusals, run under the local POSIX `sh`. They
  need no Linux and no busybox, because none of them reads anything a Mac lacks.
* The measurement itself, end to end, against the pinned busybox the image is
  built from. On Linux that is the local `sh` (it only needs /proc); anywhere
  else it runs in `docker run <pinned busybox>` when docker answers, and is
  skipped, saying why, when it does not.

Run with:  python3 tests/test_benchmark.py
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BENCH_DIR = os.path.join(ROOT, "benchmark")
BENCH_SH = os.path.join(BENCH_DIR, "bench.sh")
CGI = os.path.join(BENCH_DIR, "www", "cgi-bin", "benchmark")

# The image benchmark/.service/Dockerfile builds FROM. Read out of the Dockerfile
# rather than repeated here, so the test cannot drift from what is packed.
with open(os.path.join(BENCH_DIR, ".service", "Dockerfile")) as _f:
    PINNED_BUSYBOX = next(
        line.split()[1] for line in _f if line.startswith("FROM ")
    )

KEYS = (
    "int_ops_per_sec",
    "flt_ops_per_sec",
    "mem_bandwidth_bytes_per_sec",
    "mem_bandwidth_working_set_bytes",
    "sha256_hashes_per_sec",
)


def sh(script, env=None):
    """Run ``script`` under the local POSIX sh with bench.sh's functions loaded."""
    full_env = dict(os.environ, BENCH_LIB="1", **(env or {}))
    return subprocess.run(
        ["sh", "-c", f'. "{BENCH_SH}"; {script}'],
        capture_output=True, text=True, env=full_env, timeout=60,
    )


class ClockTests(unittest.TestCase):
    def _now_cs(self, reading):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(reading + "\n")
        try:
            out = sh('now_cs; echo "$NOW"', env={"BENCH_UPTIME": f.name})
        finally:
            os.unlink(f.name)
        self.assertEqual(out.returncode, 0, out.stderr)
        return int(out.stdout.strip())

    def test_a_reading_is_centiseconds(self):
        self.assertEqual(self._now_cs("12345.67 999.00"), 1234567)

    def test_a_leading_zero_fraction_is_not_octal(self):
        # ".08" and ".09" are invalid octal literals: read naively they are an
        # arithmetic error, and ".07" would silently be read right by accident.
        self.assertEqual(self._now_cs("12.08 0.00"), 1208)
        self.assertEqual(self._now_cs("12.09 0.00"), 1209)
        self.assertEqual(self._now_cs("12.00 0.00"), 1200)


class WorkingSetTests(unittest.TestCase):
    def _parse(self, value):
        out = sh(f'parse_working_set "{value}"; echo "$?|$WORKING_SET|$WORKING_SET_ERROR"')
        status, working_set, error = out.stdout.strip().split("|", 2)
        return int(status), working_set, error

    def test_omitted_is_the_pinned_default(self):
        status, working_set, _ = self._parse("")
        self.assertEqual(status, 0)
        self.assertEqual(working_set, "1073741824")

    def test_the_pinned_default_is_one_gib(self):
        # nodo pins the same number (src/utils/benchmark.py); a requirement that
        # names no working set is read against it, so the two must not drift.
        out = sh('echo "$DEFAULT_WORKING_SET_BYTES"')
        self.assertEqual(out.stdout.strip(), str(1 << 30))

    def test_a_valid_size_is_kept(self):
        self.assertEqual(self._parse("268435456")[:2], (0, "268435456"))

    def test_anything_but_a_positive_decimal_is_refused(self):
        for bad in ("abc", "12abc", "-5", "0", "012", "1e9", " 5"):
            with self.subTest(value=bad):
                status, _, error = self._parse(bad)
                self.assertEqual(status, 1)
                self.assertIn("positive decimal integer", error)

    def test_under_one_mib_is_refused(self):
        status, _, error = self._parse("4096")
        self.assertEqual(status, 1)
        self.assertIn("at least 1048576", error)

    def test_a_size_no_machine_has_is_refused_without_overflowing(self):
        status, _, error = self._parse("1" * 25)
        self.assertEqual(status, 1)
        self.assertIn("larger than this machine's memory", error)


class RenderJsonTests(unittest.TestCase):
    def _render(self, lines):
        proc = subprocess.run(
            ["sh", "-c", f'. "{BENCH_SH}"; render_json'],
            input="\n".join(lines) + "\n",
            capture_output=True, text=True,
            env=dict(os.environ, BENCH_LIB="1"),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_scores_are_numbers_and_the_architecture_a_string(self):
        rendered = self._render([
            "architecture=linux/amd64",
            "int_ops_per_sec=900000",
            "mem_bandwidth_bytes_per_sec=7000000000",
            "mem_bandwidth_working_set_bytes=1073741824",
        ])
        self.assertEqual(rendered, {
            "architecture": "linux/amd64",
            "int_ops_per_sec": 900000,
            "mem_bandwidth_bytes_per_sec": 7000000000,
            "mem_bandwidth_working_set_bytes": 1073741824,
            "skipped": [],
        })

    def test_a_skipped_primitive_is_listed_and_absent(self):
        rendered = self._render([
            "int_ops_per_sec=1",
            'skipped sha256_hashes_per_sec: cannot write "/tmp/x"',
        ])
        self.assertNotIn("sha256_hashes_per_sec", rendered)
        self.assertEqual(
            rendered["skipped"], ['sha256_hashes_per_sec: cannot write "/tmp/x"']
        )

    def test_a_non_integer_score_is_dropped_not_passed_through(self):
        self.assertNotIn("int_ops_per_sec", self._render(["int_ops_per_sec=1.5"]))


class CgiRefusalTests(unittest.TestCase):
    def _get(self, query):
        # Bytes, not text: universal newlines would fold the \r\n an HTTP head
        # is made of, which is exactly what is being checked.
        proc = subprocess.run(
            ["sh", CGI], capture_output=True, timeout=60,
            env=dict(os.environ, QUERY_STRING=query),
        )
        head, _, body = proc.stdout.decode().partition("\r\n\r\n")
        return head.split("\r\n")[0], json.loads(body)

    def test_a_malformed_working_set_is_a_400(self):
        status, body = self._get("working_set_bytes=lots")
        self.assertEqual(status, "HTTP/1.1 400 Bad Request")
        self.assertIn("positive decimal integer", body["error"])

    def test_the_parameter_is_found_among_others(self):
        status, body = self._get("foo=1&working_set_bytes=10&bar=2")
        self.assertEqual(status, "HTTP/1.1 400 Bad Request")
        self.assertIn("got 10", body["error"])

    def test_a_running_benchmark_turns_a_second_one_away(self):
        tmp = tempfile.mkdtemp()
        try:
            os.mkdir(os.path.join(tmp, "benchmark.lock"))
            proc = subprocess.run(
                ["sh", CGI], capture_output=True, text=True, timeout=60,
                env=dict(os.environ, QUERY_STRING="", BENCH_TMP=tmp),
            )
            self.assertTrue(proc.stdout.startswith("HTTP/1.1 409 Conflict"), proc.stdout)
            # The lock belongs to the run holding it: the refused one leaves it.
            self.assertTrue(os.path.isdir(os.path.join(tmp, "benchmark.lock")))
        finally:
            shutil.rmtree(tmp)


def _measure(args, env):
    """Run bench.sh for real; returns (stdout, how) or (None, why-not)."""
    if os.path.exists("/proc/uptime") and shutil.which("busybox"):
        cmd = ["busybox", "sh", BENCH_SH] + args
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                              env=dict(os.environ, **env))
        return proc.stdout, "local busybox"
    docker = shutil.which("docker")
    if docker and subprocess.run([docker, "info"], capture_output=True).returncode == 0:
        env_args = [a for k, v in env.items() for a in ("-e", f"{k}={v}")]
        with open(BENCH_SH) as script:
            proc = subprocess.run(
                [docker, "run", "--rm", "-i", *env_args, PINNED_BUSYBOX, "sh", "-s", *args],
                stdin=script, capture_output=True, text=True, timeout=600,
            )
        return proc.stdout, f"docker {PINNED_BUSYBOX}"
    return None, "needs Linux with busybox, or a running docker"


class MeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Short runs: this checks that every primitive measures and reports,
        # not how fast the test machine is.
        cls.stdout, cls.how = _measure(["268435456"], {"BENCH_CS": "30"})

    def setUp(self):
        if self.stdout is None:
            self.skipTest(self.how)

    def _scores(self):
        return dict(line.split("=", 1) for line in self.stdout.splitlines() if "=" in line)

    def test_every_primitive_is_measured_as_a_positive_integer(self):
        scores = self._scores()
        for key in KEYS:
            with self.subTest(key=key, how=self.how):
                self.assertIn(key, scores, self.stdout)
                self.assertGreater(int(scores[key]), 0)
        self.assertNotIn("skipped", self.stdout)

    def test_the_working_set_asked_for_is_the_one_reported(self):
        self.assertEqual(self._scores()["mem_bandwidth_working_set_bytes"], "268435456")

    def test_the_architecture_is_a_canonical_tag(self):
        self.assertIn(self._scores()["architecture"], ("linux/amd64", "linux/arm64"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
