#!/usr/bin/env python3
"""The stub ready-port must keep answering after many handshakes.

`_wait_until_ready` only completes a TCP handshake. If the harness listener
never accept()s, each handshake stays in the listen backlog. After 64 waits,
later waits hang for CHILD_READY_TIMEOUT_S and `unittest discover` never
finishes.

Run with:  python3 tests/test_harness.py
"""
import os
import socket
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from harness import LISTENING_URI  # noqa: E402


class BlockDirTests(unittest.TestCase):
    def test_bee_rpc_reads_blocks_from_the_service_directory(self):
        # Under nodo the cwd is /. bee-rpc's default <cwd>/__block__/ does not
        # hold the blocks of the children; service/__block__/ does.
        calls = sys.modules["bee_rpc.utils"].env_calls
        self.assertTrue(calls, "app.py did not call bee_rpc.utils.modify_env")
        block_dir = calls[-1]["block_dir"]
        self.assertTrue(block_dir.endswith(os.sep + os.path.join("service", "__block__") + "/"))
        self.assertTrue(os.path.isabs(block_dir))


class ListenerBacklogTests(unittest.TestCase):
    def test_the_ready_port_still_accepts_after_many_handshakes(self):
        host, _, port = LISTENING_URI.rpartition(":")
        port = int(port)
        for _ in range(80):
            with socket.create_connection((host, port), timeout=1):
                pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
