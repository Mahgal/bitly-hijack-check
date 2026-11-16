#!/usr/bin/env python3
"""Tests for bitly-hijack-check. Stdlib only, fully offline: every live
check runs against the local mock server (mock_redirect_server.py).

Run:  python3 -m unittest discover -s tests -v
"""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bitly_hijack_check as bhc
from mock_redirect_server import run_server


class MockServerMixin:
    @classmethod
    def setUpClass(cls):
        cls.server, cls.port = run_server(0)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()


class TestRedirectChain(MockServerMixin, unittest.TestCase):
    def test_clean_chain_resolves_to_example_com(self):
        hops, error = bhc.follow_redirects(self.base + "/clean")
        self.assertIsNone(error)
        self.assertEqual(len(hops), 2)
        self.assertEqual(hops[0].status, 302)
        self.assertEqual(hops[-1].host, "example.com")

    def test_hijacked_chain_resolves_to_lookalike(self):
        hops, error = bhc.follow_redirects(self.base + "/hijacked")
        self.assertIsNone(error)
        self.assertEqual(hops[-1].host, "example-secure-login.com")


class TestHeuristics(unittest.TestCase):
    def _hops(self, *hosts):
        return [bhc.Hop(302, "https://%s/x" % h) for h in hosts]

    def test_clean_verdict(self):
        verdict, _ = bhc.classify(self._hops("bit.ly", "example.com"))
        self.assertEqual(verdict, "CLEAN")

    def test_ip_literal_is_suspicious(self):
        verdict, reasons = bhc.classify(self._hops("bit.ly", "185.220.101.5"))
        self.assertEqual(verdict, "SUSPICIOUS")
        self.assertTrue(any("IP address" in r for r in reasons))

    def test_punycode_is_suspicious(self):
        verdict, _ = bhc.classify(
            self._hops("bit.ly", "xn--exmple-cua.com"))
        self.assertEqual(verdict, "SUSPICIOUS")

    def test_second_shortener_hop_is_suspicious(self):
        verdict, _ = bhc.classify(
            self._hops("bit.ly", "t.co", "example.com"))
        self.assertEqual(verdict, "SUSPICIOUS")

    def test_expect_match_is_clean(self):
        verdict, _ = bhc.classify(self._hops("bit.ly", "example.com"),
                                  expect="example.com")
        self.assertEqual(verdict, "CLEAN")

    def test_expect_mismatch(self):
        verdict, reasons = bhc.classify(
            self._hops("bit.ly", "example-secure-login.com"),
            expect="example.com")
        self.assertEqual(verdict, "MISMATCH")
        self.assertTrue(any("does not match" in r for r in reasons))

    def test_expect_ignores_www_prefix(self):
        verdict, _ = bhc.classify(self._hops("bit.ly", "www.example.com"),
                                  expect="example.com")
        self.assertEqual(verdict, "CLEAN")


class TestEndToEnd(MockServerMixin, unittest.TestCase):
    def test_mock_clean_end_to_end(self):
        hops, verdict, _reasons, error = bhc.check_url(self.base + "/clean")
        self.assertIsNone(error)
        self.assertEqual(verdict, "CLEAN")

    def test_mock_hijacked_end_to_end(self):
        hops, verdict, _reasons, error = bhc.check_url(
            self.base + "/hijacked", expect="example.com")
        self.assertIsNone(error)
        # --expect mismatch is the hard fact here
        self.assertEqual(verdict, "MISMATCH")

    def test_unreachable_host_reports_error(self):
        hops, error = bhc.follow_redirects("http://127.0.0.1:1/nope",
                                           timeout=2)
        self.assertIsNotNone(error)
        self.assertIn("failed", error)

    def test_timeout_reports_error(self):
        hops, error = bhc.follow_redirects(self.base + "/slow", timeout=0.5)
        self.assertIsNotNone(error)

    def test_redirect_loop_reports_error(self):
        hops, error = bhc.follow_redirects(self.base + "/loop")
        self.assertIsNotNone(error)
        self.assertIn("loop", error)

    def test_cli_mock_mode_exits_zero(self):
        import subprocess
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.run(
            [sys.executable, os.path.join(here, "bitly_hijack_check.py"),
             "--mock"],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Verdict: CLEAN", proc.stdout)
        self.assertIn("Verdict: MISMATCH", proc.stdout)


if __name__ == "__main__":
    unittest.main()
