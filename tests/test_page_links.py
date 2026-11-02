"""Tests for how the page turns the browser's Host header into port links."""
import unittest

from local_dev_tools.ports_dashboard import host_from_header, render_rows


def row(**over):
    r = {
        "name": "svc", "image": "svc.exe", "host": "0.0.0.0", "pid": 42,
        "bucket": "all", "buckets": ["all"], "proto": "TCP", "port": 8080,
        "service": "", "scope": "all interfaces", "raw_count": 1,
        "name_source": "none",
    }
    r.update(over)
    return r


class HostHeaderTests(unittest.TestCase):
    def test_forms(self):
        cases = {
            "": "127.0.0.1",
            "localhost": "localhost",
            "localhost:18790": "localhost",
            "100.64.0.2:18790": "100.64.0.2",
            "my-pc.example.ts.net:18790": "my-pc.example.ts.net",
            "[::1]:18790": "::1",
            "[fd7a:115c:a1e0::1]": "fd7a:115c:a1e0::1",
            "[fd7a:115c:a1e0::1]:18790": "fd7a:115c:a1e0::1",
        }
        for header, want in cases.items():
            with self.subTest(header=header):
                self.assertEqual(host_from_header(header), want)


class PortLinkTests(unittest.TestCase):
    def test_ipv6_host_is_bracketed(self):
        out = render_rows([row()], "fd7a:115c:a1e0::1")
        self.assertIn('href="http://[fd7a:115c:a1e0::1]:8080/"', out)

    def test_hostile_host_cannot_break_out_of_href(self):
        out = render_rows([row()], 'evil"><script>alert(1)</script>')
        self.assertNotIn("<script>", out)
        self.assertNotIn('evil">', out)


if __name__ == "__main__":
    unittest.main()
