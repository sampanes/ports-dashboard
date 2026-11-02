"""Tests for the dashboard's tailnet identity check. Run: python -m unittest"""
import json
import unittest

from local_dev_tools.tailnet_access import TailnetAccess, is_loopback

SELF_USER = 111
OTHER_USER = 222


def whois(user, login):
    return json.dumps({"Node": {"User": user}, "UserProfile": {"ID": user, "LoginName": login}})


class FakeTailscale:
    """Stands in for run_result: answers status/whois from a table."""

    def __init__(self, peers, self_user=SELF_USER, status_fails=False):
        self.peers = peers
        self.self_user = self_user
        self.status_fails = status_fails
        self.calls = []

    def __call__(self, cmd, timeout=4):
        self.calls.append(cmd[1:])
        if cmd[1] == "status":
            if self.status_fails:
                return 1, "", "daemon not running"
            return 0, json.dumps({"Self": {"UserID": self.self_user}}), ""
        if cmd[1] == "whois":
            ip = cmd[-1]
            if ip in self.peers:
                return 0, self.peers[ip], ""
            return 1, "", f"no match for IP {ip}"
        return 1, "", "unexpected command"


PEERS = {
    "100.64.0.2": whois(SELF_USER, "me@example.com"),
    "100.64.0.3": whois(OTHER_USER, "friend@example.com"),
}


def access(runner, **kw):
    return TailnetAccess(runner=runner, exe="tailscale", **kw)


class TailnetAccessTests(unittest.TestCase):
    def test_loopback_never_asks_tailscale(self):
        ts = FakeTailscale(PEERS)
        a = access(ts)
        for ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            self.assertEqual(a.check(ip), (True, "loopback"))
        self.assertEqual(ts.calls, [])

    def test_own_device_allowed(self):
        allowed, reason = access(FakeTailscale(PEERS)).check("100.64.0.2")
        self.assertTrue(allowed)
        self.assertEqual(reason, "own device")

    def test_shared_user_refused(self):
        allowed, reason = access(FakeTailscale(PEERS)).check("100.64.0.3")
        self.assertFalse(allowed)
        self.assertIn("another user", reason)

    def test_allowlisted_login_admitted(self):
        a = access(FakeTailscale(PEERS), allow_logins=["Friend@Example.com"])
        self.assertTrue(a.check("100.64.0.3")[0])

    def test_unknown_address_refused(self):
        self.assertFalse(access(FakeTailscale(PEERS)).check("192.168.1.50")[0])

    def test_fails_closed_when_self_unknown(self):
        a = access(FakeTailscale(PEERS, status_fails=True))
        allowed, reason = a.check("100.64.0.2")
        self.assertFalse(allowed)
        self.assertIn("could not read", reason)

    def test_own_devices_can_be_switched_off(self):
        a = access(FakeTailscale(PEERS), allow_own_devices=False)
        self.assertFalse(a.check("100.64.0.2")[0])

    def test_verdict_cached_then_expires(self):
        now = [1000.0]
        ts = FakeTailscale(PEERS)
        a = access(ts, clock=lambda: now[0])
        a.check("100.64.0.2")
        a.check("100.64.0.2")
        whois_calls = [c for c in ts.calls if c[0] == "whois"]
        self.assertEqual(len(whois_calls), 1)
        now[0] += 61
        a.check("100.64.0.2")
        whois_calls = [c for c in ts.calls if c[0] == "whois"]
        self.assertEqual(len(whois_calls), 2)

    def test_from_config(self):
        a = TailnetAccess.from_config(
            {"dashboard": {"access": {"allow_own_devices": False, "allow_logins": ["X@Y.Z"]}}}
        )
        self.assertFalse(a.allow_own_devices)
        self.assertEqual(a.allow_logins, {"x@y.z"})


if __name__ == "__main__":
    unittest.main()
