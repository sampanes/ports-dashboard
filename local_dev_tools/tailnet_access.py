#!/usr/bin/env python3
"""Decide who may load the dashboard: this PC, plus your own tailnet devices.

The dashboard binds a tailnet IP so your phone can reach it, and the page is a
map of everything listening on this PC. Tailscale's policy file is the real
gate, but a default allow-all rule also admits people you have SHARED this
machine with. This module is the backstop: every non-loopback request is looked
up with `tailscale whois`, and only devices owned by the same Tailscale user as
this PC (or a login listed in the private config) get the page.

It fails closed: if Tailscale cannot be asked, or does not know the address,
the request is refused.

Pure standard library; the command runner and clock are injectable for tests.
"""
import ipaddress
import json
import threading
import time

try:
    from local_dev_tools.sysutil import command_path, program_files_path, run_result
except ImportError:  # when run as a loose script with local_dev_tools/ on sys.path
    from sysutil import command_path, program_files_path, run_result

ALLOW_TTL_SECONDS = 60
DENY_TTL_SECONDS = 15


def is_loopback(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    return (mapped or addr).is_loopback


class TailnetAccess:
    def __init__(self, allow_own_devices=True, allow_logins=(), runner=run_result,
                 exe=None, clock=time.monotonic):
        self.allow_own_devices = bool(allow_own_devices)
        self.allow_logins = {str(x).strip().lower() for x in allow_logins if str(x).strip()}
        self.runner = runner
        self.exe = exe or command_path("tailscale", program_files_path("Tailscale", "tailscale.exe"))
        self.clock = clock
        self._self_user = None
        self._cache = {}
        self._lock = threading.Lock()

    @classmethod
    def from_config(cls, config):
        access = (config.get("dashboard") or {}).get("access") or {}
        return cls(
            allow_own_devices=access.get("allow_own_devices", True),
            allow_logins=access.get("allow_logins") or (),
        )

    def _json(self, *args):
        code, out, err = self.runner([self.exe, *args], timeout=5)
        if code != 0:
            raise RuntimeError(err or out or f"tailscale exited {code}")
        return json.loads(out)

    def _self_user_id(self):
        if self._self_user is None:
            status = self._json("status", "--json")
            user = (status.get("Self") or {}).get("UserID")
            if not user:
                raise RuntimeError("tailscale status reported no Self.UserID")
            self._self_user = user
        return self._self_user

    def _decide(self, ip):
        try:
            who = self._json("whois", "--json", ip)
        except Exception as exc:
            return False, f"not a known tailnet peer ({exc})"
        profile = who.get("UserProfile") or {}
        node = who.get("Node") or {}
        user = node.get("User") or profile.get("ID")
        login = str(profile.get("LoginName") or "").lower()

        if login and login in self.allow_logins:
            return True, f"allowed login {login}"
        if self.allow_own_devices:
            try:
                if user and user == self._self_user_id():
                    return True, "own device"
            except Exception as exc:
                return False, f"could not read this PC's Tailscale user ({exc})"
        return False, f"device of another user ({login or 'unknown'})"

    def check(self, ip):
        """Return (allowed, reason) for a client address."""
        if is_loopback(ip):
            return True, "loopback"
        now = self.clock()
        with self._lock:
            hit = self._cache.get(ip)
            if hit and hit[0] > now:
                return hit[1], hit[2]
        allowed, reason = self._decide(ip)
        ttl = ALLOW_TTL_SECONDS if allowed else DENY_TTL_SECONDS
        with self._lock:
            self._cache[ip] = (now + ttl, allowed, reason)
        return allowed, reason
