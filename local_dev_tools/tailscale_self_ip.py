#!/usr/bin/env python3
"""Print this machine's Tailscale IPv4 only when the node is online."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def tailscale_exe() -> str:
    found = shutil.which("tailscale")
    if found:
        return found

    fallback = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Tailscale" / "tailscale.exe"
    if fallback.exists():
        return str(fallback)

    return "tailscale"


def main() -> int:
    exe = tailscale_exe()
    try:
        result = subprocess.run(
            [exe, "status", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception as exc:
        print(f"[ERROR] Could not run '{exe} status --json': {exc}", file=sys.stderr)
        return 1

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        print(f"[ERROR] Tailscale status failed: {detail}", file=sys.stderr)
        return 1

    try:
        status = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(f"[ERROR] Tailscale returned invalid JSON: {exc}", file=sys.stderr)
        return 1

    self_status = status.get("Self") or {}
    health = status.get("Health") or []

    if not self_status.get("Online"):
        print("[ERROR] Tailscale reports this PC is offline.", file=sys.stderr)
        for message in health:
            print(f"        {message}", file=sys.stderr)
        return 2

    for ip in status.get("TailscaleIPs") or self_status.get("TailscaleIPs") or []:
        if "." in ip:
            print(ip)
            return 0

    print("[ERROR] Tailscale is online, but no IPv4 address was reported.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
