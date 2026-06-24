#!/usr/bin/env python3
"""Optional, pluggable health-check panels for the ports dashboard.

The dashboard works fine without this module; when present it renders a
Diagnostics section. This file ships ONE generic, broadly-useful check
(Tailscale). Machine-specific checks live in a git-ignored sibling,
``diagnostics_local.py`` (copy ``diagnostics_local.example.py`` to start one) --
it is discovered and loaded automatically when present.

A "check" is a callable:

    check(context, options) -> {"title": str, "level": str, "rows": [...]}

    context : {"tcp_ports": set[int], "udp_ports": set[int],
               "proc_names": set[str], "diag_config": dict}
    options : that check's own config block (already known to be enabled)
    rows    : list of (key, value, level); level in ok | warn | bad | neutral

A plugin module may expose:

    checks() -> {name: check_callable}
    runtime_port_labels(diag_config) -> {int_port: str_label}   # optional

Which checks run, and with what parameters, is driven entirely by the
``diagnostics`` block of your config (see config.default.json / config.local.json).
"""
import json
import re

try:
    from local_dev_tools.sysutil import run_result, command_path, program_files_path
except ImportError:  # when run as a loose script with local_dev_tools/ on sys.path
    from sysutil import run_result, command_path, program_files_path


def service_state(name):
    """(state, detail) for a Windows service via ``sc query``. Generic helper
    shared by checks."""
    rc, out, err = run_result(["sc.exe", "query", name], timeout=3)
    if rc != 0:
        return "unknown", err or out or "service query failed"
    match = re.search(r"STATE\s+:\s+\d+\s+(\w+)", out)
    if not match:
        return "unknown", "service state not found"
    return match.group(1).title(), ""


def tailscale_diag(context, options):
    """Is this node up on its tailnet, and is any phone peer online?"""
    options = options or {}
    state, state_err = service_state(options.get("service") or "Tailscale")
    exe = command_path("tailscale", program_files_path("Tailscale", "tailscale.exe"))
    rc, out, err = run_result([exe, "status", "--json"], timeout=2)

    rows = [("Service", state, "ok" if state == "Running" else "bad")]
    level = "bad" if state != "Running" else "warn"

    if rc != 0:
        rows.append(("Status", err or out or "unavailable", "bad"))
        if state_err:
            rows.append(("Detail", state_err, "warn"))
        return {"title": "Tailscale", "level": level, "rows": rows}

    try:
        status = json.loads(out)
    except json.JSONDecodeError as exc:
        rows.append(("Status", f"invalid JSON: {exc}", "bad"))
        return {"title": "Tailscale", "level": "bad", "rows": rows}

    self_status = status.get("Self") or {}
    online = bool(self_status.get("Online"))
    backend = status.get("BackendState") or "unknown"
    ips = self_status.get("TailscaleIPs") or status.get("TailscaleIPs") or []
    tailnet_ip = next((ip for ip in ips if "." in ip), "")
    health = status.get("Health") or []
    peers = list((status.get("Peer") or {}).values())
    mobile = [
        peer for peer in peers
        if str(peer.get("OS") or "").lower() in {"android", "ios"}
        or "phone" in str(peer.get("HostName") or peer.get("DNSName") or "").lower()
    ]
    online_mobile = [peer for peer in mobile if peer.get("Online")]

    rows.append(("This PC", "online" if online else "offline", "ok" if online else "bad"))
    rows.append(("Backend", backend, "ok" if backend == "Running" else "warn"))
    rows.append(("Tailnet IP", tailnet_ip or "none", "ok" if tailnet_ip else "warn"))
    rows.append((
        "Mobile peers",
        f"{len(online_mobile)} online / {len(mobile)} known",
        "ok" if online_mobile else ("warn" if mobile else "neutral"),
    ))
    rows.append(("Health", health[0] if health else "no warnings", "warn" if health else "ok"))

    level = "ok" if online and not health else ("warn" if online else "bad")
    return {"title": "Tailscale", "level": level, "rows": rows}


# name -> check. Local plugins add to this at runtime via checks().
BUILTIN_CHECKS = {
    "tailscale": tailscale_diag,
}


def _local_plugin():
    """Import the optional git-ignored diagnostics_local plugin, or None."""
    try:
        from local_dev_tools import diagnostics_local
        return diagnostics_local
    except ImportError:
        try:
            import diagnostics_local
            return diagnostics_local
        except ImportError:
            return None


def _all_checks():
    checks = dict(BUILTIN_CHECKS)
    plugin = _local_plugin()
    if plugin is not None and callable(getattr(plugin, "checks", None)):
        try:
            checks.update(plugin.checks() or {})
        except Exception:
            pass
    return checks


def is_enabled(diag_config, name):
    section = (diag_config or {}).get(name)
    return bool(section.get("enabled")) if isinstance(section, dict) else False


def collect_diagnostics(context, diag_config):
    """Run every enabled check (built-in + local plugin) and return their panels."""
    diag_config = diag_config or {}
    context = dict(context or {})
    context.setdefault("diag_config", diag_config)
    panels = []
    for name, check in _all_checks().items():
        if not is_enabled(diag_config, name):
            continue
        try:
            panels.append(check(context, diag_config.get(name) or {}))
        except Exception as exc:
            panels.append({"title": name.title(), "level": "bad",
                           "rows": [("Error", str(exc), "bad")]})
    return panels


def runtime_port_labels(diag_config):
    """Dynamic port -> label mappings contributed by a local plugin (e.g. an
    app's currently-configured port). Empty when no plugin is present."""
    labels = {}
    plugin = _local_plugin()
    if plugin is not None and callable(getattr(plugin, "runtime_port_labels", None)):
        try:
            labels.update(plugin.runtime_port_labels(diag_config or {}) or {})
        except Exception:
            pass
    return labels
