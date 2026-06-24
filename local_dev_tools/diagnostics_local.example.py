#!/usr/bin/env python3
"""EXAMPLE diagnostics plugin.

Copy this to ``diagnostics_local.py`` (git-ignored) and edit. The dashboard
discovers and loads that file automatically and renders a panel for each enabled
check. See diagnostics.py for the full contract; the short version:

  * Define check functions ``check(context, options) -> panel`` where
    ``panel = {"title": str, "level": "ok|warn|bad|neutral", "rows": [...]}``
    and each row is ``(key, value, level)``.
  * Expose ``checks() -> {name: check_callable}``.
  * A check only runs when its ``name`` is enabled in the ``diagnostics`` block
    of your config (see config.local.example.json). So to turn the sample below
    on, add ``"example": {"enabled": true, "service": "Spooler", "port": 9100}``
    under ``diagnostics`` in config.local.json.

``context`` gives you what the dashboard already collected:
  context["tcp_ports"]  -> set[int] of listening TCP ports
  context["udp_ports"]  -> set[int] of UDP ports
  context["proc_names"] -> set[str] of lowercased process image names
  context["diag_config"]-> the whole diagnostics config block
"""
try:
    from local_dev_tools.diagnostics import service_state
except ImportError:  # when run as a loose script with local_dev_tools/ on sys.path
    from diagnostics import service_state


def example_diag(context, options):
    """Report a Windows service's state and whether a port is listening."""
    options = options or {}
    service = options.get("service") or "Spooler"
    port = options.get("port")
    tcp_ports = context.get("tcp_ports") or set()

    state, _err = service_state(service)
    rows = [("Service", f"{service}: {state}", "ok" if state == "Running" else "warn")]
    level = "ok" if state == "Running" else "warn"

    if port:
        listening = int(port) in tcp_ports
        rows.append(("Port", f"{port} {'listening' if listening else 'not seen'}",
                     "ok" if listening else "warn"))
        if not listening:
            level = "warn"

    return {"title": options.get("title") or "Example", "level": level, "rows": rows}


def checks():
    return {"example": example_diag}


# Optional: contribute dynamic "port -> friendly name" mappings, e.g. reading an
# app's currently-configured port from its config file.
#
# def runtime_port_labels(diag_config):
#     return {12345: "My App"}
