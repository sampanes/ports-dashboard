#!/usr/bin/env python3
"""Load dashboard configuration: public defaults plus an optional private layer.

Two files, both at the repo root:

  config.default.json  (committed)   Generic, shareable batteries-included
                                     defaults. Always loaded. Contains nothing
                                     personal -- public port labels, common app
                                     names, the diagnostics framework with only
                                     the broadly-useful checks enabled.

  config.local.json    (gitignored)  YOUR machine: custom port nicknames,
                                     machine-specific process labels, extra
                                     pinned ports, and which diagnostics to run.
                                     Deep-merged ON TOP of the defaults, so it
                                     only needs the deltas. Optional -- the tool
                                     works fine on defaults alone.

Set the PORTS_DASHBOARD_CONFIG environment variable to load the private layer
from somewhere other than ./config.local.json.

Merge rules (so a local file only needs to express additions):
  * dicts        -> merged key by key  (local keys override / extend defaults)
  * lists        -> unioned, order kept (local entries ADD to defaults)
  * scalars      -> local replaces default

Pure standard-library JSON on purpose: still nothing to pip install, still
nothing to vet.
"""
import json
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "config.default.json"
LOCAL_CONFIG_PATH = REPO_ROOT / "config.local.json"


def deep_merge(base, overlay):
    """Merge overlay onto base. Dicts merge, lists union, scalars replace."""
    if isinstance(base, dict) and isinstance(overlay, dict):
        out = dict(base)
        for key, value in overlay.items():
            out[key] = deep_merge(out[key], value) if key in out else value
        return out
    if isinstance(base, list) and isinstance(overlay, list):
        merged = list(base)
        for item in overlay:
            if item not in merged:
                merged.append(item)
        return merged
    return overlay


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        # A missing or broken private config must never take the dashboard down.
        print(f"[WARN] ignoring config {path}: {exc}")
        return {}
    return data if isinstance(data, dict) else {}


def local_config_path():
    override = os.environ.get("PORTS_DASHBOARD_CONFIG")
    return Path(override) if override else LOCAL_CONFIG_PATH


def load_config():
    """Return the merged config dict (defaults + optional private layer)."""
    config = _load_json(DEFAULT_CONFIG_PATH)
    local = _load_json(local_config_path())
    return deep_merge(config, local) if local else config
