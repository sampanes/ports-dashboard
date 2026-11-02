#!/usr/bin/env python3
r"""
ports_dashboard.py - tiny, stdlib-only web view of THIS PC's listening ports,
with friendly names, meant to work locally first and from a phone over
Tailscale when Tailscale is healthy.

Why this exists
---------------
Tailscale only ROUTES your phone to this PC (the 100.x tailnet IP); it has no
"list this host's services" feature. This serves a page that does.

Names come from (best -> fuzziest):
  0. SELF: our own listener (matched by PID) is always "Ports dashboard". We never
     trust the window title for our own row, because Windows stamps our console
     with the launch command line ("ports-dashboard - python ...ports_dashboard.py
     --host ... --port ..."), which is the long noise you'd otherwise see.
  1. Window title from `tasklist /v`  <- your `start "my-name" ...` hygiene lands here
  2. Well-known port label (5432 -> PostgreSQL, 11434 -> Ollama, ...)
  3. Process label by image name (postgres.exe -> PostgreSQL)

Every row shows WHICH of those layers named it ("via window title", "via port
label", "via self", ...), so the labeling is auditable rather than a black box.

GOTCHA: the window-title layer only resolves when this runs in your INTERACTIVE
desktop session (launch via start-ports-dashboard.bat). As a background service,
`tasklist /v` returns blank titles.

UI: stacked cards (no horizontal scroll on a phone). Each blue port link opens
that service through the same host you used to view the dashboard; loopback-only
services are clickable when the dashboard is opened on this PC. No auto-refresh
(each refresh runs `tasklist /v`); the Refresh button re-fetches the page in
place, keeping your scroll position and which sections you've expanded, and
says so next to "updated" if the fetch fails.

Pure standard library on purpose: no pip install, nothing to vet, runs as-is.
"""
import argparse
import csv
import ctypes
import json
import html
import io
import os
import re
import socket
import subprocess
import threading
import time
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from local_dev_tools.config import load_config
except ImportError:  # when run as a loose script with local_dev_tools/ on sys.path
    from config import load_config

try:
    from local_dev_tools.sysutil import run_result
except ImportError:
    from sysutil import run_result

try:
    from local_dev_tools.tailnet_access import TailnetAccess
except ImportError:
    from tailnet_access import TailnetAccess

# Optional, pluggable diagnostics. The dashboard runs fine without it.
try:
    from local_dev_tools import diagnostics
except ImportError:
    try:
        import diagnostics
    except ImportError:
        diagnostics = None


# Everything machine-specific lives in config (config.default.json + your private
# config.local.json), not in this file. See config.py and README "Configuration".
_CONFIG = load_config()


def _int_keyed(mapping):
    out = {}
    for key, value in (mapping or {}).items():
        try:
            out[int(key)] = value
        except (TypeError, ValueError):
            continue
    return out


def _int_set(values):
    out = set()
    for value in values or []:
        try:
            out.add(int(value))
        except (TypeError, ValueError):
            continue
    return out


def _lower_keyed(mapping):
    return {str(k).lower(): v for k, v in (mapping or {}).items()}


_DASHBOARD_CFG = _CONFIG.get("dashboard") or {}
DASHBOARD_PORT = int(_DASHBOARD_CFG.get("port", 18790))
SELF_NAME = _DASHBOARD_CFG.get("self_name") or "Ports dashboard"

WELL_KNOWN = _int_keyed(_CONFIG.get("port_labels"))            # port -> friendly name
SYSTEM_PORTS = _int_set(_CONFIG.get("system_ports"))
PINNED_PORTS = _int_set(_CONFIG.get("pinned_ports"))
USER_FACING_TERMS = tuple(str(t).lower() for t in (_CONFIG.get("user_facing_terms") or []))
BACKGROUND_PROCESS_IMAGES = {str(x).lower() for x in (_CONFIG.get("background_process_images") or [])}
PROC_LABELS = _lower_keyed(_CONFIG.get("process_labels"))      # image name -> what it IS
PROC_LABEL_PREFIXES = _lower_keyed(_CONFIG.get("process_label_prefixes"))
DIAGNOSTICS_CONFIG = _CONFIG.get("diagnostics") or {}
ACCESS = TailnetAccess.from_config(_CONFIG)


def proc_label(image):
    """Friendly 'what is this app' from the process image name (+ prefix rules)."""
    name = image.lower()
    if name in PROC_LABELS:
        return PROC_LABELS[name]
    for prefix, label in PROC_LABEL_PREFIXES.items():
        if name.startswith(prefix):
            return label
    return ""


PORT_RE = re.compile(r":(\d+)$")
PRIVATE_172_RE = re.compile(r"172\.(1[6-9]|2\d|3[01])\.")


def run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout or ""
    except Exception:
        return ""


def parse_tasklist_csv(out, have_titles):
    table = {}
    title_count = 0
    for row in csv.reader(io.StringIO(out)):
        if len(row) < 2:
            continue
        try:
            pid = int(row[1])
        except ValueError:
            continue  # skips the header row too
        # plain `tasklist` has no Window Title column -> row[-1] is mem usage there
        title = row[-1].strip() if have_titles else ""
        if title in ("N/A", ""):
            title = ""
        if title:
            title_count += 1
        table[pid] = (row[0], title)
    return table, title_count


def normalize_process_image(name):
    image = (name or "").strip()
    if not image:
        return "?"
    if image.lower() in {"idle", "system", "registry", "secure system"}:
        return image
    if image.lower().endswith(".exe"):
        return image
    return f"{image}.exe"


def get_proc_table_from_winapi():
    if os.name != "nt":
        return {}, 0, "Windows API process lookup only runs on Windows"
    try:
        table, parents = winapi_process_snapshot()
        if not table:
            return {}, 0, "Windows API process snapshot returned no rows"
        for pid, title in winapi_window_titles().items():
            if pid in table:
                table[pid] = (table[pid][0], title)
        title_count = sum(1 for _image, title in table.values() if title)
        title_count += propagate_parent_titles(table, parents)
        return table, title_count, ""
    except Exception as exc:
        return {}, 0, f"Windows API process lookup failed: {exc}"


def winapi_process_snapshot():
    kernel32 = ctypes.windll.kernel32
    snapshot_flag_process = 0x00000002
    invalid_handle_value = ctypes.c_void_p(-1).value

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.CreateToolhelp32Snapshot(snapshot_flag_process, 0)
    if handle == invalid_handle_value:
        return {}, {}
    table = {}
    parents = {}
    try:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        has_entry = kernel32.Process32FirstW(handle, ctypes.byref(entry))
        while has_entry:
            pid = int(entry.th32ProcessID)
            table[pid] = (normalize_process_image(entry.szExeFile), "")
            parent_id = int(entry.th32ParentProcessID)
            if parent_id:
                parents[pid] = parent_id
            has_entry = kernel32.Process32NextW(handle, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(handle)
    return table, parents


def winapi_window_titles():
    user32 = ctypes.windll.user32
    enum_windows_proc = ctypes.WINFUNCTYPE(
        wintypes.BOOL,
        wintypes.HWND,
        wintypes.LPARAM,
    )
    titles = {}

    user32.EnumWindows.argtypes = [enum_windows_proc, wintypes.LPARAM]
    user32.EnumWindows.restype = wintypes.BOOL
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL

    @enum_windows_proc
    def collect_title(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        title = (buf.value or "").strip()
        if not title:
            return True
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value:
            titles[int(pid.value)] = title
        return True

    user32.EnumWindows(collect_title, 0)
    return titles


def get_proc_table_from_powershell():
    command = (
        "$parents = @{}; "
        "try { "
        "  Get-CimInstance Win32_Process | ForEach-Object { "
        "    $parents[[string]$_.ProcessId] = [int]$_.ParentProcessId "
        "  } "
        "} catch {}; "
        "Get-Process | ForEach-Object { "
        "  [pscustomobject]@{"
        "    Id=$_.Id;"
        "    ProcessName=$_.ProcessName;"
        "    MainWindowTitle=$_.MainWindowTitle;"
        "    ParentProcessId=$parents[[string]$_.Id]"
        "  } "
        "} | ConvertTo-Json -Compress"
    )
    rc, out, err = run_result(["powershell", "-NoProfile", "-Command", command], timeout=5)
    if rc != 0 or not out:
        return {}, 0, err or out or "Get-Process returned no rows"
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        return {}, 0, f"Get-Process JSON parse failed: {exc}"
    if isinstance(data, dict):
        data = [data]
    table = {}
    parents = {}
    title_count = 0
    for item in data if isinstance(data, list) else []:
        try:
            pid = int(item.get("Id"))
        except (TypeError, ValueError, AttributeError):
            continue
        title = str(item.get("MainWindowTitle") or "").strip()
        if title:
            title_count += 1
        try:
            parent_id = int(item.get("ParentProcessId"))
        except (TypeError, ValueError):
            parent_id = 0
        if parent_id:
            parents[pid] = parent_id
        table[pid] = (normalize_process_image(item.get("ProcessName")), title)
    title_count += propagate_parent_titles(table, parents)
    return table, title_count, ""


def propagate_parent_titles(table, parents):
    propagated = 0
    for pid, (image, title) in list(table.items()):
        if title:
            continue
        seen = {pid}
        parent_id = parents.get(pid)
        depth = 0
        while parent_id and parent_id not in seen and depth < 8:
            seen.add(parent_id)
            parent = table.get(parent_id)
            if parent and parent[1]:
                table[pid] = (image, parent[1])
                propagated += 1
                break
            parent_id = parents.get(parent_id)
            depth += 1
    return propagated


def merge_missing_titles(target, source):
    merged = 0
    for pid, (image, title) in list(target.items()):
        if title:
            continue
        source_title = (source.get(pid) or ("", ""))[1]
        if source_title:
            target[pid] = (image, source_title)
            merged += 1
    return merged


def get_proc_table():
    """Return (PID table, title_state, detail).

    `tasklist /v` (the verbose form that carries the window TITLE) needs an
    interactive desktop; with no console attached it stalls until timeout. So we
    cap it short and, if it comes back empty/stalled/blocked, fall back to plain
    `tasklist`, then PowerShell `Get-Process`. Only the verbose tasklist path is
    treated as authoritative for console title labels.
    """
    rc, out, err = run_result(["tasklist", "/v", "/fo", "csv"], timeout=2.5)
    if rc == 0 and out.strip():
        table, title_count = parse_tasklist_csv(out, have_titles=True)
        if table:
            winapi_table, _winapi_title_count, _winapi_detail = get_proc_table_from_winapi()
            if winapi_table:
                title_count += merge_missing_titles(table, winapi_table)
            return table, "ok" if title_count else "none", ""
    detail = err or "tasklist /v returned no rows"

    rc, out, err = run_result(["tasklist", "/fo", "csv"], timeout=4)
    if rc == 0 and out.strip():
        table, _title_count = parse_tasklist_csv(out, have_titles=False)
        if table:
            winapi_table, winapi_title_count, _winapi_detail = get_proc_table_from_winapi()
            if winapi_table:
                winapi_title_count = merge_missing_titles(table, winapi_table)
            return table, "ok" if winapi_title_count else "unavailable", detail
    if err:
        detail = detail or err

    table, title_count, winapi_detail = get_proc_table_from_winapi()
    if table:
        return table, "ok" if title_count else "unavailable", detail
    if winapi_detail:
        detail = detail or winapi_detail

    table, title_count, ps_detail = get_proc_table_from_powershell()
    if table:
        return table, "ok" if title_count else "unavailable", detail
    return {}, "unavailable", detail or ps_detail


PROC_CACHE_SECONDS = 10
_proc_cache = {"expires": 0.0, "value": None}
_proc_cache_lock = threading.Lock()


def get_proc_table_cached():
    now = time.monotonic()
    with _proc_cache_lock:
        cached = _proc_cache.get("value")
        if cached is not None and now < _proc_cache.get("expires", 0):
            return cached

    value = get_proc_table()
    with _proc_cache_lock:
        _proc_cache["value"] = value
        _proc_cache["expires"] = time.monotonic() + PROC_CACHE_SECONDS
    return value



def parse_addr(local):
    """('0.0.0.0:135'|'[::]:445'|'[fe80::1%19]:139') -> (host, port)."""
    m = PORT_RE.search(local)
    if not m:
        return local, None
    host = local[: m.start()].strip("[]")
    return host, int(m.group(1))


def scope_of(host):
    """Returns (bucket, label). bucket drives which section + color."""
    h = host.lower()
    if h.startswith("127.") or h == "::1":
        return "local", "loopback"
    if h in ("0.0.0.0", "::", ""):
        return "all", "ALL interfaces"
    if h.startswith("100.") or h.startswith("fd7a:115c:a1e0"):
        return "tailnet", "tailnet"
    if h.startswith("192.168.") or h.startswith("10.") or PRIVATE_172_RE.match(h):
        return "lan", "LAN only"
    if h.startswith("fe80"):
        return "local", "link-local"
    return "other", host


def get_listeners():
    """TCP LISTENING + UDP sockets from netstat -ano, de-duplicated."""
    out = run(["netstat", "-ano"])
    seen, rows = set(), []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        proto = p[0].upper()
        if proto == "TCP":
            if len(p) < 5 or p[3].upper() != "LISTENING":
                continue
            local, pid = p[1], p[4]
        elif proto == "UDP":
            local, pid = p[1], p[-1]
        else:
            continue
        host, port = parse_addr(local)
        if port is None:
            continue
        try:
            pid_i = int(pid)
        except ValueError:
            pid_i = -1
        key = (proto, host, port, pid_i)
        if key in seen:
            continue
        seen.add(key)
        bucket, label = scope_of(host)
        rows.append({
            "proto": proto, "host": host, "port": port,
            "pid": pid_i, "bucket": bucket, "scope": label,
        })
    return rows


SELF_PID = os.getpid()

# Human-readable explanation of WHICH layer produced a row's display name, so the
# UI can show "via port label" / "via window title" instead of being a black box.
NAME_SOURCE_LABELS = {
    "self": "self (PID match)",
    "title": "window title",
    "port": "port label",
    "proc": "process name",
    "image": "image name",
    "none": "no label",
}


def resolve_name(pid, title, port_label, proc_label_text, image, self_pid):
    """Pick a row's display name and report which layer it came from.

    Self is special-cased FIRST: our own listener's window title is just the
    command line Windows stamped onto our console ("ports-dashboard - python
    ...\\ports_dashboard.py --host ... --port ..."), which is noise. We know our
    own PID, so we label it plainly instead of trusting that title.
    """
    if pid == self_pid:
        return SELF_NAME, "self"
    if title:
        return title, "title"
    if port_label:
        return port_label, "port"
    if proc_label_text:
        return proc_label_text, "proc"
    if image and image != "?":
        return image, "image"
    return "", "none"


def enrich(rows, procs, port_labels=None, self_pid=SELF_PID):
    port_labels = port_labels or {}
    for r in rows:
        image, title = procs.get(r["pid"], ("?", ""))
        r["image"] = image
        r["title"] = title
        port_lbl = port_labels.get(r["port"]) or WELL_KNOWN.get(r["port"], "")
        plabel = proc_label(image) if image != "?" else ""
        r["port_label"] = port_lbl
        r["proc_label"] = plabel
        name, source = resolve_name(r["pid"], title, port_lbl, plabel, image, self_pid)
        r["is_self"] = source == "self"
        # "what is it" -- for self, force the friendly label even on a custom port.
        r["service"] = SELF_NAME if r["is_self"] else (port_lbl or plabel)
        r["name"] = name
        r["name_source"] = source
    return rows


def listening_ports(rows, proto="TCP"):
    return {r["port"] for r in rows if r["proto"] == proto}


BUCKET_ORDER = {"tailnet": 0, "all": 1, "lan": 2, "local": 3, "other": 4}
BUCKET_LABELS = {
    "tailnet": "tailnet",
    "all": "ALL interfaces",
    "lan": "LAN only",
    "local": "this PC",
    "other": "other",
}


def host_sort_key(host):
    bucket, _label = scope_of(host)
    return (BUCKET_ORDER.get(bucket, 9), host.count(":"), host)


def group_scope(buckets):
    ordered = [bucket for bucket in BUCKET_ORDER if bucket in buckets]
    if not ordered:
        return "unknown"
    if ordered == ["all"]:
        return "ALL interfaces"
    if "tailnet" in buckets and "local" in buckets and len(buckets) == 2:
        return "tailnet + this PC"
    return " + ".join(BUCKET_LABELS.get(bucket, bucket) for bucket in ordered)


def group_bucket(buckets):
    ordered = [bucket for bucket in BUCKET_ORDER if bucket in buckets]
    return ordered[0] if ordered else "other"


def summarize_hosts(hosts):
    clean = sorted({host for host in hosts if host}, key=host_sort_key)
    if not clean:
        return "unknown"
    if len(clean) <= 3:
        return ", ".join(clean)
    return f"{len(clean)} binds: " + ", ".join(clean[:3]) + ", ..."


def group_listeners(rows):
    grouped = {}
    for row in rows:
        key = (row["proto"], row["port"], row["pid"])
        group = grouped.get(key)
        if group is None:
            group = dict(row)
            group["hosts"] = []
            group["buckets"] = set()
            group["raw_count"] = 0
            grouped[key] = group
        group["hosts"].append(row["host"])
        group["buckets"].add(row["bucket"])
        group["raw_count"] += 1

    groups = []
    for group in grouped.values():
        buckets = group["buckets"]
        group["bucket"] = group_bucket(buckets)
        group["scope"] = group_scope(buckets)
        group["binds"] = summarize_hosts(group["hosts"])
        group["hosts"] = tuple(sorted(set(group["hosts"]), key=host_sort_key))
        group["buckets"] = frozenset(buckets)
        groups.append(group)
    return groups


def group_is_network_reachable(group):
    buckets = group.get("buckets") or set()
    return group["proto"] == "TCP" and bool({"tailnet", "all"} & set(buckets))


def group_is_local_only(group):
    return group["proto"] == "TCP" and not group_is_network_reachable(group)


def has_focus_label(group):
    text = " ".join(
        str(group.get(key) or "").lower()
        for key in ("name", "service", "image", "title")
    )
    return any(term in text for term in USER_FACING_TERMS)


def is_dynamic_ephemeral(group):
    port = group["port"]
    return port >= 49152 and not group.get("service") and not group.get("title")


def is_system_noise(group):
    image = str(group.get("image") or "").lower()
    port = group["port"]
    if image in BACKGROUND_PROCESS_IMAGES:
        return True
    if port in SYSTEM_PORTS:
        return True
    if group["proto"] == "UDP" and port not in PINNED_PORTS and not group.get("port_label"):
        return True
    if port in PINNED_PORTS or has_focus_label(group):
        return False
    if image in {"system", "lsass.exe", "services.exe", "wininit.exe", "spoolsv.exe",
                 "dllhost.exe", "dashost.exe", "svchost.exe"}:
        return True
    if group["proto"] == "UDP" and (port >= 49152 or port in {1900, 2177, 3702, 5353, 5355}):
        return True
    return is_dynamic_ephemeral(group)


def is_focused_group(group):
    if is_system_noise(group):
        return False
    if group["port"] in PINNED_PORTS:
        return True
    if group.get("port_label") and group["port"] not in SYSTEM_PORTS:
        return True
    if has_focus_label(group):
        return True
    if group.get("title"):
        return True
    return False


def group_sort_key(group):
    return (
        0 if is_focused_group(group) else 1,
        BUCKET_ORDER.get(group.get("bucket"), 9),
        group["port"],
        group["proto"],
        str(group.get("name") or group.get("image") or "").lower(),
    )


def diag_level(text):
    return {
        "ok": "ok",
        "warn": "warn",
        "bad": "bad",
    }.get(text, "neutral")


def runtime_port_labels():
    """Dynamic port -> label mappings contributed by the diagnostics plugin
    (e.g. an app's currently-configured port). Empty when diagnostics are off."""
    if diagnostics is None:
        return {}
    return diagnostics.runtime_port_labels(DIAGNOSTICS_CONFIG)


def collect_diagnostics(procs, listener_rows):
    """Hand the dashboard's already-collected port/process facts to the optional
    diagnostics framework, which runs whichever checks are enabled in config."""
    if diagnostics is None:
        return []
    context = {
        "tcp_ports": listening_ports(listener_rows, "TCP"),
        "udp_ports": listening_ports(listener_rows, "UDP"),
        "proc_names": {image.lower() for image, _title in procs.values()
                       if image and image != "?"},
    }
    return diagnostics.collect_diagnostics(context, DIAGNOSTICS_CONFIG)


DIAG_CACHE_SECONDS = 12
_diag_cache = {"expires": 0.0, "value": None}
_diag_cache_lock = threading.Lock()


def collect_diagnostics_cached(procs, listener_rows):
    now = time.monotonic()
    with _diag_cache_lock:
        cached = _diag_cache.get("value")
        if cached is not None and now < _diag_cache.get("expires", 0):
            return cached

    value = collect_diagnostics(procs, listener_rows)
    with _diag_cache_lock:
        _diag_cache["value"] = value
        _diag_cache["expires"] = time.monotonic() + DIAG_CACHE_SECONDS
    return value


# ----------------------------- HTML -----------------------------------------

# Tiny inline favicon (the plug emoji) so the browser tab + a phone bookmark get
# an icon, and /favicon.ico stops 404-ing in the log.
FAVICON = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
    '<text y="52" font-size="52">\U0001F50C</text></svg>'
).encode("utf-8")

STYLE = """
  :root {
    color-scheme: dark;
    --bg: #0b0c0f;
    --panel: #141519;
    --panel-2: #191b20;
    --line: #2a2d35;
    --line-soft: #20232a;
    --text: #ebe7df;
    --muted: #9aa0a6;
    --faint: #707782;
    --accent: #5aa7ff;
    --ok: #55c87a;
    --warn: #d7a52a;
    --bad: #ff6b6b;
  }
  * { box-sizing: border-box; }
  body {
    font: 14px/1.45 system-ui, Segoe UI, sans-serif;
    margin: 0;
    background: var(--bg);
    color: var(--text);
    -webkit-text-size-adjust: 100%;
    overflow-x: hidden;
  }
  header {
    position: sticky;
    top: 0;
    z-index: 2;
    background: rgba(11, 12, 15, 0.96);
    border-bottom: 1px solid var(--line);
    backdrop-filter: blur(8px);
  }
  .header-inner {
    max-width: 1320px;
    margin: 0 auto;
    padding: 14px 16px 12px;
    display: grid;
    gap: 10px;
  }
  h1 {
    font-size: 20px;
    line-height: 1.2;
    margin: 0 0 5px;
    letter-spacing: 0;
  }
  .meta { color: var(--muted); font-size: 12px; }
  .meta code {
    color: var(--accent);
    background: var(--panel);
    padding: 1px 5px;
    border-radius: 4px;
  }
  .toolbar {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 10px;
    align-items: center;
  }
  #content {
    max-width: 1320px;
    margin: 0 auto;
    padding: 12px 16px 30px;
  }
  section { padding: 0; }
  h2,
  details summary {
    color: var(--muted);
    font-size: 12px;
    font-weight: 700;
    letter-spacing: .03em;
    text-transform: uppercase;
  }
  h2 {
    margin: 18px 0 6px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--line-soft);
  }
  details summary {
    cursor: pointer;
    list-style-position: outside;
    margin: 18px 0 6px;
    padding: 0 0 6px 2px;
    border-bottom: 1px solid var(--line-soft);
  }
  .card {
    padding: 10px 4px;
    border-bottom: 1px solid var(--line-soft);
  }
  .top {
    display: grid;
    grid-template-columns: 72px minmax(0, 1fr) auto;
    align-items: center;
    gap: 10px;
  }
  .port {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 62px;
    height: 34px;
    padding: 0 10px;
    border-radius: 6px;
    background: #172338;
    color: var(--accent);
    font-size: 17px;
    font-weight: 800;
    text-align: center;
  }
  a.port { text-decoration: none; }
  a.port:active { background: #1e3a2d; }
  .port.dim {
    color: var(--faint);
    background: var(--panel);
    font-weight: 700;
  }
  .name {
    font-weight: 700;
    font-size: 15px;
    min-width: 0;
    word-break: break-word;
  }
  .svc { color: var(--muted); }
  .self {
    margin-left: 6px;
    font-size: 11px;
    font-weight: 700;
    color: #9cf0b7;
    background: #123820;
    border: 1px solid #245b35;
    border-radius: 999px;
    padding: 1px 7px;
    white-space: nowrap;
    vertical-align: middle;
  }
  .sub {
    color: var(--faint);
    font-size: 12px;
    margin-top: 4px;
    padding-left: 82px;
    word-break: break-word;
  }
  .badge {
    justify-self: end;
    font-size: 11px;
    line-height: 1;
    padding: 5px 9px;
    border-radius: 999px;
    white-space: nowrap;
    border: 1px solid transparent;
  }
  .b-tailnet { background: #123820; color: #9cf0b7; border-color: #245b35; }
  .b-all { background: #3b3111; color: #f3d66b; border-color: #6b5618; }
  .b-lan { background: #25282f; color: #d6d9de; border-color: #3b404a; }
  .b-local { background: #1d2026; color: #aeb5bf; border-color: #343941; }
  .b-other { background: #1d2026; color: #c8cdd4; border-color: #343941; }
  .empty { color: var(--faint); padding: 8px 4px; }
  .filter {
    width: 100%;
    min-width: 0;
    padding: 10px 12px;
    font: inherit;
    font-size: 14px;
    border-radius: 6px;
    border: 1px solid var(--line);
    background: #090a0d;
    color: var(--text);
  }
  .filter:focus { outline: 1px solid var(--accent); border-color: var(--accent); }
  .rbtn {
    height: 39px;
    padding: 0 14px;
    border: 1px solid var(--line);
    border-radius: 6px;
    background: var(--panel);
    color: var(--accent);
    font: inherit;
    font-size: 13px;
    font-weight: 700;
    cursor: pointer;
  }
  .rbtn:active { background: var(--panel-2); }
  .rbtn:disabled { color: var(--faint); cursor: wait; }
  #age { color: var(--accent); }
  .warn {
    padding: 8px 10px;
    border-radius: 6px;
    background: #38280d;
    color: #f4d27d;
    border: 1px solid #72551c;
    font-size: 12px;
  }
  .warn code {
    color: #f4d27d;
    background: #00000033;
    padding: 1px 4px;
    border-radius: 4px;
  }
  .card.hide { display: none; }
  .diag-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 10px;
    padding-top: 6px;
  }
  .diag {
    border: 1px solid var(--line);
    border-left-width: 4px;
    border-radius: 8px;
    background: var(--panel);
    padding: 10px 12px;
    min-height: 0;
  }
  .diag.ok { border-left-color: var(--ok); }
  .diag.warn { border-left-color: var(--warn); }
  .diag.bad { border-left-color: var(--bad); }
  .diag.neutral { border-left-color: var(--faint); }
  .diag-title {
    display: flex;
    justify-content: space-between;
    gap: 10px;
    align-items: center;
    font-weight: 800;
    margin-bottom: 8px;
  }
  .dot {
    display: inline-block;
    min-width: 0;
    max-width: 100%;
    padding: 3px 8px;
    border-radius: 999px;
    border: 1px solid var(--line);
    font-size: 11px;
    line-height: 1.1;
  }
  .dot.ok { color: #9cf0b7; background: #123820; border-color: #245b35; }
  .dot.warn { color: #f3d66b; background: #3b3111; border-color: #6b5618; }
  .dot.bad { color: #ffb4ad; background: #3c171a; border-color: #6b272d; }
  .dot.neutral { color: #d6d9de; background: #25282f; border-color: #3b404a; }
  .diag-row {
    display: grid;
    grid-template-columns: 92px minmax(0, 1fr);
    gap: 8px;
    align-items: center;
    font-size: 12px;
    border-top: 1px solid var(--line-soft);
    padding-top: 6px;
    margin-top: 6px;
  }
  .diag-key { color: var(--muted); }
  .diag-val { word-break: break-word; }
  @media (max-width: 700px) {
    .header-inner,
    #content { padding-left: 12px; padding-right: 12px; }
    .toolbar { grid-template-columns: 1fr; }
    .rbtn { width: 100%; }
    .top { grid-template-columns: 72px minmax(0, 1fr); }
    .badge {
      grid-column: 2;
      justify-self: start;
      margin-top: -2px;
    }
    .sub { padding-left: 82px; }
    .diag-grid { grid-template-columns: 1fr; }
  }
"""

PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ports - {host}</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>{style}</style></head>
<body>
<header>
  <div class="header-inner">
    <div>
      <h1>Ports on {host}</h1>
      <div class="meta">
        via <code>{bind}</code> &middot; {total}<br>
        updated <span id="age">just now</span>
      </div>
    </div>
    <div class="toolbar">
      <button id="refresh" class="rbtn">Refresh</button>
      <input id="filter" class="filter" type="search" inputmode="search" autocomplete="off"
             placeholder="Filter by port, name, or process">
    </div>
    {warn}
  </div>
</header>
<div id="content">{body}</div>
<script>
  var KEY = 'pd-open';
  function openIdx() {{
    var d = document.querySelectorAll('#content details'), out = [];
    for (var i=0;i<d.length;i++) if (d[i].open) out.push(i);
    return out;
  }}
  function restore() {{
    var saved; try {{ saved = JSON.parse(sessionStorage.getItem(KEY)) || []; }} catch(e) {{ saved = []; }}
    var d = document.querySelectorAll('#content details');
    saved.forEach(function(i){{ if (d[i]) d[i].open = true; }});
  }}
  function track() {{
    var d = document.querySelectorAll('#content details');
    for (var i=0;i<d.length;i++) d[i].addEventListener('toggle', function(e){{
      if (!e.isTrusted) return;            // ignore programmatic opens (filtering)
      sessionStorage.setItem(KEY, JSON.stringify(openIdx()));
    }});
  }}
  var filterEl = document.getElementById('filter');
  function applyFilter() {{
    var q = (filterEl.value || '').trim().toLowerCase();
    var cards = document.querySelectorAll('#content .card');
    for (var i=0;i<cards.length;i++) {{
      var hit = !q || cards[i].textContent.toLowerCase().indexOf(q) !== -1;
      cards[i].classList.toggle('hide', !hit);
    }}
    var d = document.querySelectorAll('#content details');
    if (q) {{ for (var j=0;j<d.length;j++) d[j].open = true; }}  // surface hidden matches
    else {{ restore(); }}                                        // back to your sections
  }}
  filterEl.addEventListener('input', applyFilter);
  var lastFetch = Date.now(), ageEl = document.getElementById('age'),
      btn = document.getElementById('refresh');
  function fmtAge(ms) {{
    var s = Math.floor(ms / 1000);
    if (s < 3) return 'just now';
    if (s < 60) return s + 's ago';
    return Math.floor(s / 60) + 'm ' + (s % 60) + 's ago';
  }}
  var failure = '';
  function tickAge() {{
    ageEl.textContent = fmtAge(Date.now() - lastFetch) + (failure ? ' · last refresh failed: ' + failure : '');
    ageEl.style.color = failure ? '#e5534b' : '';
  }}
  function refresh() {{
    btn.disabled = true; btn.textContent = 'Refreshing';
    fetch(location.href, {{cache:'no-store'}}).then(function(r){{
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.text();
    }}).then(function(t){{
      var doc = new DOMParser().parseFromString(t, 'text/html');
      var fresh = doc.getElementById('content');
      if (!fresh) throw new Error('unexpected response');
      var y = window.scrollY;
      document.getElementById('content').innerHTML = fresh.innerHTML;
      lastFetch = Date.now(); failure = ''; track(); applyFilter(); window.scrollTo(0, y);
    }}).catch(function(e){{
      failure = (e && e.message) || 'network error';
    }}).then(function(){{
      btn.disabled = false; btn.textContent = 'Refresh'; tickAge();
    }});
  }}
  btn.addEventListener('click', refresh);
  track(); applyFilter(); tickAge(); setInterval(tickAge, 1000);
</script>
</body></html>"""


def host_from_header(host_hdr):
    """The host part of an HTTP Host header, without the port or IPv6 brackets.

    Handles "name", "name:port", "1.2.3.4:port", "[v6]" and "[v6]:port". Falls
    back to 127.0.0.1 when the header is missing or empty.
    """
    host = (host_hdr or "").strip()
    if host.startswith("["):
        end = host.find("]")
        host = host[1:end] if end > 0 else host[1:]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host or "127.0.0.1"


def is_loopback_client(client_host):
    host = (client_host or "").strip("[]").lower()
    return host in {"localhost", "::1"} or host.startswith("127.")


def render_rows(rows, client_host):
    if not rows:
        return '<div class="empty">none</div>'
    host_for_url = html.escape(f"[{client_host}]" if ":" in client_host else client_host, quote=True)
    local_browser = is_loopback_client(client_host)
    out = []
    for r in sorted(rows, key=group_sort_key):
        name = html.escape(r["name"]) if r["name"] else "-"
        if r.get("is_self"):
            name += ' <span class="self">this app</span>'
        image = html.escape(r["image"]) if r["image"] != "?" else "?"
        bind = html.escape(r.get("binds") or r["host"])
        pid = r["pid"] if r["pid"] >= 0 else "?"
        badge = {"tailnet": "b-tailnet", "all": "b-all", "lan": "b-lan",
                 "local": "b-local"}.get(r["bucket"], "b-other")
        # Blue link only when it should work from the browser host being used.
        buckets = set(r.get("buckets") or {r["bucket"]})
        reachable = r["proto"] == "TCP" and (
            bool({"tailnet", "all"} & buckets)
            or (local_browser and "local" in buckets)
        )
        if reachable:
            port_html = (f'<a class="port" target="_blank" rel="noopener" '
                         f'href="http://{host_for_url}:{r["port"]}/">{r["port"]}</a>')
        else:
            port_html = f'<span class="port dim">{r["port"]}</span>'
        # the process exe + "what it is" (only if it adds info beyond the name)
        svc = html.escape(r["service"])
        extra = f" &middot; {svc}" if svc and svc != r["name"] else ""
        raw_count = int(r.get("raw_count") or 1)
        count = f" &middot; {raw_count} binds grouped" if raw_count > 1 else ""
        source_label = NAME_SOURCE_LABELS.get(r.get("name_source", "none"), "")
        via = f' &middot; via {html.escape(source_label)}' if source_label else ""
        sub = f'{image}{extra} &middot; bind {bind}{count} &middot; {r["proto"]} &middot; PID {pid}{via}'
        out.append(
            f'<div class="card"><div class="top">{port_html}'
            f'<span class="name">{name}</span>'
            f'<span class="badge {badge}">{html.escape(r["scope"])}</span></div>'
            f'<div class="sub">{sub}</div></div>')
    return "".join(out)


def render_diagnostics(diags):
    if not diags:
        return ""
    out = ['<section><h2>Diagnostics</h2><div class="diag-grid">']
    for diag in diags:
        level = diag_level(diag.get("level"))
        title = html.escape(diag.get("title") or "Status")
        out.append(
            f'<div class="diag {level}"><div class="diag-title">'
            f'<span>{title}</span><span class="dot {level}">{level}</span></div>'
        )
        for key, value, row_level in diag.get("rows", []):
            row_class = diag_level(row_level)
            out.append(
                f'<div class="diag-row"><span class="diag-key">{html.escape(str(key))}</span>'
                f'<span class="diag-val dot {row_class}">{html.escape(str(value))}</span></div>'
            )
        out.append('</div>')
    out.append('</div></section>')
    return "".join(out)


def render_page(bind, client_host):
    # Sequential: netstat is ~instant; the only real cost is `tasklist /v`, which
    # get_proc_table now caps + degrades gracefully. (Parallelizing the two saved
    # nothing measurable and tripped a Windows subprocess stall.)
    procs, title_state, _title_detail = get_proc_table_cached()
    rows = enrich(get_listeners(), procs, runtime_port_labels())
    groups = group_listeners(rows)
    diagnostics = collect_diagnostics_cached(procs, rows)

    tcp = [r for r in groups if r["proto"] == "TCP"]
    udp = [r for r in groups if r["proto"] == "UDP"]
    focused_tcp = [r for r in tcp if is_focused_group(r)]
    focused_udp = [r for r in udp if is_focused_group(r)]
    reachable = [r for r in focused_tcp if group_is_network_reachable(r)]
    local = [r for r in focused_tcp if group_is_local_only(r)]
    background_tcp = [r for r in tcp if not is_focused_group(r)]
    background_udp = [r for r in udp if not is_focused_group(r)]

    warn = ""
    if title_state == "none":
        warn = ('<div class="warn">&#x26A0;&#xFE0F; Window-title labels are unavailable '
                'in this launch. The dashboard is reachable, but custom '
                '<code>start "name"</code> labels will not show. For those labels, '
                'launch from your desktop via <code>start-ports-dashboard.bat</code>.</div>')
    elif title_state == "unavailable":
        warn = ('<div class="warn">&#x26A0;&#xFE0F; Window-title lookup is unavailable; '
                'using process image names and port labels where possible.</div>')

    body = [
        render_diagnostics(diagnostics),
        f'<section><h2>Network-Reachable Services &middot; {len(reachable)} TCP</h2>',
        render_rows(reachable, client_host), '</section>',
        '<section><details open><summary>This PC / LAN Services '
        f'({len(local)})</summary>',
        render_rows(local, client_host), '</details></section>',
        '<section><details><summary>App UDP Sockets '
        f'({len(focused_udp)})</summary>',
        render_rows(focused_udp, client_host), '</details></section>',
        '<section><details><summary>Background / System TCP '
        f'({len(background_tcp)} grouped endpoints)</summary>',
        render_rows(background_tcp, client_host), '</details></section>',
        '<section><details><summary>Background / System UDP '
        f'({len(background_udp)} grouped endpoints)</summary>',
        render_rows(background_udp, client_host), '</details></section>',
    ]
    shown = len(reachable) + len(local) + len(focused_udp)
    return PAGE.format(
        style=STYLE,
        host=html.escape(socket.gethostname()),
        bind=html.escape(bind),
        total=(f"{shown} focused endpoints; {len(background_tcp) + len(background_udp)} "
               f"background ({len(rows)} raw sockets grouped to {len(groups)})"),
        warn=warn,
        body="".join(body),
    )


class Handler(BaseHTTPRequestHandler):
    bind_label = "?"

    def _send(self, payload, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _refuse(self, reason):
        print(f"[DENY] {self.client_address[0]}: {reason}", flush=True)
        payload = b"403: this dashboard only answers this PC and its owner's tailnet devices.\n"
        self.send_response(403)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        allowed, reason = ACCESS.check(self.client_address[0])
        if not allowed:
            self._refuse(reason)
            return
        if self.path in ("/favicon.svg", "/favicon.ico"):
            self._send(FAVICON, "image/svg+xml")
            return
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return
        client_host = host_from_header(self.headers.get("Host", ""))
        payload = render_page(self.bind_label, client_host).encode("utf-8")
        self._send(payload, "text/html; charset=utf-8")

    def log_message(self, *a):  # quieter console
        pass


def set_console_title(title):
    """Re-stamp our own console with a short, findable title.

    `start "ports-dashboard" cmd /k python ...` opens the window titled
    'ports-dashboard', but cmd then overwrites the title with the full command
    line it is running ('ports-dashboard - python "...\\ports_dashboard.py"
    --host ... --port ...'). That long string is what Task Manager, `tasklist /v`,
    and (before self-recognition) our own port view would show. Re-stamping keeps
    the OS-level name short while still starting with 'ports-dashboard', so the
    'ports-dashboard*' match in stop-/status-ports-dashboard.bat keeps working.
    """
    if os.name != "nt":
        return
    try:
        ctypes.windll.kernel32.SetConsoleTitleW(str(title))
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description="Listening-ports web dashboard.")
    ap.add_argument(
        "--host",
        action="append",
        dest="hosts",
        help="bind address; repeat for localhost plus a tailnet IP",
    )
    ap.add_argument("--port", type=int, default=DASHBOARD_PORT)
    args = ap.parse_args()

    set_console_title(f"ports-dashboard :{args.port}")

    hosts = []
    for host in args.hosts or ["127.0.0.1"]:
        if host not in hosts:
            hosts.append(host)

    servers = []
    for host in hosts:
        try:
            servers.append((host, ThreadingHTTPServer((host, args.port), Handler)))
        except OSError as exc:
            print(f"[WARN] could not bind {host}:{args.port}: {exc}")

    if not servers:
        print("[ERROR] no dashboard bind addresses are available")
        raise SystemExit(1)

    Handler.bind_label = ", ".join(f"{host}:{args.port}" for host, _srv in servers)

    for _host, srv in servers[1:]:
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()

    print("ports-dashboard serving on:")
    for host, _srv in servers:
        print(f"  http://{host}:{args.port}/")
    print(f"  this PC: http://127.0.0.1:{args.port}/")
    print("  phone:   use the Tailscale URL printed by start-ports-dashboard.bat")
    print("  Ctrl+C to stop.")
    try:
        servers[0][1].serve_forever()
    except KeyboardInterrupt:
        print("\nstopping.")
        for _host, srv in servers:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    main()
