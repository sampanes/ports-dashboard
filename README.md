# Local Dev Tools

Small, stdlib-only Windows utilities for local process cleanup and "what can I
open from my phone over Tailscale?" visibility.

- **No `pip install`.** Pure Python standard library — nothing to vet, runs as-is.
- **Local-first.** Always serves on `127.0.0.1`; optionally also binds your
  Tailscale IP so your phone can reach it.
- **Configurable, not hardcoded.** Everything machine-specific (port nicknames,
  process labels, which diagnostics to run) lives in JSON config, so the code
  stays generic and shareable.

The stable entry points are the batch launchers:

```cmd
start-ports-dashboard.bat
stop-ports-dashboard.bat
status-ports-dashboard.bat
find-js-processes.bat
```

## Quick start

1. (Optional) Copy the example config and make it yours:

   ```cmd
   copy config.local.example.json config.local.json
   ```

   Edit `config.local.json` to add your own port nicknames, process labels, and
   to enable the diagnostics you use. It is git-ignored, so your machine details
   never get committed. The dashboard also works fine with no local config — it
   just uses the public defaults.

2. Launch it (from a normal cmd window, or double-click the file):

   ```cmd
   start-ports-dashboard.bat
   ```

   It opens `http://127.0.0.1:18790/` on this PC and prints a phone URL when
   Tailscale is online. Stop it with `stop-ports-dashboard.bat`.

> Tip: don't paste the launcher's contents into the dashboard's *own* console
> window — the script is idempotent and kills any window titled `ports-dashboard*`
> first, which would close the window you pasted into. Run it from a separate
> shell or just double-click it.

## Ports Dashboard

`start-ports-dashboard.bat` launches a tiny web page listing this PC's listening
ports with friendly names, at:

```text
http://127.0.0.1:18790/
```

When Tailscale is online, the same process also binds the current tailnet IP so
your phone can reach it. Tailscale only routes your phone to this PC; it does not
provide a built-in "what services is this host running?" view. This fills that
gap. The start script checks `tailscale status --json` first; if this PC is
offline in Tailscale it still starts the local version and labels the phone URL
unavailable instead of trusting a stale tailnet IP.

On your phone, with Tailscale up, bookmark the MagicDNS hostname rather than the
raw tailnet IP:

```text
http://your-pc.your-tailnet.ts.net:18790/
```

The page shows:

- Optional quick diagnostics (see [Configuration](#configuration)) for things
  like Tailscale reachability, VPN/port-forward health, and game-stream ports.
- A focused service list first, with Windows/system chatter and ephemeral helper
  sockets moved into collapsed background sections.
- Grouped endpoint rows, so one service bound to multiple addresses is shown as
  one card with a compact "N binds grouped" note instead of duplicate cards.

| Section | Bound to | Reachable from phone? |
|---|---|---|
| Network-reachable services | `0.0.0.0`, `::`, or the tailnet IP | Yes |
| This-PC / LAN services | `127.0.0.1`, `::1`, LAN IPs, or private ranges | Depends on bind and current network |
| App UDP sockets | pinned app UDP ports or runtime-labeled app ports | App-specific |
| Background/system TCP/UDP | Windows, helper agents, multicast, and ephemeral sockets | Usually not user-facing |

### Who can load the page

The page is a map of everything listening on this PC, so the dashboard checks
who is asking before it answers:

- **This PC** (`127.0.0.1`, `::1`) always gets the page.
- **Tailnet devices** are looked up with `tailscale whois`. A device owned by the
  same Tailscale user as this PC gets the page; anyone else gets `403`, and the
  console prints a `[DENY]` line naming the address.
- **Anything else** (a LAN address, an address Tailscale doesn't know, or
  Tailscale not answering) gets `403`. The check fails closed.

This matters when you share the PC with someone over Tailscale. Your tailnet
policy is the real gate, and Tailscale's default allow-all rule also lets in
people you've shared the machine with. The identity check is the backstop if a
rule like that is ever left in place.

To let another person's devices in, add their Tailscale login to
`dashboard.access.allow_logins` in `config.local.json` (git-ignored, so the name
never lands in the repo). Setting `dashboard.access.allow_own_devices` to
`false` limits the page to this PC plus that list. Verdicts are cached per
address for 60 seconds (15 seconds for a refusal).

### How services get their names

Names come from, best to fuzziest:

0. **Self.** The dashboard's own listener is matched by PID and always labeled
   `Ports dashboard` with a green `this app` tag. It deliberately ignores its own
   window title, because Windows stamps the launching console with the full
   command line (`ports-dashboard - python ...ports_dashboard.py --host ...
   --port ...`) — that long string would otherwise be shown as the name.
1. Window title from the Windows desktop APIs or `tasklist /v`, including a
   titled parent shell when Windows exposes that process relationship.
2. Runtime local app labels from a diagnostics plugin (for example, an app's
   currently-configured port read from its config file).
3. Friendly port label from your config (`5432` → PostgreSQL, `11434` → Ollama).
4. Process image name (`postgres.exe`).

Every row's sub-line ends with `via <layer>` (`via window title`, `via port
label`, `via process name`, `via self`, …) so you can always see *why* a row got
the name it did.

To keep the noise out of Task Manager too, the dashboard re-stamps its own
console title to `ports-dashboard :18790` on startup. That still begins with
`ports-dashboard`, so the `WINDOWTITLE eq ports-dashboard*` match used by the
stop/status scripts keeps working.

The window-title layer only resolves when this runs in your interactive desktop
session. If title lookup is unavailable, the dashboard still works and falls back
to process image names and port labels. Launch it from your desktop via
`start-ports-dashboard.bat` when you want `start "name"` labels to appear.

## Configuration

All machine-specific data is loaded from JSON, merged in this order:

| File | Committed? | Purpose |
|---|---|---|
| `config.default.json` | yes | Public, generic defaults. Always loaded. |
| `config.local.json` | **no** (git-ignored) | Your private overrides/additions. Deep-merged on top. |
| `config.local.example.json` | yes | Documented template — copy it to `config.local.json`. |

Set the `PORTS_DASHBOARD_CONFIG` environment variable to load the private layer
from a path other than `./config.local.json`.

**Merge rules** (so your local file only needs the deltas):

- **dicts** merge key by key — local keys override or extend defaults
- **lists** are unioned, order preserved — local entries *add* to defaults
- **scalars** replace

Keys you can set (all optional):

| Key | Meaning |
|---|---|
| `dashboard.port` / `dashboard.self_name` | Port to serve on; name for the dashboard's own row |
| `port_labels` | `"port"` → friendly name shown on the card |
| `pinned_ports` | ports always surfaced in the focused list |
| `user_facing_terms` | substrings that force a service into the focused list |
| `process_labels` | image name (lowercase `.exe`) → what the app is |
| `process_label_prefixes` | image-name prefix → label, for families of exes |
| `background_process_images` | image names pushed into the collapsed sections |
| `diagnostics` | which health checks to run, and their parameters |
| `process_cleanup.ai_tool_terms` | extra substrings the cleanup tool flags as AI/tool |

### Diagnostics (optional, pluggable)

The Diagnostics panel is an optional, pluggable feature in
`local_dev_tools/diagnostics.py`. The dashboard runs fine without it; when
present it renders one panel per **enabled** check.

- **Built-in:** a single generic `tailscale` check ships in the repo and is
  enabled by default (it answers "is this node up on its tailnet, and is a phone
  peer online?").
- **Your own checks:** live in a git-ignored sibling,
  `local_dev_tools/diagnostics_local.py`. Copy the committed
  `local_dev_tools/diagnostics_local.example.py` to that name and define your
  checks — it's loaded automatically when present, so your machine-specific
  monitoring never gets committed.

A check is a small function returning a panel; a plugin exposes
`checks() -> {name: fn}` (and optionally `runtime_port_labels(...)`). See
`diagnostics.py` for the full contract and `diagnostics_local.example.py` for a
copy-paste starting point.

A check only runs when its name is enabled in the `diagnostics` block of your
config, so the config and the plugin are decoupled:

```json
"diagnostics": {
  "tailscale": { "enabled": true, "service": "Tailscale" },
  "example":   { "enabled": true, "service": "Spooler", "port": 9100 }
}
```

Checks degrade gracefully when the underlying app isn't installed, and if no
check is enabled the Diagnostics section is hidden entirely.

For a worked reference on building a less obvious check — listing the local
**LLM coding-agent sessions** (Claude Code / Codex) that are running right now,
with their human-readable titles — see
[docs/llm-session-discovery.md](docs/llm-session-discovery.md). It's pure
stdlib file reads and slots straight into a `diagnostics_local.py` plugin.

## Process Cleanup

`find-js-processes.bat` launches an interactive process cleanup view. It filters
toward likely dev, server, and AI-tool processes; shows ports, memory, age,
project hints, parent process, `Advice`, and `Why`; and previews the full
`taskkill /T` process tree before terminating anything.

Safe read-only check:

```cmd
python find-js-processes.py --no-color
```

## Layout

```text
config.default.json        public, committed config defaults
config.local.example.json  template to copy -> config.local.json
config.local.json          your private config (git-ignored)

local_dev_tools\
  config.py                    config loader (defaults + private layer merge)
  sysutil.py                   shared stdlib subprocess/path helpers
  ports_dashboard.py           real dashboard implementation
  process_cleanup.py           process cleanup implementation
  diagnostics.py               pluggable diagnostics framework + Tailscale check
  diagnostics_local.example.py template for your own diagnostics plugin
  diagnostics_local.py         your private checks (git-ignored, not present until you add it)
  tailscale_self_ip.py         prints the tailnet IPv4 when this node is online
  tailnet_access.py            who may load the page (loopback + own tailnet devices)

tests\                    stdlib unit tests: python -m unittest
ports_dashboard.py        compatibility entry point
find-js-processes.py      process cleanup entry point
```

## Notes

- Port `18790` is used to avoid low-port Windows blocks; change it via
  `dashboard.port` or `--port`.
- The start script always binds `127.0.0.1`, then also binds the current
  Tailscale IP when Tailscale reports this PC online.
- Binding `0.0.0.0` (`python ports_dashboard.py --host 0.0.0.0 --port 18790`)
  makes the port reachable on the LAN, but LAN clients still get `403`: only
  this PC and verified tailnet devices are answered (see
  [Who can load the page](#who-can-load-the-page)).
- No `pip install` is required.
