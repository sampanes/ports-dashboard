# Discovering local LLM coding-agent sessions

Coding agents like **Claude Code** and **Codex CLI** leave their session
transcripts as plain JSONL files on disk. With nothing but the Python standard
library you can answer *"which agent chats are running right now, and what is
each one about?"* — a natural fit for a pluggable diagnostics panel (see
[Diagnostics in the README](../README.md#diagnostics-optional-pluggable)).

This page is **reference knowledge only**; the repo ships no such check. Build
one in your git-ignored `local_dev_tools/diagnostics_local.py` if you want it.

> An interactive agent process does **not** open a listening socket (on Windows
> it runs under `node.exe`), so it won't show up as a port row. That's why this
> belongs in a *diagnostics panel* that lists sessions, not in port-row naming.

## On-disk layout

| Tool | Per-session transcript | Live-session registry |
|---|---|---|
| Claude Code | `~/.claude/projects/<munged-cwd>/<sessionId>.jsonl` | `~/.claude/sessions/<pid>.json` |
| Codex CLI | `~/.codex/sessions/**/*.jsonl` | _(none — no live registry)_ |

A genuine session file is named with a UUID. Filter out other `.jsonl` noise:

```python
import re
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
```

## The live registry is keyed by PID

Claude Code's registry directory holds one small JSON per **running** process,
named `<pid>.json`. The filename *is* the OS process id, and the body carries
everything needed to connect a process to its chat:

```json
{
  "pid": 12345,
  "sessionId": "00000000-0000-0000-0000-000000000000",
  "cwd": "<working directory>",
  "status": "busy",
  "kind": "interactive",
  "entrypoint": "cli",
  "version": "x.y.z",
  "startedAt": 1700000000000,
  "updatedAt": 1700000000000
}
```

| Field | Use |
|---|---|
| filename `<pid>.json` / `pid` | O(1) join from a process id to its session — no scanning |
| `sessionId` | Locates the transcript (see layout) for title extraction |
| `cwd` | Working directory, already resolved |
| `status` | Live activity: `busy` (model running) vs `idle` |
| `version` | Agent build |
| `startedAt` / `updatedAt` | Epoch ms; sort by `updatedAt` desc for "most recent first" |

Because the registry only contains running processes, a present `<pid>.json` is
itself a reasonable "this session is live now" signal. Codex CLI has no
equivalent registry, so treat Codex sessions as never-known-live.

## Resolving a human-readable title (Claude Code)

Three layers, best to weakest — all read from the `<sessionId>.jsonl` transcript:

1. **Custom / AI title** — scan the **tail** of the file (titles are *appended*,
   so the newest is last) for `{"type": "custom-title", "customTitle": ...}`
   (user rename) or `{"type": "ai-title", "aiTitle": ...}` (auto-title). Most
   recent match wins. This is the best title when present.
2. **Summary record** — scan the **head** for `{"type": "summary", "summary": ...}`.
3. **First user message** — `{"type": "user", "message": {"content": ...}}`.
   Content is either a string or a `[{"type": "text", "text": ...}]` block array.
   Skip messages starting with `<` (system prompts) or `Caveat:` (injected
   preambles); collapse whitespace to a single line.

Codex CLI uses a different schema — look for `user_message` event records (and
the alternate `response_item` with `role: user` form), rejecting any that start
with system XML tags.

## cwd → transcript folder (the munge rule)

To map a registry `cwd` onto its `~/.claude/projects/` folder, replace **every
non-alphanumeric character with `-`** (consecutive specials produce consecutive
dashes; existing dashes and letter case are preserved):

```text
C:\dev\My_App   ->  C--dev-My-App
/home/you/code  ->  -home-you-code
```

## Wiring it into a diagnostics plugin

A panel listing active sessions fits the check contract in
`local_dev_tools/diagnostics.py` directly — a check is
`check(context, options) -> {"title", "level", "rows"}` where each row is
`(key, value, level)`:

```python
import json, pathlib

def llm_sessions_diag(context, options):
    reg = pathlib.Path.home() / ".claude" / "sessions"
    rows = []
    for f in sorted(reg.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            d = json.loads(f.read_text("utf-8"))
        except (OSError, ValueError):
            continue
        title = resolve_title(d["sessionId"], d["cwd"])   # the 3 layers above
        rows.append((
            title or d["sessionId"][:8],
            f'{d.get("status", "?")} · {pathlib.Path(d["cwd"]).name}',
            "ok" if d.get("status") == "busy" else "neutral",
        ))
    return {"title": "Active LLM sessions", "level": "neutral",
            "rows": rows or [("none", "no running sessions", "neutral")]}

def checks():
    return {"llm_sessions": llm_sessions_diag}
```

Enable it from `config.local.json`:

```json
"diagnostics": { "llm_sessions": { "enabled": true } }
```

> Everything here is pure `json` + `pathlib` reads of files already on disk — no
> sockets, no IPC, no third-party packages — so it honors this repo's
> stdlib-only, `pip`-free constraint.
