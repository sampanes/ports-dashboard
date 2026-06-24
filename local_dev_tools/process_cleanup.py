import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from local_dev_tools.config import load_config
except ImportError:  # when run as a loose script with local_dev_tools/ on sys.path
    from config import load_config


# Future prettier terminal UI: consider the third-party `rich` package
# (`python -m pip install rich`) for tables, colors, and prompts. This script
# intentionally stays stdlib-only so the desktop shortcut works anywhere.

# Keep the old workspace root even though the implementation now lives inside
# ports-dashboard. Project-name and self-process heuristics depend on this.
ROOT = Path(__file__).resolve().parents[2]
SELF_PID = os.getpid()

DEV_PROCESS_NAMES = {
    "bun.exe",
    "deno.exe",
    "node.exe",
    "npm.exe",
    "npx.exe",
    "pnpm.exe",
    "python.exe",
    "python3.exe",
    "pythonw.exe",
    "yarn.exe",
    "yarnpkg.exe",
}

SERVER_PROCESS_NAMES = {
    "air.exe",
    "cargo.exe",
    "dotnet.exe",
    "go.exe",
    "java.exe",
    "llama-server.exe",
    "ollama.exe",
    "php.exe",
    "ruby.exe",
    "uvicorn.exe",
}

KNOWN_LISTENING_NAMES = SERVER_PROCESS_NAMES | {
    "node.exe",
    "ollama app.exe",
    "ollama.exe",
    "postgres.exe",
    "python.exe",
    "python3.exe",
    "pythonw.exe",
}

SHELL_PROCESS_NAMES = {
    "bash.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "sh.exe",
    "tail.exe",
}

SYSTEM_NOISE_NAMES = {
    "csrss.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "idle",
    "lsass.exe",
    "registry",
    "services.exe",
    "smss.exe",
    "spoolsv.exe",
    "svchost.exe",
    "system",
    "wininit.exe",
    "winlogon.exe",
}

PROTECTED_PIDS = {"0", "4"}
PROTECTED_PROCESS_NAMES = SYSTEM_NOISE_NAMES | {"secure system"}

# Substrings that mark a process as an "AI/tool" worth surfacing. The generic
# ones ship in config.default.json; your own (e.g. private project names) go in
# config.local.json under process_cleanup.ai_tool_terms. See config.py.
_CLEANUP_CFG = load_config().get("process_cleanup") or {}
AI_TOOL_TERMS = tuple(
    _CLEANUP_CFG.get("ai_tool_terms") or ("claude-code", "codex", "gemini", "mcp")
)

INTERESTING_TERMS = AI_TOOL_TERMS + (
    "fastapi",
    "flask",
    "jupyter",
    "next",
    "npm",
    "pnpm",
    "pytest",
    "serve-site",
    "streamlit",
    "uvicorn",
    "vite",
    "webpack",
    "yarn",
)

DEV_SERVER_PATTERNS = (
    r"\bvite\b",
    r"\bnext\b",
    r"\bwebpack\b",
    r"\bwebpack-dev-server\b",
    r"\bserve-site\b",
    r"\buvicorn\b",
    r"\bflask\b",
    r"\bfastapi\b",
    r"\bstreamlit\b",
    r"\bnpm(?:\.cmd)?\s+run\s+(dev|start|serve)\b",
    r"\bpnpm(?:\.cmd)?\s+(dev|start|serve)\b",
    r"\byarn(?:\.cmd)?\s+(dev|start|serve)\b",
)

COMMON_PORTS = {
    "3000": "web",
    "3001": "web",
    "3306": "mysql",
    "5000": "api",
    "5173": "vite",
    "5432": "postgres",
    "6379": "redis",
    "8000": "api",
    "8080": "web",
    "9200": "elastic",
    "11434": "ollama",
    "27017": "mongo",
}

SERVICE_PORTS = {
    "3306",
    "5432",
    "6379",
    "9200",
    "11434",
    "27017",
}

SERVICE_PROCESS_NAMES = {
    "mysqld.exe",
    "ollama app.exe",
    "ollama.exe",
    "postgres.exe",
    "redis-server.exe",
}

CATEGORY_ORDER = {
    "AI/tool": 0,
    "Dev server": 1,
    "Listening": 2,
    "Tests": 3,
    "JS runtime": 4,
    "Python": 5,
    "Shell": 6,
    "Other": 7,
}

WARNINGS = []


def add_warning(message):
    if message not in WARNINGS:
        WARNINGS.append(message)


def first_error_line(text):
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def run_powershell(command, label="PowerShell query", warn=True):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            check=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        if warn:
            add_warning(f"{label} timed out")
        return ""
    except subprocess.CalledProcessError as exc:
        if warn:
            detail = first_error_line(exc.stderr or exc.stdout)
            add_warning(f"{label} failed" + (f": {detail}" if detail else ""))
        return ""
    except Exception as exc:
        if warn:
            add_warning(f"{label} failed: {exc}")
        return ""
    return result.stdout.strip()


def as_list_from_json(output):
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    if data is None:
        return []
    if isinstance(data, dict):
        return [data]
    return data


def get_processes():
    command = """
Get-CimInstance Win32_Process |
Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, WorkingSetSize,
    @{Name='CreationDate';Expression={ if ($_.CreationDate) { $_.CreationDate.ToString('o') } else { $null } }} |
ConvertTo-Json -Depth 3
"""
    return as_list_from_json(run_powershell(command, "process query"))


def get_listening_ports():
    command = """
Get-NetTCPConnection -State Listen -ErrorAction Stop |
Select-Object LocalAddress, LocalPort, OwningProcess |
ConvertTo-Json -Depth 3
"""
    rows = as_list_from_json(run_powershell(command, "listening-port query", warn=False))
    if rows:
        ports_by_pid = {}
        for row in rows:
            pid = str(row.get("OwningProcess") or "")
            port = row.get("LocalPort")
            if pid and port:
                ports_by_pid.setdefault(pid, set()).add(str(port))
        return ports_by_pid

    return get_listening_ports_from_netstat()


def get_listening_ports_from_netstat():
    try:
        result = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return {}

    ports_by_pid = {}
    for line in result.stdout.splitlines():
        if "LISTENING" not in line:
            continue
        parts = re.split(r"\s+", line.strip())
        if len(parts) < 5:
            continue
        address = parts[1]
        pid = parts[-1]
        port = address.rsplit(":", 1)[-1]
        if port.isdigit():
            ports_by_pid.setdefault(pid, set()).add(port)
    return ports_by_pid


def parse_creation_date(value):
    if not value:
        return None
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized)
        except ValueError:
            return None
    return None


def format_age(value):
    created = parse_creation_date(value)
    if not created:
        return "-"
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    delta = datetime.now(created.tzinfo) - created
    seconds = max(0, int(delta.total_seconds()))
    minutes = seconds // 60
    if minutes < 1:
        return "<1m"
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h{minutes:02d}m"
    days, hours = divmod(hours, 24)
    return f"{days}d{hours}h"


def format_memory(value):
    try:
        size = int(value or 0)
    except (TypeError, ValueError):
        return "-"
    if size <= 0:
        return "-"
    mb = size / 1024 / 1024
    if mb < 100:
        return f"{mb:.1f}M"
    return f"{mb:.0f}M"


def short_path(text):
    if not text:
        return ""
    return text.replace(str(ROOT), ".")


def project_name(command_line, executable_path):
    haystack = f"{command_line or ''} {executable_path or ''}"
    pattern = re.escape(str(ROOT)) + r"[\\/]+([^\\/\s\"']+)"
    match = re.search(pattern, haystack, re.IGNORECASE)
    if match:
        return match.group(1)
    return "-"


def first_term(text, terms):
    for term in terms:
        if term in text:
            return term
    return ""


def first_dev_server_match(command_line):
    for pattern in DEV_SERVER_PATTERNS:
        match = re.search(pattern, command_line)
        if match:
            return match.group(0).replace(".cmd", "")
    return ""


def format_ports(port_list):
    if not port_list:
        return "-"
    values = []
    for port in port_list:
        label = COMMON_PORTS.get(str(port))
        values.append(f"{port}/{label}" if label else str(port))
    return ",".join(values)


def short_reason(text):
    return re.sub(r"\s+", " ", text).strip()


def classify_process(proc, ports):
    name = (proc.get("Name") or "").lower()
    cmd = (proc.get("CommandLine") or "").lower()
    raw_pid = proc.get("ProcessId")
    pid = str(raw_pid) if raw_pid is not None else ""

    if any(term in cmd for term in AI_TOOL_TERMS):
        return "AI/tool"
    if "--test" in cmd or "npm-cli.js\" test" in cmd or "pytest" in cmd:
        return "Tests"
    if any(re.search(pattern, cmd) for pattern in DEV_SERVER_PATTERNS):
        return "Dev server"
    if pid in ports:
        return "Listening"
    if name in {"node.exe", "bun.exe", "deno.exe"}:
        return "JS runtime"
    if name.startswith("python"):
        return "Python"
    if name in SHELL_PROCESS_NAMES:
        return "Shell"
    return "Other"


def advice_for_process(proc, category, port_list, project):
    name = (proc.get("Name") or "").lower()
    raw_pid = proc.get("ProcessId")
    pid = str(raw_pid) if raw_pid is not None else ""
    port_set = set(port_list)

    if pid in PROTECTED_PIDS or name in PROTECTED_PROCESS_NAMES:
        return "leave"
    if category == "AI/tool":
        return "leave"
    if name in SERVICE_PROCESS_NAMES or port_set & SERVICE_PORTS:
        return "service"
    if category in {"Dev server", "Tests"}:
        return "kill ok"
    if category == "Listening":
        if project != "-" or name in {"node.exe", "python.exe", "python3.exe", "pythonw.exe", "uvicorn.exe"}:
            return "caution"
        return "service"
    if category in {"JS runtime", "Python", "Shell"}:
        return "caution"
    return "caution"


def why_process(proc, category, port_list, project):
    name = (proc.get("Name") or "").lower()
    cmd = (proc.get("CommandLine") or "").lower()
    reasons = []

    ai_term = first_term(cmd, AI_TOOL_TERMS)
    if ai_term:
        reasons.append(f"ai:{ai_term}")

    dev_match = first_dev_server_match(cmd)
    if dev_match:
        reasons.append(f"dev:{short_reason(dev_match)}")

    if "--test" in cmd or "npm-cli.js\" test" in cmd or "pytest" in cmd:
        reasons.append("test runner")

    if port_list:
        reasons.append(f"listens:{format_ports(port_list)}")

    if project != "-":
        reasons.append(f"project:{project}")

    if not reasons and name in DEV_PROCESS_NAMES:
        reasons.append(name.replace(".exe", " runtime"))
    if not reasons:
        reasons.append(category.lower())

    unique = []
    for reason in reasons:
        if reason not in unique:
            unique.append(reason)
    return "; ".join(unique[:3])


def is_self_process(proc):
    pid = int(proc.get("ProcessId") or 0)
    cmd = (proc.get("CommandLine") or "").lower()
    return pid == SELF_PID or "find-js-processes.py" in cmd


def is_interesting_process(proc, ports):
    if is_self_process(proc):
        return False

    name = (proc.get("Name") or "").lower()
    cmd = (proc.get("CommandLine") or "").lower()
    raw_pid = proc.get("ProcessId")
    pid = str(raw_pid) if raw_pid is not None else ""

    if name in DEV_PROCESS_NAMES:
        return True
    if name in SERVER_PROCESS_NAMES and pid in ports:
        return True
    if str(ROOT).lower() in cmd and (pid in ports or any(term in cmd for term in INTERESTING_TERMS)):
        return True
    if any(term in cmd for term in INTERESTING_TERMS):
        return True
    if pid in ports and name in KNOWN_LISTENING_NAMES and name not in SYSTEM_NOISE_NAMES:
        return True
    return False


def build_rows(show_all=False):
    WARNINGS.clear()
    ports = get_listening_ports()
    processes = get_processes()
    processes_by_pid = {
        str(proc.get("ProcessId")): proc
        for proc in processes
        if proc.get("ProcessId") is not None
    }
    rows = []

    for proc in processes:
        if not show_all and not is_interesting_process(proc, ports):
            continue
        if show_all and is_self_process(proc):
            continue

        raw_pid = proc.get("ProcessId")
        pid = str(raw_pid) if raw_pid is not None else ""
        command_line = proc.get("CommandLine") or proc.get("ExecutablePath") or ""
        port_list = sorted(ports.get(pid, []), key=lambda value: int(value) if value.isdigit() else value)
        category = classify_process(proc, ports)
        project = project_name(command_line, proc.get("ExecutablePath"))
        parent_pid = str(proc.get("ParentProcessId") or "")
        parent = processes_by_pid.get(parent_pid)
        parent_name = parent.get("Name") if parent else ""
        rows.append(
            {
                "pid": pid,
                "name": proc.get("Name") or "-",
                "category": category,
                "advice": advice_for_process(proc, category, port_list, project),
                "why": why_process(proc, category, port_list, project),
                "ports": format_ports(port_list),
                "memory": format_memory(proc.get("WorkingSetSize")),
                "age": format_age(proc.get("CreationDate")),
                "project": project,
                "parent": f"{parent_pid} {parent_name}".strip() if parent_pid else "-",
                "command": short_path(command_line),
            }
        )

    rows.sort(
        key=lambda row: (
            CATEGORY_ORDER.get(row["category"], 99),
            row["project"].lower(),
            row["name"].lower(),
            int(row["pid"]) if row["pid"].isdigit() else 0,
        )
    )
    return rows


def supports_color(disable_color=False):
    return not disable_color and sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def color(text, code, enabled):
    if not enabled:
        return text
    return f"\033[{code}m{text}\033[0m"


def truncate(text, width):
    text = str(text)
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def print_table(rows, show_all=False, use_color=True):
    columns = [
        ("#", 4),
        ("PID", 7),
        ("Advice", 9),
        ("Name", 13),
        ("Ports", 14),
        ("Mem", 7),
        ("Age", 8),
        ("Kind", 10),
        ("Why", 20),
    ]
    fixed_width = sum(width for _, width in columns) + len(columns) - 1
    terminal_width = shutil.get_terminal_size((120, 30)).columns
    command_width = max(16, terminal_width - fixed_width - 1)

    mode = "all visible processes" if show_all else "likely dev/server processes"
    print(color(f"Running processes ({mode})", "1;36", use_color))
    print(color("Enter numbers to terminate, r to refresh, a to toggle all, q to quit.", "2", use_color))
    print()

    if WARNINGS:
        for warning in WARNINGS:
            print(color(f"Warning: {warning}", "33", use_color))
        print()

    if not rows:
        print("No matching processes found.")
        if WARNINGS:
            print("The empty list may be caused by the warning above.")
        return

    header_values = [label.ljust(width) for label, width in columns]
    header = " ".join(header_values) + " " + "Command"
    print(color(header, "1", use_color))
    print(color("-" * min(len(header), terminal_width), "2", use_color))

    for index, row in enumerate(rows, start=1):
        values = [
            str(index).rjust(3).ljust(4),
            row["pid"].ljust(7),
            row["advice"].ljust(9),
            truncate(row["name"], 13).ljust(13),
            truncate(row["ports"], 14).ljust(14),
            row["memory"].rjust(6).ljust(7),
            row["age"].ljust(8),
            truncate(row["category"], 10).ljust(10),
            truncate(row["why"], 20).ljust(20),
        ]
        command = truncate(row["command"], command_width)
        line = " ".join(values) + " " + command
        if row["advice"] == "kill ok":
            line = color(line, "32", use_color)
        elif row["advice"] == "service":
            line = color(line, "33", use_color)
        elif row["advice"] == "leave":
            line = color(line, "2", use_color)
        elif row["category"] in {"AI/tool", "Dev server", "Listening"}:
            line = color(line, "36", use_color)
        print(line)


def parse_selection(raw, rows):
    selected = []
    tokens = re.split(r"[\s,]+", raw.strip())
    for token in tokens:
        if not token:
            continue
        if not token.isdigit():
            return [], f"'{token}' is not a number."
        index = int(token)
        if index < 1 or index > len(rows):
            return [], f"{index} is outside the list."
        selected.append(rows[index - 1])

    unique = {}
    for row in selected:
        unique[row["pid"]] = row
    return list(unique.values()), None


def terminate_processes(rows, force=False):
    for row in rows:
        process_name = row["name"].lower()
        if row["pid"] in PROTECTED_PIDS or process_name in PROTECTED_PROCESS_NAMES:
            print(f"refused: PID {row['pid']} {row['name']} looks like a critical system process")
            continue

        command = ["taskkill", "/PID", row["pid"], "/T"]
        if force:
            command.append("/F")
        result = subprocess.run(command, capture_output=True, text=True)
        status = "ok" if result.returncode == 0 else "failed"
        detail = (result.stdout or result.stderr).strip()
        print(f"{status}: PID {row['pid']} {row['name']}")
        if detail:
            print(f"  {detail}")


def process_maps():
    processes = get_processes()
    by_pid = {
        str(proc.get("ProcessId")): proc
        for proc in processes
        if proc.get("ProcessId") is not None
    }
    children_by_parent = defaultdict(list)
    for proc in processes:
        pid = proc.get("ProcessId")
        parent_pid = proc.get("ParentProcessId")
        if pid is None or parent_pid is None:
            continue
        children_by_parent[str(parent_pid)].append(proc)
    return by_pid, children_by_parent


def collect_descendants(pid, children_by_parent):
    descendants = []
    queue = list(children_by_parent.get(str(pid), []))
    seen = {str(pid)}
    while queue:
        proc = queue.pop(0)
        child_pid = str(proc.get("ProcessId") or "")
        if not child_pid or child_pid in seen:
            continue
        seen.add(child_pid)
        descendants.append(proc)
        queue.extend(children_by_parent.get(child_pid, []))
    return descendants


def describe_process(proc):
    pid = str(proc.get("ProcessId") or "-")
    name = proc.get("Name") or "-"
    command = short_path(proc.get("CommandLine") or proc.get("ExecutablePath") or "")
    return f"PID {pid} {name} {truncate(command, 110)}"


def confirm_and_terminate(selected):
    by_pid, children_by_parent = process_maps()
    print()
    print("Selected process tree(s):")
    risky = []
    for row in selected:
        if row["advice"] in {"leave", "service"}:
            risky.append(row)
        print(f"  PID {row['pid']} {row['name']} [{row['advice']}]")
        print(f"    why: {row['why']}")
        print(f"    ports: {row['ports']}  age: {row['age']}  memory: {row['memory']}")
        print(f"    project: {row['project']}  parent: {row['parent']}")
        print(f"    command: {row['command']}")

        descendants = collect_descendants(row["pid"], children_by_parent)
        if descendants:
            print(f"    taskkill /T will also include {len(descendants)} child process(es):")
            for child in descendants[:8]:
                print(f"      {describe_process(child)}")
            if len(descendants) > 8:
                print(f"      ... and {len(descendants) - 8} more")
        else:
            live = by_pid.get(row["pid"])
            if live is None:
                print("    note: process is no longer running")
            else:
                print("    taskkill /T has no visible child processes right now")

    if risky:
        labels = ", ".join(f"PID {row['pid']} {row['advice']}" for row in risky)
        print(f"Warning: selected row(s) are marked {labels}.")

    answer = input("Terminate selected process tree(s)? y/N, or f for taskkill /F: ").strip().lower()
    if answer not in {"y", "yes", "f", "force"}:
        print("Cancelled.")
        return
    terminate_processes(selected, force=answer in {"f", "force"})


def interactive_loop(show_all=False, disable_color=False):
    use_color = supports_color(disable_color)
    while True:
        if sys.stdout.isatty():
            os.system("cls")
        rows = build_rows(show_all=show_all)
        print_table(rows, show_all=show_all, use_color=use_color)
        print()
        raw = input("> ").strip().lower()

        if raw in {"q", "quit", "exit"}:
            return
        if raw in {"", "r", "refresh"}:
            continue
        if raw in {"a", "all"}:
            show_all = not show_all
            continue

        selected, error = parse_selection(raw, rows)
        if error:
            print(error)
            input("Press Enter to continue...")
            continue
        if selected:
            confirm_and_terminate(selected)
            input("Press Enter to refresh...")


def main():
    parser = argparse.ArgumentParser(description="Show and optionally terminate dev/server processes.")
    parser.add_argument("-i", "--interactive", action="store_true", help="open the refreshable prompt")
    parser.add_argument("--all", action="store_true", help="show all visible processes instead of the filtered dev/server view")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    args = parser.parse_args()

    if args.interactive:
        interactive_loop(show_all=args.all, disable_color=args.no_color)
        return

    rows = build_rows(show_all=args.all)
    print_table(rows, show_all=args.all, use_color=supports_color(args.no_color))


if __name__ == "__main__":
    main()
