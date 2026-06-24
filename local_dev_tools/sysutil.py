#!/usr/bin/env python3
"""Generic Windows subprocess / path helpers.

Leaf module with no project dependencies, shared by the dashboard core and the
diagnostics framework so neither has to import the other. Pure standard library.
"""
import os
import shutil
import subprocess
from pathlib import Path


def run_result(cmd, timeout=4):
    """Run a command, returning (returncode, stdout, stderr) with errors mapped
    to conventional-ish codes instead of raising."""
    label = Path(cmd[0]).name
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", f"{label} not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{label} timed out after {timeout}s"
    except Exception as exc:
        return 1, "", str(exc)


def program_files_path(*parts):
    return Path(os.environ.get("ProgramFiles", r"C:\Program Files")).joinpath(*parts)


def command_path(name, fallback):
    """Resolve an executable by name on PATH, else a known fallback path, else
    just the bare name (so the caller still gets a 'not found' from run_result)."""
    found = shutil.which(name)
    if found:
        return found
    if fallback.exists():
        return str(fallback)
    return name
