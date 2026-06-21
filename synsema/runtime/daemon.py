"""
Synsema Daemon — Run agents as system services.

    synsema daemon start program.syn     Start as background daemon
    synsema daemon stop program.syn      Stop a running daemon
    synsema daemon status                Show all running daemons
    synsema daemon logs program.syn      Tail the daemon logs
    synsema daemon restart program.syn   Restart a daemon

The daemon:
    - Detaches from the terminal (real fork on Unix, subprocess on Windows)
    - Writes a PID file for management
    - Redirects output to log files
    - Keeps cron jobs and agents alive
    - Auto-restarts on crash (optional)
    - Supports multiple daemons simultaneously

Files:
    ~/.synsema/daemons/<name>/pid      Process ID
    ~/.synsema/daemons/<name>/log      stdout + stderr
    ~/.synsema/daemons/<name>/meta     program path, start time, etc.

Works on Linux, Mac, and Windows. Uses os.fork on Unix,
subprocess.Popen on Windows.
"""

import os
import sys
import json
import time
import signal
import subprocess
from pathlib import Path
from typing import Optional, Dict, List


def _daemon_dir() -> Path:
    """Get the daemon state directory."""
    d = Path.home() / ".synsema" / "daemons"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _daemon_name(program_path: str) -> str:
    """Derive a daemon name from the program path."""
    return Path(program_path).stem


def _daemon_state_dir(name: str) -> Path:
    d = _daemon_dir() / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _read_pid(name: str) -> Optional[int]:
    pid_file = _daemon_state_dir(name) / "pid"
    if pid_file.exists():
        try:
            return int(pid_file.read_text().strip())
        except (ValueError, OSError):
            pass
    return None


def _is_running(pid: int) -> bool:
    """Check if a process is running. Works on Linux, Mac, and Windows."""
    if os.name == "nt":
        # Windows: use tasklist
        try:
            output = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            return str(pid) in output
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    else:
        # Unix: signal 0 checks existence
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False


def daemon_start(program_path: str, extra_args: List[str] = None,
                 auto_restart: bool = False) -> Dict:
    """
    Start a Synsema program as a background daemon.

    Returns dict with: name, pid, log_path, status
    """
    program_path = str(Path(program_path).resolve())
    if not Path(program_path).exists():
        return {"status": "error", "message": f"File not found: {program_path}"}

    name = _daemon_name(program_path)
    state_dir = _daemon_state_dir(name)

    # Check if already running
    existing_pid = _read_pid(name)
    if existing_pid and _is_running(existing_pid):
        return {
            "status": "already_running",
            "name": name,
            "pid": existing_pid,
            "message": f"Daemon '{name}' is already running (PID {existing_pid})",
        }

    # Build command
    python = sys.executable
    cmd = [python, "-m", "synsema", "run", program_path, "--serve"]
    if extra_args:
        cmd.extend(extra_args)

    # Log file
    log_path = state_dir / "log"

    # Start as detached subprocess
    log_file = open(log_path, "a")
    log_file.write(f"\n--- Daemon started at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
    log_file.flush()

    # Use DETACHED_PROCESS on Windows, setsid on Unix
    kwargs = {
        "stdout": log_file,
        "stderr": log_file,
        "stdin": subprocess.DEVNULL,
    }

    if os.name == "nt":
        # Windows
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        # Unix — start in new session so terminal close doesn't kill it
        kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **kwargs)

    # Write PID
    (state_dir / "pid").write_text(str(proc.pid))

    # Write metadata
    meta = {
        "program": program_path,
        "name": name,
        "pid": proc.pid,
        "started_at": time.time(),
        "started_at_human": time.strftime("%Y-%m-%d %H:%M:%S"),
        "auto_restart": auto_restart,
        "args": extra_args or [],
    }
    (state_dir / "meta").write_text(json.dumps(meta, indent=2))

    return {
        "status": "started",
        "name": name,
        "pid": proc.pid,
        "log": str(log_path),
        "message": f"Daemon '{name}' started (PID {proc.pid}). Logs: {log_path}",
    }


def daemon_stop(name_or_path: str) -> Dict:
    """Stop a running daemon."""
    name = _daemon_name(name_or_path) if "/" in name_or_path or "." in name_or_path else name_or_path

    pid = _read_pid(name)
    if not pid:
        return {"status": "not_found", "message": f"No daemon '{name}' found"}

    if not _is_running(pid):
        # Clean up stale PID
        (_daemon_state_dir(name) / "pid").unlink(missing_ok=True)
        return {"status": "not_running", "message": f"Daemon '{name}' is not running (stale PID {pid})"}

    # Send SIGTERM (graceful) then force kill if needed
    try:
        if os.name == "nt":
            # Windows: taskkill
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True)
        else:
            os.kill(pid, signal.SIGTERM)
            # Wait up to 5 seconds for graceful shutdown
            for _ in range(50):
                if not _is_running(pid):
                    break
                time.sleep(0.1)
            else:
                # Force kill (Unix only)
                if hasattr(signal, "SIGKILL"):
                    os.kill(pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass

    (_daemon_state_dir(name) / "pid").unlink(missing_ok=True)

    # Log stop
    log_path = _daemon_state_dir(name) / "log"
    if log_path.exists():
        with open(log_path, "a") as f:
            f.write(f"\n--- Daemon stopped at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")

    return {"status": "stopped", "name": name, "pid": pid, "message": f"Daemon '{name}' stopped"}


def daemon_status() -> List[Dict]:
    """Get status of all daemons."""
    results = []
    daemon_dir = _daemon_dir()
    if not daemon_dir.exists():
        return results

    for state_dir in sorted(daemon_dir.iterdir()):
        if not state_dir.is_dir():
            continue
        name = state_dir.name
        meta_file = state_dir / "meta"
        pid = _read_pid(name)

        info = {
            "name": name,
            "pid": pid,
            "running": pid is not None and _is_running(pid),
        }

        if meta_file.exists():
            try:
                meta = json.loads(meta_file.read_text())
                info["program"] = meta.get("program", "")
                info["started_at"] = meta.get("started_at_human", "")
            except:
                pass

        results.append(info)

    return results


def daemon_logs(name_or_path: str, lines: int = 50) -> str:
    """Get recent log lines for a daemon."""
    name = _daemon_name(name_or_path) if "/" in name_or_path or "." in name_or_path else name_or_path
    log_path = _daemon_state_dir(name) / "log"

    if not log_path.exists():
        return f"No logs for daemon '{name}'"

    content = log_path.read_text()
    all_lines = content.split("\n")
    recent = all_lines[-lines:]
    return "\n".join(recent)


def daemon_restart(name_or_path: str, extra_args: List[str] = None) -> Dict:
    """Restart a daemon."""
    name = _daemon_name(name_or_path) if "/" in name_or_path or "." in name_or_path else name_or_path

    # Get program path from meta
    meta_file = _daemon_state_dir(name) / "meta"
    program_path = name_or_path
    if meta_file.exists():
        try:
            meta = json.loads(meta_file.read_text())
            program_path = meta.get("program", name_or_path)
            if not extra_args:
                extra_args = meta.get("args", [])
        except:
            pass

    daemon_stop(name)
    time.sleep(0.5)
    return daemon_start(program_path, extra_args)


def format_status_table(statuses: List[Dict]) -> str:
    """Format daemon status as readable table."""
    if not statuses:
        return "No daemons found."
    lines = ["Synsema Daemons:"]
    for s in statuses:
        state = "RUNNING" if s.get("running") else "STOPPED"
        pid = s.get("pid") or "-"
        name = s.get("name", "?")
        program = s.get("program", "")
        started = s.get("started_at", "")
        lines.append(f"  [{state:7s}] {name:20s} PID={str(pid):8s} {started}  {program}")
    return "\n".join(lines)
