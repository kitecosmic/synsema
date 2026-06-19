"""
Syntecnia Capability Enforcer.

Wraps side-effecting operations with capability checks.
This module provides secure versions of I/O operations that
only work if the caller has the required capabilities.
"""

import os
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List
from .model import (
    Capability, CapabilityType, CapabilitySet, CapabilityViolation,
    parse_capability,
)


class SecureOperations:
    """
    Provides side-effecting operations gated by capabilities AND intent.

    Every operation:
    1. Checks the required capability
    2. Checks the intent enforcer (is this action within the mandate?)
    3. Logs the check to the audit trail
    4. Only proceeds if BOTH pass
    5. Returns result or raises CapabilityViolation

    This is the ONLY way to perform I/O in Syntecnia.
    The interpreter calls these instead of raw Python I/O.
    """

    def __init__(self, capabilities: CapabilitySet):
        self.capabilities = capabilities
        self.intent_enforcer = None  # set by engine

    def _check_intent(self, category, detail: str = "",
                      domain: str = None, path: str = None):
        """Check intent enforcer if present. Raises on violation in strict mode."""
        if self.intent_enforcer:
            from .intent import IntentViolation as _IV
            if not self.intent_enforcer.check_action(category, detail, domain, path):
                raise CapabilityViolation(
                    f"Intent violation: {detail} — action not within declared intent"
                )

    # -- File operations --

    def read_file(self, path: str, source: str = "") -> str:
        """Read a file, requires file.read or file capability + intent."""
        from .intent import ActionCategory
        cap = Capability(CapabilityType.FILE_READ, path)
        self.capabilities.require(cap, source)
        self._check_intent(ActionCategory.FILE_READ, f"read_file({path})", path=path)
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {path}")
        return p.read_text(encoding="utf-8")

    def write_file(self, path: str, content: str, source: str = "") -> None:
        """Write a file, requires file.write or file capability + intent."""
        from .intent import ActionCategory
        cap = Capability(CapabilityType.FILE_WRITE, path)
        self.capabilities.require(cap, source)
        self._check_intent(ActionCategory.FILE_WRITE, f"write_file({path})", path=path)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    def list_dir(self, path: str, source: str = "") -> List[str]:
        """List directory contents, requires file.read capability."""
        cap = Capability(CapabilityType.FILE_READ, path + "/*")
        self.capabilities.require(cap, source)
        return os.listdir(path)

    def file_exists(self, path: str, source: str = "") -> bool:
        """Check if file exists, requires file.read capability."""
        cap = Capability(CapabilityType.FILE_READ, path)
        self.capabilities.require(cap, source)
        return Path(path).exists()

    # -- Network operations --

    def http_request(self, url: str, method: str = "GET",
                     headers: Dict = None, body: str = None,
                     source: str = "") -> Dict[str, Any]:
        """
        Make an HTTP request, requires net capability for the domain.
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.hostname or url

        cap = Capability(CapabilityType.NET, domain)
        self.capabilities.require(cap, source)

        from .intent import ActionCategory
        net_cat = ActionCategory.NET_WRITE if method in ("POST", "PUT", "DELETE", "PATCH") else ActionCategory.NET_READ
        self._check_intent(net_cat, f"http_{method}({url})", domain=domain)

        import urllib.request
        import urllib.error
        import json

        req = urllib.request.Request(url, method=method)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        if body:
            req.data = body.encode("utf-8")

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                response_body = resp.read().decode("utf-8")
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": response_body,
                }
        except urllib.error.HTTPError as e:
            return {
                "status": e.code,
                "headers": dict(e.headers) if e.headers else {},
                "body": e.read().decode("utf-8") if e.fp else "",
                "error": str(e),
            }
        except urllib.error.URLError as e:
            return {"status": 0, "error": str(e)}

    # -- Process execution --

    def execute(self, command: str, args: List[str] = None,
                timeout: int = 30, source: str = "") -> Dict[str, Any]:
        """Execute an external process, requires exec capability + intent."""
        cap = Capability(CapabilityType.EXEC, command)
        self.capabilities.require(cap, source)
        from .intent import ActionCategory
        self._check_intent(ActionCategory.EXEC, f"execute({command})")

        try:
            cmd = [command] + (args or [])
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"exit_code": -1, "error": f"Timed out after {timeout}s"}
        except FileNotFoundError:
            return {"exit_code": -1, "error": f"Command not found: {command}"}

    # -- Environment variables --

    def get_env(self, name: str, source: str = "") -> Optional[str]:
        """Read an environment variable, requires env capability."""
        cap = Capability(CapabilityType.ENV, name)
        self.capabilities.require(cap, source)
        return os.environ.get(name)

    # -- System --

    def require_time(self, source: str = "") -> None:
        """Gate on the time capability (no clock read), for time-derived ops."""
        cap = Capability(CapabilityType.TIME)
        self.capabilities.require(cap, source)

    def get_time(self, source: str = "") -> float:
        """Get current time, requires time capability."""
        import time
        self.require_time(source)
        return time.time()

    def get_random(self, source: str = "") -> float:
        """Get random number, requires random capability."""
        import random
        cap = Capability(CapabilityType.RANDOM)
        self.capabilities.require(cap, source)
        return random.random()

    def write_stdout(self, text: str, source: str = "") -> None:
        """Write to stdout, requires stdout capability."""
        cap = Capability(CapabilityType.STDOUT)
        self.capabilities.require(cap, source)
        print(text, end="")
