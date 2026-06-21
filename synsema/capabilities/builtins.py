"""
Synsema Secure Builtins.

These are built-in tasks that require capabilities.
They replace raw Python I/O with capability-checked operations.

Regular builtins (math, string ops) don't need capabilities.
These builtins do because they have side effects:
    - fetch(url)          → requires net
    - read_file(path)     → requires file.read
    - write_file(path, content) → requires file.write
    - run(command, args)  → requires exec
    - get_env(name)       → requires env
    - now()               → requires time
    - random()            → requires random
"""

from typing import List
from ..core.types import (
    SynValue, BuiltinTask,
    syn_number, syn_text, syn_bool, syn_nothing, syn_list, syn_map,
    SynText, SynList, SynMap,
)


def _opt_pattern(args: List[SynValue]):
    """Return the strftime/strptime pattern from a 2nd arg, or None if absent."""
    if len(args) > 1 and isinstance(args[1].type, SynText):
        return str(args[1].raw)
    return None
from .enforcer import SecureOperations


def register_secure_builtins(env, secure_ops: SecureOperations):
    """Register all capability-gated builtins into an environment."""

    def _fetch(args: List[SynValue]) -> SynValue:
        """fetch(url) or fetch(url, method, headers, body)"""
        url = str(args[0].raw)
        method = str(args[1].raw) if len(args) > 1 else "GET"
        headers = {}
        if len(args) > 2 and isinstance(args[2].type, SynMap):
            headers = {str(k): str(v) for k, v in args[2].raw.items()}
        body = str(args[3].raw) if len(args) > 3 else None

        result = secure_ops.http_request(url, method, headers, body, source="fetch()")
        # Convert to SynValue map
        result_map = {}
        for k, v in result.items():
            if isinstance(v, int):
                result_map[k] = syn_number(v)
            elif isinstance(v, dict):
                result_map[k] = syn_map({sk: syn_text(str(sv)) for sk, sv in v.items()})
            else:
                result_map[k] = syn_text(str(v))
        return syn_map(result_map)

    def _read_file(args: List[SynValue]) -> SynValue:
        """read_file(path) → text content"""
        path = str(args[0].raw)
        content = secure_ops.read_file(path, source="read_file()")
        return syn_text(content)

    def _write_file(args: List[SynValue]) -> SynValue:
        """write_file(path, content)"""
        path = str(args[0].raw)
        content = str(args[1].raw)
        secure_ops.write_file(path, content, source="write_file()")
        return syn_bool(True)

    def _list_dir(args: List[SynValue]) -> SynValue:
        """list_dir(path) → list of filenames"""
        path = str(args[0].raw)
        entries = secure_ops.list_dir(path, source="list_dir()")
        return syn_list([syn_text(e) for e in entries])

    def _file_exists(args: List[SynValue]) -> SynValue:
        """file_exists(path) → bool"""
        path = str(args[0].raw)
        return syn_bool(secure_ops.file_exists(path, source="file_exists()"))

    def _run_command(args: List[SynValue]) -> SynValue:
        """run(command, args_list, timeout)"""
        command = str(args[0].raw)
        cmd_args = []
        if len(args) > 1 and isinstance(args[1].type, SynList):
            cmd_args = [str(a.raw) for a in args[1].raw]
        timeout = int(args[2].raw) if len(args) > 2 else 30

        result = secure_ops.execute(command, cmd_args, timeout, source="run()")
        result_map = {}
        for k, v in result.items():
            if isinstance(v, int):
                result_map[k] = syn_number(v)
            else:
                result_map[k] = syn_text(str(v))
        return syn_map(result_map)

    def _get_env(args: List[SynValue]) -> SynValue:
        """get_env(name) → text or nothing"""
        name = str(args[0].raw)
        value = secure_ops.get_env(name, source="get_env()")
        if value is None:
            return syn_nothing()
        return syn_text(value)

    def _now(args: List[SynValue]) -> SynValue:
        """now() → unix timestamp"""
        return syn_number(secure_ops.get_time(source="now()"))

    def _sleep(args: List[SynValue]) -> SynValue:
        """sleep(seconds) → pause execution. Requires the time capability."""
        import time as _time
        # Gate on the time capability (same as now()).
        secure_ops.get_time(source="sleep()")
        seconds = float(args[0].raw) if args else 0.0
        if seconds < 0:
            seconds = 0.0
        _time.sleep(min(seconds, 3600))  # cap a single sleep at 1 hour
        return syn_nothing()

    def _format_time(args: List[SynValue]) -> SynValue:
        """
        format_time(timestamp, pattern?) → text. Requires the time capability.

        Default is ISO-8601 in UTC ("2026-06-19T02:41:30Z"). With a strftime
        pattern the timestamp is formatted in UTC (format_time(t, "%Y-%m-%d")).
        """
        import datetime
        secure_ops.require_time(source="format_time()")
        ts = float(args[0].raw)
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        pattern = _opt_pattern(args)
        if pattern is not None:
            return syn_text(dt.strftime(pattern))
        return syn_text(dt.strftime("%Y-%m-%dT%H:%M:%SZ"))

    def _parse_time(args: List[SynValue]) -> SynValue:
        """
        parse_time(text, pattern?) → timestamp. Requires the time capability.

        Inverse of format_time. Without a pattern, parses ISO-8601 (a trailing
        'Z' is accepted); naive/pattern times are interpreted as UTC.
        """
        import datetime
        secure_ops.require_time(source="parse_time()")
        s = str(args[0].raw)
        pattern = _opt_pattern(args)
        if pattern is not None:
            dt = datetime.datetime.strptime(s, pattern)
        else:
            dt = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return syn_number(dt.timestamp())

    def _date_parts(args: List[SynValue]) -> SynValue:
        """date_parts(timestamp) → {year, month, day, hour, minute, second} (UTC)."""
        import datetime
        secure_ops.require_time(source="date_parts()")
        ts = float(args[0].raw)
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        return syn_map({
            "year": syn_number(dt.year),
            "month": syn_number(dt.month),
            "day": syn_number(dt.day),
            "hour": syn_number(dt.hour),
            "minute": syn_number(dt.minute),
            "second": syn_number(dt.second),
        })

    def _random(args: List[SynValue]) -> SynValue:
        """random() → float between 0 and 1"""
        return syn_number(secure_ops.get_random(source="random()"))

    def _random_int(args: List[SynValue]) -> SynValue:
        """random_int(min, max) → integer"""
        import random as rng
        # Still requires random capability
        secure_ops.get_random(source="random_int()")
        lo = int(args[0].raw)
        hi = int(args[1].raw)
        return syn_number(rng.randint(lo, hi))

    # Register all
    builtins = {
        "fetch": BuiltinTask("fetch", _fetch),
        "read_file": BuiltinTask("read_file", _read_file, 1),
        "write_file": BuiltinTask("write_file", _write_file, 2),
        "list_dir": BuiltinTask("list_dir", _list_dir, 1),
        "file_exists": BuiltinTask("file_exists", _file_exists, 1),
        "run": BuiltinTask("run", _run_command),
        "get_env": BuiltinTask("get_env", _get_env, 1),
        "now": BuiltinTask("now", _now, 0),
        "sleep": BuiltinTask("sleep", _sleep, 1),
        "format_time": BuiltinTask("format_time", _format_time, -1),
        "parse_time": BuiltinTask("parse_time", _parse_time, -1),
        "date_parts": BuiltinTask("date_parts", _date_parts, 1),
        "random": BuiltinTask("random", _random, 0),
        "random_int": BuiltinTask("random_int", _random_int, 2),
    }

    from ..core.types import SynTask
    for name, builtin in builtins.items():
        env.set(name, SynValue(raw=builtin, type=SynTask()))
