"""
Synsema CLI — Command-line interface.

Usage:
    synsema run program.syn           Run a .syn file
    synsema run program.syn --serve   Run and keep alive (for crons/agents)
    synsema repl                      Start interactive mode
    synsema check program.syn         Parse and check without running
    synsema tokens program.syn        Show token stream (debug)
    synsema ast program.syn           Show AST (debug)
    synsema testgen program.syn       Auto-generate and run tests
    synsema daemon start program.syn  Run as background service
    synsema daemon stop program.syn   Stop a background service
    synsema daemon status             Show all running services
    synsema daemon logs program.syn   View service logs
    synsema daemon restart program.syn  Restart a service
    synsema version                   Show version
"""

import sys
import json
from pathlib import Path


def main():
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h", "help"):
        print(__doc__.strip())
        return

    command = args[0]

    if command == "version":
        from . import __version__
        print(f"Synsema v{__version__}")
        return

    if command == "daemon":
        from .runtime.daemon import (
            daemon_start, daemon_stop, daemon_status,
            daemon_logs, daemon_restart, format_status_table,
        )
        if len(args) < 2:
            print("Usage: synsema daemon <start|stop|status|logs|restart> [program.syn]")
            sys.exit(1)

        action = args[1]

        if action == "status":
            statuses = daemon_status()
            print(format_status_table(statuses))
            return

        if len(args) < 3 and action != "status":
            print(f"Usage: synsema daemon {action} <program.syn>")
            sys.exit(1)

        target = args[2] if len(args) > 2 else ""
        extra = args[3:]

        if action == "start":
            result = daemon_start(target, extra)
            print(result["message"])
        elif action == "stop":
            result = daemon_stop(target)
            print(result["message"])
        elif action == "restart":
            result = daemon_restart(target, extra)
            print(result["message"])
        elif action == "logs":
            lines = int(args[3]) if len(args) > 3 and args[3].isdigit() else 50
            print(daemon_logs(target, lines))
        else:
            print(f"Unknown daemon action: {action}")
            sys.exit(1)
        return

    if command == "repl":
        from .runtime.engine import SynsemaEngine
        engine = SynsemaEngine()
        engine.repl()
        return

    if command == "testgen":
        if len(args) < 2:
            print("Usage: synsema testgen <file.syn>")
            sys.exit(1)
        filepath = args[1]
        source = Path(filepath).read_text(encoding="utf-8")
        from .core.testgen import TestGenerator
        gen = TestGenerator()
        gen.load_program(source)
        cases = gen.generate_all()
        stats = gen.run_all(cases)
        print(gen.format_report(cases, stats))
        sys.exit(0 if stats["failed"] == 0 else 1)

    if command in ("run", "check", "tokens", "ast"):
        if len(args) < 2:
            print(f"Usage: synsema {command} <file.syn>")
            sys.exit(1)

        filepath = args[1]
        if not Path(filepath).exists():
            print(f"Error: File not found: {filepath}")
            sys.exit(1)

        source = Path(filepath).read_text(encoding="utf-8")

        # Flat syntax support: .fsyn files or --flat flag
        if filepath.endswith(".fsyn") or "--flat" in args:
            from .core.flat_syntax import translate_flat
            source = translate_flat(source)

        if command == "tokens":
            from .core.lexer import Lexer
            lexer = Lexer(source, filepath)
            try:
                tokens = lexer.tokenize()
                for tok in tokens:
                    print(f"  {tok}")
            except Exception as e:
                print(f"Lexer error: {e}")
                sys.exit(1)
            return

        if command == "ast":
            from .core.lexer import Lexer
            from .core.parser import Parser
            lexer = Lexer(source, filepath)
            tokens = lexer.tokenize_filtered()
            parser = Parser(tokens, filepath)
            try:
                program = parser.parse()
                _print_ast(program, indent=0)
            except Exception as e:
                print(f"Parse error: {e}")
                sys.exit(1)
            return

        if command == "check":
            from .core.lexer import Lexer
            from .core.parser import Parser
            try:
                lexer = Lexer(source, filepath)
                tokens = lexer.tokenize_filtered()
                parser = Parser(tokens, filepath)
                program = parser.parse()
                print(f"OK: {len(program.statements)} statements parsed.")
            except Exception as e:
                print(f"Error: {e}")
                sys.exit(1)
            return

        if command == "run":
            from .runtime.engine import SynsemaEngine

            # Parse flags
            secure = "--secure" in args
            verbose = "--verbose" in args or "-v" in args

            engine = SynsemaEngine(secure=secure)

            # LLM provider
            provider_name = None
            for i, a in enumerate(args):
                if a == "--provider" and i + 1 < len(args):
                    provider_name = args[i + 1]
                elif a == "--grant" and i + 1 < len(args):
                    parts = args[i + 1].split(":", 1)
                    cap_name = parts[0]
                    cap_scope = parts[1] if len(parts) > 1 else None
                    engine.grant_capability(cap_name, cap_scope)

            if provider_name:
                engine.configure_llm_provider(provider_name)

            result = engine.run_source(source, filename=filepath)

            if result.output:
                for line in result.output:
                    print(line)

            if not result.success:
                # Show rich diagnostics if available
                if result.diagnostics:
                    for diag in result.diagnostics:
                        print(diag.format_human(), file=sys.stderr)
                else:
                    for err in result.errors:
                        print(f"Error: {err}", file=sys.stderr)
                sys.exit(1)

            if verbose:
                print("\n" + result.summary())

            if "--audit" in args:
                print("\n" + engine.get_audit_report())

            if "--dashboard" in args:
                # Wait for agents to finish before showing dashboard
                engine.swarm.wait_all(timeout=10)
                print("\n" + engine.swarm.format_dashboard())

            if engine.servers:
                # An HTTP server (serve on PORT) is running — keep alive.
                print(
                    f"\n{len(engine.servers)} HTTP server(s) running. "
                    f"Press Ctrl+C to stop."
                )
                try:
                    engine.wait_servers()
                except KeyboardInterrupt:
                    pass
                engine.cron_scheduler.cancel_all()
                engine.db_manager.close_all()
                print("\nStopped.")
                return

            if "--serve" in args:
                # Keep process alive for cron jobs and agents
                jobs = engine.cron_scheduler.list_jobs()
                if jobs:
                    print(f"\nServing {len(jobs)} cron job(s). Press Ctrl+C to stop.")
                else:
                    print("\nServe mode. Press Ctrl+C to stop.")
                try:
                    import time
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    engine.cron_scheduler.cancel_all()
                    engine.db_manager.close_all()
                    print("\nStopped.")
            return

    print(f"Unknown command: {command}")
    print("Run 'synsema help' for usage.")
    sys.exit(1)


def _print_ast(node, indent=0):
    """Pretty-print an AST node recursively."""
    prefix = "  " * indent
    name = type(node).__name__

    # Get relevant fields (skip location)
    fields = {}
    if hasattr(node, '__dataclass_fields__'):
        for field_name in node.__dataclass_fields__:
            if field_name in ('location',):
                continue
            val = getattr(node, field_name)
            if val is not None and val != [] and val != {} and val != "":
                fields[field_name] = val

    # Print node header
    simple_fields = {}
    complex_fields = {}
    for k, v in fields.items():
        if isinstance(v, (str, int, float, bool)):
            simple_fields[k] = v
        else:
            complex_fields[k] = v

    simple_str = " ".join(f"{k}={v!r}" for k, v in simple_fields.items())
    if simple_str:
        print(f"{prefix}{name} ({simple_str})")
    else:
        print(f"{prefix}{name}")

    # Print complex children
    for k, v in complex_fields.items():
        if isinstance(v, list):
            if v:
                print(f"{prefix}  {k}:")
                for item in v:
                    if hasattr(item, '__dataclass_fields__'):
                        _print_ast(item, indent + 2)
                    else:
                        print(f"{prefix}    {item!r}")
        elif hasattr(v, '__dataclass_fields__'):
            print(f"{prefix}  {k}:")
            _print_ast(v, indent + 2)
        elif isinstance(v, dict):
            print(f"{prefix}  {k}: {v}")


if __name__ == "__main__":
    main()
