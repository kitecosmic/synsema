# Running OS processes — `run`

Synsema orchestrates external tools (git, ffmpeg, python, node, a shell…) with one builtin: `run`.
**Deliberately not `bash`**: args go as a **list** (no shell parsing, no quoting injection), and each
command is gated by the **`exec`** capability — auditable by reading the `require` lines.

```
require exec("git")
let r be run("git", ["status", "--short"])
when r["exit_code"] == 0
    print(r["stdout"])
otherwise
    print("git failed: " + r["stderr"])
```

## Signature & return
```
run(cmd, args_list?, timeout?, opts?) -> map
```
- `cmd` (text): the command. **Capability scope is checked against `cmd` as written** (before PATH resolution).
- `args_list` (list, optional): one argument per element. Absent = no args. Non-list → error.
- `timeout` (number, optional): seconds. **Default 120.** On expiry: kill the process and **raise**.
- `opts` (map, optional): `{cwd, env, stdin, max_output}`.

Returns `{exit_code, stdout, stderr, stdout_truncated, stderr_truncated}`:
- `exit_code` number (`-1` if killed by signal). `stdout`/`stderr` text (lossy, up to `max_output`).
- `*_truncated` bool — `true` if that stream exceeded `max_output` (default 10 MB).

**Non-zero `exit_code` is DATA, not an error** — a linter with findings / a failing test returns
normally; you decide. Only **timeout** and **can't-launch** (missing command / OS permission) raise
(catch with `try`/`recover`).

## Capability — `require exec`
Deny-by-default; **not auto-granted even in `run`/`conform`** (unlike time/random). Scoped by command name:
```
require exec("git")        -- only git
require exec("py*")        -- glob: python, py, pytest…
require exec("*")          -- any command (== `require exec` with no scope)
```
Without it: `Capability not granted: exec("<cmd>")`. See [capabilities.md](capabilities.md).

## Patterns
**Specific tool (safest, injection-proof)** — args as a list, even if from an LLM/user:
```
require exec("ffmpeg")
run("ffmpeg", ["-i", input, "-vn", output])
```
**Inline code:**
```
require exec("node")
run("node", ["-e", "console.log(40+2)"])     -- or run("python", ["-c", code])
```
**Pipelines / shell features** (`run` has no pipes; the shell does — pass the script as one arg):
```
require exec("bash")
run("bash", ["-c", "ls | grep .syn | wc -l"])
require exec("powershell")
run("powershell", ["-Command", "Get-Process | Sort CPU -Descending | Select -First 5"])
```
⚠️ `bash -c "<string>"` re-opens shell injection if the string is LLM/user-built. Prefer the specific
tool for audited contexts.

**opts:**
```
run("git", ["status"], 30, {"cwd": "./repo"})
run("node", ["build.js"], 120, {"env": {"NODE_ENV": "production"}})   -- inherits environ + overrides
run("sort", [], 30, {"stdin": "b\na\n"})                              -- text/bytes → stdin, then EOF
run("find", ["."], 60, {"max_output": 1000000})                      -- cap capture (check *_truncated)
```
**Timeout (raise, catchable):**
```
try
    run("cargo", ["build"], 600)
recover err
    print("hung: " + err)        -- run: "cargo" timed out after 600s
```

## Generate-and-run (coding-agent loop)
```
require llm
require file("./work/*")
require exec("python")
let code be generate "a python script that ..." given spec
write_file("./work/gen.py", code)
let r be run("python", ["./work/gen.py"], 60, {"cwd": "./work"})
```
Combine with `grep` + `edit_file` (see [builtins.md](builtins.md)) for search → edit → run.

## Give an LLM a shell tool (least-privilege)
A tool is a user task; wrap `run` and dispatch with `call_tool` (runs with ONLY what it declares):
```
task shell(cmd)
    require exec("bash")
    give run("bash", ["-c", cmd])
let out be call_tool(shell, "uname -a")   -- runs with only exec("bash")
```
See [llm.md](llm.md) (tool-calling) and [capabilities.md](capabilities.md) (`call_tool`).

## Corporate ↔ throwaway: one knob
Same language; the difference is one visible `require` line:
- **Locked-down:** `require exec("git")` / `exec("ffmpeg")` — scoped tools, args-as-list, no shell.
- **Personal / disposable container:** `require exec("bash")` or `require exec` — full shell power.

No hidden "dangerous mode": the broad grant is declared and audited like any other.

## Live processes — `proc_*` (incremental output, live stdin, kill) — engine v0.6.7+

`run` captures everything and returns at the end. An agent driving `cargo test`, `npm run
build`, a long `python worker.py` needs to **see the output as it comes**, feed stdin, and
kill it: that is a process as a **handle** with events. Same gate as `run` (`exec(cmd)`,
scope = the cmd as written), args as a list, never a shell. Pipes by default (a program
that checks "is a tty" behaves as in CI); `pty: true` gives it a real terminal — see
§ Pseudo-terminal below.

```
require exec("cargo")
let p be proc_spawn("cargo", ["test"], {"cwd": "./repo"})
while true
    let ev be proc_recv(p, 60)          -- {type: "stdout"|"stderr"|"exit", data} or nothing (timeout)
    when ev == nothing
        proc_kill(p)                     -- no output in 60 s: TERM (KILL with "KILL")
    otherwise when ev["type"] == "exit"
        print("exit " + text(ev["data"]["exit_code"]))
        stop
    otherwise
        print(ev["type"] + ": " + ev["data"])   -- one event per LINE (no trailing \n / \r)
proc_close(p)
```

| Builtin | Returns |
|---|---|
| `proc_spawn(cmd, args?, opts?)` | handle (int) — also in `select` |
| `proc_recv(h, timeout?)` | next event, or `nothing` at the timeout |
| `proc_select(list \| map, timeout?)` | first ready event among processes (`select` accepts any handle) |
| `proc_send(h, text \| bytes)` | `true`; error if stdin is closed. **Blocking write** — a child that never reads its stdin blocks the caller (pipe semantics) |
| `proc_close_stdin(h)` | `true` (EOF to the child). **Pipes only** — a pty has no separate stdin: send the EOF key (`bytes([4])` Ctrl-D / `bytes([26, 13])` Ctrl-Z+Enter) |
| `proc_resize(h, cols, rows)` | `true`; **pty only** (SIGWINCH / ResizePseudoConsole) — error on a pipe process |
| `proc_status(h)` | `"running"` \| `"exited"` \| `"killed"` \| `"closed"` (after `proc_close`/unknown) |
| `proc_kill(h, signal?)` | `true`; `"TERM"` (default, Unix SIGTERM) / `"KILL"`; Windows: both `TerminateProcess` |
| `proc_wait(h, timeout?)` | `{exit_code, signal}` or `nothing` at the timeout |
| `proc_stats(h)` | `{pid, cmd, status, exit_code, pty, queued, queued_bytes, dropped, uptime}` |
| `proc_close(h)` | releases the handle; **kills if still alive** (TERM, KILL after 2 s, then wait) — no orphans, idempotent |

Events: `{type: "stdout"|"stderr", data: text}` (lossy UTF-8; `line_mode: false` gives raw
`bytes` chunks of ≤ 64 KiB); `{type: "exit", data: {exit_code, signal}}` once, after the
pipes are drained (`exit_code` `-1` when killed by a signal; `signal` is `nothing` on a
normal exit and always on Windows). Every event from `select`/`proc_recv` also carries
`source: "proc"`, `handle` (and `name` when you passed a map).

`opts`: `cwd`, `env` (inherits + overrides; a `secret` value → error, `reveal()` it
explicitly), `line_mode` (default `true`), `stderr` (`"separate"` default | `"merge"` →
everything arrives as `stdout`), `pty` (+ `cols`, `rows`, `term` — see below), and the
bounded queue: `max_queue` (4096 events), `max_queue_bytes` (64 MiB), `on_full` =
`"block"` (default: the reader stops draining the pipe, the child blocks on its `write` —
real backpressure, no loss) | `"drop_oldest"` | `"error"` (the next recv raises a
catchable error and the process is killed).

Lifecycle: **when the interpreter ends, every live process is killed** (end of a request
under `serve`, end of the program, end of an agent). A handler never leaves a ghost; for
work that must outlive the request use `cron_after` or an agent (own lifecycle). Budget:
`SYNSEMA_PROC_MAX` live processes per interpreter (default 64, hard ceiling 1024) → error
over it. A grandchild that keeps the pipe open after the child exited cannot hang you:
1 s grace, then the `exit` event is delivered.

### Pseudo-terminal — `pty: true` (engine v0.6.8+)

Many programs check "am I talking to a terminal?" and, on a pipe, skip the question,
assume "no", hang or refuse: `y/N` prompts that read `/dev/tty`, `ssh`/`sudo`/`gpg`
passwords, arrow-key menus (`inquirer`, `prompts`), `docker run -it`, REPLs, progress
bars, and every TUI (`vim`, `htop`, an agentic CLI like Claude Code). `pty: true` runs
the child inside a real pseudo-terminal (openpty on Linux/macOS, ConPTY on Windows ≥ 10
1809). **Same API, same events, same `exec(cmd)` gate** — a pty grants no OS power a
pipe doesn't; it changes how the child behaves, not what it may do. `sandbox` denies it
like any `exec`.

```
require exec("npm")
let p be proc_spawn("npm", ["install"], {"pty": true, "cols": 120, "rows": 40})
let screen be ""
while true
    let ev be proc_recv(p, 60)
    when ev == nothing
        proc_kill(p)
    otherwise when ev["type"] == "exit"
        stop
    otherwise
        set screen to screen + ev["data"]             -- raw bytes, ANSI included
        when contains(strip_ansi(screen), "[y/N]")   -- read it like a human
            proc_send(p, "y\r")                      -- keystrokes: Enter is \r on a tty
            set screen to ""
proc_close(p)
```

What changes in pty mode (all consequences of "it is a terminal", not new API):
- **One stream**: the tty doesn't separate stderr — everything arrives as `stdout`.
- **Raw bytes with escape sequences**: `line_mode` defaults to `false` (chunks, never
  split inside a UTF-8 character). Feed them to xterm.js as-is, or `strip_ansi(text)`
  to get what a human would see (colors, cursor moves, OSC titles removed; `\r`
  redraws keep the last frame). The runtime never interprets VT.
- **Echo is on**: what you `proc_send` comes back in the output. A revealed secret you
  type is echoed in clear — the same secret rules apply (`secret` in args/env/send →
  error).
- **Keys, not lines**: Enter is `"\r"`, Ctrl-C is `bytes([3])`, Ctrl-D `bytes([4])`,
  arrows `esc + "[A"` etc. No `proc_close_stdin` (error tells you which key to send).
- **Size**: `cols`/`rows` (default 80×24), `proc_resize(h, cols, rows)` later. `term`
  sets `TERM` (default `xterm-256color`; `env.TERM` wins).
- **Kill is session-wide on Unix**: the child is a session leader, `proc_kill`/`proc_close`
  signal the whole process group — no grandchild survives holding the tty. Windows:
  `TerminateProcess` + closing the pseudo console.
- **Windows handshake handled for you**: ConPTY emits `ESC[6n` at start and delivers
  nothing until it is answered; the runtime answers that first one and strips it (an
  xterm.js on the other end won't see it, so no double reply). Later `ESC[6n` are the
  app's and pass through.
- `exit_code` is `-1` when killed by a signal; on a pty `signal` is the number when
  known (`15`, `9`, `1`, `2`) else `nothing`.

Web terminal = `socket` route + pty in one `select`: browser bytes → `proc_send`, proc
events → `socket_send`, a `{resize}` message → `proc_resize` (xterm.js renders). It
is an app-level `auth` decision who gets that socket — the runtime adds no capability
because there is nothing new to gate.

## Gotchas
- Shell injection: `run(tool, [args])` is safe; `run("bash", ["-c", llm_string])` is not. Choose by trust.
- `proc_*` is pipes by default: `vim`, password prompts, `y/N` that read the tty, progress bars won't work — add `pty: true`. Try the non-interactive flag first (`--yes`, `CI=1`, `DEBIAN_FRONTEND=noninteractive`): cheaper and deterministic.
- `proc_send` blocks if the child never reads stdin; `proc_close_stdin` sends EOF (many tools wait for it) — pipes only.
- Cancellation (route `timeout`, shutdown, `agent_stop`) kills the children of `run`/`proc_spawn` — they don't survive the handler.
- No pipes/redirects/globs in `run` itself — use a shell for those.
- `run` has no TTY/interactivity (capture only) — for `vim`/prompts use `proc_spawn(..., {pty: true})`.
- `exit_code != 0` does NOT raise; `raise(...)` yourself if you want failure.
- Default timeout 120s — pass a larger one for long commands.
- Cross-platform: resolves via PATH (`.exe` on Windows); `bash` isn't on stock Windows (use powershell);
  `node`/`python` only if installed.
- `exec` is never auto-granted (even in `run`).
