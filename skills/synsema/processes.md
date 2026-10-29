# Running OS processes — `run`

Synsema orchestrates external tools (git, ffmpeg, python, node, a shell…) with one builtin: `run`.
**Deliberately not `bash`**: args go as a **list** (no shell parsing, no quoting injection), and each
command is gated by the **`exec`** capability — auditable by reading the `require` lines.

```synsema
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
- **`cwd` + a relative command (v0.6.46+, BREAKING):** a command with a path separator (`./tool`,
  `bin/tool`) resolves against `cwd`, like `cd sub && ./tool`, and **that** is the scope to grant:
  `run("./tool.bat", [], 60, {"cwd": "sub"})` (and `proc_spawn("./tool.bat", [], {"cwd": "sub"})`) ask
  for `exec("./sub/tool.bat")` and run `sub/tool.bat`. Before, they asked for `exec("./tool.bat")` and
  the file that ran depended on the OS (the one in `sub` on Unix, the one next to the program on
  Windows). A command without a separator (`git`, `tool.bat`) is still looked up in `PATH` (never in
  `cwd`); an absolute path is unchanged. Migrate: grant exactly what the error names —
  `Capability not granted: exec("./sub/tool.bat") … add `require exec("./sub/tool.bat")`` — with the
  `./` (`exec("sub/tool.bat")` does not match).

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
```synsema
require exec("ffmpeg")
run("ffmpeg", ["-i", input, "-vn", output])
```
**Inline code:**
```synsema
require exec("node")
run("node", ["-e", "console.log(40+2)"])     -- or run("python", ["-c", code])
```
**Pipelines / shell features** (`run` has no pipes; the shell does — pass the script as one arg):
```synsema
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
```synsema
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

**Note (v0.6.14+):** `run`/`proc_spawn` no longer leak Synsema's secrets to the child — the LLM
provider keys, the human-channel secrets and `.env`-loaded variables are stripped from the child's
environment (the base OS env like `PATH` stays, so commands work). A secret the child truly needs is
passed explicitly via `opts.env`. So `run("printenv")` under `require exec` no longer dumps your API
keys. **v0.6.45+:** the same holds for `proc_spawn(…, {"pty": true})` (the pty path used to skip it).

**A child with no inherited environment — `{"env_clean": true}` (v0.6.45+, `run` and `proc_spawn`).**
The child starts with only what `env` passes (plus `SystemRoot` on Windows, without which the C
runtime and sockets do not start). The command itself is still found on the parent's `PATH`; pass
`PATH` in `env` if the child starts other programs:

```synsema
require exec("git")
let r be run("git", ["status", "--short"], 30, {"env_clean": true, "env": {"PATH": "/usr/bin:/bin", "LANG": "C"}})
print(r["stdout"])
```

**Windows, a `--no-console` binary (v0.6.45+):** `run`, `proc_spawn` and `run_program` with pipes
create children with `CREATE_NO_WINDOW` when the process has no console — before, each child
(`ssh`, `git`, `powershell`) got its own visible console window, and closing it killed the child.
From a terminal nothing changes: the child shares the console, so `ssh` can still ask for a password.

## Run **Synsema** under a ceiling — `run_program` (v0.6.14+)

To run **generated Synsema code** (an agent's own output, a plugin, a playground snippet), don't
`exec` the `synsema` binary and parse stderr — use `run_program`, which runs it in a child process
of the **same** binary under a ceiling ∩ the parent's, and returns the result (and audit) as a value:

```
require sandbox_run
require net("api.example.com")               -- what you'll LEND, you must hold
let r be run_program(generated_code, {
    "ceiling": "stdout,net=api.example.com",  -- --cap-set syntax (or "sandbox" / "none")
    "profile": "pure",                        -- default "pure"; "native" only if the parent is native
    "env":     {"TOOL": "x"},                 -- REPLACES the child's environment
    "timeout": 30                             -- seconds; on expiry the child tree is killed
})
-- r = {ok, output:[…], errors:[…], audit:[…], exit, timed_out, llm_tokens}
```

The child **can never exceed the parent** (`net=*` under a parent that only holds `net("api.x")`
collapses to nothing; the trim is recorded in the parent audit as `above parent ceiling`), a `secret`
in `env` is refused (`reveal()` it on purpose), and no `synsema` on the `PATH` or stderr-parsing is
involved. **`ceiling` also takes a captoken (v0.6.28+):** `run_program(src, {"ceiling": captoken_verify(t,
key)})` runs the child under **that token's authority** — the third way the token is the ceiling, beside a
`serve` request and `sandbox under`. The child keeps `stdout` and `time` (process-local, not the token's to
give) unless the token carries `deterministic: true`; a plain `{capability: scopes}` map works the same way. This is the language-level "run the code the LLM generated, safely" — the ceiling is
enforced by the child process itself. See [capabilities.md](capabilities.md) and [builtins.md](builtins.md).

**The child inherits every layer that limited its caller (v0.6.51+)** — its grants, its host ceiling,
its enclosing `sandbox under` blocks and its tokens (with all their blocks), plus the token passed as
`ceiling`. That matters for private addresses: a caller with `require net("*")` reaches only public
ones, so a child given `"ceiling": "stdout,net=127.0.0.1:47999"` does not reach `127.0.0.1` either
(before v0.6.51 it did: the wildcard covered the name). The child's error says where the limit is:
``http_get: `127.0.0.1` resolved to 127.0.0.1, a private address; the ceiling of the program that
called run_program reaches only public addresses for it: name it there (`net("127.0.0.1:47999")`)``.

**A caller whose limits do not fit is refused (v0.6.51+), on every platform.** What limits the caller
travels to the child in an environment variable, and its ceiling and `filename` on the command line;
Windows caps each near 32 767 characters. Past 30 000:
- ``run_program: the caller's capabilities are too many to pass to the child (N bytes; the limit is 30000)``
  — hundreds of long grants: grant a folder with `**` instead of each subfolder.
- ``run_program: the child's command line would be N characters (its ceiling and filename); the limit is 30000``
  — shorten the `filename` (it is only a label) or the ceiling.

**What `run_program` refuses and where the child lives (v0.6.45+):**
- An `env` that sets `SYNSEMA_*` or a variable the engine uses to pick host paths: `HOME`,
  `USERPROFILE`, `TMP`/`TEMP`/`TMPDIR`, `APPDATA`, `XDG_*`, `OLLAMA_MODELS`, `HF_*` (`SYNSEMA_AUDIT`
  made the child create or truncate any file; `HOME` chose where `reveal` audits).
- A ceiling whose scope has a comma or is empty (`{"file.read": "x,exec"}` split into extra items and
  gave the child `exec`). One scope per item; several scopes = a list.
- A `filename` with folders: it is a label for the child's errors, not a path.
- The ceiling travels with **absolute** paths, anchored where the parent decided them: `./data/**`
  means the parent's `./data`, also with `cwd` (it used to resolve against the child's folder). On
  Windows a `/data/**` scope is the working directory's drive.
- The child's state and temporary files go where the parent keeps its own (the folder of the
  parent's `memory` database), never in the `cwd` you pass. A parent whose memory does not persist
  (stdin, `--profile pure`) gives the child none: its memory lives in memory for that run. A **pure**
  child (the default profile) never touches the disk.
- A `"native"` child whose ceiling grants `memory=m` shares `m.db` with the parent (also from a
  `cron` tick or a `serve` handler): each process writes only the entries it changed, the child's new
  ids are marked (`mem_<n>_p<process>`), and the parent reloads when the child returns.

## Give an LLM a shell tool (least-privilege)
A tool is a user task; wrap `run` and dispatch with `call_tool` (runs with ONLY what it declares):
```synsema
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

```synsema
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
| `proc_kill(h, signal?)` | `true`; `"TERM"` (default, Unix SIGTERM) / `"KILL"`; Windows: both terminate. Reaches the **whole process tree** (v0.6.9+, see Lifecycle) |
| `proc_wait(h, timeout?)` | `{exit_code, signal}` or `nothing` at the timeout |
| `proc_stats(h)` | `{pid, cmd, status, exit_code, pty, tree, queued, queued_bytes, dropped, uptime}` — `tree` = kill reaches grandchildren |
| `proc_close(h)` | releases the handle; **kills if still alive** (TERM, KILL after 2 s, then wait) — the whole tree, no orphans, idempotent |

Events: `{type: "stdout"|"stderr", data: text}` (lossy UTF-8; `line_mode: false` gives raw
raw **text** chunks of ≤ 64 KiB — `data` is always text, UTF-8 lossy, never split inside a character); `{type: "exit", data: {exit_code, signal}}` once, after the
pipes are drained (`exit_code` `-1` when killed by a signal; `signal` is `nothing` on a
normal exit and always on Windows). Every event from `select`/`proc_recv` also carries
`source: "proc"`, `handle` (and `name` when you passed a map).

`opts`: `cwd`, `env` (inherits + overrides; a `secret` value → error, `reveal()` it
explicitly), `line_mode` (default `true`), `stderr` (`"separate"` default | `"merge"` →
everything arrives as `stdout`), `pty` (+ `cols`, `rows`, `term` — see below), `process_group` (default `true`: own
process group / Job Object so kill reaches the tree; `false` deliberately detaches a
daemon that must survive `proc_close` — then only the direct child is killed), and the
bounded queue: `max_queue` (4096 events), `max_queue_bytes` (64 MiB), `on_full` =
`"block"` (default: the reader stops draining the pipe, the child blocks on its `write` —
real backpressure, no loss) | `"drop_oldest"` | `"error"` (the next recv raises a
catchable error and the process is killed).

Lifecycle: **when the interpreter ends, every live process is killed** (end of a request
under `serve`, end of the program, end of an agent). **The whole tree, not just the
child** (v0.6.9+): the child starts in its own process group (Unix) / Job Object with
kill-on-close (Windows), so `proc_kill`/`proc_close` on `sh -c "npm run dev"` also kill
the `node` underneath — on Windows even a crash of the interpreter closes the job and
takes the tree with it. `proc_stats(h)["tree"]` says whether that is in effect. A handler never leaves a ghost; for
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

**Windows (v0.6.46+): a pty runs the name as written.** A command with a path that does not exist
as written is an error — `proc_spawn: cannot start "…\sub/notes": no such file (with pty, the exact
name is run; no PATHEXT extension is added)`. Before, the terminal layer tried `PATHEXT`, so a grant
for `notes.txt` could run `notes.bat` and `C:/x/node` ran `node.exe`. Name the file with its
extension (`./notes.bat`). A command without a separator (`notes`) is still looked up in `PATH` with
`PATHEXT`.

```synsema
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
        set screen to screen + ev["data"]             -- raw text chunks, ANSI included
        when contains(strip_ansi(screen), "[y/N]")   -- read it like a human
            proc_send(p, "y\r")                      -- keystrokes: Enter is \r on a tty
            set screen to ""
proc_close(p)
```

What changes in pty mode (all consequences of "it is a terminal", not new API):
- **One stream**: the tty doesn't separate stderr — everything arrives as `stdout`.
- **Raw text with escape sequences**: `line_mode` defaults to `false` — `data` is still
  **text** (not `bytes`): UTF-8 chunks, never split inside a character, invalid bytes →
  U+FFFD. Send them to xterm.js as text frames as-is, or `strip_ansi(text)`
  to get what a human would see (colors, cursor moves, OSC titles removed; `\r`
  redraws keep the last frame). The runtime never interprets VT.
- **Echo is on**: what you `proc_send` comes back in the output. A revealed secret you
  type is echoed in clear — the same secret rules apply (`secret` in args/env/send →
  error).
- **Keys, not lines**: Enter is `"\r"`, Ctrl-C is `bytes([3])`, Ctrl-D `bytes([4])`,
  arrows `esc + "[A"` etc. No `proc_close_stdin` (error tells you which key to send).
- **Size**: `cols`/`rows` (default 80×24), `proc_resize(h, cols, rows)` later. `term`
  sets `TERM` (default `xterm-256color`; `env.TERM` wins).
- **Kill reaches the tree** (as with pipes since v0.6.9): on Unix the child is a session
  leader and the whole process group is signalled; on Windows the Job Object is
  terminated and the pseudo console closed — no grandchild survives holding the tty.
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

## The program's own terminal — `term_*` (engine v0.6.11+)

`read_line` gives one cooked line at a time. `term_open` puts the terminal in raw mode and
delivers **every key as an event** in the same hub as `proc_*`/`bus_*`/`watch` — so a chat
CLI, a `/` command palette that filters as you type, a line editor with history, or a ↑↓ menu
for `approve` is a `select` loop in Synsema, not a runtime feature. Gate: `require stdin` to open it;
`term_write` also needs `stdout`, like `print` (v0.6.51+; denied inside a plain `sandbox`, even with a
terminal opened outside).

```synsema
require stdin
require stdout
let term be term_open()                  -- nothing without a TTY / under serve, test, wasm
when term == nothing
    let line be read_line("> ")          -- same program, pipes/CI keep working
otherwise
    let buf be ""
    while true
        term_write(term, "\r\x1b[2K> " + buf)          -- redraw NOW (made for redraws; `print` on engines ≤ v0.6.28 was buffered)
        let ev be select({"keys": term, "agent": sub}, 60)  -- keys + a sub-agent's bus events
        when ev != nothing                       -- nothing at the timeout: loop again (no `continue` in Synsema)
            when ev["source"] == "bus"
                term_write(term, "\r\n[agent] " + json_encode(ev["data"]) + "\r\n")
            otherwise when ev["type"] == "eof"
                stop
            otherwise when ev["type"] == "paste"
                set buf to buf + ev["text"]
            otherwise when ev["key"] == "char"
                set buf to buf + ev["text"]
            otherwise when ev["key"] == "backspace"
                set buf to slice(buf, 0, length(buf) - 1)
            otherwise when ev["key"] == "enter" and ev["alt"]
                set buf to buf + "\n"                        -- Alt+Enter = multi-line
            otherwise when ev["key"] == "enter"
                stop
    term_close(term)
```

| Builtin | Returns |
|---|---|
| `term_open(opts?)` | handle (int) — in `select`, tagged `source: "term"`; **`nothing`** when stdin/stdout is not a TTY, under `serve`/`test`/`conform`, in wasm |
| `term_recv(h, timeout?)` | next event or `nothing` (default timeout 30 s — pass one when waiting for a human) |
| `term_size(h)` | `{cols, rows}` |
| `term_write(h, text)` | writes to stdout immediately (needs `stdout`); ANSI escapes allowed |
| `term_stats(h)` | `{kitty, paste, ansi, keys, queued, dropped}` |
| `term_close(h)` | restores the terminal; idempotent (the runtime restores anyway on drop/error/panic) |

Events: `{type: "key", key, text, ctrl, alt, shift}` where `key` is a **name** — `"char"`
(`text` = the character, Shift applied), `"enter"`, `"tab"`, `"backtab"`, `"backspace"`,
`"delete"`, `"insert"`, `"escape"`, `"up"/"down"/"left"/"right"`, `"home"/"end"`,
`"pageup"/"pagedown"`, `"f1"`…`"f12"`; Tab/Enter never come as `"\t"`/`"\r"`; `ctrl: true` →
`text` is the lowercase letter; presses only. `{type: "paste", text}` (one event per paste, Unix;
on Windows a paste is a burst of keys — `term_stats.paste` tells). `{type: "resize", cols, rows}`,
`{type: "focus", gained}`. `{type: "eof"}` once, then the handle is gone (not an error).

`opts`: `paste` (true), `kitty` (true — kitty keyboard protocol when the terminal supports it:
Windows Terminal/kitty/WezTerm/foot/Ghostty; that is what makes **Shift+Enter** visible — use
**Alt+Enter** as the portable multi-line shortcut), `ctrl_c` (`"exit"`: restore + exit 130, like
SIGINT; `"key"`: delivered as Ctrl+c and you decide), `max_queue` (16384).

Guarantees: `print`/`log` still work (runtime writes `\r\n`, no staircase); free-text `ask`,
`approve`, `confirm` work with the terminal open (raw mode is suspended while the human answers);
one terminal per process (a spawned agent gets an error while main holds it); restoring is the
runtime's job — undo only what you drew yourself (hidden cursor, colours).

## File-watch — `watch` (engine v0.6.9+)

Changes on disk as a **handle with events**, in the same hub as processes, sockets and the
bus (so it goes into `select`). Gate: `file_read(path)` — watching a tree is reading it:
`require file.read("src/**")` (v0.6.45+: `**` covers `src`, everything below it and `src` itself;
the old `file("src")` + `file("src/*")` pair no longer reaches subfolders).

**A recursive watch (the default) needs `file.read("<dir>/**")` (v0.6.46+, BREAKING)**, like `grep`
and `static`: with only `file.read("src")` → `Capability not granted: file_read("src/**") … add
`require file.read("src/**")``; with only `"src/*"` the message names `file_read("src")` (`*` does not
cover the folder itself). Before, only the root was checked, so the watch reported names under
`src/sub/` the program could not read. Grant `"src/**"`, or pass `{"recursive": false}` (needs only
the folder, like `list_dir`; `watch_stats(h).recursive` is then `false`). A root that is a **file**
when the watch starts is watched as `recursive: false` (if a folder replaces it, only its first level
is seen). A missing root is still an error: `watch: cannot watch "nope": no such file or directory`.

```synsema
require file.read("src/**")
require exec("cargo")
let w be watch("src", {"interval": 0.2, "ignore": ["*.tmp", "target"]})
let build be nothing
while true
    let ev be select({"files": w, "build": build}, 60)
    when ev != nothing                       -- nothing at the timeout: loop again (no `continue` in Synsema)
        when ev["source"] == "watch"                 -- {type: "create"|"modify"|"delete", path, is_dir}
            when build != nothing
                proc_close(build)                    -- kills the previous build (whole tree)
            set build to proc_spawn("cargo", ["build"])
        otherwise when ev["type"] == "exit"
            print("build exit " + text(ev["data"]["exit_code"]))
```

| Builtin | Returns |
|---|---|
| `watch(path, opts?)` | handle (int) — also in `select`, tagged `source: "watch"` |
| `watch_recv(h, timeout?)` | next event, or `nothing` at the timeout |
| `watch_stats(h)` | `{path, recursive, interval, entries, scans, queued, dropped}` |
| `watch_close(h)` | releases the handle and stops the scanner; idempotent |

Events: `{type: "create" | "modify" | "delete", path, is_dir}` — `path` uses `/` and stays
relative if you gave a relative root. A rename is `delete` + `create`. Directories only
emit `create`/`delete` (their mtime changes with every child — noise). Nothing is emitted
for what already existed when the watch started.

`opts`: `recursive` (default `true`), `interval` seconds (default `0.5`, floor `0.02`),
`ignore` (list of entry names, `*` glob allowed; default `[".git", "node_modules",
"target"]` — pass `[]` to watch those too), `max_entries` (default 100 000 — over it
`watch()` errors, and a tree that grows past it later makes the next recv raise and
retires the handle), `max_queue` (4096; overflow drops the oldest, counted in `dropped`).

How it works — and what it means: it is **polling with a snapshot** (`mtime` + size per
entry, compared every `interval`), not inotify/FSEvents/ReadDirectoryChangesW. Identical
semantics on Linux, macOS and Windows, no kernel watch limits, no extra dependency; the
cost is one directory walk per tick (hence `ignore`/`max_entries`) and a latency equal to
`interval`. A change that is made and undone inside one interval is not seen (you get
the state, not the history). A file that changes content but keeps size and mtime (rare;
same-second rewrite on a coarse filesystem) is not seen either. Budget: `SYNSEMA_WATCH_MAX`
live watches per interpreter (default 64). Lifecycle: like processes, every watch dies
with the interpreter that opened it.

## Gotchas
- `proc_close` kills the **tree** (v0.6.9+). A helper you wanted to keep alive (a daemon started by the child) dies too — spawn it with `{"process_group": false}` on purpose.
- `watch` is polling: latency = `interval`, a change undone within one tick is invisible, and a huge tree costs a walk per tick — narrow the path or `ignore` (`node_modules`, `target`, `.git` are ignored by default).
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
