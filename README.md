# Synsema

**A programming language designed for AI agents.**

Build agents, APIs and data workflows with LLM operations, scoped permissions,
multi-agent coordination and human approval built into the language. Synsema uses
readable `.syn` source files and ships as a single native executable.

Run your programs with the Synsema engine, or bundle a program and its assets with
the engine into a standalone executable for deployment.

[Website](https://synsema.com/lang) · [Documentation](https://synsema.dev) · [Learn by building](https://try.synsema.org) · [Changelog](CHANGELOG.md) · [Discord](https://discord.gg/qCJuwsF5bT)

## Get started

Install on **macOS or Linux**:

```sh
curl -fsSL https://synsema.com/install.sh | sh
```

Install on **Windows** with PowerShell:

```powershell
irm https://synsema.com/install.ps1 | iex
```

Or install through **npm** on Linux, macOS or Windows:

```sh
npm i -g synsema
```

The npm package installs the same native engine. Direct installs do not require
Python or Node.js. See [releases](https://github.com/kitecosmic/synsema/releases)
for downloadable binaries.

Create `hello.syn`:

```synsema
intent: "Greet someone and check the result"

task greet(name)
    give "Hello, " + name + "!"

print(greet("World"))

test "greeting includes the name"
    assert_eq(greet("Synsema"), "Hello, Synsema!")
```

Run it and its test:

```sh
synsema run hello.syn
synsema test hello.syn
```

To scaffold a project with example code and configuration, use
`synsema init my-project`. Update a direct installation with `synsema update`,
or an npm installation with `npm i -g synsema@latest`.

### Serve an API

Save this as `app.syn`:

```synsema
require serve(8080)

serve on 8080
    route "GET /hello/:name"
        give {"message": "Hello, " + params.name + "!"}

    route "POST /greet"
        expect body {name: text}
        give {"message": "Hello, " + request.json.name + "!"}
```

Start it with `synsema serve app.syn` and visit
[`http://localhost:8080/hello/World`](http://localhost:8080/hello/World).
The POST route validates the JSON body before running the handler.

Continue with the [quickstart](https://synsema.dev/en/0.6.x/00-quickstart)
and [examples](examples/).

## What you can build

| Capability | Built into Synsema | Reference |
| --- | --- | --- |
| AI agents | `reason`, `decide`, `analyze`, `generate`, tool calling and response validation | [LLM integration](skills/synsema/llm.md) |
| Agent coordination | Agents, shared blackboards, signals, resource locks and persistent memory | [Agents](skills/synsema/agents.md) · [Memory](skills/synsema/memory.md) |
| Human oversight | `approve`, `confirm` and `ask` for decisions that need a person | [Syntax](skills/synsema/syntax.md) |
| APIs and web apps | HTTP, WebSocket, SSE, request validation, authentication, TLS and templates | [Web server](skills/synsema/serve.md) |
| Data workflows | SQL, CSV, Parquet, columnar tables, joins, aggregations and charts | [Data and visualization](skills/synsema/dataviz.md) |
| Reusable libraries | `use` / `export`, pinned dependencies and capability review with `synsema get` | [Modules and packages](skills/synsema/modules.md) |
| Deployment | Standalone app bundles, desktop apps, installable web apps and WebAssembly | [Deployment](skills/synsema/deploy.md) |

LLM operations connect to a configured provider. See the
[provider setup](skills/synsema/llm.md); `synsema llm status` reports the resolved
configuration and missing settings.

### Permissions you can inspect and constrain

Use `require` to scope access to network hosts, files, databases, secrets and other
resources. The server enforces capability checks; plain `run` provides some ambient
permissions for development. A host can impose a capability ceiling with
`--sandbox` or `--cap-set` that the program and its dependencies cannot expand.

Packages declare their own capabilities, and dependency updates that add permissions
require explicit acceptance. For sensitive workloads, Synsema also supports
information-flow labels, audit receipts and attestation.

Read about [capabilities](skills/synsema/capabilities.md),
[secrets](skills/synsema/secrets.md), [information-flow labels](skills/synsema/labels.md)
and [attestation](skills/synsema/attestation.md).

## Set up your coding agent

Install the Synsema skill so your coding agent can look up syntax, builtins,
security rules and working patterns:

```sh
npx skills add kitecosmic/synsema --skill synsema -g -y
```

The skill uses the open [Agent Skills](https://agentskills.io) format and works
with agents that support it, including Claude Code, Codex and Cursor.
After updating Synsema, rerun the command to refresh the skill.
See [agent setup](https://synsema.dev/en/0.6.x/02-ai-agents) for other installation
methods, or read the [skill index](skills/synsema/INDEX.md) directly.

### Connect the documentation MCP

The public docs MCP lets agents search documentation, retrieve examples and run
or test snippets in a sandbox. It needs no API key.

```sh
# Claude Code
claude mcp add --transport http synsema-docs https://synsema.dev/mcp

# Codex
codex mcp add synsema-docs --url https://synsema.dev/mcp
```

For other MCP clients, use the streamable HTTP endpoint `https://synsema.dev/mcp`.
The sandbox restricts network and process access; check programs that need external
services in your own environment.

## Explore and contribute

- **Learn:** [Documentation](https://synsema.dev) · [Guided projects](https://try.synsema.org) · [Example programs](examples/)
- **Use an editor:** [VS Code, Cursor and Windsurf extension](editors/vscode/README.md)
- **Follow changes:** [Changelog](CHANGELOG.md) · [Releases](https://github.com/kitecosmic/synsema/releases)
- **Ask or report a bug:** [Discord](https://discord.gg/qCJuwsF5bT) · [GitHub issues](https://github.com/kitecosmic/synsema/issues)
- **Contribute:** Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a code change.
- **Explore the hosted platform:** [synsema.com/platform](https://synsema.com/platform)

### Build from source

With the Rust toolchain installed:

```sh
git clone https://github.com/kitecosmic/synsema.git
cd synsema
cargo build --release --manifest-path engine/Cargo.toml
```

The executable is produced under `engine/target/release/`. To run the engine's
unit and integration tests:

```sh
cargo test --manifest-path engine/Cargo.toml --workspace
```

## License

[Apache License 2.0](LICENSE). Free to use, modify and distribute, with an explicit
patent grant.

**Trademark:** "Synsema" is a project trademark. The license covers the code;
forks and derivative works must use a different name. See [NOTICE](NOTICE).
