# Syntecnia Skill Index

Read ONLY the sections you need. Do not load everything.

## Quick reference
- [syntax.md](syntax.md) — Complete syntax, keywords, operators, statement patterns
- [builtins.md](builtins.md) — All built-in tasks and their signatures
- [types.md](types.md) — Type system, property access, values

## By topic
- [stdlib.md](stdlib.md) — HTTP requests, SQL database, cron scheduler (zero dependencies)
- [capabilities.md](capabilities.md) — Security model, require, sandbox, intent
- [agents.md](agents.md) — Multi-agent coordination, blackboard, swarm, signals
- [llm.md](llm.md) — LLM operations: reason, decide, analyze, generate
- [human.md](human.md) — Human interaction: approve, confirm, ask, show
- [observability.md](observability.md) — trace, log, measure, checkpoint, error diagnostics
- [memory.md](memory.md) — Agent memory, owner rules, progress tracking
- [patterns.md](patterns.md) — Common patterns and idioms

## Project structure
- [structure.md](structure.md) — File map of the codebase

## Deployment
- [deploy.md](deploy.md) — Daemon mode, Docker, VPS, Kubernetes, systemd

## Troubleshooting
- [pitfalls.md](pitfalls.md) — **Read first if something fails.** Common errors, surprises, and anti-patterns with solutions.

## When to read what
- Something broke → pitfalls.md
- Writing a new .syn program → syntax.md, builtins.md
- HTTP / SQL / cron → stdlib.md
- Deploying to server → deploy.md
- Adding security → capabilities.md
- Multi-agent system → agents.md
- Using AI reasoning → llm.md
- Debugging errors → observability.md
- Agent that learns → memory.md
- Understanding the codebase → structure.md
