# Synsema — VS Code extension

Syntax highlighting for the Synsema language (`.syn`, `.fsyn`).

Works in **VS Code, Cursor, Windsurf, VSCodium** and any VS Code–family editor (one
extension, all of them) — no editor fork needed.

## What it does (v0.1)

- Syntax highlighting via a TextMate grammar: keywords (control / security / agent / LLM /
  human / observability / serve), built-in functions, strings + escapes, numbers, comments
  (`--`), `task`/`type`/`agent` definitions, and call expressions.
- Language config: `--` line comments, bracket matching, auto-closing pairs, indentation.

## Install

### From source (until published)

```bash
cd editors/vscode
npm install -g @vscode/vsce      # one time
vsce package                     # produces synsema-0.1.0.vsix
code --install-extension synsema-0.1.0.vsix   # or: cursor / windsurf --install-extension
```

Or, for quick local use, copy this folder to your editor's extensions dir
(`~/.vscode/extensions/synsema` and reload).

### Marketplaces (planned)

- **VS Code Marketplace** (`vsce publish`) — for VS Code.
- **Open VSX** (`ovsx publish`) — for Cursor, Windsurf, VSCodium, Gitpod, etc.

## The grammar powers the website too

`syntaxes/synsema.tmLanguage.json` is a TextMate grammar. The same file is consumed by
**Shiki** (and Prism/highlight.js with a small adapter), so the docs/blog code blocks on
the site use the exact same highlighting as the editor — one grammar, both surfaces.

## Roadmap

- [ ] Publish to VS Code Marketplace + Open VSX
- [ ] Language Server (LSP): autocomplete, diagnostics, hover, go-to-definition
- [ ] Snippets for common constructs (`task`, `serve`, `route`, agents)
