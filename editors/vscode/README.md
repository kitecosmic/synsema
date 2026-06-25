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

### From a release — no clone needed (recommended)

Download the packaged `.vsix` from GitHub Releases and install it directly — you don't
need to check out the repo:

```bash
curl -L -o synsema.vsix https://github.com/kitecosmic/synsema/releases/latest/download/synsema-vscode.vsix
code --install-extension synsema.vsix      # or: cursor / windsurf --install-extension
```

(Or download the `.vsix` from the [Releases page](https://github.com/kitecosmic/synsema/releases)
and use **Extensions → … → Install from VSIX…** in the editor UI.)

### From source (build it yourself)

```bash
cd editors/vscode
npm install -g @vscode/vsce      # one time
vsce package                     # produces synsema-<version>.vsix
code --install-extension synsema-*.vsix   # or: cursor / windsurf --install-extension
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
