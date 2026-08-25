# synsema

[Synsema](https://docs.synsema.com) — the programming language for AI agents — installed from npm.
This package puts the **native `synsema` binary** (Rust, single static executable) on your
PATH; it is the same binary as the GitHub release, wrapped for the Node ecosystem.

```sh
npm i -g synsema          # global: `synsema run app.syn`
npx synsema run app.syn   # or per project, no global install
npx synsema init          # scaffold a project (hello.syn, .env.example, .gitignore)
```

How it works: `synsema` depends on one platform package per target
(`@synsema/cli-linux-x64`, `@synsema/cli-darwin-arm64`, `@synsema/cli-darwin-x64`,
`@synsema/cli-win32-x64`) as `optionalDependencies` with `os`/`cpu` filters, so npm
installs only the binary for your machine. `bin/synsema.js` is a 40-line launcher that
runs it with your arguments — no `postinstall`, no downloads at install time, works with
`--ignore-scripts` and mirrored registries.

Updating: `npm i -g synsema@latest` (the binary's own `synsema update` notices it was
installed by npm and tells you the same). Other install paths — `curl -fsSL
https://synsema.com/install.sh | sh`, PowerShell, Docker, the WebAssembly artifacts and
the embeddable [`@synsema/wasm`](https://www.npmjs.com/package/@synsema/wasm) — are in the
[docs](https://docs.synsema.com/en/latest/00-quickstart).
