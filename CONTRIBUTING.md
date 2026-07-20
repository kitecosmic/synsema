# Contributing to Synsema

Synsema is free and open source under the [Apache License 2.0](LICENSE). You are
welcome to **use it, fork it, and build on it** — that's what the license is for.

Contributions *back* into this repository, however, are **curated**. Synsema is
developed and maintained by its author, who sets the language's direction. This
keeps the design coherent; it is not an invitation for drive-by changes.

## How you can help (most valuable first)

1. **Report a bug or a rough edge.** Open an [issue](../../issues) with a minimal
   `.syn` snippet that reproduces it, what you expected, and what happened. A good
   bug report is the most useful contribution there is.
2. **Ask a question or propose an idea.** Open an issue and describe the use case.
   Direction is discussed *before* code, not in a surprise pull request.
3. **Send a fix — after we've agreed on it.** For anything beyond a typo, **open an
   issue first** and wait for a 👍 from the maintainer. This avoids you spending
   time on a change that doesn't fit the roadmap.

## What happens to a pull request

- `main` is protected. Every change that lands goes through a pull request, passes
  CI (`test` + `audit`), and is reviewed and merged **by the maintainer**. There is
  no path for a change to enter without that review.
- **Unsolicited pull requests — especially large ones — may be closed without a
  merge.** This isn't personal: an unrequested change is a maintenance liability the
  project didn't choose. Open an issue first and the answer is often "yes, please."
- Keep PRs small and focused. One concern per PR. Match the surrounding code's
  style, comments, and idioms. Add or update tests — the suite is the contract.

## Ground rules for code

- **Tests are mandatory.** New behavior needs a test; a bug fix needs a test that
  fails before and passes after. Run `cargo test --manifest-path engine/Cargo.toml
  --workspace` locally before pushing.
- **No new C/`*-sys` dependencies.** Synsema ships as a single static binary; new
  dependencies must be pure-Rust. New crates need a justification in the PR.
- **Security-sensitive code** (anything under `blockchain*`, `secrets`, capability
  checks) gets extra scrutiny and needs vectors from an authoritative source, not
  just "it works for me."

## Licensing of your contribution (inbound = outbound)

By opening a pull request you agree that your contribution is licensed under the
**Apache License 2.0**, the same license as the project, and that you have the right
to submit it. Please sign off your commits to certify this
([Developer Certificate of Origin](https://developercertificate.org/)):

```
git commit -s -m "your message"
```

which appends a `Signed-off-by: Your Name <you@example.com>` line.

## Security

**Do not report security vulnerabilities in a public issue or pull request.** See
[SECURITY.md](SECURITY.md) for private reporting.
