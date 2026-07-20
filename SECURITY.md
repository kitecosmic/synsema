# Security Policy

Synsema handles security-sensitive material — private keys sealed as secrets,
signing capabilities, blockchain transaction building. Please treat vulnerabilities
accordingly.

## Reporting a vulnerability

**Do not open a public issue or pull request for a security problem.** A public
report tells attackers about the flaw before there is a fix.

Instead, report it privately through GitHub:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** (GitHub private vulnerability reporting).
3. Describe the issue, the affected version, and a reproduction if you have one.

This opens a private advisory visible only to you and the maintainer.

## Scope

Especially interested in:

- Any way a **private key, seed, or secret can be made to materialize** in plaintext,
  a log, an error message, or an LLM-visible value.
- A **capability check that can be bypassed** — signing, custody (`wallet`), network,
  or the `sandbox` / `--cap-set` host ceiling.
- **Incorrect transaction construction** that could sign or broadcast something other
  than what the caller intended (wrong sighash, wrong amount, wrong network).
- A parser or decoder that **panics or misbehaves on hostile input** (a malicious RPC
  node, a crafted PSBT, an oversized frame).

Out of scope: issues that require an already-compromised host, and the deliberate,
documented behavior of `reveal()` under its gated + audited capability.

## Response

This is a single-maintainer project; reports are handled on a best-effort basis.
You'll get an acknowledgement, and once a fix ships it will be noted in the release.
Supported version: the **latest published release**.
