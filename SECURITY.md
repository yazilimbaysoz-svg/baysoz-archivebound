# Security Policy — Baysöz Labs <baysozlabs@proton.me>

## Supported use

`archivebound` is an offline defensive analysis tool for authorized appsec
red teams, blue teams, and CI pipelines. It reads untrusted archive metadata
in memory and does not extract payloads to the host filesystem.

## Reporting vulnerabilities

Email `baysozlabs@proton.me` with a minimal reproducer (archive descriptor or
small crafted sample), affected version, and impact statement. Do not open a
public issue for an unpatched vulnerability. Baysöz Labs acknowledges reports
within five working days and coordinates disclosure with the reporter.

## Tool threat model

- The engine never calls `extract`, `extractall`, or shell commands.
- ZIP link targets are capped at 4096 bytes before decoding.
- Entry count, declared total size, symlink hops, and compression ratio are
  bounded by `Limits`.
- Generated corpora are inert descriptors and small synthetic archives; they
  contain no live exploit payloads.
- `--fail-on` defaults to `high` so CI gates fail closed on confinement
  escapes.

## Non-goals

No network calls, no LLM inference, no service dependencies, and no runtime
dependencies beyond Python 3.13+ standard library.

Attribution: Baysöz Labs <baysozlabs@proton.me>
