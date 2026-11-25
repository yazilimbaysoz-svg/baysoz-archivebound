# Changelog — Baysöz Labs <baysozlabs@proton.me>

## 1.0.0 — 2026-11-25

- Initial release of the offline archive-extraction confinement oracle.
- Four differential profiles: `lexical-data`, `physical-root`,
  `strict-data`, `fully-trusted`.
- Virtual filesystem simulation of symlink re-rooting chains, hardlink
  escapes, root-replacing links, and canonicalization divergence.
- Read-only ZIP/TAR metadata parsing with bounded link-target reads.
- Deterministic adversarial corpus forger covering 2026 advisory patterns.
- Text, JSON, and SARIF 2.1.0 reports with CI exit codes.
- Zero runtime dependencies; Python 3.13+ and `uv` workflow.

Attribution: Baysöz Labs <baysozlabs@proton.me>
