# PLAN — Baysöz Labs <baysozlabs@proton.me>

Version 1.0.0 — completed end-to-end on 2026-11-25.

## Phase 1 — Research

- [x] Inspect `existing-repos.json` and avoid overlapping tool categories.
- [x] Mine live GitHub repository and issue signals with `gh search`.
- [x] Cross-check 2026 advisories for Argo CD, DDEV, BBOT, CPython, zip-rs.
- [x] Select archive-extraction confinement as the unmet deep need.

## Phase 2 — Engine

- [x] Model members, profiles, and bounded limits as immutable dataclasses.
- [x] Implement profile-specific name canonicalization.
- [x] Implement virtual filesystem with physical symlink resolution.
- [x] Implement link, root-replacement, divergence, and resource rules.
- [x] Decode real ZIP/TAR metadata without extracting.

## Phase 3 — Interface

- [x] Forge deterministic adversarial ZIP/TAR corpus and JSON manifest.
- [x] CLI: `scan`, `forge`, `profiles`, `--version`, `--help`.
- [x] Text, JSON, and SARIF 2.1.0 renderers with attribution.
- [x] CI failure semantics via `--fail-on`.

## Phase 4 — Assurance

- [x] Unit and CLI tests over real adversarial archives.
- [x] `uv` editable install and pytest gate.
- [x] Ruff `E,F,W,S,B` gate.
- [x] Semgrep `p/default` gate.
- [x] Supreme Grand Jury Tribunal live adversarial review.

## Phase 5 — Release

- [x] Public repository with description and topics.
- [x] Strict machine-readable factory result artifact.

Attribution: Baysöz Labs <baysozlabs@proton.me>
