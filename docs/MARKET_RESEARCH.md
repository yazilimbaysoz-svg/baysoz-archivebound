# Market Research — Baysöz Labs <baysozlabs@proton.me>

Project: `baysoz-archivebound` (2026–2027 appsec-redteam line).

## Decision

Build an offline, deterministic **archive-extraction confinement differential
oracle**: it parses real ZIP/TAR member metadata, replays each archive under
four extraction-policy profiles on an in-memory filesystem, detects symlink
re-rooting chains, hardlink escapes, canonicalization divergence, resource
exhaustion, stdlib shadowing, and emits CI-ready JSON/SARIF/terminal reports.

This is a deep production library and CLI, not a trivial filename grep or toy
utility. It models extraction *sequences*: earlier link members change the
meaning of later paths. That temporal semantics is exactly what production
incidents in 2026 keep getting wrong.

## Live ecosystem evidence gathered 2026-11-25

GitHub search (`gh search repos`, `gh search issues`) and repository API:

- `snyk/zip-slip-vulnerability` — 861 stars, updated 2026-11-25. The canonical
  Zip Slip reference corpus is still active nine years after disclosure.
- `zip-rs/zip2` — 391 stars, updated 2026-11-23; its advisory
  `GHSA-4v9h-p7m9-rh26` (2026-10-09) confirms that a major Rust ZIP extractor
  passed only the *entry path* check while creating symlinks with arbitrary
  external targets.
- Open issues found live in November 2026 include
  `eikek/docspell#3379` ("Path traversal (Zip Slip) in addon archive
  extraction"), `jbangdev/jbang-gradle-plugin#29`,
  `xmake-io/xmake#7861`, `krnzhnr/k-tools#83`, and
  `Stellatinus/Stellatinus-Installer#44`. These are independent projects
  re-learning the same lesson, which demonstrates an unmet reusable oracle.

Live advisories and CPython issues (web research cross-checked against the
GitHub API):

- Argo CD `GHSA-rq7v-q562-vwcq` (2026-11-20): a tar archive plants a symlink,
  then a second symlink through it, then writes a regular file through the
  chain; text-only path checks pass and the file lands outside the root.
- DDEV `GHSA-vxj4-5gfg-97c2` (2026-11-20): the v1.25.4 lexical
  `filepath.Clean` fix was bypassed by a re-rooting `d/s -> ..`,
  `d/s/x -> ..` chain; confirmed on 1.25.5 and `main`.
- BBOT `CVE-2026-14966` (2026-10-14): legacy DOS-attribute prefixes before
  the Unix mode hid symlink members from the guard in ZIP/7z listings.
- CPython `python/cpython#160097` / `CVE-2026-114583` (2026-10-21):
  `tarfile.tar_filter` missed empty/directory-like link names that could
  re-root the destination; no patched 3.13.x release existed at discovery.
- CPython `python/cpython#161705` / `CVE-2026-115791` (opened 2026-11-09):
  `python -m tarfile` / `zipfile` extracts into `sys.path`, so a planted
  `traceback.py` can be imported and executed on a later error.
- 2026 supply-chain trend reports show `semgrep` (~17.8k stars), `grype`
  (~13.3k), `osv-scanner` (~11.6k) and the newly prominent
  `NVIDIA/SkillSpector` (~27.5k) all converging on SARIF/JSON gate output and
  zero-network/offline fallback. This validates the interface shape.

## Why existing work does not cover this

Existing Baysöz Labs lines cover SSRF canonicalization, GraphQL cost, CSP,
JOSE confusion, HTTP desync, BOLA, Kubernetes reachability, PromQL, DDL,
distributed traces, and GitHub Actions drift. None models *stateful filesystem
containment*, where member N creates a link that changes the meaning of
member N+1. A filename regex cannot express that; a plain `realpath` check on
each member independently cannot either (that is the DDEV bug).

Commercial/open scanners (`grype`, `osv-scanner`, `trivy`) answer "is this
dependency CVE-known?" They do not answer "does this untrusted bundle escape
my extractor under profile X?" `SkillSpector` scans agent skills with static
patterns and optional LLM semantics; our tool is deterministic, has no LLM,
no network, and operates on byte-level archive structure and virtual
filesystem semantics.

## 2026–2027 relevance

Trend data shows security-auditing and supply-chain tooling among the fastest
growing GitHub categories. Meanwhile the advisory stream above is dominated
by *confinement bypasses*, not by new CVE databases. CI teams need a cheap,
dependency-free gate that can ingest a sample archive and demonstrate the
differential: weak guard passes, hardened guard blocks. That is the core
value of `baysoz-archivebound`.

## Chosen stack

Python 3.13+, `uv`, standard library only (`zipfile`, `tarfile`, `stat`,
`argparse`, `json`). Zero services, zero local LLMs, zero runtime
dependencies. The CLI is installable as `archivebound` and the library API
(`simulate`, `read_archive`, `forge_cases`) is importable for CI harnesses.

Attribution: Baysöz Labs <baysozlabs@proton.me>
