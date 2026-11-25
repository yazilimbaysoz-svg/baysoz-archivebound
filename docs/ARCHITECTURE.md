# Architecture — Baysöz Labs <baysozlabs@proton.me>

## System shape

```
CLI (cli.py) ──> archive.py ──> Member[] ──> engine.py ──> Finding[]
                   │                            │
                   │                            └──> report.py
                   └──> forge.py ──> real ZIP/TAR bytes ──┘
```

`src/baysoz_archivebound/` is a single dependency-free package:

- `models.py` — `Member`, `Limits`, `Profile`, `Finding`, four named profiles.
- `archive.py` — read-only ZIP/TAR metadata decoding; no writes to disk.
- `forge.py` — deterministic adversarial descriptors and real sample bytes.
- `engine.py` — virtual filesystem, name canonicalization, link resolution,
  differential comparison, rule emission.
- `report.py` — text, JSON, SARIF 2.1.0 renderers.
- `cli.py` — `scan`, `forge`, `profiles` subcommands and CI exit codes.

## Virtual filesystem semantics

The destination root is `/dest`. The engine keeps a dictionary of
`tuple[str, ...] -> Node(kind, target)`. Every member is processed in archive
order. For each member it computes:

1. **Name view** — profile-specific separator handling (`\`, U+2215,
   U+2044, U+FF3C), NUL truncation or rejection, drive-prefix rejection,
   leading-slash stripping/rejection, and lexical `..` containment.
2. **Guard decision** — whether this profile would refuse the member. The
   lexical profile checks text only; the physical-root profile resolves the
   parent through existing symlinks before every write; strict rejects all
   links; fully-trusted has no guard.
3. **Actual write** — always performed against the virtual filesystem using
   physical parent resolution, even when the guard accepted the member. This
   is what exposes the 2026 re-rooting class: the guard believes the path is
   inside, the operating system follows a planted link to the outside.

Symlink hops are bounded (`max_symlink_hops`, default 40). A link whose
declared destination is the root is treated as a root-replacing link
(`AB1002`), matching the empty-name/directory-like link CVE pattern.

## Differential rule set

| Rule | Class | Meaning |
| --- | --- | --- |
| AB1001 | high | Absolute or traversing write escapes the root |
| AB1002 | critical | Symlink re-rooting chain redirects later writes |
| AB1003 | high | Hardlink target resolves outside the root |
| AB1005 | high | Name canonicalization diverges between profiles |
| AB1006 | medium | DOS-prefixed ZIP mode hides a symlink |
| AB1007 | high | Stdlib-shadowing module name planted in the root |
| AB1008 | high | Entry-count, size, or compression-ratio cap exceeded |

`AB1004` is reserved and never emitted. Every finding carries source,
profile, member index, observed path, detail, remediation, and the mandatory
Baysöz Labs attribution string.

## Profile matrix

| Profile | Backslash | Unicode slash | Physical parent | Links |
| --- | --- | --- | --- | --- |
| lexical-data | literal | literal | no | allowed, text target check |
| physical-root | separator | separator | yes | allowed, physical target check |
| strict-data | separator | separator | yes | rejected |
| fully-trusted | separator | separator | no | allowed, no check |

The oracle's central assertion is that `lexical-data` can report PASS while
`physical-root` reports a blocked member and `fully-trusted` escapes. That
divergence is the evidence CI gates consume, not a heuristic score.

## Threat model

In scope: untrusted ZIP/TAR bundles consumed by CI agents, plugin sidecars,
OTA updaters, import commands, and CLI extraction. Attacker controls member
names, order, link targets, external attributes, and sizes. The analyzer is
offline and never extracts attacker bytes to the host filesystem.

Out of scope: exploitation of a live extractor, network fetches, decompression
of except-sized payloads into memory, and detection of malware payload
semantics. The tool reports confinement risk, not payload intent.

## Quality gates

`uv venv`, `uv pip install -e .`, `uv pip install pytest`, `uv run pytest -q`,
`ruff check --select E,F,W,S,B .`, and
`semgrep --config p/default --error .` must all be clean. The forger feeds
real adversarial archives back through the CLI before release.

Attribution: Baysöz Labs <baysozlabs@proton.me>
