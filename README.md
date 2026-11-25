# baysoz-archivebound

[![CI](https://github.com/yazilimbaysoz-svg/baysoz-archivebound/actions/workflows/ci.yml/badge.svg)](https://github.com/yazilimbaysoz-svg/baysoz-archivebound/actions/workflows/ci.yml)
[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Ruff](https://img.shields.io/badge/ruff-E%2CF%2CW%2CS%2CB-passing)](https://docs.astral.sh/ruff/)
[![Semgrep](https://img.shields.io/badge/semgrep-p%2Fdefault-clean)](https://semgrep.dev/)
[![Baysöz Labs](https://img.shields.io/badge/Bays%C3%B6z%20Labs-baysozlabs%40proton.me-orange)](mailto:baysozlabs@proton.me)

**Offline archive-extraction confinement oracle for appsec red teams.**
Baysöz Labs <baysozlabs@proton.me>

## Why

2026 produced a wave of confinement bypasses where an archive plants a
symlink and later members are written *through* it: Argo CD
`GHSA-rq7v-q562-vwcq`, DDEV `GHSA-vxj4-5gfg-97c2`, CPython
`CVE-2026-114583`, BBOT `CVE-2026-14966`, and zip-rs
`GHSA-4v9h-p7m9-rh26`. Text-only path checks pass because each member looks
harmless in isolation. `archivebound` replays member order on an in-memory
filesystem and shows the divergence between guards.

## Install

```bash
uv tool install git+https://github.com/yazilimbaysoz-svg/baysoz-archivebound.git
# or, from a checkout
uv venv
uv pip install -e .
uv run archivebound --version
```

Python 3.13+ is required. There are **zero runtime dependencies**, no
services, no network calls, and no local LLMs.

## Quick start

```bash
# Forge real adversarial ZIP/TAR samples plus a JSON manifest
archivebound forge --out-dir ./corpus

# Scan them with the differential engine and emit SARIF for CI
archivebound scan ./corpus --format sarif --output archivebound.sarif

# CI gate: fail on high or critical findings
archivebound scan ./corpus --fail-on high
```

### Real CLI output

```text
archivebound 1.0.0 — Baysöz Labs <baysozlabs@proton.me>
scan: archives=1 profiles=4 members=4
[CRITICAL] AB1002 profile=fully-trusted source=corpus/ddev-reroot.tar member=2 'd/s/x'
    path: /dest
    detail: symlink target '..' resolves outside the extraction root
    fix: Reject links whose lexical or physical target leaves the destination and never create a link at the destination root.
[CRITICAL] AB1002 profile=lexical-data source=corpus/ddev-reroot.tar member=2 'd/s/x'
    path: /dest
    detail: symlink target '..' resolves outside the extraction root
    fix: Reject links whose lexical or physical target leaves the destination and never create a link at the destination root.
[CRITICAL] AB1002 profile=fully-trusted source=corpus/ddev-reroot.tar member=3 'd/s/x/pwn.txt'
    path: <outside-root>
    detail: earlier symlink re-roots this write outside the root
    fix: Reject links whose lexical or physical target leaves the destination and never create a link at the destination root.
[CRITICAL] AB1002 profile=lexical-data source=corpus/ddev-reroot.tar member=3 'd/s/x/pwn.txt'
    path: <outside-root>
    detail: earlier symlink re-roots this write outside the root
    fix: Reject links whose lexical or physical target leaves the destination and never create a link at the destination root.
summary: findings=4 verdict=FAIL fail_on=high
attribution: Baysöz Labs <baysozlabs@proton.me>
```

## Library API

```python
from pathlib import Path

from baysoz_archivebound.archive import read_archive
from baysoz_archivebound.engine import simulate
from baysoz_archivebound.report import ScanReport, to_sarif

archive = read_archive(Path("corpus/ddev-reroot.tar"))
result = simulate(archive.members, archive.path)
sarif = to_sarif(
    ScanReport(
        archives=(archive.path,),
        profiles=tuple(result.outcomes),
        member_count=result.member_count,
        findings=result.findings,
        verdict="FAIL",
        fail_on="high",
    )
)
```

## Architecture

`archive.py` decodes metadata only. `forge.py` materializes deterministic
samples. `engine.py` canonicalizes names per profile, resolves symlinks on a
virtual filesystem, and emits rules. `report.py` renders text/JSON/SARIF.
`cli.py` owns exit codes. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
and [docs/MARKET_RESEARCH.md](docs/MARKET_RESEARCH.md).

| Profile | Separators | Physical parent | Links |
| --- | --- | --- | --- |
| `lexical-data` | POSIX only | no | text target check |
| `physical-root` | POSIX + backslash + Unicode | yes | physical target check |
| `strict-data` | POSIX + backslash + Unicode | yes | rejected |
| `fully-trusted` | all | no | unchecked baseline |

## Rules

`AB1001` escape, `AB1002` symlink re-root chain, `AB1003` hardlink escape,
`AB1005` canonicalization divergence, `AB1006` ambiguous ZIP mode,
`AB1007` stdlib shadowing, `AB1008` resource caps.

## Quality gates

```bash
uv venv && uv pip install -e . && uv pip install pytest
uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
```

## Security

See [SECURITY.md](SECURITY.md). Vulnerability reports:
`baysozlabs@proton.me`.

## License

MIT — [LICENSE](LICENSE). Copyright (c) 2026 Baysöz Labs
<baysozlabs@proton.me>. Never use legal entity suffixes for this project.

Attribution: Baysöz Labs <baysozlabs@proton.me>
