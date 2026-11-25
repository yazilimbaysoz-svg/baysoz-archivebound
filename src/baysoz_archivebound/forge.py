# Baysöz Labs <baysozlabs@proton.me> — deterministic adversarial corpus forger.
"""Forge real ZIP/TAR samples and descriptors for extraction-confinement tests."""

from __future__ import annotations

import io
import json
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .models import ATTRIBUTION, Member

REFERENCES: tuple[str, ...] = (
    "https://github.com/argoproj/argo-cd/security/advisories/"
    "GHSA-rq7v-q562-vwcq",
    "https://github.com/ddev/ddev/security/advisories/GHSA-vxj4-5gfg-97c2",
    "https://advisories.gitlab.com/pypi/bbot/CVE-2026-14966/",
    "https://github.com/python/cpython/issues/160097",
    "https://github.com/python/cpython/issues/161705",
    "https://github.com/zip-rs/zip2/security/advisories/GHSA-4v9h-p7m9-rh26",
)


@dataclass(frozen=True)
class ForgeCase:
    """One adversarial archive plan with its expected detection rules."""

    slug: str
    title: str
    family: str
    members: tuple[Member, ...]
    expected_rules: tuple[str, ...]
    references: tuple[str, ...]


def forge_cases() -> tuple[ForgeCase, ...]:
    """Return the deterministic 2026 adversarial corpus."""
    return (
        ForgeCase(
            slug="zipslip-direct",
            title="Direct parent traversal to a cron drop-in",
            family="CWE-22",
            members=(
                Member("../../etc/cron.d/baysöz-probe", "file", size=32),
            ),
            expected_rules=("AB1001",),
            references=REFERENCES[:1],
        ),
        ForgeCase(
            slug="ddev-reroot",
            title="Two-hop relative symlink re-rooting chain",
            family="CWE-59",
            members=(
                Member("d/", "dir"),
                Member("d/s", "symlink", target=".."),
                Member("d/s/x", "symlink", target=".."),
                Member("d/s/x/pwn.txt", "file", size=16),
            ),
            expected_rules=("AB1002",),
            references=REFERENCES[1:2],
        ),
        ForgeCase(
            slug="argo-symlink-chain",
            title="Nested chart symlink chain escaping a repo checkout",
            family="CWE-59",
            members=(
                Member("charts/", "dir"),
                Member("charts/link", "symlink", target=".."),
                Member("charts/link/deep", "symlink", target="../.."),
                Member("charts/link/deep/evil.sh", "file", size=24),
            ),
            expected_rules=("AB1002",),
            references=REFERENCES[:1],
        ),
        ForgeCase(
            slug="hardlink-escape",
            title="Symlink parent plus hardlink to an external file",
            family="CWE-59",
            members=(
                Member("d/", "dir"),
                Member("d/s", "symlink", target=".."),
                Member(
                    "d/s/h",
                    "hardlink",
                    target="../../etc/passwd",
                    size=0,
                ),
            ),
            expected_rules=("AB1003",),
            references=REFERENCES[5:6],
        ),
        ForgeCase(
            slug="root-link",
            title="Link member replacing the extraction root",
            family="CWE-59",
            members=(
                Member(".", "symlink", target="tmp"),
                Member("payload.txt", "file", size=16),
            ),
            expected_rules=("AB1002",),
            references=REFERENCES[3:4],
        ),
        ForgeCase(
            slug="backslash-polyglot",
            title="Backslash separator interpreted only by some extractors",
            family="CWE-22",
            members=(
                Member("..\\..\\outside\\probe.txt", "file", size=16),
            ),
            expected_rules=("AB1005",),
            references=REFERENCES[4:5],
        ),
        ForgeCase(
            slug="unicode-slash-polyglot",
            title="Unicode division slash bypassing ASCII-only checks",
            family="CWE-22",
            members=(Member("..\u2215..\u2215probe.txt", "file", size=16),),
            expected_rules=("AB1005",),
            references=REFERENCES[2:3],
        ),
        ForgeCase(
            slug="nul-truncation",
            title="NUL byte truncating a benign-looking member name",
            family="CWE-22",
            members=(
                Member(
                    "safe.txt\x00../../etc/cron.d/probe",
                    "file",
                    size=16,
                ),
            ),
            expected_rules=("AB1005",),
            references=REFERENCES[4:5],
        ),
        ForgeCase(
            slug="drive-prefix",
            title="Windows drive prefix ignored by POSIX-only guards",
            family="CWE-22",
            members=(
                Member("C:\\Windows\\System32\\probe.dll", "file", size=16),
            ),
            expected_rules=("AB1005",),
            references=REFERENCES[4:5],
        ),
        ForgeCase(
            slug="stdlib-shadow",
            title="Archive plants traceback.py for import shadowing",
            family="CWE-427",
            members=(Member("traceback.py", "file", size=64),),
            expected_rules=("AB1007",),
            references=REFERENCES[4:5],
        ),
        ForgeCase(
            slug="legacy-dos-link",
            title="ZIP link mode hidden behind a DOS attribute prefix",
            family="CWE-59",
            members=(
                Member("plugin/", "dir"),
                Member(
                    "plugin/shell",
                    "symlink",
                    target="../../etc/passwd",
                    encoding_note="DOS-prefixed Unix mode bits",
                ),
            ),
            expected_rules=("AB1006",),
            references=REFERENCES[2:3],
        ),
        ForgeCase(
            slug="compression-bomb",
            title="Extreme compression ratio beyond configured caps",
            family="CWE-409",
            members=(
                Member(
                    "blob.bin",
                    "file",
                    size=50_000_000,
                    compressed_size=1_000,
                ),
            ),
            expected_rules=("AB1008",),
            references=REFERENCES[2:3],
        ),
    )


def _payload(member: Member) -> bytes:
    if member.kind == "symlink" and member.target:
        return member.target.encode("utf-8", errors="replace")
    if member.kind in {"dir", "hardlink"}:
        return b""
    return b"payload"[: min(64, max(0, member.size))]


def _zip_mode(member: Member) -> int:
    if member.kind == "symlink" and "DOS-prefixed" in member.encoding_note:
        return (stat.S_IFLNK | 0o777) << 8
    if member.kind == "symlink":
        return (stat.S_IFLNK | 0o777) << 16
    if member.kind == "dir":
        return (stat.S_IFDIR | 0o755) << 16
    if member.kind == "special":
        return (stat.S_IFCHR | 0o600) << 16
    return (stat.S_IFREG | 0o644) << 16


def build_archive_bytes(case: ForgeCase, fmt: str) -> bytes:
    """Materialize one case as real ZIP or TAR bytes in memory."""
    buffer = io.BytesIO()
    if fmt == "zip":
        with zipfile.ZipFile(buffer, mode="w") as handle:
            for member in case.members:
                name = member.name
                if not name.endswith("/") and member.kind == "dir":
                    name += "/"
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = _zip_mode(member)
                handle.writestr(info, _payload(member))
        return buffer.getvalue()
    if fmt == "tar":
        with tarfile.open(fileobj=buffer, mode="w") as handle:
            for member in case.members:
                item = tarfile.TarInfo(member.name)
                item.uid = 0
                item.gid = 0
                item.uname = "baysöz"
                item.gname = "baysöz"
                if member.kind == "symlink":
                    item.type = tarfile.SYMTYPE
                    item.linkname = member.target or ""
                    item.size = 0
                elif member.kind == "hardlink":
                    item.type = tarfile.LNKTYPE
                    item.linkname = member.target or ""
                    item.size = 0
                elif member.kind == "dir":
                    item.type = tarfile.DIRTYPE
                    item.size = 0
                elif member.kind == "special":
                    item.type = tarfile.CHRTYPE
                    item.size = 0
                else:
                    data = _payload(member)
                    item.type = tarfile.REGTYPE
                    item.size = len(data)
                    handle.addfile(item, io.BytesIO(data))
                    continue
                handle.addfile(item)
        return buffer.getvalue()
    raise ValueError(f"unsupported forge format: {fmt}")


def write_corpus(out_dir: Path) -> tuple[Path, ...]:
    """Write all forgeable cases as real archives plus a JSON manifest."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    manifest: list[dict[str, object]] = []
    for case in forge_cases():
        available: list[str] = []
        for fmt in ("tar", "zip"):
            try:
                data = build_archive_bytes(case, fmt)
            except (ValueError, UnicodeError):
                continue
            target = out_dir / f"{case.slug}.{fmt}"
            target.write_bytes(data)
            written.append(target)
            available.append(fmt)
        manifest.append(
            {
                "slug": case.slug,
                "title": case.title,
                "family": case.family,
                "expected_rules": list(case.expected_rules),
                "formats": available,
                "references": list(case.references),
                "attribution": ATTRIBUTION,
            }
        )
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "attribution": ATTRIBUTION,
                "cases": manifest,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    written.append(manifest_path)
    return tuple(written)
