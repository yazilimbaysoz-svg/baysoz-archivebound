# Baysöz Labs <baysozlabs@proton.me> — read-only archive member decoder.
"""Parse ZIP and TAR metadata without extracting anything to disk."""

from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .models import Limits, Member

ARCHIVE_SUFFIXES: tuple[str, ...] = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
)


class ArchiveReadError(ValueError):
    """Raised when a path is not a supported archive."""


@dataclass(frozen=True)
class Archive:
    """An archive and its observed member metadata."""

    path: str
    format: str
    members: tuple[Member, ...]

    def as_dict(self) -> dict[str, object]:
        """Expose summary metadata as JSON-safe values."""
        return {
            "path": self.path,
            "format": self.format,
            "member_count": len(self.members),
            "attribution": "Baysöz Labs <baysozlabs@proton.me>",
        }


def _zip_kind(info: zipfile.ZipInfo) -> tuple[str, str]:
    mode = info.external_attr >> 16
    shifted = (info.external_attr >> 8) & 0o170000
    if stat.S_ISLNK(mode):
        return "symlink", ""
    if shifted == stat.S_IFLNK:
        return "symlink", "DOS-prefixed Unix mode bits"
    if stat.S_ISDIR(mode) or info.filename.endswith("/"):
        return "dir", ""
    if stat.S_ISREG(mode) or mode & 0o170000 == 0:
        return "file", ""
    return "special", "unrecognized Unix mode bits"


def _read_zip(path: str, data: bytes, limits: Limits) -> Archive:
    members: list[Member] = []
    with zipfile.ZipFile(io.BytesIO(data)) as handle:
        for info in handle.infolist():
            kind, note = _zip_kind(info)
            target = ""
            if kind == "symlink":
                if info.file_size <= 4096:
                    with handle.open(info) as stream:
                        target = stream.read(4096).decode(
                            "utf-8", errors="replace"
                        )
                else:
                    note = f"{note}; link target omitted (size cap)".strip("; ")
            members.append(
                Member(
                    name=info.filename,
                    kind=kind,  # type: ignore[arg-type]
                    target=target or None,
                    size=info.file_size,
                    compressed_size=info.compress_size,
                    encoding_note=note,
                )
            )
    return Archive(path, "zip", tuple(members[: limits.max_entries]))


def _tar_kind(info: tarfile.TarInfo) -> str:
    if info.issym():
        return "symlink"
    if info.islnk():
        return "hardlink"
    if info.isdir():
        return "dir"
    if info.isreg():
        return "file"
    return "special"


def _read_tar(path: str, data: bytes, limits: Limits) -> Archive:
    members: list[Member] = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as handle:
        for info in handle.getmembers():
            kind = _tar_kind(info)
            target = info.linkname if kind in {"symlink", "hardlink"} else None
            members.append(
                Member(
                    name=info.name,
                    kind=kind,  # type: ignore[arg-type]
                    target=target,
                    size=info.size,
                    compressed_size=0,
                )
            )
    return Archive(path, "tar", tuple(members[: limits.max_entries]))


def read_archive(path: Path, limits: Limits | None = None) -> Archive:
    """Read one ZIP or TAR archive in memory and return its members."""
    active_limits = limits if limits is not None else Limits()
    data = path.read_bytes()
    label = str(path)
    if data[:4] in {b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"}:
        return _read_zip(label, data, active_limits)
    try:
        return _read_tar(label, data, active_limits)
    except tarfile.ReadError as error:
        raise ArchiveReadError(f"unsupported archive: {path}") from error


def collect_archive_paths(inputs: Sequence[str]) -> list[Path]:
    """Resolve files and archive directories into a deterministic list."""
    found: list[Path] = []
    for raw in inputs:
        candidate = Path(raw)
        if candidate.is_dir():
            children = sorted(
                child
                for child in candidate.rglob("*")
                if child.is_file()
                and child.name.lower().endswith(ARCHIVE_SUFFIXES)
            )
            found.extend(children)
        elif candidate.is_file():
            found.append(candidate)
        else:
            raise ArchiveReadError(f"path does not exist: {raw}")
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in found:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique
