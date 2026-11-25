# Baysöz Labs <baysozlabs@proton.me> — archivebound core data models.
"""Immutable data models shared by the archivebound engine and CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"
TOOL_NAME = "archivebound"

Severity = Literal["low", "medium", "high", "critical"]
MemberKind = Literal["file", "symlink", "hardlink", "dir", "special"]

SEVERITY_RANK: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


@dataclass(frozen=True)
class Member:
    """One archive member as observed before any extraction happens."""

    name: str
    kind: MemberKind
    target: str | None = None
    size: int = 0
    compressed_size: int = 0
    encoding_note: str = ""

    def display(self) -> str:
        """Return a deterministic, log-safe member label."""
        if self.kind in {"symlink", "hardlink"} and self.target is not None:
            return f"{self.name!r} -> {self.target!r}"
        return repr(self.name)


@dataclass(frozen=True)
class Limits:
    """Bounded resource limits for offline analysis."""

    max_entries: int = 10_000
    max_total_bytes: int = 100 * 1024 * 1024
    max_compression_ratio: int = 200
    max_symlink_hops: int = 40

    def as_dict(self) -> dict[str, int]:
        """Expose limits as JSON-safe values."""
        return {
            "max_entries": self.max_entries,
            "max_total_bytes": self.max_total_bytes,
            "max_compression_ratio": self.max_compression_ratio,
            "max_symlink_hops": self.max_symlink_hops,
        }


@dataclass(frozen=True)
class Profile:
    """An extraction-confinement policy profile."""

    name: str
    description: str
    backslash_separator: bool
    unicode_separator: bool
    physical_parent_check: bool
    reject_links: bool
    strip_absolute: bool
    reject_absolute: bool
    reject_unusual_names: bool


PROFILES: tuple[Profile, ...] = (
    Profile(
        name="lexical-data",
        description=(
            "Lexical containment plus leading-slash stripping; link targets "
            "checked as text only. Represents the weak guard that the 2026 "
            "re-rooting advisories bypassed."
        ),
        backslash_separator=False,
        unicode_separator=False,
        physical_parent_check=False,
        reject_links=False,
        strip_absolute=True,
        reject_absolute=False,
        reject_unusual_names=False,
    ),
    Profile(
        name="physical-root",
        description=(
            "Lexical containment plus physical parent resolution before each "
            "write; link targets resolved on the virtual filesystem. Models "
            "os.Root-style confinement."
        ),
        backslash_separator=True,
        unicode_separator=True,
        physical_parent_check=True,
        reject_links=False,
        strip_absolute=True,
        reject_absolute=True,
        reject_unusual_names=True,
    ),
    Profile(
        name="strict-data",
        description=(
            "Physical-root checks plus rejection of every link, device, and "
            "ambiguous name. The hardened baseline for untrusted bundles."
        ),
        backslash_separator=True,
        unicode_separator=True,
        physical_parent_check=True,
        reject_links=True,
        strip_absolute=True,
        reject_absolute=True,
        reject_unusual_names=True,
    ),
    Profile(
        name="fully-trusted",
        description=(
            "No confinement checks. Included as the adversary's upper bound "
            "and as a differential baseline, not as a recommended setting."
        ),
        backslash_separator=True,
        unicode_separator=True,
        physical_parent_check=False,
        reject_links=False,
        strip_absolute=False,
        reject_absolute=False,
        reject_unusual_names=False,
    ),
)

PROFILE_BY_NAME = {profile.name: profile for profile in PROFILES}


@dataclass(frozen=True)
class Finding:
    """A deterministic, SARIF-ready finding."""

    rule_id: str
    severity: Severity
    source: str
    profile: str
    member_index: int
    member_name: str
    observed_path: str
    detail: str
    remediation: str

    def as_dict(self) -> dict[str, str | int]:
        """Return a JSON-safe representation."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "source": self.source,
            "profile": self.profile,
            "member_index": self.member_index,
            "member_name": self.member_name,
            "observed_path": self.observed_path,
            "detail": self.detail,
            "remediation": self.remediation,
            "attribution": ATTRIBUTION,
        }
