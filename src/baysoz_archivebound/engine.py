# Baysöz Labs <baysozlabs@proton.me> — differential virtual extraction engine.
"""Offline, side-effect-free simulation of archive extraction confinement."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from .models import (
    ATTRIBUTION,
    PROFILES,
    SEVERITY_RANK,
    Finding,
    Limits,
    Member,
    Profile,
    Severity,
)

RULES: dict[str, dict[str, str]] = {
    "AB1001": {
        "title": "Extraction member escapes the confinement root",
        "remediation": (
            "Resolve symlinks in parent directories before every write and "
            "fail closed when the resolved parent leaves the destination."
        ),
    },
    "AB1002": {
        "title": "Symlink re-rooting chain redirects later writes",
        "remediation": (
            "Reject links whose lexical or physical target leaves the "
            "destination and never create a link at the destination root."
        ),
    },
    "AB1003": {
        "title": "Hardlink target resolves outside the confinement root",
        "remediation": (
            "Resolve hardlink targets on the destination filesystem and "
            "reject any target that is not a regular file inside the root."
        ),
    },
    "AB1004": {
        "title": "Reserved for archive metadata drift",
        "remediation": "Use a supported archive profile.",
    },
    "AB1005": {
        "title": "Member name canonicalization diverges across profiles",
        "remediation": (
            "Normalize separators, NUL bytes, and drive prefixes explicitly "
            "before containment checks; reject ambiguous names."
        ),
    },
    "AB1006": {
        "title": "Ambiguous ZIP external attributes hide link type",
        "remediation": (
            "Decode both aligned and DOS-prefixed Unix mode bits before "
            "deciding whether a ZIP member is a symbolic link."
        ),
    },
    "AB1007": {
        "title": "Archive plants an importable module name",
        "remediation": (
            "Extract into a private directory that is not on sys.path and "
            "reject stdlib-shadowing names at the CLI boundary."
        ),
    },
    "AB1008": {
        "title": "Resource-exhaustion limits exceeded",
        "remediation": (
            "Enforce entry-count, total-size, and compression-ratio caps "
            "before allocating or writing any member payload."
        ),
    },
}

UNICODE_SEPARATORS = ("\u2215", "\u2044", "\uFF3C")
STDLIB_SHADOW_NAMES = frozenset(
    {
        "os.py",
        "sys.py",
        "site.py",
        "sitecustomize.py",
        "usercustomize.py",
        "traceback.py",
        "zipfile.py",
        "tarfile.py",
        "subprocess.py",
        "importlib.py",
    }
)


@dataclass(frozen=True)
class NameView:
    """How one profile canonicalizes a raw archive member name."""

    components: tuple[str, ...]
    absolute_escape: bool
    rejected_reason: str
    flags: tuple[str, ...]


@dataclass(frozen=True)
class Node:
    """A virtual filesystem node."""

    kind: str
    target: str = ""


@dataclass(frozen=True)
class ResolveResult:
    """The physical location reached by walking the virtual filesystem."""

    components: tuple[str, ...]
    followed: tuple[str, ...]
    outside: bool


@dataclass(frozen=True)
class MemberOutcome:
    """Per-profile guard decision for one member."""

    escaped: bool
    guard_rejected: bool
    reason: str


@dataclass(frozen=True)
class Simulation:
    """All findings and per-profile outcomes for one archive."""

    findings: tuple[Finding, ...]
    outcomes: dict[str, tuple[MemberOutcome, ...]]
    member_count: int


class VirtualFS:
    """An in-memory model of the destination directory."""

    def __init__(self, max_hops: int) -> None:
        self.max_hops = max_hops
        self.nodes: dict[tuple[str, ...], Node] = {}

    def resolve(self, components: tuple[str, ...]) -> ResolveResult:
        """Walk components, following links in every parent position."""
        followed: list[str] = []
        root = self.nodes.get(())
        if root is not None and root.kind == "symlink":
            followed.append("<root>")
            target = root.target
            if target.startswith("/") or target.strip("/") not in {"", "."}:
                return ResolveResult((), tuple(followed), True)
        current: list[str] = []
        pending = list(components)
        hops = 0
        while pending:
            part = pending.pop(0)
            if part in {"", "."}:
                continue
            if part == "..":
                if not current:
                    return ResolveResult(tuple(current), tuple(followed), True)
                current.pop()
                continue
            candidate = tuple(current + [part])
            node = self.nodes.get(candidate)
            if node is not None and node.kind == "symlink":
                hops += 1
                if hops > self.max_hops:
                    return ResolveResult(
                        tuple(current), tuple(followed), True
                    )
                followed.append("/".join(candidate))
                target = node.target
                if target.startswith("/"):
                    return ResolveResult(tuple(current), tuple(followed), True)
                pending = list(target.split("/")) + pending
                continue
            current.append(part)
        return ResolveResult(tuple(current), tuple(followed), False)

    def put(self, components: tuple[str, ...], node: Node) -> None:
        """Write a node, implicitly creating its parent directories."""
        for index in range(1, len(components)):
            parent = tuple(components[:index])
            if parent not in self.nodes:
                self.nodes[parent] = Node("dir")
        self.nodes[components] = node


def normalize_name(name: str, profile: Profile) -> NameView:
    """Canonicalize a member name according to one extraction profile."""
    flags: list[str] = []
    if "\\" in name:
        flags.append("backslash-separator")
    if any(separator in name for separator in UNICODE_SEPARATORS):
        flags.append("unicode-separator")
    if "\x00" in name:
        flags.append("nul-truncation")
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        flags.append("drive-prefix")
    if name.startswith("/"):
        flags.append("absolute-path")

    if profile.reject_unusual_names and "nul-truncation" in flags:
        return NameView((), False, "NUL byte in member name", tuple(flags))
    if profile.reject_unusual_names and "drive-prefix" in flags:
        return NameView((), False, "drive prefix in member name", tuple(flags))

    text = name.split("\x00", 1)[0] if "\x00" in name else name
    if profile.unicode_separator:
        for separator in UNICODE_SEPARATORS:
            text = text.replace(separator, "/")
    if profile.backslash_separator:
        text = text.replace("\\", "/")

    absolute_escape = False
    if text.startswith("/"):
        if profile.reject_absolute:
            return NameView(
                (), False, "absolute member name", tuple(flags)
            )
        if not profile.strip_absolute:
            absolute_escape = True
        text = text.lstrip("/")

    components: list[str] = []
    for part in text.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not components:
                absolute_escape = True
                continue
            components.pop()
            continue
        components.append(part)
    return NameView(tuple(components), absolute_escape, "", tuple(flags))


def lexical_target(
    target: str, parent: tuple[str, ...], profile: Profile
) -> tuple[tuple[str, ...], bool]:
    """Resolve a link target as plain text, without touching the VFS."""
    if target.startswith("/"):
        if profile.reject_absolute or not profile.strip_absolute:
            return (), True
        parts = [part for part in target.split("/") if part]
    else:
        parts = list(target.split("/"))
    current = list(parent)
    for part in parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not current:
                return (), True
            current.pop()
            continue
        current.append(part)
    return tuple(current), False


def _physical_target(
    target: str, parent: ResolveResult, vfs: VirtualFS
) -> ResolveResult:
    if target.startswith("/"):
        return ResolveResult(parent.components, parent.followed, True)
    parts = tuple(part for part in target.split("/") if part not in {"", "."})
    return vfs.resolve(parent.components + parts)


def _path_label(components: tuple[str, ...], outside: bool) -> str:
    prefix = "<outside-root>" if outside else "/dest"
    if not components:
        return prefix
    return f"{prefix}/{'/'.join(components)}"


def _make_finding(
    rule_id: str,
    severity: Severity,
    source: str,
    profile: str,
    index: int,
    member: Member,
    path: str,
    detail: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        source=source,
        profile=profile,
        member_index=index,
        member_name=member.name,
        observed_path=path,
        detail=detail,
        remediation=RULES[rule_id]["remediation"],
    )


def _simulate_profile(
    members: tuple[Member, ...],
    profile: Profile,
    limits: Limits,
    source: str,
) -> tuple[list[Finding], list[MemberOutcome]]:
    vfs = VirtualFS(limits.max_symlink_hops)
    findings: list[Finding] = []
    outcomes: list[MemberOutcome] = []
    link_kinds = {"symlink", "hardlink"}

    for index, member in enumerate(members):
        view = normalize_name(member.name, profile)
        guard_rejected = False
        reason = ""

        if view.rejected_reason:
            guard_rejected = True
            reason = view.rejected_reason
        elif view.absolute_escape and profile.name != "fully-trusted":
            guard_rejected = True
            reason = "name escapes the root lexically"
        elif member.kind in link_kinds and profile.reject_links:
            guard_rejected = True
            reason = "profile rejects all link members"
        elif (
            member.kind in link_kinds
            and profile.physical_parent_check
            and view.components == ()
        ):
            guard_rejected = True
            reason = "link at destination root"

        declared = view.components
        parent = vfs.resolve(declared[:-1]) if declared else ResolveResult(
            (), (), False
        )
        if profile.physical_parent_check and parent.outside and not guard_rejected:
            guard_rejected = True
            reason = "physical parent resolves outside the root"

        if member.kind in link_kinds and member.target and not guard_rejected:
            lex_components, lex_outside = lexical_target(
                member.target, declared[:-1], profile
            )
            if lex_outside and profile.name != "fully-trusted":
                guard_rejected = True
                reason = "link target escapes lexically"
            elif profile.physical_parent_check:
                target_result = _physical_target(member.target, parent, vfs)
                if target_result.outside:
                    guard_rejected = True
                    reason = "link target resolves outside physically"
                elif lex_components != target_result.components:
                    reason = "lexical and physical link targets disagree"

        if member.kind in link_kinds and declared == () and not guard_rejected:
            findings.append(
                _make_finding(
                    "AB1002",
                    "critical",
                    source,
                    profile.name,
                    index,
                    member,
                    "/dest",
                    "link member resolves to the extraction root and can "
                    "re-root every subsequent write",
                )
            )
            outcomes.append(MemberOutcome(True, False, "root-replacing link"))
            vfs.put((), Node("symlink", member.target or ""))
            continue

        if guard_rejected:
            outcomes.append(MemberOutcome(False, True, reason))
            continue

        followed = parent.followed
        if member.kind in link_kinds and member.target:
            target_result = _physical_target(member.target, parent, vfs)
            if target_result.outside:
                followed += target_result.followed
                rule_id = "AB1003" if member.kind == "hardlink" else "AB1002"
                if not followed:
                    rule_id = "AB1001"
                findings.append(
                    _make_finding(
                        rule_id,
                        "critical" if rule_id == "AB1002" else "high",
                        source,
                        profile.name,
                        index,
                        member,
                        _path_label(parent.components, False),
                        f"{member.kind} target {member.target!r} resolves "
                        "outside the extraction root",
                    )
                )
                outcomes.append(
                    MemberOutcome(True, False, "link target outside root")
                )
                destination = parent.components + (declared[-1],)
                vfs.put(
                    destination,
                    Node(member.kind, member.target),
                )
                continue
            destination = parent.components + (declared[-1],)
            vfs.put(destination, Node(member.kind, member.target or ""))
            outcomes.append(MemberOutcome(False, False, reason))
            continue

        escape = view.absolute_escape or parent.outside
        if escape:
            if not followed and view.absolute_escape:
                rule_id = "AB1001"
                detail = "member path is absolute or traverses above the root"
            elif followed:
                rule_id = "AB1002"
                detail = "earlier symlink re-roots this write outside the root"
            else:
                rule_id = "AB1001"
                detail = "member parent resolves outside the root"
            severity: Severity = "critical" if rule_id == "AB1002" else "high"
            findings.append(
                _make_finding(
                    rule_id,
                    severity,
                    source,
                    profile.name,
                    index,
                    member,
                    _path_label(
                        parent.components,
                        view.absolute_escape or parent.outside,
                    ),
                    detail,
                )
            )
            outcomes.append(MemberOutcome(True, False, detail))
            continue

        vfs.put(parent.components + (declared[-1],), Node(member.kind))
        outcomes.append(MemberOutcome(False, False, reason))

    return findings, outcomes


def simulate(
    members: tuple[Member, ...],
    source: str,
    profiles: tuple[Profile, ...] = PROFILES,
    limits: Limits | None = None,
) -> Simulation:
    """Simulate one archive under every selected profile."""
    active_limits = limits if limits is not None else Limits()
    findings: list[Finding] = []
    outcomes: dict[str, tuple[MemberOutcome, ...]] = {}

    for profile in profiles:
        profile_findings, profile_outcomes = _simulate_profile(
            members, profile, active_limits, source
        )
        findings.extend(profile_findings)
        outcomes[profile.name] = tuple(profile_outcomes)

    total_size = sum(member.size for member in members)
    if len(members) > active_limits.max_entries:
        findings.append(
            Finding(
                rule_id="AB1008",
                severity="high",
                source=source,
                profile="*",
                member_index=-1,
                member_name="<archive>",
                observed_path="<archive>",
                detail=(
                    f"entry count {len(members)} exceeds "
                    f"{active_limits.max_entries}"
                ),
                remediation=RULES["AB1008"]["remediation"],
            )
        )
    if total_size > active_limits.max_total_bytes:
        findings.append(
            Finding(
                rule_id="AB1008",
                severity="high",
                source=source,
                profile="*",
                member_index=-1,
                member_name="<archive>",
                observed_path="<archive>",
                detail=(
                    f"declared total size {total_size} exceeds "
                    f"{active_limits.max_total_bytes}"
                ),
                remediation=RULES["AB1008"]["remediation"],
            )
        )
    for index, member in enumerate(members):
        if member.compressed_size > 0 and member.size > 0:
            ratio = member.size // member.compressed_size
            if ratio > active_limits.max_compression_ratio:
                findings.append(
                    _make_finding(
                        "AB1008",
                        "high",
                        source,
                        "*",
                        index,
                        member,
                        member.name,
                        f"compression ratio {ratio}:1 exceeds "
                        f"{active_limits.max_compression_ratio}:1",
                    )
                )
        if member.encoding_note:
            findings.append(
                _make_finding(
                    "AB1006",
                    "medium",
                    source,
                    "*",
                    index,
                    member,
                    member.name,
                    f"ambiguous ZIP attributes: {member.encoding_note}",
                )
            )
        basename = PurePosixPath(member.name.replace("\\", "/")).name
        if basename in STDLIB_SHADOW_NAMES:
            findings.append(
                _make_finding(
                    "AB1007",
                    "high",
                    source,
                    "*",
                    index,
                    member,
                    member.name,
                    f"member name {basename!r} shadows a Python stdlib module",
                )
            )

    name_flags = tuple(
        normalize_name(member.name, PROFILES[0]).flags for member in members
    )
    for index, flags in enumerate(name_flags):
        if not flags:
            continue
        states: set[str] = set()
        for profile in profiles:
            outcome = outcomes[profile.name][index]
            if outcome.escaped:
                states.add("escape")
            elif outcome.guard_rejected:
                states.add("blocked")
            else:
                states.add("allowed")
        if len(states) > 1:
            findings.append(
                _make_finding(
                    "AB1005",
                    "high",
                    source,
                    "*",
                    index,
                    members[index],
                    members[index].name,
                    "name features "
                    + ", ".join(flags)
                    + f" produce divergent outcomes: {', '.join(sorted(states))}",
                )
            )

    ordered = sorted(
        findings,
        key=lambda item: (
            item.source,
            item.member_index,
            item.rule_id,
            item.profile,
        ),
    )
    return Simulation(tuple(ordered), outcomes, len(members))


def attribution() -> str:
    """Return the mandatory project attribution string."""
    return ATTRIBUTION


def severity_at_least(
    severity: Literal["low", "medium", "high", "critical"],
    threshold: Literal["low", "medium", "high", "critical"],
) -> bool:
    """Compare two severity labels using the shared ranking table."""
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold]
