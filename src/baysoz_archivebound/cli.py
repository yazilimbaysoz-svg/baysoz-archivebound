# Baysöz Labs <baysozlabs@proton.me> — archivebound command-line interface.
"""Argparse CLI for offline extraction-confinement analysis and forging."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from . import __version__
from .archive import ArchiveReadError, collect_archive_paths, read_archive
from .engine import RULES, severity_at_least, simulate
from .forge import forge_cases, write_corpus
from .models import (
    ATTRIBUTION,
    PROFILES,
    PROFILE_BY_NAME,
    Finding,
    Limits,
)
from .report import ScanReport, to_json, to_sarif, to_text

VERSION_LINE = f"archivebound {__version__} — {ATTRIBUTION}"
EPILOG = (
    f"{ATTRIBUTION} | offline archive-extraction confinement oracle | "
    "no network, no extraction, no LLM"
)


def _add_attribution(parser: argparse.ArgumentParser) -> None:
    parser.epilog = EPILOG
    parser.formatter_class = argparse.RawDescriptionHelpFormatter


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="archivebound",
        description=(
            "Differential archive-extraction confinement oracle for "
            "appsec red teams."
        ),
    )
    _add_attribution(parser)
    parser.add_argument(
        "--version",
        action="version",
        version=VERSION_LINE,
        help="show version and Baysöz Labs attribution",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="scan real ZIP/TAR archives for confinement bypasses",
        description="Scan archives offline under multiple extraction profiles.",
    )
    _add_attribution(scan)
    scan.add_argument("archives", nargs="+", help="archive files or directories")
    scan.add_argument(
        "--profile",
        action="append",
        choices=sorted(PROFILE_BY_NAME),
        help="profile to evaluate; repeatable (default: all)",
    )
    scan.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="report format (default: text)",
    )
    scan.add_argument("--output", help="write the report to a file")
    scan.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="high",
        help="minimum severity that fails CI (default: high)",
    )
    scan.add_argument(
        "--max-entries", type=int, default=10_000, help="entry-count cap"
    )
    scan.add_argument(
        "--max-bytes",
        type=int,
        default=100 * 1024 * 1024,
        help="declared total-size cap",
    )
    scan.add_argument(
        "--max-ratio", type=int, default=200, help="compression-ratio cap"
    )
    scan.set_defaults(handler=_cmd_scan)

    forge = subparsers.add_parser(
        "forge",
        help="forge the deterministic adversarial corpus",
        description="Forge real ZIP/TAR adversarial samples or a JSON plan.",
    )
    _add_attribution(forge)
    forge.add_argument(
        "--out-dir", help="write real ZIP/TAR samples and manifest.json here"
    )
    forge.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="plan format when --out-dir is not used",
    )
    forge.add_argument("--output", help="write the plan to a file")
    forge.set_defaults(handler=_cmd_forge)

    profiles = subparsers.add_parser(
        "profiles",
        help="list extraction-confinement profiles",
        description="List the differential extraction profiles and semantics.",
    )
    _add_attribution(profiles)
    profiles.set_defaults(handler=_cmd_profiles)
    return parser


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def _cmd_scan(args: argparse.Namespace) -> int:
    limits = Limits(
        max_entries=args.max_entries,
        max_total_bytes=args.max_bytes,
        max_compression_ratio=args.max_ratio,
    )
    profiles = (
        tuple(PROFILE_BY_NAME[name] for name in args.profile)
        if args.profile
        else PROFILES
    )
    paths = collect_archive_paths(args.archives)
    findings: list[Finding] = []
    member_count = 0
    for path in paths:
        archive = read_archive(path, limits)
        member_count += len(archive.members)
        findings.extend(
            simulate(archive.members, str(path), profiles, limits).findings
        )
    findings.sort(
        key=lambda item: (
            item.source,
            item.member_index,
            item.rule_id,
            item.profile,
        )
    )
    verdict = "PASS"
    if args.fail_on != "none":
        if any(
            severity_at_least(item.severity, args.fail_on)
            for item in findings
        ):
            verdict = "FAIL"
    report = ScanReport(
        archives=tuple(str(path) for path in paths),
        profiles=tuple(profile.name for profile in profiles),
        member_count=member_count,
        findings=tuple(findings),
        verdict=verdict,
        fail_on=args.fail_on,
    )
    rendered = {
        "text": to_text,
        "json": to_json,
        "sarif": to_sarif,
    }[args.format](report)
    _emit(rendered, args.output)
    return 1 if verdict == "FAIL" else 0


def _cmd_forge(args: argparse.Namespace) -> int:
    cases = forge_cases()
    if args.out_dir:
        written = write_corpus(Path(args.out_dir))
        text = "\n".join(
            [
                VERSION_LINE,
                f"forged files: {len(written)}",
                *[f"  {path}" for path in written],
                f"attribution: {ATTRIBUTION}",
            ]
        ) + "\n"
        _emit(text, args.output)
        return 0
    document = {
        "attribution": ATTRIBUTION,
        "cases": [
            {
                "slug": case.slug,
                "title": case.title,
                "family": case.family,
                "expected_rules": list(case.expected_rules),
                "references": list(case.references),
                "members": [
                    {
                        "name": member.name,
                        "kind": member.kind,
                        "target": member.target,
                        "size": member.size,
                    }
                    for member in case.members
                ],
            }
            for case in cases
        ],
    }
    if args.format == "json":
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    else:
        lines = [VERSION_LINE, f"cases: {len(cases)}"]
        for case in cases:
            lines.append(
                f"  {case.slug:24} {','.join(case.expected_rules):16} "
                f"{case.title}"
            )
        lines.append(
            "rules: "
            + ", ".join(
                f"{rule_id}={metadata['title']}"
                for rule_id, metadata in sorted(RULES.items())
            )
        )
        lines.append(f"attribution: {ATTRIBUTION}")
        text = "\n".join(lines) + "\n"
    _emit(text, args.output)
    return 0


def _cmd_profiles(args: argparse.Namespace) -> int:
    lines = [VERSION_LINE, f"profiles: {len(PROFILES)}"]
    for profile in PROFILES:
        lines.append(f"  {profile.name:14} {profile.description}")
    lines.append(f"attribution: {ATTRIBUTION}")
    print("\n".join(lines))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a deterministic process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except ArchiveReadError as error:
        parser.exit(2, f"archivebound: error: {error}\n{EPILOG}\n")
    return 2
