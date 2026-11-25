# Baysöz Labs <baysozlabs@proton.me> — deterministic report renderers.
"""JSON, SARIF 2.1.0, and terminal renderers for archivebound findings."""

from __future__ import annotations

import json
from dataclasses import dataclass

from . import __version__
from .engine import RULES
from .models import ATTRIBUTION, TOOL_NAME, Finding

SARIF_LEVELS = {
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


@dataclass(frozen=True)
class ScanReport:
    """Aggregated, deterministic result of one scan invocation."""

    archives: tuple[str, ...]
    profiles: tuple[str, ...]
    member_count: int
    findings: tuple[Finding, ...]
    verdict: str
    fail_on: str

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-safe report document."""
        return {
            "tool": TOOL_NAME,
            "version": __version__,
            "attribution": ATTRIBUTION,
            "archives": list(self.archives),
            "profiles": list(self.profiles),
            "member_count": self.member_count,
            "fail_on": self.fail_on,
            "verdict": self.verdict,
            "findings": [finding.as_dict() for finding in self.findings],
        }


def to_json(report: ScanReport) -> str:
    """Render the report as stable, indented JSON."""
    return json.dumps(report.as_dict(), indent=2, sort_keys=True) + "\n"


def _sarif_rule(finding: Finding) -> dict[str, object]:
    metadata = RULES[finding.rule_id]
    return {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": metadata["title"]},
        "fullDescription": {"text": metadata["title"]},
        "helpUri": (
            "https://github.com/yazilimbaysoz-svg/"
            "baysoz-archivebound#rules"
        ),
        "defaultConfiguration": {
            "level": SARIF_LEVELS[finding.severity]
        },
        "properties": {"attribution": ATTRIBUTION},
    }


def to_sarif(report: ScanReport) -> str:
    """Render the report as a SARIF 2.1.0 document."""
    rules_by_id: dict[str, dict[str, object]] = {}
    for finding in report.findings:
        if finding.rule_id not in rules_by_id:
            rules_by_id[finding.rule_id] = _sarif_rule(finding)
    rules = [rules_by_id[key] for key in sorted(rules_by_id)]
    results: list[dict[str, object]] = []
    for finding in report.findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVELS[finding.severity],
                "message": {"text": finding.detail},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.source},
                            "region": {
                                "startLine": max(1, finding.member_index + 1)
                            },
                        }
                    }
                ],
                "properties": {
                    "attribution": ATTRIBUTION,
                    "severity": finding.severity,
                    "profile": finding.profile,
                    "member": finding.member_name,
                    "observed_path": finding.observed_path,
                    "remediation": finding.remediation,
                },
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": f"{ATTRIBUTION.split(' <')[0]} {TOOL_NAME}",
                        "version": __version__,
                        "informationUri": (
                            "https://github.com/yazilimbaysoz-svg/"
                            "baysoz-archivebound"
                        ),
                        "rules": rules,
                        "properties": {"attribution": ATTRIBUTION},
                    }
                },
                "results": results,
                "properties": {
                    "attribution": ATTRIBUTION,
                    "verdict": report.verdict,
                    "profiles": list(report.profiles),
                    "fail_on": report.fail_on,
                },
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def to_text(report: ScanReport) -> str:
    """Render a compact, human-readable terminal report."""
    lines = [
        f"{TOOL_NAME} {__version__} — {ATTRIBUTION}",
        (
            f"scan: archives={len(report.archives)} "
            f"profiles={len(report.profiles)} "
            f"members={report.member_count}"
        ),
    ]
    if not report.findings:
        lines.append("findings: none")
    for finding in report.findings:
        lines.append(
            f"[{finding.severity.upper():8}] {finding.rule_id} "
            f"profile={finding.profile} source={finding.source} "
            f"member={finding.member_index} "
            f"{finding.member_name!r}"
        )
        lines.append(f"    path: {finding.observed_path}")
        lines.append(f"    detail: {finding.detail}")
        lines.append(f"    fix: {finding.remediation}")
    lines.append(
        f"summary: findings={len(report.findings)} "
        f"verdict={report.verdict} fail_on={report.fail_on}"
    )
    lines.append(f"attribution: {ATTRIBUTION}")
    return "\n".join(lines) + "\n"
