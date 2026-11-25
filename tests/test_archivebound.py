# Baysöz Labs <baysozlabs@proton.me> — archivebound assurance suite.

from __future__ import annotations

import json
from pathlib import Path

import pytest

from baysoz_archivebound import ATTRIBUTION, __version__
from baysoz_archivebound.archive import read_archive
from baysoz_archivebound.cli import main
from baysoz_archivebound.engine import simulate
from baysoz_archivebound.forge import (
    ForgeCase,
    build_archive_bytes,
    forge_cases,
    write_corpus,
)
from baysoz_archivebound.models import Limits, Member
from baysoz_archivebound.report import ScanReport, to_sarif, to_text

REPO_ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "baysoz_archivebound.egg-info",
}


def test_version_and_all_help_outputs_carry_attribution(capsys):
    with pytest.raises(SystemExit) as version_exit:
        main(["--version"])
    assert version_exit.value.code == 0
    version_output = capsys.readouterr().out
    assert __version__ in version_output
    assert ATTRIBUTION in version_output

    for argv in (
        ["--help"],
        ["scan", "--help"],
        ["forge", "--help"],
        ["profiles", "--help"],
    ):
        with pytest.raises(SystemExit) as help_exit:
            main(argv)
        assert help_exit.value.code == 0
        output = capsys.readouterr().out
        assert ATTRIBUTION in output
        assert "baysozlabs@proton.me" in output


def test_every_public_text_file_is_attributed():
    candidates = [
        path
        for path in REPO_ROOT.rglob("*")
        if path.is_file()
        and not any(part in EXCLUDED_DIRS for part in path.parts)
        and path.name != "uv.lock"
        and path.suffix != ".pyc"
    ]
    assert candidates
    for path in candidates:
        content = path.read_text(encoding="utf-8", errors="ignore")
        assert "Baysöz Labs" in content, str(path)
        assert "baysozlabs@proton.me" in content, str(path)


def test_forge_corpus_meets_all_expected_rules():
    for case in forge_cases():
        result = simulate(case.members, case.slug)
        observed = {finding.rule_id for finding in result.findings}
        for rule_id in case.expected_rules:
            assert rule_id in observed, (case.slug, rule_id)


def test_ddev_re_rooting_diverges_between_profiles():
    case = next(item for item in forge_cases() if item.slug == "ddev-reroot")
    result = simulate(case.members, case.slug)
    assert result.outcomes["lexical-data"][-1].escaped
    assert not result.outcomes["physical-root"][-1].escaped
    assert not result.outcomes["strict-data"][-1].escaped
    assert "AB1002" in {item.rule_id for item in result.findings}


def test_scan_real_tar_emits_attributed_json(tmp_path, capsys):
    case = next(item for item in forge_cases() if item.slug == "ddev-reroot")
    archive = tmp_path / "ddev-reroot.tar"
    archive.write_bytes(build_archive_bytes(case, "tar"))

    code = main(["scan", str(archive), "--format", "json"])
    output = capsys.readouterr().out
    document = json.loads(output)

    assert code == 1
    assert document["verdict"] == "FAIL"
    assert document["attribution"] == ATTRIBUTION
    assert document["member_count"] == 4
    assert any(item["rule_id"] == "AB1002" for item in document["findings"])
    assert all(
        item["attribution"] == ATTRIBUTION for item in document["findings"]
    )


def test_zip_legacy_mode_is_detected(tmp_path):
    case = next(item for item in forge_cases() if item.slug == "legacy-dos-link")
    archive = tmp_path / "legacy-dos-link.zip"
    archive.write_bytes(build_archive_bytes(case, "zip"))

    parsed = read_archive(archive)
    link = next(member for member in parsed.members if member.kind == "symlink")
    assert "DOS-prefixed" in link.encoding_note
    result = simulate(parsed.members, str(archive))
    assert "AB1006" in {item.rule_id for item in result.findings}


def test_benign_archive_passes(tmp_path, capsys):
    benign = ForgeCase(
        slug="benign",
        title="Benign documentation bundle",
        family="NONE",
        members=(
            Member("docs/readme.txt", "file", size=64),
            Member("bin/tool.sh", "file", size=128),
        ),
        expected_rules=(),
        references=(),
    )
    archive = tmp_path / "benign.tar"
    archive.write_bytes(build_archive_bytes(benign, "tar"))

    code = main(["scan", str(archive), "--fail-on", "low"])
    output = capsys.readouterr().out

    assert code == 0
    assert "findings: none" in output
    assert "verdict=PASS" in output
    assert ATTRIBUTION in output


def test_sarif_and_text_renderers_are_deterministic():
    case = next(item for item in forge_cases() if item.slug == "zipslip-direct")
    result = simulate(case.members, case.slug)
    report = ScanReport(
        archives=(case.slug,),
        profiles=tuple(result.outcomes),
        member_count=result.member_count,
        findings=result.findings,
        verdict="FAIL",
        fail_on="high",
    )
    first = to_sarif(report)
    assert first == to_sarif(report)
    document = json.loads(first)
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["properties"]["attribution"] == ATTRIBUTION
    assert document["runs"][0]["results"]
    assert ATTRIBUTION in to_text(report)


def test_forged_corpus_written_and_scanned(tmp_path, capsys):
    corpus = tmp_path / "corpus"
    written = write_corpus(corpus)
    assert len(written) >= 20
    assert (corpus / "manifest.json").is_file()

    code = main(["scan", str(corpus), "--format", "text"])
    output = capsys.readouterr().out
    assert code == 1
    assert "AB1002" in output
    assert "AB1005" in output
    assert ATTRIBUTION in output


def test_resource_limits_are_enforced():
    member = Member("blob.bin", "file", size=5_000, compressed_size=1)
    result = simulate(
        (member,),
        "limits",
        limits=Limits(max_total_bytes=1_000, max_compression_ratio=10),
    )
    assert "AB1008" in {item.rule_id for item in result.findings}


def test_profiles_command_lists_all_profiles(capsys):
    assert main(["profiles"]) == 0
    output = capsys.readouterr().out
    for name in ("lexical-data", "physical-root", "strict-data", "fully-trusted"):
        assert name in output
    assert ATTRIBUTION in output
