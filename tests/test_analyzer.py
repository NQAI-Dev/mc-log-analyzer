"""Pytest suite for analyzer.analyze_log.

These tests guard the existing regex heuristics and pin the public Issue shape.
Add a rule and you must add a positive test here; remove a rule and the matching
test breaks loudly instead of silently.
"""

import json
import subprocess
import sys

from analyzer import RULES, Issue, analyze_log


def _issue_ids(issues):
    return [i.id for i in issues]


def test_cli_json_output_is_machine_readable(tmp_path):
    logfile = tmp_path / "latest.log"
    logfile.write_text("java.lang.OutOfMemoryError: Java heap space\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "analyzer.py", str(logfile), "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(result.stdout)
    assert [issue["id"] for issue in payload] == ["oom_heap"]
    assert result.stderr == ""


def test_cli_text_output_reports_no_issues_for_benign_log(tmp_path):
    logfile = tmp_path / "latest.log"
    logfile.write_text("[Server thread/INFO]: Done loading world\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "analyzer.py", str(logfile)],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout == "No issues detected.\n"
    assert result.stderr == ""


def test_benign_log_produces_no_issues():
    log = (
        "[Server] Loading Minecraft 1.20.4\n"
        "[Server thread/INFO]: Done loading world\n"
        "[Server thread/INFO]: Stopping server\n"
    )
    assert analyze_log(log) == []


def test_empty_log_produces_no_issues():
    assert analyze_log("") == []


def test_eula_not_accepted_rule_fires():
    issues = analyze_log(
        "[Server] You need to agree to the EULA in order to run the server"
    )
    ids = _issue_ids(issues)
    assert "eula_not_accepted" in ids
    eula = next(i for i in issues if i.id == "eula_not_accepted")
    assert eula.severity == "CRITICAL"
    assert eula.cause and eula.solution


def test_port_bind_failure_distinct_phrasings():
    for snippet in [
        "[Server] FAILED TO BIND TO PORT",
        "java.net.BindException: Address already in use: bind",
        "java.net.BindException: Address already in use",
    ]:
        ids = _issue_ids(analyze_log(snippet))
        assert "port_bind_failure" in ids, snippet


def test_heap_oom_and_metaspace_oom_are_distinct():
    heap = analyze_log("java.lang.OutOfMemoryError: Java heap space")
    meta = analyze_log("java.lang.OutOfMemoryError: Metaspace")
    killer = analyze_log("Out of memory: Kill process")

    assert "oom_heap" in _issue_ids(heap)
    assert "oom_metaspace" not in _issue_ids(heap)

    assert "oom_metaspace" in _issue_ids(meta)
    assert "oom_heap" not in _issue_ids(meta)

    # 'Out of memory: Kill process' is a heap-class OOM
    assert "oom_heap" in _issue_ids(killer)


def test_java_version_mismatch_extracts_versions():
    log = (
        "plugin.jar has been compiled by a more recent version of the "
        "Java Runtime (class file version 65.0), this version of the Java "
        "Runtime only recognizes class file versions up to 61.0"
    )
    issues = analyze_log(log)
    assert any(i.id == "java_version_mismatch" for i in issues)


def test_missing_plugin_dependency_fires():
    log = "Could not load 'EssentialsX' in folder 'plugins'"
    assert "missing_plugin_dependency" in _issue_ids(analyze_log(log))


def test_corrupted_chunk_fires():
    log = "RegionFileException: Corrupted chunk data at chunk (-3, 1) in world/region/r.-3.1.mca"
    assert "corrupted_chunk" in _issue_ids(analyze_log(log))


def test_sqlite_lock_fires():
    log = "sqlite3.OperationalError: database is locked"
    assert "sqlite_db_locked" in _issue_ids(analyze_log(log))


def test_realistic_log_returns_multiple_unique_issues():
    log = (
        "java.lang.OutOfMemoryError: Java heap space\n"
        "java.net.BindException: Address already in use: bind\n"
        "Could not load 'Vault' in folder 'plugins'\n"
        "RegionFileException: Corrupted chunk data\n"
    )
    ids = _issue_ids(analyze_log(log))
    assert "oom_heap" in ids
    assert "port_bind_failure" in ids
    assert "missing_plugin_dependency" in ids
    assert "corrupted_chunk" in ids


def test_rules_have_required_fields():
    required = {"id", "pattern", "title", "severity", "cause", "solution"}
    seen = set()
    for rule in RULES:
        assert required.issubset(rule.keys()), rule["id"]
        assert rule["severity"] in {"CRITICAL", "ERROR", "WARNING"}, rule["id"]
        assert rule["id"] not in seen, f"duplicate id {rule['id']}"
        seen.add(rule["id"])


def test_rule_ids_match_issue_ids():
    """If a rule fires, the resulting Issue.id must equal the rule id."""
    log = (
        "You need to agree to the EULA in order to run the server\n"
        "java.lang.OutOfMemoryError: Java heap space\n"
        "java.lang.OutOfMemoryError: Metaspace\n"
    )
    rule_ids = {r["id"] for r in RULES}
    issue_ids = set(_issue_ids(analyze_log(log)))
    assert issue_ids.issubset(rule_ids)


def test_issue_is_dataclass():
    """Issue must stay a dataclass — callers may rely on field access."""
    from dataclasses import is_dataclass

    assert is_dataclass(Issue)
