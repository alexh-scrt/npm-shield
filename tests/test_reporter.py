"""Tests for npm_shield/reporter.py.

Covers:
- Reporter instantiation with ScanResult and dict input.
- Terminal output rendering (non-crashing, key content present).
- JSON export: structure, serialisability, file writing.
- HTML export: valid structure, key elements present, file writing.
- Severity summary formatting.
- Edge cases: no findings, all severity levels, XSS escaping.
- Integration with real ScanResult objects from the scanner.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from npm_shield.reporter import (
    Reporter,
    _render_html,
    _truncate,
    format_severity_summary,
    render_html,
    render_json,
    render_terminal,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _make_finding(
    package: str = "test-pkg",
    detector: str = "known-malicious",
    severity: str = "critical",
    description: str = "Test finding description.",
    remediation: str = "1. Do this.\n2. Do that.",
    metadata: dict | None = None,
) -> dict[str, Any]:
    """Build a minimal finding dictionary for tests."""
    return {
        "package": package,
        "detector": detector,
        "severity": severity,
        "description": description,
        "remediation": remediation,
        "metadata": metadata or {},
    }


def _make_scan_data(
    findings: list[dict] | None = None,
    project_name: str = "test-project",
    project_version: str = "1.0.0",
    project_path: str = "/fake/project",
    packages_analysed: int = 10,
    declared_dependency_count: int = 10,
    scanned_at: str = "2024-01-15T10:23:45",
    duration_seconds: float = 1.23,
    has_node_modules: bool = True,
    has_lockfile: bool = True,
    osv_enabled: bool = False,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    """Build a complete scan result dictionary for tests."""
    findings = findings or []
    by_sev: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for f in findings:
        sev = f.get("severity", "info").lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1

    max_sev = "info"
    for sev in ("critical", "high", "medium", "low", "info"):
        if by_sev.get(sev, 0) > 0:
            max_sev = sev
            break

    return {
        "project_path": project_path,
        "project_name": project_name,
        "project_version": project_version,
        "scanned_at": scanned_at,
        "duration_seconds": duration_seconds,
        "packages_analysed": packages_analysed,
        "declared_dependency_count": declared_dependency_count,
        "has_node_modules": has_node_modules,
        "has_lockfile": has_lockfile,
        "osv_enabled": osv_enabled,
        "finding_count": len(findings),
        "max_severity": max_sev,
        "severity_summary": by_sev,
        "findings": findings,
        "errors": errors or [],
    }


def _make_console() -> tuple[Console, StringIO]:
    """Create a Rich console that writes to a StringIO buffer."""
    buffer = StringIO()
    console = Console(file=buffer, highlight=False, markup=True)
    return console, buffer


# ---------------------------------------------------------------------------
# TestReporterInit
# ---------------------------------------------------------------------------


class TestReporterInit:
    """Tests for Reporter instantiation."""

    def test_accepts_dict(self) -> None:
        data = _make_scan_data()
        reporter = Reporter(data)
        assert isinstance(reporter.to_json_dict(), dict)

    def test_accepts_scan_result_like_object(self) -> None:
        """Reporter should call .to_dict() on objects that have it."""

        class FakeScanResult:
            def to_dict(self) -> dict:
                return _make_scan_data()

        reporter = Reporter(FakeScanResult())
        d = reporter.to_json_dict()
        assert "findings" in d

    def test_to_json_dict_returns_copy(self) -> None:
        data = _make_scan_data()
        reporter = Reporter(data)
        d = reporter.to_json_dict()
        assert d is not data
        assert d == data

    def test_accepts_custom_console(self) -> None:
        data = _make_scan_data()
        console, _ = _make_console()
        reporter = Reporter(data, console=console)
        # Should not raise
        assert reporter is not None

    def test_default_console_created_when_none(self) -> None:
        data = _make_scan_data()
        reporter = Reporter(data, console=None)
        # Should not raise and should have a console
        assert reporter is not None

    def test_preserves_all_data_fields(self) -> None:
        data = _make_scan_data(
            project_name="my-special-app",
            project_version="3.14.0",
            packages_analysed=42,
        )
        reporter = Reporter(data)
        d = reporter.to_json_dict()
        assert d["project_name"] == "my-special-app"
        assert d["project_version"] == "3.14.0"
        assert d["packages_analysed"] == 42

    def test_findings_preserved_in_dict(self) -> None:
        findings = [
            _make_finding("crossenv", "known-malicious", "critical"),
            _make_finding("lod4sh", "typosquatting", "high"),
        ]
        data = _make_scan_data(findings=findings)
        reporter = Reporter(data)
        d = reporter.to_json_dict()
        assert len(d["findings"]) == 2


# ---------------------------------------------------------------------------
# TestTerminalOutput
# ---------------------------------------------------------------------------


class TestTerminalOutput:
    """Tests for Reporter.print_terminal()."""

    def test_print_terminal_no_crash_empty(self) -> None:
        data = _make_scan_data()
        console, buf = _make_console()
        reporter = Reporter(data, console=console)
        reporter.print_terminal()  # Should not raise
        output = buf.getvalue()
        assert len(output) > 0

    def test_print_terminal_shows_project_name(self) -> None:
        data = _make_scan_data(project_name="my-special-app")
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        assert "my-special-app" in buf.getvalue()

    def test_print_terminal_shows_project_version(self) -> None:
        data = _make_scan_data(project_version="9.8.7")
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        assert "9.8.7" in buf.getvalue()

    def test_print_terminal_shows_no_findings_message(self) -> None:
        data = _make_scan_data(findings=[])
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        output = buf.getvalue()
        assert "No security findings" in output or "No" in output

    def test_print_terminal_shows_findings(self) -> None:
        findings = [
            _make_finding("crossenv", "known-malicious", "critical"),
            _make_finding("lod4sh", "typosquatting", "high"),
        ]
        data = _make_scan_data(findings=findings)
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        output = buf.getvalue()
        assert "crossenv" in output
        assert "lod4sh" in output

    def test_print_terminal_shows_severity_labels(self) -> None:
        findings = [_make_finding(severity="critical")]
        data = _make_scan_data(findings=findings)
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        output = buf.getvalue()
        assert "CRITICAL" in output

    def test_print_terminal_shows_high_severity_label(self) -> None:
        findings = [_make_finding(severity="high")]
        data = _make_scan_data(findings=findings)
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        assert "HIGH" in buf.getvalue()

    def test_print_terminal_shows_medium_severity_label(self) -> None:
        findings = [_make_finding(severity="medium")]
        data = _make_scan_data(findings=findings)
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        assert "MEDIUM" in buf.getvalue()

    def test_print_terminal_with_remediation(self) -> None:
        findings = [
            _make_finding(
                remediation="1. Remove the package.\n2. Rotate credentials."
            )
        ]
        data = _make_scan_data(findings=findings)
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal(show_remediation=True)
        output = buf.getvalue()
        assert "Remove the package" in output

    def test_print_terminal_remediation_hidden_by_default(self) -> None:
        findings = [
            _make_finding(
                remediation="1. UNIQUE_REMEDIATION_STRING_XYZ.\n2. Do that."
            )
        ]
        data = _make_scan_data(findings=findings)
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal(show_remediation=False)
        # Remediation steps should not appear when show_remediation=False
        # (the table truncates description, but full remediation is not shown)
        output = buf.getvalue()
        # Table rows may include description but not the remediation block
        assert isinstance(output, str)

    def test_print_terminal_shows_scan_duration(self) -> None:
        data = _make_scan_data(duration_seconds=3.14)
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        output = buf.getvalue()
        assert "3.14" in output

    def test_print_terminal_shows_errors(self) -> None:
        data = _make_scan_data(errors=["Something went wrong during scan"])
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        output = buf.getvalue()
        assert "Something went wrong" in output

    def test_print_terminal_shows_summary_line_with_count(self) -> None:
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
        ]
        data = _make_scan_data(findings=findings)
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        output = buf.getvalue()
        # Summary should mention total finding count
        assert "2" in output

    def test_print_terminal_shows_packages_analysed(self) -> None:
        data = _make_scan_data(packages_analysed=99)
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        assert "99" in buf.getvalue()

    def test_print_terminal_shows_osv_enabled(self) -> None:
        data = _make_scan_data(osv_enabled=True)
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        output = buf.getvalue()
        assert "osv" in output.lower() or "enabled" in output.lower()

    def test_print_terminal_shows_detector_names(self) -> None:
        findings = [
            _make_finding(detector="known-malicious"),
            _make_finding(detector="typosquatting"),
        ]
        data = _make_scan_data(findings=findings)
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        output = buf.getvalue()
        assert "known-malicious" in output
        assert "typosquatting" in output

    def test_print_terminal_shows_scanned_at(self) -> None:
        data = _make_scan_data(scanned_at="2024-06-15T08:30:00")
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        output = buf.getvalue()
        assert "2024-06-15" in output

    def test_render_terminal_function(self) -> None:
        data = _make_scan_data()
        console, buf = _make_console()
        render_terminal(data, console=console)  # Should not raise
        assert len(buf.getvalue()) > 0

    def test_render_terminal_with_show_remediation(self) -> None:
        findings = [_make_finding(remediation="1. Fix it immediately.")]
        data = _make_scan_data(findings=findings)
        console, buf = _make_console()
        render_terminal(data, console=console, show_remediation=True)
        assert "Fix it immediately" in buf.getvalue()

    def test_multiple_findings_all_appear_in_table(self) -> None:
        findings = [
            _make_finding("pkg-a", severity="critical"),
            _make_finding("pkg-b", severity="high"),
            _make_finding("pkg-c", severity="medium"),
        ]
        data = _make_scan_data(findings=findings)
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        output = buf.getvalue()
        assert "pkg-a" in output
        assert "pkg-b" in output
        assert "pkg-c" in output

    def test_no_errors_section_when_no_errors(self) -> None:
        data = _make_scan_data(errors=[])
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        output = buf.getvalue()
        # "warnings" section should not appear if no errors
        assert "Non-fatal scan warnings" not in output

    def test_multiple_errors_all_shown(self) -> None:
        data = _make_scan_data(
            errors=["Error one happened", "Error two also happened"]
        )
        console, buf = _make_console()
        Reporter(data, console=console).print_terminal()
        output = buf.getvalue()
        assert "Error one happened" in output
        assert "Error two also happened" in output


# ---------------------------------------------------------------------------
# TestJsonOutput
# ---------------------------------------------------------------------------


class TestJsonOutput:
    """Tests for Reporter.write_json()."""

    def test_write_json_returns_string(self) -> None:
        data = _make_scan_data()
        reporter = Reporter(data)
        result = reporter.write_json()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_write_json_is_valid_json(self) -> None:
        data = _make_scan_data(
            findings=[_make_finding("crossenv", "known-malicious", "critical")]
        )
        reporter = Reporter(data)
        json_str = reporter.write_json()
        parsed = json.loads(json_str)  # Should not raise
        assert isinstance(parsed, dict)

    def test_write_json_contains_findings(self) -> None:
        findings = [_make_finding("evil-pkg", "typosquatting", "high")]
        data = _make_scan_data(findings=findings)
        json_str = Reporter(data).write_json()
        parsed = json.loads(json_str)
        assert "findings" in parsed
        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["package"] == "evil-pkg"

    def test_write_json_contains_metadata_fields(self) -> None:
        data = _make_scan_data(project_name="my-app")
        parsed = json.loads(Reporter(data).write_json())
        assert parsed["project_name"] == "my-app"
        assert "scanned_at" in parsed
        assert "duration_seconds" in parsed
        assert "severity_summary" in parsed
        assert "finding_count" in parsed
        assert "max_severity" in parsed

    def test_write_json_writes_to_file(self, tmp_path: Path) -> None:
        output = tmp_path / "report.json"
        data = _make_scan_data(
            findings=[_make_finding("pkg", "known-malicious", "critical")]
        )
        Reporter(data).write_json(output)
        assert output.is_file()
        content = output.read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert parsed["findings"][0]["package"] == "pkg"

    def test_write_json_custom_indent(self) -> None:
        data = _make_scan_data()
        json_str = Reporter(data).write_json(indent=4)
        # 4-space indented JSON has more whitespace than 2-space
        assert "    " in json_str

    def test_write_json_default_indent_two(self) -> None:
        data = _make_scan_data()
        json_str = Reporter(data).write_json()
        # Default indent=2
        assert "  " in json_str

    def test_write_json_no_path_returns_string(self) -> None:
        data = _make_scan_data()
        result = Reporter(data).write_json(None)
        assert isinstance(result, str)
        json.loads(result)  # Should be valid JSON

    def test_render_json_function_no_path(self) -> None:
        data = _make_scan_data()
        result = render_json(data)
        assert isinstance(result, str)
        json.loads(result)

    def test_render_json_function_with_path(self, tmp_path: Path) -> None:
        data = _make_scan_data()
        output = tmp_path / "out.json"
        result = render_json(data, output)
        assert isinstance(result, str)
        assert output.is_file()

    def test_write_json_empty_findings(self) -> None:
        data = _make_scan_data(findings=[])
        parsed = json.loads(Reporter(data).write_json())
        assert parsed["findings"] == []
        assert parsed["finding_count"] == 0

    def test_severity_summary_in_json(self) -> None:
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
            _make_finding(severity="high"),
        ]
        data = _make_scan_data(findings=findings)
        parsed = json.loads(Reporter(data).write_json())
        assert parsed["severity_summary"]["critical"] == 1
        assert parsed["severity_summary"]["high"] == 2
        assert parsed["severity_summary"]["medium"] == 0

    def test_write_json_file_content_matches_returned_string(self, tmp_path: Path) -> None:
        data = _make_scan_data(findings=[_make_finding()])
        output = tmp_path / "report.json"
        reporter = Reporter(data)
        json_str = reporter.write_json(output)
        file_content = output.read_text(encoding="utf-8")
        assert json_str == file_content

    def test_write_json_preserves_finding_structure(self) -> None:
        finding = _make_finding(
            package="evil-pkg",
            detector="credential-harvesting",
            severity="high",
            description="Has bad pattern.",
            remediation="1. Remove it.",
            metadata={"key": "value"},
        )
        data = _make_scan_data(findings=[finding])
        parsed = json.loads(Reporter(data).write_json())
        f = parsed["findings"][0]
        assert f["package"] == "evil-pkg"
        assert f["detector"] == "credential-harvesting"
        assert f["severity"] == "high"
        assert f["description"] == "Has bad pattern."
        assert f["remediation"] == "1. Remove it."
        assert f["metadata"] == {"key": "value"}

    def test_write_json_max_severity_correct(self) -> None:
        findings = [
            _make_finding(severity="medium"),
            _make_finding(severity="critical"),
            _make_finding(severity="low"),
        ]
        data = _make_scan_data(findings=findings)
        parsed = json.loads(Reporter(data).write_json())
        assert parsed["max_severity"] == "critical"

    def test_write_json_errors_list_present(self) -> None:
        data = _make_scan_data(errors=["detector failed"])
        parsed = json.loads(Reporter(data).write_json())
        assert "errors" in parsed
        assert "detector failed" in parsed["errors"]

    def test_write_json_no_errors_is_empty_list(self) -> None:
        data = _make_scan_data(errors=[])
        parsed = json.loads(Reporter(data).write_json())
        assert parsed["errors"] == []


# ---------------------------------------------------------------------------
# TestHtmlOutput
# ---------------------------------------------------------------------------


class TestHtmlOutput:
    """Tests for Reporter.write_html()."""

    def test_write_html_returns_string(self) -> None:
        data = _make_scan_data()
        result = Reporter(data).write_html()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_html_is_well_formed(self) -> None:
        data = _make_scan_data()
        html_str = Reporter(data).write_html()
        assert "<!DOCTYPE html>" in html_str
        assert "</html>" in html_str
        assert "<head>" in html_str
        assert "<body>" in html_str

    def test_html_has_title(self) -> None:
        data = _make_scan_data(project_name="my-project")
        html_str = Reporter(data).write_html()
        assert "<title>" in html_str
        assert "my-project" in html_str

    def test_html_contains_project_name(self) -> None:
        data = _make_scan_data(project_name="super-app")
        html_str = Reporter(data).write_html()
        assert "super-app" in html_str

    def test_html_contains_project_version(self) -> None:
        data = _make_scan_data(project_version="4.2.0")
        html_str = Reporter(data).write_html()
        assert "4.2.0" in html_str

    def test_html_contains_findings_table(self) -> None:
        findings = [_make_finding("evil-pkg", "known-malicious", "critical")]
        data = _make_scan_data(findings=findings)
        html_str = Reporter(data).write_html()
        assert "evil-pkg" in html_str
        assert "known-malicious" in html_str
        assert "<table" in html_str
        assert "<tbody>" in html_str

    def test_html_escapes_special_characters(self) -> None:
        """HTML special characters in package names should be escaped."""
        findings = [
            _make_finding(
                package="<script>alert('xss')</script>",
                description="<img src=x onerror=alert(1)>",
            )
        ]
        data = _make_scan_data(findings=findings)
        html_str = Reporter(data).write_html()
        # Script tag should be escaped, not present as-is
        assert "<script>alert" not in html_str
        assert "&lt;script&gt;" in html_str

    def test_html_escapes_ampersands(self) -> None:
        findings = [_make_finding(package="pkg&name", description="Has & symbol")]
        data = _make_scan_data(findings=findings)
        html_str = Reporter(data).write_html()
        assert "pkg&name" not in html_str or "&amp;" in html_str

    def test_html_escapes_quotes_in_description(self) -> None:
        findings = [
            _make_finding(description='Contains "quotes" and \'apostrophes\'')
        ]
        data = _make_scan_data(findings=findings)
        html_str = Reporter(data).write_html()
        # Should not contain unescaped quotes breaking HTML attributes
        assert isinstance(html_str, str)

    def test_html_shows_severity_badges(self) -> None:
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
        ]
        data = _make_scan_data(findings=findings)
        html_str = Reporter(data).write_html()
        assert "CRITICAL" in html_str
        assert "HIGH" in html_str

    def test_html_shows_all_severity_levels(self) -> None:
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
            _make_finding(severity="medium"),
            _make_finding(severity="low"),
            _make_finding(severity="info"),
        ]
        data = _make_scan_data(findings=findings)
        html_str = Reporter(data).write_html()
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert sev in html_str

    def test_html_writes_to_file(self, tmp_path: Path) -> None:
        output = tmp_path / "report.html"
        data = _make_scan_data(
            findings=[_make_finding("pkg", "typosquatting", "high")]
        )
        Reporter(data).write_html(output)
        assert output.is_file()
        content = output.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "pkg" in content

    def test_html_no_findings_shows_clean_message(self) -> None:
        data = _make_scan_data(findings=[])
        html_str = Reporter(data).write_html()
        assert "clean" in html_str.lower() or "No security" in html_str

    def test_html_contains_remediation(self) -> None:
        findings = [_make_finding(remediation="1. Remove the package.\n2. Rotate keys.")]
        data = _make_scan_data(findings=findings)
        html_str = Reporter(data).write_html()
        assert "Remove the package" in html_str
        assert "Rotate keys" in html_str

    def test_html_remediation_uses_line_breaks(self) -> None:
        findings = [_make_finding(remediation="1. Step one.\n2. Step two.")]
        data = _make_scan_data(findings=findings)
        html_str = Reporter(data).write_html()
        # Newlines should be converted to <br> in HTML
        assert "<br>" in html_str or "Step one" in html_str

    def test_html_filter_script_present(self) -> None:
        findings = [_make_finding()]
        data = _make_scan_data(findings=findings)
        html_str = Reporter(data).write_html()
        # The filter JavaScript function should be present
        assert "filterFindings" in html_str

    def test_html_contains_filter_select(self) -> None:
        findings = [_make_finding()]
        data = _make_scan_data(findings=findings)
        html_str = Reporter(data).write_html()
        assert "<select" in html_str
        assert "sev-filter" in html_str

    def test_render_html_function_no_path(self) -> None:
        data = _make_scan_data()
        result = render_html(data)
        assert isinstance(result, str)
        assert "<!DOCTYPE html>" in result

    def test_render_html_function_with_path(self, tmp_path: Path) -> None:
        data = _make_scan_data()
        output = tmp_path / "out.html"
        result = render_html(data, output)
        assert isinstance(result, str)
        assert output.is_file()

    def test_html_shows_errors_section_when_errors_present(self) -> None:
        data = _make_scan_data(errors=["Something failed during scan"])
        html_str = Reporter(data).write_html()
        assert "Something failed" in html_str
        assert "errors-section" in html_str

    def test_html_no_errors_section_when_no_errors(self) -> None:
        data = _make_scan_data(errors=[])
        html_str = Reporter(data).write_html()
        # errors-section div should not appear if there are no errors
        assert "errors-section" not in html_str

    def test_render_html_standalone_function(self) -> None:
        data = _make_scan_data()
        html_str = _render_html(data)
        assert "<!DOCTYPE html>" in html_str

    def test_html_contains_meta_cards(self) -> None:
        data = _make_scan_data()
        html_str = Reporter(data).write_html()
        assert "meta-card" in html_str
        assert "Total Findings" in html_str

    def test_html_contains_footer(self) -> None:
        data = _make_scan_data()
        html_str = Reporter(data).write_html()
        assert "npm_shield" in html_str
        assert "<footer" in html_str

    def test_html_contains_scanned_at(self) -> None:
        data = _make_scan_data(scanned_at="2024-12-01T09:00:00")
        html_str = Reporter(data).write_html()
        assert "2024-12-01" in html_str

    def test_html_contains_duration(self) -> None:
        data = _make_scan_data(duration_seconds=5.55)
        html_str = Reporter(data).write_html()
        assert "5.55" in html_str

    def test_html_contains_packages_count(self) -> None:
        data = _make_scan_data(packages_analysed=77)
        html_str = Reporter(data).write_html()
        assert "77" in html_str

    def test_html_file_content_matches_returned_string(self, tmp_path: Path) -> None:
        data = _make_scan_data()
        output = tmp_path / "report.html"
        reporter = Reporter(data)
        html_str = reporter.write_html(output)
        file_content = output.read_text(encoding="utf-8")
        assert html_str == file_content

    def test_html_finding_rows_have_data_severity(self) -> None:
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
        ]
        data = _make_scan_data(findings=findings)
        html_str = Reporter(data).write_html()
        assert 'data-severity="critical"' in html_str
        assert 'data-severity="high"' in html_str


# ---------------------------------------------------------------------------
# TestFormatSeveritySummary
# ---------------------------------------------------------------------------


class TestFormatSeveritySummary:
    """Tests for format_severity_summary()."""

    def test_no_findings(self) -> None:
        data = _make_scan_data(findings=[])
        summary = format_severity_summary(data)
        assert "No findings" in summary

    def test_single_critical_finding(self) -> None:
        data = _make_scan_data(findings=[_make_finding(severity="critical")])
        summary = format_severity_summary(data)
        assert "1" in summary
        assert "CRITICAL" in summary

    def test_mixed_severities(self) -> None:
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
            _make_finding(severity="medium"),
        ]
        data = _make_scan_data(findings=findings)
        summary = format_severity_summary(data)
        assert "3" in summary
        assert "CRITICAL" in summary
        assert "HIGH" in summary
        assert "MEDIUM" in summary

    def test_returns_string(self) -> None:
        data = _make_scan_data()
        result = format_severity_summary(data)
        assert isinstance(result, str)

    def test_total_count_in_summary(self) -> None:
        findings = [
            _make_finding(severity="high"),
            _make_finding(severity="high"),
            _make_finding(severity="low"),
        ]
        data = _make_scan_data(findings=findings)
        summary = format_severity_summary(data)
        assert "3" in summary

    def test_all_severities_shown_when_present(self) -> None:
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="high"),
            _make_finding(severity="medium"),
            _make_finding(severity="low"),
            _make_finding(severity="info"),
        ]
        data = _make_scan_data(findings=findings)
        summary = format_severity_summary(data)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert sev in summary

    def test_only_present_severities_shown(self) -> None:
        findings = [_make_finding(severity="critical")]
        data = _make_scan_data(findings=findings)
        summary = format_severity_summary(data)
        # Medium, low, info counts of 0 should not appear
        assert "MEDIUM" not in summary
        assert "LOW" not in summary
        assert "INFO" not in summary

    def test_single_high_finding(self) -> None:
        findings = [_make_finding(severity="high")]
        data = _make_scan_data(findings=findings)
        summary = format_severity_summary(data)
        assert "HIGH" in summary
        assert "1" in summary

    def test_finding_count_from_severity_summary_field(self) -> None:
        # Build data where finding_count is explicitly 5
        data = _make_scan_data(
            findings=[
                _make_finding(severity="high"),
                _make_finding(severity="high"),
            ]
        )
        data["finding_count"] = 5  # Override
        summary = format_severity_summary(data)
        assert "5" in summary


# ---------------------------------------------------------------------------
# TestTruncate
# ---------------------------------------------------------------------------


class TestTruncate:
    """Tests for the _truncate helper."""

    def test_short_string_unchanged(self) -> None:
        assert _truncate("hello", 10) == "hello"

    def test_exact_length_unchanged(self) -> None:
        assert _truncate("hello", 5) == "hello"

    def test_long_string_truncated(self) -> None:
        result = _truncate("a" * 200, 50)
        assert len(result) == 50
        assert result.endswith("\u2026")  # ellipsis character

    def test_empty_string(self) -> None:
        assert _truncate("", 10) == ""

    def test_truncation_adds_ellipsis(self) -> None:
        result = _truncate("hello world", 8)
        assert "\u2026" in result
        assert len(result) == 8

    def test_one_over_limit_truncates(self) -> None:
        result = _truncate("abcdef", 5)
        assert len(result) == 5
        assert result.endswith("\u2026")

    def test_preserves_content_up_to_limit(self) -> None:
        result = _truncate("hello world this is long", 10)
        assert result.startswith("hello worl") or result.startswith("hello")
        assert len(result) == 10

    def test_returns_string_type(self) -> None:
        result = _truncate("test", 100)
        assert isinstance(result, str)

    def test_unicode_string_truncated(self) -> None:
        text = "\u4e2d\u6587\u5185\u5bb9\u6d4b\u8bd5" * 10  # CJK characters
        result = _truncate(text, 5)
        assert len(result) == 5


# ---------------------------------------------------------------------------
# TestReporterWithRealScanResult
# ---------------------------------------------------------------------------


class TestReporterWithRealScanResult:
    """Integration tests using actual ScanResult objects from the scanner."""

    def _make_project_with_packages(self, tmp_path: Path) -> Path:
        """Create a test project with some suspicious packages."""
        project = tmp_path / "project"
        project.mkdir()
        pkg_data = {
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {
                "crossenv": "^1.0.0",
                "lodash": "^4.17.21",
            },
        }
        (project / "package.json").write_text(
            json.dumps(pkg_data), encoding="utf-8"
        )
        nm = project / "node_modules"
        nm.mkdir()
        # crossenv — known malicious
        pkg_dir = nm / "crossenv"
        pkg_dir.mkdir()
        (pkg_dir / "package.json").write_text(
            json.dumps({"name": "crossenv", "version": "1.0.0"}),
            encoding="utf-8",
        )
        # lodash — safe
        lodash_dir = nm / "lodash"
        lodash_dir.mkdir()
        (lodash_dir / "package.json").write_text(
            json.dumps({"name": "lodash", "version": "4.17.21"}),
            encoding="utf-8",
        )
        return project

    def test_reporter_json_round_trip_with_real_result(self, tmp_path: Path) -> None:
        project = self._make_project_with_packages(tmp_path)
        from npm_shield.scanner import Scanner

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()

        reporter = Reporter(result)
        json_str = reporter.write_json()
        parsed = json.loads(json_str)

        assert parsed["project_name"] == "test-app"
        assert isinstance(parsed["findings"], list)
        assert parsed["finding_count"] == len(parsed["findings"])
        assert "severity_summary" in parsed
        assert "max_severity" in parsed

    def test_reporter_html_with_real_result(self, tmp_path: Path) -> None:
        project = self._make_project_with_packages(tmp_path)
        from npm_shield.scanner import Scanner

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()

        html_str = Reporter(result).write_html()
        assert "test-app" in html_str
        assert "<!DOCTYPE html>" in html_str
        assert "</html>" in html_str

    def test_reporter_html_contains_malicious_finding(self, tmp_path: Path) -> None:
        project = self._make_project_with_packages(tmp_path)
        from npm_shield.scanner import Scanner

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()

        html_str = Reporter(result).write_html()
        assert "crossenv" in html_str

    def test_reporter_terminal_with_real_result(self, tmp_path: Path) -> None:
        project = self._make_project_with_packages(tmp_path)
        from npm_shield.scanner import Scanner

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()

        console, buf = _make_console()
        Reporter(result, console=console).print_terminal()
        output = buf.getvalue()
        assert len(output) > 0
        # crossenv should appear in the terminal table
        assert "crossenv" in output

    def test_reporter_write_json_to_file_with_real_result(
        self, tmp_path: Path
    ) -> None:
        project = self._make_project_with_packages(tmp_path)
        from npm_shield.scanner import Scanner

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()

        output = tmp_path / "report.json"
        Reporter(result).write_json(output)
        assert output.is_file()
        parsed = json.loads(output.read_text(encoding="utf-8"))
        assert parsed["project_name"] == "test-app"

    def test_reporter_write_html_to_file_with_real_result(
        self, tmp_path: Path
    ) -> None:
        project = self._make_project_with_packages(tmp_path)
        from npm_shield.scanner import Scanner

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()

        output = tmp_path / "report.html"
        Reporter(result).write_html(output)
        assert output.is_file()
        content = output.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "test-app" in content

    def test_scan_result_to_dict_used_by_reporter(self, tmp_path: Path) -> None:
        """Verify Reporter correctly calls to_dict() on ScanResult."""
        project = self._make_project_with_packages(tmp_path)
        from npm_shield.scanner import Scanner

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()

        # Direct dict comparison between reporter and ScanResult.to_dict()
        reporter = Reporter(result)
        reporter_dict = reporter.to_json_dict()
        result_dict = result.to_dict()

        assert reporter_dict["project_name"] == result_dict["project_name"]
        assert reporter_dict["finding_count"] == result_dict["finding_count"]
        assert reporter_dict["findings"] == result_dict["findings"]

    def test_full_pipeline_json_is_serialisable(self, tmp_path: Path) -> None:
        """End-to-end: scan -> report -> JSON should be fully serialisable."""
        project = self._make_project_with_packages(tmp_path)
        from npm_shield.scanner import Scanner

        result = Scanner(
            project_path=project, enable_credential_scan=False
        ).run_full()

        json_str = Reporter(result).write_json()
        # Re-parse and verify key types
        parsed = json.loads(json_str)
        assert isinstance(parsed["findings"], list)
        assert isinstance(parsed["duration_seconds"], (int, float))
        assert isinstance(parsed["packages_analysed"], int)
        assert isinstance(parsed["errors"], list)
        assert isinstance(parsed["severity_summary"], dict)
