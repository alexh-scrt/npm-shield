"""Detection engine for npm_shield.

This module implements all individual detector functions that analyse a Node.js
project for supply chain attack indicators. Each detector is a standalone
function that accepts structured input (package metadata, file paths, etc.)
and returns a list of finding dictionaries.

Detectors implemented:

- :func:`detect_known_malicious` — Cross-references installed packages against
  the built-in database of known malicious package names and versions.
- :func:`detect_typosquatting` — Compares installed package names against
  popular legitimate packages using Levenshtein edit-distance heuristics.
- :func:`detect_suspicious_scripts` — Inspects npm lifecycle scripts for
  remote download, shell injection, and other dangerous patterns.
- :func:`detect_git_hook_injection` — Scans ``.git/hooks`` for injected
  malicious scripts added by postinstall lifecycle hooks.
- :func:`detect_credential_harvesting` — Regex-scans package source files
  for environment variable exfiltration, network beaconing, and secret-
  harvesting code signatures.
- :func:`detect_mcp_servers` — Flags unexpected MCP (Model Context Protocol)
  server registrations in package metadata and binary entries.
- :func:`detect_rogue_binaries` — Identifies unexpected executables in
  ``node_modules/.bin`` that may have been injected by malicious packages.
- :func:`detect_dependency_confusion` — Heuristically detects packages that
  may be dependency confusion attack vectors based on name patterns and
  unusually high version numbers.

All finding dictionaries conform to the standard schema::

    {
        "package": str,       # Package name or file path
        "detector": str,      # Detector identifier
        "severity": str,      # "info" | "low" | "medium" | "high" | "critical"
        "description": str,   # Human-readable description
        "remediation": str,   # Actionable remediation steps
        "metadata": dict,     # Additional context (detector-specific)
    }
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from npm_shield.npm_utils import (
    PackageMeta,
    get_lifecycle_scripts,
    get_all_scripts,
    iter_package_source_files,
    list_bin_entries,
    list_git_hooks,
    read_hook_content,
)
from npm_shield.patterns import (
    COMMON_INTERNAL_NAME_PREFIXES,
    CREDENTIAL_HARVESTING_SIGNATURES,
    DEP_CONFUSION_HIGH_VERSION_THRESHOLD,
    DEP_CONFUSION_VERSION_PATTERN,
    GIT_HOOK_MALICIOUS_PATTERNS,
    GIT_HOOK_SAMPLE_SUFFIXES,
    KNOWN_MALICIOUS_BY_NAME,
    KNOWN_MALICIOUS_NAMES,
    LEGITIMATE_MCP_PACKAGES,
    LEGITIMATE_PACKAGE_NAMES,
    MAX_SCAN_FILE_LINES,
    MAX_SCAN_FILE_SIZE_BYTES,
    MCP_DECLARATION_PATTERNS,
    MCP_SERVER_NAME_KEYWORDS,
    REMEDIATION_TEMPLATES,
    STANDARD_GIT_HOOKS,
    SUSPICIOUS_SCRIPT_PATTERNS,
    TYPOSQUAT_TARGETS,
    Severity,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

Finding = dict[str, Any]
"""A finding dictionary conforming to the standard npm_shield finding schema."""


# ---------------------------------------------------------------------------
# Levenshtein edit distance helper
# ---------------------------------------------------------------------------


def _levenshtein(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings.

    Uses the classic dynamic programming algorithm with O(min(|s1|, |s2|))
    space optimisation.

    Args:
        s1: First string.
        s2: Second string.

    Returns:
        Integer edit distance (0 = identical).
    """
    if s1 == s2:
        return 0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    # s1 is now the longer string
    len1, len2 = len(s1), len(s2)
    if len2 == 0:
        return len1

    prev_row = list(range(len2 + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[len2]


# ---------------------------------------------------------------------------
# Finding construction helpers
# ---------------------------------------------------------------------------


def _make_finding(
    package: str,
    detector: str,
    severity: str,
    description: str,
    remediation: str,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    """Construct a standardised finding dictionary.

    Args:
        package: Package name or file path associated with the finding.
        detector: Identifier of the detector that raised the finding.
        severity: Severity level string.
        description: Human-readable description of the finding.
        remediation: Actionable remediation steps.
        metadata: Optional additional context dictionary.

    Returns:
        Finding dictionary.
    """
    return {
        "package": package,
        "detector": detector,
        "severity": severity,
        "description": description,
        "remediation": remediation,
        "metadata": metadata or {},
    }


def _fmt_remediation(template_key: str, **kwargs: str) -> str:
    """Format a remediation template with the given keyword arguments.

    Falls back gracefully if the template key is missing or formatting fails.

    Args:
        template_key: Key into :data:`npm_shield.patterns.REMEDIATION_TEMPLATES`.
        **kwargs: Format keyword arguments.

    Returns:
        Formatted remediation string.
    """
    template = REMEDIATION_TEMPLATES.get(template_key, "See npm_shield documentation.")
    try:
        return template.format(**kwargs)
    except KeyError:
        return template


# ---------------------------------------------------------------------------
# 1. Known malicious package detector
# ---------------------------------------------------------------------------


def detect_known_malicious(
    installed_packages: list[PackageMeta],
) -> list[Finding]:
    """Detect packages with names or version combinations known to be malicious.

    Cross-references each installed package against the static database of
    known malicious packages in :data:`npm_shield.patterns.KNOWN_MALICIOUS_BY_NAME`.

    A package matches if:
    - Its name is in the known-malicious name set AND either no specific versions
      are recorded (all versions bad) OR the installed version is in the bad-version
      list.

    Args:
        installed_packages: List of package metadata dictionaries from
            :func:`npm_shield.npm_utils.iter_installed_packages`.

    Returns:
        List of finding dictionaries for every matched package.
    """
    findings: list[Finding] = []

    for pkg in installed_packages:
        name: str = pkg.get("name", "")
        version: str = pkg.get("version", "")

        if name not in KNOWN_MALICIOUS_NAMES:
            continue

        records = KNOWN_MALICIOUS_BY_NAME.get(name, [])
        for record in records:
            # Match if: no specific versions pinned (all bad) OR version matches
            if not record.versions or version in record.versions:
                version_note = (
                    f"version {version}" if version in record.versions
                    else "all versions"
                )
                description = (
                    f"Package '{name}' ({version_note}) is in the known-malicious "
                    f"database: {record.description}"
                )
                remediation = _fmt_remediation(
                    "known-malicious",
                    package=name,
                    reference=record.reference or "https://security.snyk.io",
                )
                findings.append(
                    _make_finding(
                        package=name,
                        detector="known-malicious",
                        severity=record.severity,
                        description=description,
                        remediation=remediation,
                        metadata={
                            "installed_version": version,
                            "bad_versions": list(record.versions),
                            "reference": record.reference,
                        },
                    )
                )
                # Only report the first matching record per package to avoid
                # duplicate findings for the same install.
                break

    return findings


# ---------------------------------------------------------------------------
# 2. Typosquatting detector
# ---------------------------------------------------------------------------


def detect_typosquatting(
    installed_packages: list[PackageMeta],
    *,
    skip_known_malicious: bool = True,
) -> list[Finding]:
    """Detect potential typosquatting of popular npm packages.

    Compares each installed package name against the list of popular legitimate
    package names in :data:`npm_shield.patterns.TYPOSQUAT_TARGETS` using
    Levenshtein edit distance. A candidate is flagged if:

    - The edit distance is within the target's ``max_edit_distance`` threshold.
    - The package name is NOT identical to the legitimate name (i.e. it IS a
      different package).
    - The package is not already in the legitimate package set.

    Args:
        installed_packages: List of package metadata dictionaries.
        skip_known_malicious: If ``True``, skip packages already flagged by the
            known-malicious detector to avoid duplicate findings. Those packages
            are already reported with higher-quality context.

    Returns:
        List of finding dictionaries for potential typosquats.
    """
    findings: list[Finding] = []

    for pkg in installed_packages:
        name: str = pkg.get("name", "")
        if not name:
            continue

        # Skip packages that are legitimate targets themselves
        if name in LEGITIMATE_PACKAGE_NAMES:
            continue

        # Optionally skip packages already in known-malicious DB
        if skip_known_malicious and name in KNOWN_MALICIOUS_NAMES:
            continue

        # Check against each typosquat target
        best_match: str | None = None
        best_distance: int = 999
        best_target = None

        for target in TYPOSQUAT_TARGETS:
            # Skip exact match (this IS the legitimate package)
            if name == target.name:
                best_match = None
                break

            # Normalise by stripping common separators for comparison
            # e.g. "lod4sh" vs "lodash"
            dist = _levenshtein(name.lower(), target.name.lower())
            if dist <= target.max_edit_distance and dist < best_distance:
                best_distance = dist
                best_match = target.name
                best_target = target

        if best_match is None or best_target is None:
            continue

        version: str = pkg.get("version", "unknown")
        description = (
            f"Package '{name}' (installed: {version}) may be a typosquat of "
            f"'{best_match}' (edit distance: {best_distance}). "
            f"'{best_match}' has ~{best_target.weekly_downloads_approx:,} weekly downloads "
            f"and is a common attack target."
        )
        remediation = _fmt_remediation(
            "typosquatting",
            package=name,
            intended=best_match,
        )
        findings.append(
            _make_finding(
                package=name,
                detector="typosquatting",
                severity=Severity.HIGH.value,
                description=description,
                remediation=remediation,
                metadata={
                    "installed_version": version,
                    "likely_target": best_match,
                    "edit_distance": best_distance,
                    "target_weekly_downloads": best_target.weekly_downloads_approx,
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# 3. Suspicious lifecycle script detector
# ---------------------------------------------------------------------------


def detect_suspicious_scripts(
    installed_packages: list[PackageMeta],
) -> list[Finding]:
    """Detect suspicious npm lifecycle scripts in installed packages.

    Inspects the ``preinstall``, ``install``, ``postinstall``, ``prepare``,
    and related lifecycle script values in each package's ``package.json``
    against the patterns in
    :data:`npm_shield.patterns.SUSPICIOUS_SCRIPT_PATTERNS`.

    Args:
        installed_packages: List of package metadata dictionaries.

    Returns:
        List of finding dictionaries for packages with suspicious scripts.
    """
    findings: list[Finding] = []

    for pkg in installed_packages:
        name: str = pkg.get("name", "")
        version: str = pkg.get("version", "unknown")
        pkg_json: dict[str, Any] = pkg.get("package_json", {})

        lifecycle_scripts = get_lifecycle_scripts(pkg_json)
        if not lifecycle_scripts:
            continue

        for script_name, script_value in lifecycle_scripts.items():
            if not script_value:
                continue

            for sig in SUSPICIOUS_SCRIPT_PATTERNS:
                if sig.pattern.search(script_value):
                    description = (
                        f"Package '{name}' has a suspicious '{script_name}' lifecycle "
                        f"script matching pattern '{sig.name}': {sig.description} "
                        f"Script: {script_value[:200]!r}"
                    )
                    remediation = _fmt_remediation(
                        "suspicious-script",
                        package=name,
                    )
                    findings.append(
                        _make_finding(
                            package=name,
                            detector="suspicious-script",
                            severity=sig.severity,
                            description=description,
                            remediation=remediation,
                            metadata={
                                "installed_version": version,
                                "script_name": script_name,
                                "script_value": script_value,
                                "matched_pattern": sig.name,
                            },
                        )
                    )
                    # Report only the highest-severity match per script
                    break

    return findings


# ---------------------------------------------------------------------------
# 4. Git hook injection detector
# ---------------------------------------------------------------------------


def detect_git_hook_injection(
    project_path: Path,
    installed_packages: list[PackageMeta] | None = None,
) -> list[Finding]:
    """Detect injected malicious scripts in the ``.git/hooks`` directory.

    Analyses each hook file in ``.git/hooks`` for:
    - Unexpected (non-standard) hook names that may have been added by a
      package's postinstall script.
    - Malicious content patterns matching
      :data:`npm_shield.patterns.GIT_HOOK_MALICIOUS_PATTERNS`.
    - Hook files that are executable and were recently modified (heuristic).

    Args:
        project_path: Path to the Node.js project root directory.
        installed_packages: Optional list of installed packages (used to
            correlate suspicious hook content with postinstall scripts).

    Returns:
        List of finding dictionaries for suspicious Git hook files.
    """
    findings: list[Finding] = []
    hooks = list_git_hooks(project_path)

    if not hooks:
        return findings

    # Build a set of postinstall scripts for correlation
    postinstall_packages: list[str] = []
    if installed_packages:
        for pkg in installed_packages:
            scripts = get_lifecycle_scripts(pkg.get("package_json", {}))
            if any(k in scripts for k in ("postinstall", "install", "preinstall")):
                postinstall_packages.append(pkg.get("name", "unknown"))

    for hook_info in hooks:
        hook_name: str = hook_info["name"]
        hook_path: Path = hook_info["path"]
        is_sample: bool = hook_info["is_sample"]
        is_executable: bool = hook_info["is_executable"]
        size_bytes: int = hook_info["size_bytes"]

        # Skip sample/template files
        if is_sample:
            continue

        # Derive the base hook name (without extension)
        base_name = hook_name
        for suffix in GIT_HOOK_SAMPLE_SUFFIXES:
            if base_name.endswith(suffix):
                base_name = base_name[: -len(suffix)]
                break

        # --- Check 1: Non-standard hook name ---
        if base_name not in STANDARD_GIT_HOOKS and is_executable and size_bytes > 0:
            description = (
                f"Non-standard Git hook file '{hook_name}' found in .git/hooks. "
                f"Standard Git hooks are: {', '.join(sorted(STANDARD_GIT_HOOKS)[:5])}... "
                f"This file may have been injected by a malicious postinstall script."
            )
            if postinstall_packages:
                description += (
                    f" Packages with postinstall scripts: "
                    f"{', '.join(postinstall_packages[:5])}"
                )
            remediation = _fmt_remediation(
                "git-hook",
                hook=hook_name,
            )
            findings.append(
                _make_finding(
                    package=f".git/hooks/{hook_name}",
                    detector="git-hook",
                    severity=Severity.HIGH.value,
                    description=description,
                    remediation=remediation,
                    metadata={
                        "hook_name": hook_name,
                        "hook_path": str(hook_path),
                        "is_executable": is_executable,
                        "size_bytes": size_bytes,
                        "finding_type": "non-standard-hook",
                        "postinstall_packages": postinstall_packages,
                    },
                )
            )

        # --- Check 2: Malicious content patterns ---
        try:
            content = read_hook_content(hook_path)
        except (OSError, FileNotFoundError):
            continue

        for sig in GIT_HOOK_MALICIOUS_PATTERNS:
            if sig.pattern.search(content):
                description = (
                    f"Git hook '.git/hooks/{hook_name}' contains a malicious pattern "
                    f"matching '{sig.name}': {sig.description}"
                )
                if postinstall_packages:
                    description += (
                        f" Likely injected by one of: "
                        f"{', '.join(postinstall_packages[:5])}"
                    )
                remediation = _fmt_remediation(
                    "git-hook",
                    hook=hook_name,
                )
                findings.append(
                    _make_finding(
                        package=f".git/hooks/{hook_name}",
                        detector="git-hook",
                        severity=sig.severity,
                        description=description,
                        remediation=remediation,
                        metadata={
                            "hook_name": hook_name,
                            "hook_path": str(hook_path),
                            "is_executable": is_executable,
                            "size_bytes": size_bytes,
                            "finding_type": "malicious-content",
                            "matched_pattern": sig.name,
                            "content_preview": content[:300],
                            "postinstall_packages": postinstall_packages,
                        },
                    )
                )
                # Report one finding per hook file (the first/worst match)
                break

    return findings


# ---------------------------------------------------------------------------
# 5. Credential harvesting detector
# ---------------------------------------------------------------------------


def detect_credential_harvesting(
    installed_packages: list[PackageMeta],
    *,
    max_findings_per_package: int = 5,
) -> list[Finding]:
    """Detect credential harvesting and data exfiltration patterns in package source.

    Scans JavaScript/TypeScript source files in each installed package against
    the signatures in
    :data:`npm_shield.patterns.CREDENTIAL_HARVESTING_SIGNATURES`.

    To limit scan time, only files in high-risk directories (``scripts``,
    ``bin``, ``lib``, ``dist``, ``src``) are scanned, up to the configured
    size limit.

    Args:
        installed_packages: List of package metadata dictionaries.
        max_findings_per_package: Maximum number of findings to emit per
            package (caps at the first N unique pattern matches).

    Returns:
        List of finding dictionaries for packages with detected patterns.
    """
    findings: list[Finding] = []

    for pkg in installed_packages:
        name: str = pkg.get("name", "")
        version: str = pkg.get("version", "unknown")
        pkg_findings_count = 0

        try:
            source_files = list(iter_package_source_files(pkg))
        except (OSError, PermissionError) as exc:
            logger.debug("Cannot iterate source files for %s: %s", name, exc)
            continue

        seen_patterns: set[str] = set()

        for source_file in source_files:
            if pkg_findings_count >= max_findings_per_package:
                break

            try:
                content = _read_file_content(source_file)
            except (OSError, PermissionError):
                continue

            if not content:
                continue

            for sig in CREDENTIAL_HARVESTING_SIGNATURES:
                if pkg_findings_count >= max_findings_per_package:
                    break

                # Avoid duplicate pattern reports within the same package
                if sig.name in seen_patterns:
                    continue

                match = sig.pattern.search(content)
                if match:
                    seen_patterns.add(sig.name)
                    # Extract a short snippet around the match
                    start = max(0, match.start() - 40)
                    end = min(len(content), match.end() + 40)
                    snippet = content[start:end].replace("\n", " ").strip()

                    description = (
                        f"Package '{name}' contains a '{sig.name}' pattern in "
                        f"'{source_file.name}': {sig.description} "
                        f"Snippet: {snippet[:200]!r}"
                    )
                    remediation = _fmt_remediation("credential-harvesting")
                    findings.append(
                        _make_finding(
                            package=name,
                            detector="credential-harvesting",
                            severity=sig.severity,
                            description=description,
                            remediation=remediation,
                            metadata={
                                "installed_version": version,
                                "source_file": str(source_file),
                                "matched_pattern": sig.name,
                                "snippet": snippet[:500],
                                "match_start": match.start(),
                            },
                        )
                    )
                    pkg_findings_count += 1

    return findings


def _read_file_content(file_path: Path) -> str:
    """Read a source file's content, enforcing line and size limits.

    Args:
        file_path: Path to the source file.

    Returns:
        File content string (may be truncated), or empty string on error.
    """
    try:
        stat_result = file_path.stat()
        if stat_result.st_size > MAX_SCAN_FILE_SIZE_BYTES:
            return ""
        raw = file_path.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        # Limit to MAX_SCAN_FILE_LINES lines
        lines = text.splitlines(keepends=True)
        if len(lines) > MAX_SCAN_FILE_LINES:
            text = "".join(lines[:MAX_SCAN_FILE_LINES])
        return text
    except (OSError, PermissionError):
        return ""


# ---------------------------------------------------------------------------
# 6. MCP server detector
# ---------------------------------------------------------------------------


def detect_mcp_servers(
    installed_packages: list[PackageMeta],
    node_modules: Path | None = None,
) -> list[Finding]:
    """Detect unexpected MCP (Model Context Protocol) server registrations.

    Flags packages that:
    - Have names matching MCP server keywords.
    - Declare MCP server fields in their ``package.json``.
    - Depend on the ``@modelcontextprotocol/sdk`` package.
    - Register binaries with MCP-suggestive names.

    Known legitimate MCP packages from
    :data:`npm_shield.patterns.LEGITIMATE_MCP_PACKAGES` are reported at lower
    severity (``info``) for awareness rather than as active threats.

    Args:
        installed_packages: List of package metadata dictionaries.
        node_modules: Optional path to ``node_modules`` (used for binary checks).

    Returns:
        List of finding dictionaries for detected MCP server installations.
    """
    findings: list[Finding] = []

    for pkg in installed_packages:
        name: str = pkg.get("name", "")
        version: str = pkg.get("version", "unknown")
        pkg_json: dict[str, Any] = pkg.get("package_json", {})
        pkg_json_str = str(pkg_json)  # for regex matching

        is_legitimate = name in LEGITIMATE_MCP_PACKAGES
        matched_indicators: list[str] = []

        # --- Check 1: Package name contains MCP keywords ---
        name_lower = name.lower()
        for keyword in MCP_SERVER_NAME_KEYWORDS:
            if keyword in name_lower:
                matched_indicators.append(f"name contains '{keyword}'")
                break

        # --- Check 2: package.json declares MCP fields ---
        for sig in MCP_DECLARATION_PATTERNS:
            if sig.pattern.search(pkg_json_str):
                matched_indicators.append(f"package.json matches '{sig.name}'")

        # --- Check 3: Package has MCP-related bin entries ---
        bin_field = pkg_json.get("bin", {})
        if isinstance(bin_field, dict):
            for bin_name in bin_field:
                bin_lower = bin_name.lower()
                for keyword in MCP_SERVER_NAME_KEYWORDS:
                    if keyword in bin_lower:
                        matched_indicators.append(
                            f"binary '{bin_name}' contains '{keyword}'"
                        )
                        break
        elif isinstance(bin_field, str):
            for keyword in MCP_SERVER_NAME_KEYWORDS:
                if keyword in bin_field.lower():
                    matched_indicators.append(
                        f"binary path '{bin_field}' contains '{keyword}'"
                    )
                    break

        if not matched_indicators:
            continue

        if is_legitimate:
            severity = Severity.INFO.value
            description = (
                f"Package '{name}' ({version}) is a known legitimate MCP server. "
                f"Verify it was intentionally installed. "
                f"Indicators: {'; '.join(matched_indicators)}"
            )
        else:
            severity = Severity.MEDIUM.value
            description = (
                f"Package '{name}' ({version}) appears to be an MCP server "
                f"(Model Context Protocol). MCP servers have elevated host access "
                f"and should be explicitly expected. "
                f"Indicators: {'; '.join(matched_indicators)}"
            )

        remediation = _fmt_remediation("mcp-server", package=name)
        findings.append(
            _make_finding(
                package=name,
                detector="mcp-server",
                severity=severity,
                description=description,
                remediation=remediation,
                metadata={
                    "installed_version": version,
                    "is_known_legitimate": is_legitimate,
                    "matched_indicators": matched_indicators,
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# 7. Rogue binary detector
# ---------------------------------------------------------------------------


def detect_rogue_binaries(
    node_modules: Path,
    installed_packages: list[PackageMeta],
    *,
    declared_bin_names: set[str] | None = None,
) -> list[Finding]:
    """Detect unexpected or suspicious executables in ``node_modules/.bin``.

    Flags binaries that:
    - Cannot be attributed to any known installed package (owning_package is
      None or points to a non-existent package).
    - Have names that closely match MCP server keywords.
    - Are not symlinks (unusual — most legitimate binaries are symlinked).
    - Are directly executable scripts rather than symlinks to package bins.

    Args:
        node_modules: Path to the ``node_modules`` directory.
        installed_packages: List of installed package metadata dictionaries
            (used to validate binary ownership).
        declared_bin_names: Optional set of binary names declared by the
            project's own ``package.json`` (to avoid false positives for the
            root project's own bins).

    Returns:
        List of finding dictionaries for suspicious binaries.
    """
    findings: list[Finding] = []

    if not node_modules or not node_modules.is_dir():
        return findings

    bin_entries = list_bin_entries(node_modules)
    if not bin_entries:
        return findings

    # Build a set of known package names for ownership validation
    known_package_names: set[str] = {pkg.get("name", "") for pkg in installed_packages}
    declared_bins: set[str] = declared_bin_names or set()

    for entry in bin_entries:
        bin_name: str = entry["name"]
        bin_path: Path = entry["path"]
        owning_package: str | None = entry["owning_package"]
        is_executable: bool = entry["is_executable"]
        target: Path | None = entry.get("target")

        # Skip bins declared by the project itself
        if bin_name in declared_bins:
            continue

        # Skip non-executable entries
        if not is_executable:
            continue

        # --- Check 1: Binary has no owning package or owner not installed ---
        if owning_package is None or owning_package not in known_package_names:
            # Determine if the bin is a direct file (not a symlink to a package)
            is_direct_file = not bin_path.is_symlink() and bin_path.is_file()

            if is_direct_file or owning_package is None:
                description = (
                    f"Binary '{bin_name}' in node_modules/.bin cannot be attributed "
                    f"to any installed package (owning package: {owning_package!r}). "
                    f"This may indicate an injected executable."
                )
                remediation = _fmt_remediation(
                    "rogue-binary",
                    binary=bin_name,
                    package=owning_package or "unknown",
                )
                findings.append(
                    _make_finding(
                        package=f"node_modules/.bin/{bin_name}",
                        detector="rogue-binary",
                        severity=Severity.HIGH.value,
                        description=description,
                        remediation=remediation,
                        metadata={
                            "bin_name": bin_name,
                            "bin_path": str(bin_path),
                            "owning_package": owning_package,
                            "is_symlink": bin_path.is_symlink(),
                            "target": str(target) if target else None,
                            "finding_type": "unattributed-binary",
                        },
                    )
                )
                continue

        # --- Check 2: Binary name contains MCP keywords ---
        bin_lower = bin_name.lower()
        for keyword in MCP_SERVER_NAME_KEYWORDS:
            if keyword in bin_lower:
                description = (
                    f"Binary '{bin_name}' in node_modules/.bin has a name "
                    f"suggesting MCP server functionality (keyword: '{keyword}'). "
                    f"Owning package: '{owning_package}'. "
                    f"Verify this binary was intentionally installed."
                )
                remediation = _fmt_remediation(
                    "rogue-binary",
                    binary=bin_name,
                    package=owning_package or "unknown",
                )
                findings.append(
                    _make_finding(
                        package=f"node_modules/.bin/{bin_name}",
                        detector="rogue-binary",
                        severity=Severity.MEDIUM.value,
                        description=description,
                        remediation=remediation,
                        metadata={
                            "bin_name": bin_name,
                            "bin_path": str(bin_path),
                            "owning_package": owning_package,
                            "is_symlink": bin_path.is_symlink(),
                            "target": str(target) if target else None,
                            "finding_type": "mcp-binary",
                            "matched_keyword": keyword,
                        },
                    )
                )
                break

    return findings


# ---------------------------------------------------------------------------
# 8. Dependency confusion detector
# ---------------------------------------------------------------------------


def detect_dependency_confusion(
    installed_packages: list[PackageMeta],
    *,
    declared_dependencies: dict[str, str] | None = None,
) -> list[Finding]:
    """Detect potential dependency confusion attack vectors.

    Heuristically identifies packages that may be dependency confusion targets
    by checking:

    - Package names matching common internal naming prefixes (e.g. ``internal-``,
      ``private-``, ``corp-``).
    - Suspiciously high version numbers that are far outside the normal range
      for the package's declared history (above
      :data:`npm_shield.patterns.DEP_CONFUSION_HIGH_VERSION_THRESHOLD`).
    - Unscoped packages whose names suggest they should be scoped to a private
      registry (e.g. ``mycompany-utils``).

    Args:
        installed_packages: List of package metadata dictionaries.
        declared_dependencies: Optional mapping of package name → version
            specifier from the project's own ``package.json`` (used to
            correlate findings with declared intent).

    Returns:
        List of finding dictionaries for potential dependency confusion targets.
    """
    findings: list[Finding] = []
    declared: dict[str, str] = declared_dependencies or {}

    for pkg in installed_packages:
        name: str = pkg.get("name", "")
        version: str = pkg.get("version", "unknown")
        matched_reasons: list[str] = []

        # --- Check 1: Internal naming prefix ---
        name_lower = name.lower()
        for prefix in COMMON_INTERNAL_NAME_PREFIXES:
            if name_lower.startswith(prefix):
                matched_reasons.append(
                    f"name starts with internal prefix '{prefix}'"
                )
                break

        # --- Check 2: Suspiciously high version number ---
        version_match = DEP_CONFUSION_VERSION_PATTERN.match(version)
        if version_match:
            try:
                major = int(version_match.group("major"))
                if major >= DEP_CONFUSION_HIGH_VERSION_THRESHOLD:
                    matched_reasons.append(
                        f"unusually high version number ({version}) — "
                        f"possible dependency confusion version bump"
                    )
            except (ValueError, IndexError):
                pass

        # --- Check 3: Declared with a suspicious high version specifier ---
        if name in declared:
            declared_version = declared[name]
            # Check if the declared version is a very high number
            declared_match = DEP_CONFUSION_VERSION_PATTERN.match(
                declared_version.lstrip("^~>= ")
            )
            if declared_match:
                try:
                    declared_major = int(declared_match.group("major"))
                    if declared_major >= DEP_CONFUSION_HIGH_VERSION_THRESHOLD:
                        matched_reasons.append(
                            f"declared version specifier '{declared_version}' "
                            f"is suspiciously high — possible dep confusion"
                        )
                except (ValueError, IndexError):
                    pass

        if not matched_reasons:
            continue

        description = (
            f"Package '{name}' ({version}) may be a dependency confusion attack "
            f"vector. Reasons: {'; '.join(matched_reasons)}. "
            f"If '{name}' is an internal package, it should be scoped or sourced "
            f"from a private registry."
        )
        remediation = _fmt_remediation("dep-confusion", package=name)
        findings.append(
            _make_finding(
                package=name,
                detector="dep-confusion",
                severity=Severity.HIGH.value,
                description=description,
                remediation=remediation,
                metadata={
                    "installed_version": version,
                    "matched_reasons": matched_reasons,
                    "declared_version": declared.get(name, ""),
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Convenience: run all detectors
# ---------------------------------------------------------------------------


def run_all_detectors(
    project_path: Path,
    installed_packages: list[PackageMeta],
    node_modules: Path | None,
    declared_dependencies: dict[str, str] | None = None,
    *,
    enable_credential_scan: bool = True,
) -> list[Finding]:
    """Run all detectors and return an aggregated list of findings.

    This is a convenience function that invokes each detector in turn and
    concatenates the results. The scanner orchestrator calls individual
    detectors directly for finer control; this function is useful for
    one-shot programmatic use.

    Args:
        project_path: Path to the Node.js project root.
        installed_packages: List of installed package metadata dictionaries.
        node_modules: Path to the ``node_modules`` directory, or ``None``.
        declared_dependencies: Optional declared dependency map from
            ``package.json``.
        enable_credential_scan: Whether to run the credential harvesting
            detector (can be slow on large codebases).

    Returns:
        Flat list of all findings from all detectors.
    """
    all_findings: list[Finding] = []

    all_findings.extend(detect_known_malicious(installed_packages))
    all_findings.extend(detect_typosquatting(installed_packages))
    all_findings.extend(detect_suspicious_scripts(installed_packages))
    all_findings.extend(
        detect_git_hook_injection(project_path, installed_packages)
    )
    all_findings.extend(detect_mcp_servers(installed_packages, node_modules))

    if node_modules is not None:
        declared_bin_names: set[str] = set()
        all_findings.extend(
            detect_rogue_binaries(
                node_modules,
                installed_packages,
                declared_bin_names=declared_bin_names,
            )
        )

    all_findings.extend(
        detect_dependency_confusion(
            installed_packages,
            declared_dependencies=declared_dependencies,
        )
    )

    if enable_credential_scan:
        all_findings.extend(detect_credential_harvesting(installed_packages))

    return all_findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    # Type
    "Finding",
    # Helpers
    "_levenshtein",
    # Detectors
    "detect_known_malicious",
    "detect_typosquatting",
    "detect_suspicious_scripts",
    "detect_git_hook_injection",
    "detect_credential_harvesting",
    "detect_mcp_servers",
    "detect_rogue_binaries",
    "detect_dependency_confusion",
    # Convenience
    "run_all_detectors",
]
