"""Static pattern database for npm_shield.

This module contains the curated, static knowledge base that all detector
functions reference. It includes:

- Known malicious and historically compromised package names with version pinning.
- Popular legitimate packages used as typosquatting targets (with edit-distance
  thresholds).
- Regex signatures for credential harvesting, environment variable exfiltration,
  and network beaconing patterns found in malicious packages.
- Suspicious lifecycle script patterns that indicate post-install payload delivery.
- MCP (Model Context Protocol) server indicators and rogue binary heuristics.
- Git hook injection markers.
- Severity level definitions and scoring constants.

All collections are intentionally immutable (tuples / frozensets where practical)
so detectors cannot accidentally mutate shared state.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, NamedTuple

# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Ordered severity levels for findings.

    The string value is used directly in report output and JSON serialisation.
    Comparison via ``.value`` or the helper :func:`severity_rank` is recommended
    for ordering.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Numeric rank for each severity level (higher == more severe).
SEVERITY_RANK: dict[str, int] = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


def severity_rank(severity: str) -> int:
    """Return the numeric rank for a severity string.

    Args:
        severity: One of ``info``, ``low``, ``medium``, ``high``, ``critical``.

    Returns:
        Integer rank (0 = info … 4 = critical). Returns -1 for unknown values.
    """
    return SEVERITY_RANK.get(severity.lower(), -1)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KnownMaliciousPackage:
    """A package name (and optional version) known to be malicious.

    Attributes:
        name: The exact npm package name.
        versions: A tuple of known-bad version strings. Empty tuple means *all*
            versions of this package are considered malicious.
        severity: The default severity level for findings about this package.
        description: Human-readable description of the threat this package poses.
        reference: Optional URL to an advisory, blog post, or CVE.
    """

    name: str
    versions: tuple[str, ...] = field(default_factory=tuple)
    severity: str = Severity.CRITICAL.value
    description: str = ""
    reference: str = ""


@dataclass(frozen=True)
class TyposquatTarget:
    """A popular legitimate package that is commonly typosquatted.

    Attributes:
        name: The canonical, legitimate package name.
        weekly_downloads_approx: Approximate weekly download count (used to
            weight the risk score — higher download counts imply more valuable
            targets).
        max_edit_distance: Maximum Levenshtein edit distance at which a candidate
            package name should be flagged as a potential typosquat of this one.
    """

    name: str
    weekly_downloads_approx: int = 1_000_000
    max_edit_distance: int = 2


class RegexSignature(NamedTuple):
    """A compiled regex pattern paired with metadata for reporting.

    Attributes:
        pattern: Pre-compiled ``re.Pattern`` object.
        name: Short identifier for the signature (used in finding names).
        severity: Default severity when this signature fires.
        description: Human-readable description of what the pattern detects.
    """

    pattern: re.Pattern[str]
    name: str
    severity: str
    description: str


# ---------------------------------------------------------------------------
# Known malicious packages
# ---------------------------------------------------------------------------

#: Packages that are known to be malicious or have had malicious versions
#: published to the npm registry. Sources include npm security advisories,
#: Snyk vulnerability database, GitHub Security Lab reports, and community
#: disclosures.
KNOWN_MALICIOUS_PACKAGES: tuple[KnownMaliciousPackage, ...] = (
    # event-stream / flatmap-stream supply chain attack (2018)
    KnownMaliciousPackage(
        name="event-stream",
        versions=("3.3.6",),
        severity=Severity.CRITICAL.value,
        description=(
            "Version 3.3.6 was trojaned via the flatmap-stream dependency to steal "
            "Bitcoin wallets from Copay application users."
        ),
        reference="https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
    ),
    KnownMaliciousPackage(
        name="flatmap-stream",
        versions=("0.1.1",),
        severity=Severity.CRITICAL.value,
        description=(
            "Malicious dependency injected into event-stream@3.3.6 that contained "
            "an encrypted payload to steal Bitcoin wallet credentials."
        ),
        reference="https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
    ),
    # crossenv — typosquat of cross-env
    KnownMaliciousPackage(
        name="crossenv",
        versions=(),
        severity=Severity.CRITICAL.value,
        description=(
            "Malicious typosquat of the legitimate 'cross-env' package. "
            "Harvests environment variables and sends them to a remote server."
        ),
        reference="https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry",
    ),
    # ua-parser-js supply chain attack (2021)
    KnownMaliciousPackage(
        name="ua-parser-js",
        versions=("0.7.29", "0.8.0", "1.0.0"),
        severity=Severity.CRITICAL.value,
        description=(
            "Three versions were published by an attacker after the maintainer's "
            "npm account was compromised. The trojaned versions install a crypto-miner "
            "and credential stealer."
        ),
        reference="https://github.com/advisories/GHSA-pjwm-rvh2-c87w",
    ),
    # coa and rc hijacking (2021)
    KnownMaliciousPackage(
        name="coa",
        versions=("2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.0.1", "3.1.3"),
        severity=Severity.CRITICAL.value,
        description=(
            "Account compromise led to malicious versions being published that "
            "install a password-stealing trojan."
        ),
        reference="https://github.com/advisories/GHSA-73qr-pfmq-6rp8",
    ),
    KnownMaliciousPackage(
        name="rc",
        versions=("1.2.9", "1.3.9", "2.3.9"),
        severity=Severity.CRITICAL.value,
        description=(
            "Account compromise. Malicious versions install a password-stealing "
            "trojan similar to the coa attack."
        ),
        reference="https://github.com/advisories/GHSA-g2q5-5433-rhrf",
    ),
    # node-ipc protestware (2022)
    KnownMaliciousPackage(
        name="node-ipc",
        versions=("10.1.1", "10.1.2"),
        severity=Severity.CRITICAL.value,
        description=(
            "Maintainer intentionally introduced code that overwrites files on disk "
            "for users in certain geographic regions (protestware / sabotage)."
        ),
        reference="https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/",
    ),
    # peacenotwar (embedded in node-ipc)
    KnownMaliciousPackage(
        name="peacenotwar",
        versions=(),
        severity=Severity.HIGH.value,
        description=(
            "Protestware package that writes messages and files to the desktop "
            "of users in targeted geographic regions."
        ),
        reference="https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/",
    ),
    # colors / faker sabotage (2022)
    KnownMaliciousPackage(
        name="colors",
        versions=("1.4.44-liberty-2", "1.4.1", "1.4.2"),
        severity=Severity.HIGH.value,
        description=(
            "Maintainer published sabotaged versions that print an infinite loop of "
            "garbage text, causing downstream application denial-of-service."
        ),
        reference="https://snyk.io/blog/open-source-npm-packages-colors-faker/",
    ),
    KnownMaliciousPackage(
        name="faker",
        versions=("6.6.6", "7.5.0"),
        severity=Severity.HIGH.value,
        description=(
            "Maintainer published a sabotaged version (6.6.6) that broke downstream "
            "builds intentionally."
        ),
        reference="https://snyk.io/blog/open-source-npm-packages-colors-faker/",
    ),
    # eslint-scope account hijack (2018)
    KnownMaliciousPackage(
        name="eslint-scope",
        versions=("3.7.2",),
        severity=Severity.CRITICAL.value,
        description=(
            "A compromised maintainer account published a version containing code "
            "that reads and exfiltrates the victim's npm authentication token."
        ),
        reference="https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/",
    ),
    # bootstrap-sass account hijack (2019)
    KnownMaliciousPackage(
        name="bootstrap-sass",
        versions=("3.2.0.3",),
        severity=Severity.CRITICAL.value,
        description=(
            "Backdoored version published via a compromised RubyGems account. "
            "Contains a remote code execution backdoor."
        ),
        reference="https://snyk.io/vuln/SNYK-RUBY-BOOTSTRAPSASS-174827",
    ),
    # left-pad (historical — not malicious but a notable supply chain risk example)
    # Skipped as it was not malicious.
    # azure-cli credential harvester
    KnownMaliciousPackage(
        name="azure-arm-compute",
        versions=("99.0.0",),
        severity=Severity.CRITICAL.value,
        description=(
            "A version number far beyond the legitimate range was observed in "
            "the wild as a dependency confusion attack vector."
        ),
        reference="https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
    ),
    # Dependency confusion PoC packages
    KnownMaliciousPackage(
        name="internal-placeholder",
        versions=(),
        severity=Severity.HIGH.value,
        description=(
            "Generic placeholder name used in dependency confusion attack "
            "demonstrations."
        ),
        reference="https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
    ),
    # twilio-npm (typosquat)
    KnownMaliciousPackage(
        name="twilio-npm",
        versions=(),
        severity=Severity.CRITICAL.value,
        description=(
            "Malicious package impersonating the Twilio SDK. Opens a reverse bash "
            "shell to a remote server."
        ),
        reference="https://www.npmjs.com/advisories/1636",
    ),
    # discord malware packages
    KnownMaliciousPackage(
        name="discord-lofy",
        versions=(),
        severity=Severity.CRITICAL.value,
        description=(
            "Malicious package targeting Discord users; contains a token grabber "
            "and keylogger."
        ),
        reference="https://blog.sonatype.com/discord-lofy-discordnitro-free-noblox.js-npm-malware",
    ),
    KnownMaliciousPackage(
        name="discordnitro-free",
        versions=(),
        severity=Severity.CRITICAL.value,
        description=(
            "Malicious package targeting Discord users; steals tokens and "
            "sensitive browser data."
        ),
        reference="https://blog.sonatype.com/discord-lofy-discordnitro-free-noblox.js-npm-malware",
    ),
    KnownMaliciousPackage(
        name="free-discord-nitro",
        versions=(),
        severity=Severity.CRITICAL.value,
        description=(
            "Malicious package masquerading as a Discord Nitro generator; "
            "steals credentials and tokens."
        ),
        reference="https://blog.sonatype.com/discord-lofy-discordnitro-free-noblox.js-npm-malware",
    ),
    # noblox.js-proxied
    KnownMaliciousPackage(
        name="noblox.js-proxied",
        versions=(),
        severity=Severity.CRITICAL.value,
        description=(
            "Typosquat of noblox.js (Roblox API wrapper) with an embedded "
            "credential stealer and token logger."
        ),
        reference="https://blog.sonatype.com/discord-lofy-discordnitro-free-noblox.js-npm-malware",
    ),
    # Sandworm-style packages
    KnownMaliciousPackage(
        name="rpc-websockets",
        versions=("7.5.1",),
        severity=Severity.HIGH.value,
        description=(
            "Version 7.5.1 was found to contain a dependency on the malicious "
            "package 'bignum' referencing an attacker-controlled fork."
        ),
        reference="https://github.com/elpheria/rpc-websockets/issues/226",
    ),
    # Generic known-bad names
    KnownMaliciousPackage(
        name="electron-native-notify",
        versions=(),
        severity=Severity.HIGH.value,
        description=(
            "Known malicious package that exfiltrates environment variables to a "
            "remote server on install."
        ),
        reference="https://blog.reversinglabs.com/blog/mining-for-malicious-ruby-gems",
    ),
    KnownMaliciousPackage(
        name="web3-utils-decrypt",
        versions=(),
        severity=Severity.CRITICAL.value,
        description=(
            "Fake web3 utility package that intercepts and logs wallet private keys."
        ),
        reference="",
    ),
    KnownMaliciousPackage(
        name="jest-next-dynamic",
        versions=(),
        severity=Severity.HIGH.value,
        description=(
            "Malicious package masquerading as a Jest plugin; contains an "
            "exfiltration payload targeting CI environment variables."
        ),
        reference="https://blog.sonatype.com/npm-package-jest-next-dynamic-found-containing-malicious-code",
    ),
    KnownMaliciousPackage(
        name="data-faker",
        versions=(),
        severity=Severity.HIGH.value,
        description=(
            "Typosquat of the 'faker' package containing code that exfiltrates "
            "environment variables."
        ),
        reference="",
    ),
    KnownMaliciousPackage(
        name="dotenv-defaults",
        versions=("2.0.2",),
        severity=Severity.CRITICAL.value,
        description=(
            "Version 2.0.2 contained a credential harvesting payload that sends "
            ".env file contents to an external server."
        ),
        reference="https://snyk.io/vuln/SNYK-JS-DOTENVDEFAULTS-1048935",
    ),
)

#: Fast lookup set of known malicious package names.
KNOWN_MALICIOUS_NAMES: FrozenSet[str] = frozenset(
    pkg.name for pkg in KNOWN_MALICIOUS_PACKAGES
)

#: Mapping from package name to its KnownMaliciousPackage record(s).
KNOWN_MALICIOUS_BY_NAME: dict[str, list[KnownMaliciousPackage]] = {}
for _pkg in KNOWN_MALICIOUS_PACKAGES:
    KNOWN_MALICIOUS_BY_NAME.setdefault(_pkg.name, []).append(_pkg)


# ---------------------------------------------------------------------------
# Typosquatting targets
# ---------------------------------------------------------------------------

#: Popular npm packages that are frequently typosquatted. The detector uses
#: Levenshtein edit distance to find lookalike names within ``max_edit_distance``.
TYPOSQUAT_TARGETS: tuple[TyposquatTarget, ...] = (
    TyposquatTarget("lodash", weekly_downloads_approx=50_000_000, max_edit_distance=2),
    TyposquatTarget("express", weekly_downloads_approx=30_000_000, max_edit_distance=2),
    TyposquatTarget("react", weekly_downloads_approx=25_000_000, max_edit_distance=2),
    TyposquatTarget("react-dom", weekly_downloads_approx=22_000_000, max_edit_distance=2),
    TyposquatTarget("axios", weekly_downloads_approx=20_000_000, max_edit_distance=2),
    TyposquatTarget("typescript", weekly_downloads_approx=45_000_000, max_edit_distance=2),
    TyposquatTarget("webpack", weekly_downloads_approx=25_000_000, max_edit_distance=2),
    TyposquatTarget("babel-core", weekly_downloads_approx=15_000_000, max_edit_distance=2),
    TyposquatTarget("moment", weekly_downloads_approx=18_000_000, max_edit_distance=2),
    TyposquatTarget("chalk", weekly_downloads_approx=30_000_000, max_edit_distance=2),
    TyposquatTarget("commander", weekly_downloads_approx=20_000_000, max_edit_distance=2),
    TyposquatTarget("dotenv", weekly_downloads_approx=22_000_000, max_edit_distance=2),
    TyposquatTarget("eslint", weekly_downloads_approx=28_000_000, max_edit_distance=2),
    TyposquatTarget("prettier", weekly_downloads_approx=20_000_000, max_edit_distance=2),
    TyposquatTarget("jest", weekly_downloads_approx=20_000_000, max_edit_distance=2),
    TyposquatTarget("mocha", weekly_downloads_approx=8_000_000, max_edit_distance=2),
    TyposquatTarget("nodemon", weekly_downloads_approx=5_000_000, max_edit_distance=2),
    TyposquatTarget("cross-env", weekly_downloads_approx=12_000_000, max_edit_distance=2),
    TyposquatTarget("uuid", weekly_downloads_approx=40_000_000, max_edit_distance=1),
    TyposquatTarget("underscore", weekly_downloads_approx=10_000_000, max_edit_distance=2),
    TyposquatTarget("async", weekly_downloads_approx=15_000_000, max_edit_distance=2),
    TyposquatTarget("bluebird", weekly_downloads_approx=8_000_000, max_edit_distance=2),
    TyposquatTarget("classnames", weekly_downloads_approx=15_000_000, max_edit_distance=2),
    TyposquatTarget("prop-types", weekly_downloads_approx=20_000_000, max_edit_distance=2),
    TyposquatTarget("redux", weekly_downloads_approx=12_000_000, max_edit_distance=2),
    TyposquatTarget("vue", weekly_downloads_approx=8_000_000, max_edit_distance=1),
    TyposquatTarget("angular", weekly_downloads_approx=5_000_000, max_edit_distance=2),
    TyposquatTarget("next", weekly_downloads_approx=6_000_000, max_edit_distance=1),
    TyposquatTarget("gatsby", weekly_downloads_approx=2_000_000, max_edit_distance=2),
    TyposquatTarget("nuxt", weekly_downloads_approx=2_000_000, max_edit_distance=1),
    TyposquatTarget("socket.io", weekly_downloads_approx=5_000_000, max_edit_distance=2),
    TyposquatTarget("mongoose", weekly_downloads_approx=4_000_000, max_edit_distance=2),
    TyposquatTarget("sequelize", weekly_downloads_approx=3_000_000, max_edit_distance=2),
    TyposquatTarget("knex", weekly_downloads_approx=2_000_000, max_edit_distance=2),
    TyposquatTarget("pm2", weekly_downloads_approx=3_000_000, max_edit_distance=1),
    TyposquatTarget("passport", weekly_downloads_approx=2_500_000, max_edit_distance=2),
    TyposquatTarget("jsonwebtoken", weekly_downloads_approx=8_000_000, max_edit_distance=2),
    TyposquatTarget("bcrypt", weekly_downloads_approx=3_000_000, max_edit_distance=2),
    TyposquatTarget("sharp", weekly_downloads_approx=4_000_000, max_edit_distance=2),
    TyposquatTarget("multer", weekly_downloads_approx=2_000_000, max_edit_distance=2),
    TyposquatTarget("cors", weekly_downloads_approx=10_000_000, max_edit_distance=1),
    TyposquatTarget("helmet", weekly_downloads_approx=2_500_000, max_edit_distance=2),
    TyposquatTarget("body-parser", weekly_downloads_approx=15_000_000, max_edit_distance=2),
    TyposquatTarget("morgan", weekly_downloads_approx=5_000_000, max_edit_distance=2),
    TyposquatTarget("compression", weekly_downloads_approx=5_000_000, max_edit_distance=2),
    TyposquatTarget("cookie-parser", weekly_downloads_approx=5_000_000, max_edit_distance=2),
    TyposquatTarget("debug", weekly_downloads_approx=30_000_000, max_edit_distance=2),
    TyposquatTarget("semver", weekly_downloads_approx=30_000_000, max_edit_distance=2),
    TyposquatTarget("minimist", weekly_downloads_approx=20_000_000, max_edit_distance=2),
    TyposquatTarget("yargs", weekly_downloads_approx=20_000_000, max_edit_distance=2),
    TyposquatTarget("inquirer", weekly_downloads_approx=8_000_000, max_edit_distance=2),
    TyposquatTarget("glob", weekly_downloads_approx=25_000_000, max_edit_distance=2),
    TyposquatTarget("rimraf", weekly_downloads_approx=18_000_000, max_edit_distance=2),
    TyposquatTarget("mkdirp", weekly_downloads_approx=12_000_000, max_edit_distance=2),
    TyposquatTarget("fs-extra", weekly_downloads_approx=15_000_000, max_edit_distance=2),
    TyposquatTarget("chokidar", weekly_downloads_approx=15_000_000, max_edit_distance=2),
    TyposquatTarget("tar", weekly_downloads_approx=20_000_000, max_edit_distance=1),
    TyposquatTarget("node-fetch", weekly_downloads_approx=20_000_000, max_edit_distance=2),
    TyposquatTarget("ws", weekly_downloads_approx=25_000_000, max_edit_distance=1),
    TyposquatTarget("mime", weekly_downloads_approx=18_000_000, max_edit_distance=1),
    TyposquatTarget("qs", weekly_downloads_approx=25_000_000, max_edit_distance=1),
    TyposquatTarget("form-data", weekly_downloads_approx=20_000_000, max_edit_distance=2),
    TyposquatTarget("twilio", weekly_downloads_approx=1_000_000, max_edit_distance=2),
    TyposquatTarget("aws-sdk", weekly_downloads_approx=5_000_000, max_edit_distance=2),
    TyposquatTarget("firebase", weekly_downloads_approx=3_000_000, max_edit_distance=2),
    TyposquatTarget("stripe", weekly_downloads_approx=1_500_000, max_edit_distance=2),
    TyposquatTarget("puppeteer", weekly_downloads_approx=3_000_000, max_edit_distance=2),
    TyposquatTarget("playwright", weekly_downloads_approx=2_500_000, max_edit_distance=2),
    TyposquatTarget("cypress", weekly_downloads_approx=3_000_000, max_edit_distance=2),
    TyposquatTarget("vite", weekly_downloads_approx=8_000_000, max_edit_distance=2),
    TyposquatTarget("rollup", weekly_downloads_approx=5_000_000, max_edit_distance=2),
    TyposquatTarget("esbuild", weekly_downloads_approx=10_000_000, max_edit_distance=2),
    TyposquatTarget("turbo", weekly_downloads_approx=2_000_000, max_edit_distance=2),
    TyposquatTarget("nx", weekly_downloads_approx=2_000_000, max_edit_distance=1),
    TyposquatTarget("lerna", weekly_downloads_approx=1_000_000, max_edit_distance=2),
)

#: Set of all legitimate target names for fast membership testing.
LEGITIMATE_PACKAGE_NAMES: FrozenSet[str] = frozenset(
    t.name for t in TYPOSQUAT_TARGETS
)


# ---------------------------------------------------------------------------
# Credential and secret harvesting regex signatures
# ---------------------------------------------------------------------------

def _c(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    """Compile a regex pattern, raising ValueError with context on failure."""
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise ValueError(f"Invalid regex pattern '{pattern}': {exc}") from exc


#: Regex signatures that, when found in JavaScript/TypeScript source files,
#: indicate credential harvesting or data exfiltration behaviour.
CREDENTIAL_HARVESTING_SIGNATURES: tuple[RegexSignature, ...] = (
    RegexSignature(
        pattern=_c(r"process\.env\b.*(?:curl|fetch|http|request|axios|got|needle|superagent)"),
        name="env-var-exfiltration-network",
        severity=Severity.CRITICAL.value,
        description=(
            "Environment variables are passed directly to a network call, "
            "suggesting credential exfiltration."
        ),
    ),
    RegexSignature(
        pattern=_c(
            r"(?:require|import)\s*\(?['\"](?:http|https|net|tls)['\"]\)?.*"
            r"process\.env",
            re.IGNORECASE | re.DOTALL,
        ),
        name="env-var-network-import",
        severity=Severity.HIGH.value,
        description=(
            "File imports a network module and references process.env, which "
            "may indicate environment variable exfiltration."
        ),
    ),
    RegexSignature(
        pattern=_c(
            r"(?:os\.homedir|path\.join\s*\([^)]*home)|__dirname).*\.(?:npmrc|netrc|aws|ssh)"
        ),
        name="credential-file-access",
        severity=Severity.CRITICAL.value,
        description=(
            "Code accesses known credential files such as .npmrc, .netrc, "
            ".aws/credentials, or .ssh/id_rsa."
        ),
    ),
    RegexSignature(
        pattern=_c(
            r"(?:fs\.read(?:File|FileSync)?|fs\.open)\s*\([^)]*"
            r"\.(?:npmrc|netrc|aws/credentials|ssh/id_rsa|ssh/id_ed25519|pgpass|gitconfig)"
        ),
        name="credential-file-read",
        severity=Severity.CRITICAL.value,
        description=(
            "Direct filesystem read of a known sensitive credential file."
        ),
    ),
    RegexSignature(
        pattern=_c(
            r"(?:btoa|Buffer\.from|base64).*(?:token|password|passwd|secret|api_key|apikey|auth)",
        ),
        name="credential-base64-encode",
        severity=Severity.HIGH.value,
        description=(
            "Credential or secret values are being base64-encoded, which is a "
            "common step before exfiltration."
        ),
    ),
    RegexSignature(
        pattern=_c(r"eval\s*\(\s*(?:Buffer\.from|atob|unescape)\s*\("),
        name="eval-obfuscated-payload",
        severity=Severity.CRITICAL.value,
        description=(
            "eval() is called on a decoded/unescaped value — a common obfuscation "
            "technique used to hide malicious payloads."
        ),
    ),
    RegexSignature(
        pattern=_c(
            r"new\s+Function\s*\(.*(?:process|require|global|Buffer)"
        ),
        name="dynamic-function-construction",
        severity=Severity.HIGH.value,
        description=(
            "new Function() is used with references to Node.js globals, which may "
            "indicate a dynamic payload loader."
        ),
    ),
    RegexSignature(
        pattern=_c(
            r"child_process.*(?:exec|spawn|execFile|fork)\s*\(.*"
            r"(?:curl|wget|bash|sh|powershell|cmd\.exe|nc\b|ncat|netcat)"
        ),
        name="reverse-shell-command",
        severity=Severity.CRITICAL.value,
        description=(
            "child_process execution of common reverse shell tools detected."
        ),
    ),
    RegexSignature(
        pattern=_c(
            r"(?:http|https)\.(?:get|request|post)\s*\(['\"]https?://"
            r"(?!(?:registry\.npmjs\.org|registry\.yarnpkg\.com|nodejs\.org))"
        ),
        name="unexpected-network-request",
        severity=Severity.MEDIUM.value,
        description=(
            "An outbound HTTP/HTTPS request to a non-standard host is made from "
            "package code; may indicate beaconing or data exfiltration."
        ),
    ),
    RegexSignature(
        pattern=_c(
            r"(?:HOME|USERPROFILE|APPDATA|AWS_|GITHUB_TOKEN|NPM_TOKEN|CI_|GITLAB_)"
            r".*(?:fetch|request|post|put|send)",
        ),
        name="ci-secret-exfiltration",
        severity=Severity.CRITICAL.value,
        description=(
            "CI/CD environment variable names appear alongside network send calls, "
            "indicating potential secret exfiltration from CI environments."
        ),
    ),
    RegexSignature(
        pattern=_c(r"dns\.resolve\s*\(.*(?:process\.env|Buffer\.from|base64)"),
        name="dns-exfiltration",
        severity=Severity.CRITICAL.value,
        description=(
            "DNS lookups constructed from environment variables or encoded data "
            "are a known covert exfiltration channel."
        ),
    ),
    RegexSignature(
        pattern=_c(
            r"(?:setInterval|setTimeout)\s*\(\s*function.*"
            r"(?:fetch|http|request|exec|spawn)",
            re.DOTALL,
        ),
        name="scheduled-beacon",
        severity=Severity.HIGH.value,
        description=(
            "A scheduled timer callback containing network or process execution "
            "calls may indicate periodic beaconing."
        ),
    ),
)


# ---------------------------------------------------------------------------
# Suspicious lifecycle script patterns
# ---------------------------------------------------------------------------

#: Regex patterns matched against npm lifecycle script values (install,
#: postinstall, preinstall, prepare, etc.). A match indicates the script may
#: be executing a remote payload or performing suspicious system operations.
SUSPICIOUS_SCRIPT_PATTERNS: tuple[RegexSignature, ...] = (
    RegexSignature(
        pattern=_c(r"curl\s+.*\|\s*(?:bash|sh|node|python|perl|ruby)"),
        name="curl-pipe-shell",
        severity=Severity.CRITICAL.value,
        description=(
            "Lifecycle script pipes curl output directly into a shell interpreter, "
            "a classic remote code execution pattern."
        ),
    ),
    RegexSignature(
        pattern=_c(r"wget\s+.*\|\s*(?:bash|sh|node|python|perl|ruby)"),
        name="wget-pipe-shell",
        severity=Severity.CRITICAL.value,
        description=(
            "Lifecycle script pipes wget output directly into a shell interpreter."
        ),
    ),
    RegexSignature(
        pattern=_c(r"(?:curl|wget)\s+(?:-[a-zA-Z]*s[a-zA-Z]*\s+)?https?://"),
        name="remote-download-in-script",
        severity=Severity.HIGH.value,
        description=(
            "Lifecycle script downloads content from a remote URL."
        ),
    ),
    RegexSignature(
        pattern=_c(r"node\s+-e\s+['\"].*(?:require|http|process\.env|exec)"),
        name="node-inline-eval",
        severity=Severity.HIGH.value,
        description=(
            "Lifecycle script passes inline JavaScript to node -e, which may be "
            "used to obfuscate a payload."
        ),
    ),
    RegexSignature(
        pattern=_c(r"python(?:3)?\s+-c\s+['\"].*(?:import\s+os|subprocess|socket|urllib)"),
        name="python-inline-eval",
        severity=Severity.HIGH.value,
        description=(
            "Lifecycle script passes inline Python to the interpreter that imports "
            "OS or network modules."
        ),
    ),
    RegexSignature(
        pattern=_c(r"(?:cp|copy|mv|move)\s+.*\.git[\\/]hooks[\\/]"),
        name="git-hook-injection-via-script",
        severity=Severity.HIGH.value,
        description=(
            "Lifecycle script copies files into the .git/hooks directory, which is "
            "a known method for persisting malicious Git hooks."
        ),
    ),
    RegexSignature(
        pattern=_c(r"chmod\s+[+a-z0-9]*x\s+.*\.git[\\/]hooks[\\/]"),
        name="git-hook-chmod",
        severity=Severity.HIGH.value,
        description=(
            "Lifecycle script makes a file in .git/hooks executable."
        ),
    ),
    RegexSignature(
        pattern=_c(r"(?:base64\s+-d|atob|Buffer\.from.*base64).*\|\s*(?:bash|sh|node)"),
        name="base64-decode-pipe-shell",
        severity=Severity.CRITICAL.value,
        description=(
            "Lifecycle script decodes a base64 payload and pipes it to a shell "
            "— a common payload obfuscation technique."
        ),
    ),
    RegexSignature(
        pattern=_c(r"(?:rm|del|rmdir)\s+(?:-rf?\s+)?[\/\\.]?(?:\*|node_modules|package-lock)"),
        name="destructive-file-operation",
        severity=Severity.HIGH.value,
        description=(
            "Lifecycle script performs potentially destructive file system operations."
        ),
    ),
    RegexSignature(
        pattern=_c(
            r"(?:ssh|scp|sftp|rsync)\s+.*(?:@|known_hosts|authorized_keys|id_rsa)"
        ),
        name="ssh-in-lifecycle-script",
        severity=Severity.HIGH.value,
        description=(
            "Lifecycle script invokes SSH-related tools, which may indicate "
            "credential exfiltration or remote access setup."
        ),
    ),
    RegexSignature(
        pattern=_c(r"(?:require|import)\s*\(?['\"]child_process['"]\)?\s*.*exec"),
        name="child-process-exec-in-script",
        severity=Severity.MEDIUM.value,
        description=(
            "Lifecycle script string references child_process.exec, which may "
            "indicate command execution."
        ),
    ),
)


# ---------------------------------------------------------------------------
# MCP server and rogue binary indicators
# ---------------------------------------------------------------------------

#: Keywords in package names or binary names that suggest MCP (Model Context
#: Protocol) server functionality. MCP servers have elevated access to the host
#: environment and should be explicitly expected by the developer.
MCP_SERVER_NAME_KEYWORDS: tuple[str, ...] = (
    "mcp-server",
    "mcp_server",
    "mcpserver",
    "mcp-proxy",
    "mcp-bridge",
    "mcp-gateway",
    "model-context",
    "modelcontextprotocol",
    "@modelcontextprotocol",
)

#: Field names inside package.json that MCP servers commonly use to declare
#: their entry point or transport configuration.
MCP_PACKAGE_JSON_FIELDS: tuple[str, ...] = (
    "mcp",
    "mcpServer",
    "mcp-server",
    "modelContextProtocol",
)

#: Regex patterns applied to package.json content to detect MCP server declarations.
MCP_DECLARATION_PATTERNS: tuple[RegexSignature, ...] = (
    RegexSignature(
        pattern=_c(r'["\']mcp(?:Server|-server)?["\']\s*:\s*\{'),
        name="mcp-json-field",
        severity=Severity.MEDIUM.value,
        description=(
            "Package declares an 'mcp' or 'mcpServer' field in package.json, "
            "indicating it registers itself as an MCP server."
        ),
    ),
    RegexSignature(
        pattern=_c(r'["\']modelContextProtocol["\']\s*:\s*\{'),
        name="model-context-protocol-field",
        severity=Severity.MEDIUM.value,
        description=(
            "Package declares a 'modelContextProtocol' field in package.json."
        ),
    ),
    RegexSignature(
        pattern=_c(r"@modelcontextprotocol/sdk"),
        name="mcp-sdk-dependency",
        severity=Severity.LOW.value,
        description=(
            "Package depends on the official MCP SDK. This is expected for "
            "legitimate MCP server packages but warrants review if unexpected."
        ),
    ),
)

#: Known legitimate MCP server packages that should NOT be flagged as suspicious
#: (unless other indicators are present).
LEGITIMATE_MCP_PACKAGES: FrozenSet[str] = frozenset(
    [
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-gitlab",
        "@modelcontextprotocol/server-google-drive",
        "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/server-slack",
        "@modelcontextprotocol/server-memory",
        "@modelcontextprotocol/server-puppeteer",
        "@modelcontextprotocol/server-brave-search",
        "@modelcontextprotocol/server-google-maps",
        "@modelcontextprotocol/server-fetch",
        "@modelcontextprotocol/server-everything",
        "@modelcontextprotocol/server-sqlite",
        "@anthropic-ai/mcp",
    ]
)


# ---------------------------------------------------------------------------
# Git hook indicators
# ---------------------------------------------------------------------------

#: Standard Git hook filenames. Any file in .git/hooks NOT in this set (and
#: that is executable) may have been injected by a package postinstall script.
STANDARD_GIT_HOOKS: FrozenSet[str] = frozenset(
    [
        "applypatch-msg",
        "pre-applypatch",
        "post-applypatch",
        "pre-commit",
        "pre-merge-commit",
        "prepare-commit-msg",
        "commit-msg",
        "post-commit",
        "pre-rebase",
        "post-checkout",
        "post-merge",
        "pre-push",
        "pre-receive",
        "update",
        "proc-receive",
        "post-receive",
        "post-update",
        "reference-transaction",
        "push-to-checkout",
        "pre-auto-gc",
        "post-rewrite",
        "sendemail-validate",
        "fsmonitor-watchman",
        "p4-changelist",
        "p4-prepare-changelist",
        "p4-post-changelist",
        "p4-pre-submit",
        "post-index-change",
    ]
)

#: Sample/template hook file names created by git init (safe to ignore).
GIT_HOOK_SAMPLE_SUFFIXES: tuple[str, ...] = (".sample", ".bak", ".orig", ".disabled")

#: Regex patterns matched against Git hook file contents to identify injected
#: malicious code.
GIT_HOOK_MALICIOUS_PATTERNS: tuple[RegexSignature, ...] = (
    RegexSignature(
        pattern=_c(r"curl\s+.*\|\s*(?:bash|sh)"),
        name="git-hook-curl-pipe",
        severity=Severity.CRITICAL.value,
        description=(
            "Git hook pipes curl output to a shell — strong indicator of a "
            "persisted RCE backdoor."
        ),
    ),
    RegexSignature(
        pattern=_c(r"(?:nc|ncat|netcat)\s+[-\w]*\s+\d{2,5}"),
        name="git-hook-netcat",
        severity=Severity.CRITICAL.value,
        description=(
            "Git hook contains a netcat command, which may establish a reverse shell."
        ),
    ),
    RegexSignature(
        pattern=_c(r"(?:wget|curl)\s+.*https?://"),
        name="git-hook-remote-download",
        severity=Severity.HIGH.value,
        description=(
            "Git hook downloads content from a remote URL."
        ),
    ),
    RegexSignature(
        pattern=_c(r"(?:base64\s+-d|openssl\s+base64\s+-d).*\|\s*(?:bash|sh|python|perl)"),
        name="git-hook-base64-exec",
        severity=Severity.CRITICAL.value,
        description=(
            "Git hook decodes a base64 payload and pipes it to an interpreter."
        ),
    ),
    RegexSignature(
        pattern=_c(r"node\s+-e\s+['\"].*"),
        name="git-hook-node-inline",
        severity=Severity.HIGH.value,
        description=(
            "Git hook executes inline Node.js code, which may hide a payload."
        ),
    ),
    RegexSignature(
        pattern=_c(
            r"(?:HOME|AWS_|GITHUB_TOKEN|NPM_TOKEN|CI_|SSH_)\w*\s*="
        ),
        name="git-hook-env-manipulation",
        severity=Severity.HIGH.value,
        description=(
            "Git hook sets or reads sensitive environment variables."
        ),
    ),
)


# ---------------------------------------------------------------------------
# Dependency confusion indicators
# ---------------------------------------------------------------------------

#: Version number patterns that suggest a dependency confusion attack.
#: Legitimate internal packages are typically published at very low version
#: numbers; an unusually high version is a red flag.
DEP_CONFUSION_HIGH_VERSION_THRESHOLD: int = 9000

#: Regex to detect suspiciously high semver versions in package.json.
DEP_CONFUSION_VERSION_PATTERN: re.Pattern[str] = _c(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
)

#: Common internal package name prefixes. If a package matches one of these
#: prefixes AND is not scoped to a known registry, it may be a dependency
#: confusion target.
COMMON_INTERNAL_NAME_PREFIXES: tuple[str, ...] = (
    "internal-",
    "private-",
    "corp-",
    "company-",
    "local-",
    "my-company-",
    "mycompany-",
    "proprietary-",
)


# ---------------------------------------------------------------------------
# Remediation templates
# ---------------------------------------------------------------------------

#: Per-detector remediation guidance templates. These are used by the reporter
#: to attach actionable steps to each finding.
REMEDIATION_TEMPLATES: dict[str, str] = {
    "typosquatting": (
        "1. Verify the intended package name in your package.json.\n"
        "2. Remove the suspicious package: npm uninstall {package}\n"
        "3. Install the correct package: npm install {intended}\n"
        "4. Audit your package-lock.json for further anomalies.\n"
        "5. Check if any credentials were exposed to this package."
    ),
    "known-malicious": (
        "1. Immediately uninstall the flagged package: npm uninstall {package}\n"
        "2. Check your system for indicators of compromise (unexpected processes, "
        "network connections).\n"
        "3. Review the package's postinstall and preinstall scripts for executed payloads.\n"
        "4. Rotate all secrets and credentials accessible from the affected environment.\n"
        "5. Review: {reference}"
    ),
    "git-hook": (
        "1. Inspect the flagged hook file: cat .git/hooks/{hook}\n"
        "2. If malicious, remove or restore it: rm .git/hooks/{hook}\n"
        "3. Identify the package that injected the hook by reviewing postinstall scripts.\n"
        "4. Remove the offending package and rotate any credentials that may have been exposed."
    ),
    "credential-harvesting": (
        "1. Review the flagged source file for the specific pattern reported.\n"
        "2. Immediately rotate any credentials or secrets that may have been accessed.\n"
        "3. Check your CI/CD environment variables for unexpected access.\n"
        "4. Remove the offending package and audit its transitive dependencies."
    ),
    "mcp-server": (
        "1. Verify that this MCP server package was intentionally installed.\n"
        "2. Review the package's declared permissions and transport configuration.\n"
        "3. If unexpected, remove it: npm uninstall {package}\n"
        "4. Check whether the package accesses sensitive files or environment variables."
    ),
    "suspicious-script": (
        "1. Review the lifecycle script for the flagged package: "
        "cat node_modules/{package}/package.json\n"
        "2. If the script is malicious, immediately uninstall: npm uninstall {package}\n"
        "3. Rotate any secrets accessible from this environment.\n"
        "4. Report the package to the npm security team: https://www.npmjs.com/support"
    ),
    "rogue-binary": (
        "1. Identify which package registered the binary: "
        "ls -la node_modules/.bin/{binary}\n"
        "2. Review the binary's source and declared purpose.\n"
        "3. If unexpected, uninstall the owning package: npm uninstall {package}\n"
        "4. Check if the binary was added to PATH or called by any scripts."
    ),
    "dep-confusion": (
        "1. Verify whether {package} is an internal package that should not be "
        "on the public registry.\n"
        "2. Use a private registry or scoped packages (@yourorg/{package}) to "
        "prevent confusion attacks.\n"
        "3. Uninstall if sourced from public registry unexpectedly: "
        "npm uninstall {package}\n"
        "4. Configure .npmrc to enforce registry scoping for internal packages."
    ),
    "osv-vulnerability": (
        "1. Review the OSV advisory for {package}: {reference}\n"
        "2. Update to a patched version: npm update {package}\n"
        "3. If no patch is available, evaluate alternative packages or mitigations.\n"
        "4. Check your application code for exploitation of the vulnerable functionality."
    ),
}


# ---------------------------------------------------------------------------
# File extension sets for source code scanning
# ---------------------------------------------------------------------------

#: File extensions that should be scanned for credential harvesting patterns.
SCANNABLE_EXTENSIONS: FrozenSet[str] = frozenset(
    [
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".mts",
        ".cts",
        ".jsx",
        ".tsx",
        ".json",   # only specific files like package.json
    ]
)

#: Directories within node_modules packages that are most likely to contain
#: malicious code (installation scripts, CLI entry points).
HIGH_RISK_PACKAGE_DIRS: tuple[str, ...] = (
    "scripts",
    "bin",
    "lib",
    "dist",
    "src",
)

#: Maximum file size (bytes) to scan. Files larger than this are skipped to
#: avoid scanning minified bundles or large data files.
MAX_SCAN_FILE_SIZE_BYTES: int = 512 * 1024  # 512 KiB

#: Maximum number of lines to scan per file. This prevents excessive scanning
#: time on very large minified files.
MAX_SCAN_FILE_LINES: int = 5_000


# ---------------------------------------------------------------------------
# Public API surface
# ---------------------------------------------------------------------------

__all__ = [
    # Enums and helpers
    "Severity",
    "SEVERITY_RANK",
    "severity_rank",
    # Data structures
    "KnownMaliciousPackage",
    "TyposquatTarget",
    "RegexSignature",
    # Known malicious packages
    "KNOWN_MALICIOUS_PACKAGES",
    "KNOWN_MALICIOUS_NAMES",
    "KNOWN_MALICIOUS_BY_NAME",
    # Typosquatting
    "TYPOSQUAT_TARGETS",
    "LEGITIMATE_PACKAGE_NAMES",
    # Regex signatures
    "CREDENTIAL_HARVESTING_SIGNATURES",
    "SUSPICIOUS_SCRIPT_PATTERNS",
    # MCP indicators
    "MCP_SERVER_NAME_KEYWORDS",
    "MCP_PACKAGE_JSON_FIELDS",
    "MCP_DECLARATION_PATTERNS",
    "LEGITIMATE_MCP_PACKAGES",
    # Git hook indicators
    "STANDARD_GIT_HOOKS",
    "GIT_HOOK_SAMPLE_SUFFIXES",
    "GIT_HOOK_MALICIOUS_PATTERNS",
    # Dependency confusion
    "DEP_CONFUSION_HIGH_VERSION_THRESHOLD",
    "DEP_CONFUSION_VERSION_PATTERN",
    "COMMON_INTERNAL_NAME_PREFIXES",
    # Remediation
    "REMEDIATION_TEMPLATES",
    # File scanning config
    "SCANNABLE_EXTENSIONS",
    "HIGH_RISK_PACKAGE_DIRS",
    "MAX_SCAN_FILE_SIZE_BYTES",
    "MAX_SCAN_FILE_LINES",
]
