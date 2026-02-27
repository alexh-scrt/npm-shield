"""npm_shield — CLI security tool for scanning Node.js dependencies for supply chain attacks.

This package exposes the version string and top-level public API for programmatic use.
The primary interface is the CLI entry point: ``npm-shield scan <path>``.

Example programmatic usage::

    from npm_shield import __version__, run_scan
    findings = run_scan("/path/to/node-project")
    for finding in findings:
        print(finding)
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "npm_shield contributors"
__license__ = "MIT"

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "run_scan",
]


def run_scan(project_path: str, *, enable_osv: bool = False) -> list[dict]:
    """Run a full security scan on a Node.js project directory.

    This is the primary programmatic entry point for npm_shield. It orchestrates
    all detection modules and returns a list of finding dictionaries.

    Args:
        project_path: Absolute or relative path to the root of the Node.js project
            (the directory containing ``package.json``).
        enable_osv: When ``True``, cross-references findings against the OSV.dev
            vulnerability database (requires network access).

    Returns:
        A list of finding dictionaries. Each dictionary contains at minimum:
        - ``package`` (str): The package name associated with the finding.
        - ``detector`` (str): The name of the detector that raised the finding.
        - ``severity`` (str): One of ``info``, ``low``, ``medium``, ``high``, ``critical``.
        - ``description`` (str): Human-readable description of the finding.
        - ``remediation`` (str): Suggested remediation steps.

    Raises:
        FileNotFoundError: If ``project_path`` does not exist or contains no
            ``package.json``.
        ValueError: If ``project_path`` is not a directory.
    """
    # Import here to avoid circular imports and allow the package to be imported
    # even before all sub-modules are fully initialised during early phases.
    from pathlib import Path

    path = Path(project_path)
    if not path.exists():
        raise FileNotFoundError(f"Project path does not exist: {project_path}")
    if not path.is_dir():
        raise ValueError(f"Project path must be a directory, got: {project_path}")

    # Defer heavy imports so the package stays importable during scaffolding.
    try:
        from npm_shield.scanner import Scanner

        scanner = Scanner(project_path=path, enable_osv=enable_osv)
        return scanner.run()
    except ImportError:
        # Scanner not yet implemented (earlier phases); return empty list.
        return []
