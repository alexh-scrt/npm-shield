"""Test suite for npm_shield.

This package contains unit tests, integration tests, and fixture data used
to validate npm_shield's detection, scanning, and reporting functionality.

Test modules:
    - ``test_detectors``: Unit tests for each individual detector function.
    - ``test_scanner``: Integration tests for the scanner orchestrator using
      a synthetic fake node_modules tree.
    - ``test_reporter``: Tests for report rendering and JSON export correctness.

Fixtures:
    - ``fixtures/fake_project/``: A sample Node.js project containing both
      benign and intentionally suspicious packages for test scenarios.
"""
