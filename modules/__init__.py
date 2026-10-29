"""OpenGuard - Project Security and Deployment Readiness Platform.

Modules:
    archive_handler: Safe ZIP extraction and path traversal prevention.
    project_profiler: Project metadata, language, and manifest discovery.
    secret_scanner: Pattern-based secret & credential detection with masking.
    security_scanner: Static code security and injection vulnerability checks.
    dependency_scanner: Dependency manifest parsing and CVE advisory evaluation.
    configuration_scanner: Docker, Compose, and environment file checks.
    risk_scorer: Deterministic readiness index calculation (0-100).
    report_generator: Structured JSON and self-contained HTML audit exports.
"""

__version__ = "1.0.0"
__product__ = "OpenGuard"
