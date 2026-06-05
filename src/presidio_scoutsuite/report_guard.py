"""Post-run integrity and sanitization checks on the generated report.

ScoutSuite renders a static HTML report (plus ``inc-*`` assets and the raw
``scoutsuite-results`` data). This guard:

* injects a strict Content-Security-Policy ``<meta>`` into each HTML file so the
  static viewer can't load remote/inline script if a finding string ever
  contained markup;
* scans the whole tree for leaked secrets (fail-closed option);
* records a SHA-256 manifest so a report can be integrity-checked later.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import redact
from .errors import ReportGuardError

#: Locked-down CSP for the static report viewer. ``'unsafe-inline'`` is allowed
#: for styles only (ScoutSuite ships inline styles); scripts must come from the
#: report's own files, and no network/object/frame access is permitted.
CSP_VALUE = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'none'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'"
)

_CSP_META = f'<meta http-equiv="Content-Security-Policy" content="{CSP_VALUE}">'
_HEAD_RE = re.compile(r"<head[^>]*>", re.IGNORECASE)
_HAS_CSP_RE = re.compile(r"http-equiv=[\"']Content-Security-Policy", re.IGNORECASE)


@dataclass
class GuardResult:
    """Summary of a :func:`guard_report` run."""

    report_dir: Path
    html_hardened: list[str] = field(default_factory=list)
    secret_findings: dict[str, list[str]] = field(default_factory=dict)
    manifest: dict[str, str] = field(default_factory=dict)

    @property
    def has_secrets(self) -> bool:
        return bool(self.secret_findings)


def inject_csp(html: str) -> tuple[str, bool]:
    """Insert the CSP ``<meta>`` right after ``<head>``.

    Returns ``(html, changed)``. No-op (``changed=False``) if a CSP meta is
    already present or there is no ``<head>`` to anchor to.
    """

    if _HAS_CSP_RE.search(html):
        return html, False
    match = _HEAD_RE.search(html)
    if not match:
        return html, False
    insert_at = match.end()
    return html[:insert_at] + _CSP_META + html[insert_at:], True


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def guard_report(
    report_dir: str | Path,
    *,
    fail_on_secret: bool = False,
) -> GuardResult:
    """Harden and verify a finished report directory.

    Injects CSP into HTML files, scans the tree for secrets, and builds a
    SHA-256 manifest (computed *after* hardening so the hashes match what a user
    will open). When ``fail_on_secret`` is set, any surviving secret raises
    :class:`ReportGuardError`.
    """

    root = Path(report_dir)
    if not root.is_dir():
        raise ReportGuardError(f"report dir {root} does not exist")

    result = GuardResult(report_dir=root)

    for html_file in sorted([*root.rglob("*.html"), *root.rglob("*.htm")]):
        text = html_file.read_text(encoding="utf-8", errors="replace")
        hardened, changed = inject_csp(text)
        if changed:
            html_file.write_text(hardened, encoding="utf-8")
            result.html_hardened.append(str(html_file.relative_to(root)))

    for file in sorted(root.rglob("*")):
        if not file.is_file():
            continue
        try:
            findings = redact.scan(file.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, OSError):
            findings = []
        if findings:
            result.secret_findings[str(file.relative_to(root))] = findings
        result.manifest[str(file.relative_to(root))] = _sha256(file)

    if fail_on_secret and result.has_secrets:
        files = ", ".join(sorted(result.secret_findings))
        raise ReportGuardError(f"secrets present in report after redaction: {files}")

    return result
