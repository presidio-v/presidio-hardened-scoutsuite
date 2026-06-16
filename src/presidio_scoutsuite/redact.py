"""Detect and redact cloud credentials / secrets from ScoutSuite output.

ScoutSuite collects raw cloud configuration into its report (``*.js`` /
``*.json``) and emits diagnostic logs. Either can incidentally contain
credentials. This module provides deterministic, dependency-free scanning and
redaction, plus a fail-closed :func:`assert_clean` guard.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from .errors import RedactionError

#: Replacement written in place of a detected secret.
PLACEHOLDER = "[REDACTED]"

#: (name, compiled-pattern) pairs. Patterns are intentionally specific to keep
#: false positives low; entropy-based heuristics are deliberately avoided so the
#: result is reproducible and auditable.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AROA|AIDA)[0-9A-Z]{16}\b")),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    ("gcp_service_account_key", re.compile(r'"private_key"\s*:\s*"[^"]+"')),
    ("azure_account_key", re.compile(r"AccountKey=[A-Za-z0-9+/=]{16,}")),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*\S+")),
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{12,}")),
    ("authorization_header", re.compile(r'(?i)("?authorization"?\s*[:=]\s*)"[^"\n]+"')),
)


#: Type of an extra (name, compiled-pattern) redactor supplied by org config.
ExtraPatterns = Iterable[tuple[str, "re.Pattern[str]"]]


def _all_patterns(extra: ExtraPatterns | None) -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Built-in patterns plus any org-supplied extras (see compose.parse_redaction_patterns)."""

    return PATTERNS if not extra else (*PATTERNS, *extra)


def scan(text: str, *, extra: ExtraPatterns | None = None) -> list[str]:
    """Return the names of every secret pattern that matches ``text``.

    A name may appear more than once if it matches multiple times. ``extra``
    supplies additional org-defined (name, pattern) redactors.
    """

    found: list[str] = []
    for name, pattern in _all_patterns(extra):
        found.extend(name for _ in pattern.finditer(text))
    return found


def redact_text(text: str, *, extra: ExtraPatterns | None = None) -> tuple[str, list[str]]:
    """Redact secrets in ``text``.

    Returns ``(redacted_text, findings)`` where ``findings`` lists the pattern
    names that fired. For the ``authorization_header`` pattern the key/prefix is
    preserved and only the value replaced. ``extra`` adds org-defined redactors.
    """

    findings: list[str] = []
    result = text
    for name, pattern in _all_patterns(extra):
        if name == "authorization_header":

            def _repl(match: re.Match[str], _name: str = name) -> str:
                findings.append(_name)
                return f'{match.group(1)}"{PLACEHOLDER}"'

            result = pattern.sub(_repl, result)
        else:

            def _repl(match: re.Match[str], _name: str = name) -> str:  # noqa: F811
                findings.append(_name)
                return PLACEHOLDER

            result = pattern.sub(_repl, result)
    return result, findings


def assert_clean(text: str, *, where: str = "output", extra: ExtraPatterns | None = None) -> None:
    """Raise :class:`RedactionError` if any secret is present in ``text``.

    The error message names the patterns and location but never echoes the
    matched secret. ``extra`` adds org-defined redactors.
    """

    findings = scan(text, extra=extra)
    if findings:
        unique = ", ".join(sorted(set(findings)))
        raise RedactionError(f"secret(s) detected in {where}: {unique}")


def redact_file(path: str | Path, *, extra: ExtraPatterns | None = None) -> list[str]:
    """Redact a single file in place. Returns the findings (empty if clean).

    Binary/undecodable files are skipped (returns ``[]``). The file is only
    rewritten when something actually changed. ``extra`` adds org-defined redactors.
    """

    p = Path(path)
    try:
        original = p.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    cleaned, findings = redact_text(original, extra=extra)
    if cleaned != original:
        p.write_text(cleaned, encoding="utf-8")
    return findings


#: File suffixes worth scanning inside a report directory.
_SCANNABLE_SUFFIXES = frozenset({".js", ".json", ".html", ".htm", ".txt", ".log", ".csv"})


def redact_report_dir(
    report_dir: str | Path,
    *,
    suffixes: Iterable[str] = _SCANNABLE_SUFFIXES,
    extra: ExtraPatterns | None = None,
) -> dict[str, list[str]]:
    """Redact every scannable file under ``report_dir`` in place.

    Returns a mapping of relative file path -> findings, including only files
    where at least one secret was redacted. ``extra`` adds org-defined redactors.
    """

    root = Path(report_dir)
    wanted = {s.lower() for s in suffixes}
    results: dict[str, list[str]] = {}
    for file in sorted(root.rglob("*")):
        if file.is_file() and file.suffix.lower() in wanted:
            findings = redact_file(file, extra=extra)
            if findings:
                results[str(file.relative_to(root))] = findings
    return results
