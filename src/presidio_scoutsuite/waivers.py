"""Suppress accepted findings via a checked-in, **expiring** waiver file.

Real audits always have a tail of findings an organisation has reviewed and
consciously accepted (a deliberately-public bucket, a break-glass role). Hiding
them by weakening the ruleset is dangerous; tracking them out-of-band rots. This
module lets you check in the exceptions as data — each with a **justification**,
an **owner**, and a mandatory **expiry** — so a waived finding is documented,
attributable, and automatically resurfaces when the waiver lapses.

A waiver matches a finding by rule (``<service>/<key>``) and, optionally, a
resource pattern (``fnmatch`` against the finding's flagged resources). With no
resource (or ``"*"``) it waives the whole finding; with a pattern it waives only
the matching resources, and the finding survives — with a reduced count — if any
flagged resource is left unwaived.

Fail-closed throughout:

* a missing/malformed waiver file, or one missing a required field, **errors**
  (it is never read as "waive nothing" or "waive everything");
* an **expired** waiver does *not* suppress — the finding comes back — and is
  surfaced so it gets renewed or removed, rather than quietly hiding risk.

Waiver files are JSON (stdlib-only; no YAML dependency). Pure, deterministic,
offline-testable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import date
from fnmatch import fnmatchcase
from pathlib import Path

from .errors import WaiverError
from .findings import Finding, FindingsReport

#: Schema identifier for the waiver file.
WAIVERS_SCHEMA = "presidio-scout/waivers/v1"
_REQUIRED_FIELDS = ("rule", "justification", "owner", "expires")


@dataclass(frozen=True)
class Waiver:
    """A single, expiring exception for a finding (optionally one resource)."""

    rule: str
    justification: str
    owner: str
    expires: date
    resource: str | None = None

    def is_expired(self, today: date) -> bool:
        return self.expires < today

    @property
    def is_finding_level(self) -> bool:
        return self.resource in (None, "*")

    def matches_rule(self, finding: Finding) -> bool:
        rule = finding.rule
        stripped = rule[:-5] if rule.endswith(".json") else rule
        candidates = {
            f"{finding.service}/{rule}",
            f"{finding.service}/{stripped}",
            rule,
            stripped,
        }
        return self.rule in candidates

    def matches_resource(self, item: str) -> bool:
        if self.is_finding_level:
            return True
        return fnmatchcase(item, self.resource)  # type: ignore[arg-type]


def _parse_waiver(entry: object, *, index: int) -> Waiver:
    if not isinstance(entry, dict):
        raise WaiverError(f"waiver #{index} is not an object")
    missing = [f for f in _REQUIRED_FIELDS if not entry.get(f)]
    if missing:
        raise WaiverError(f"waiver #{index} is missing required field(s): {', '.join(missing)}")
    raw_expires = str(entry["expires"])
    try:
        expires = date.fromisoformat(raw_expires)
    except ValueError as exc:
        raise WaiverError(
            f"waiver #{index} has invalid expiry {raw_expires!r} (expected YYYY-MM-DD): {exc}"
        ) from exc
    resource = entry.get("resource")
    return Waiver(
        rule=str(entry["rule"]),
        justification=str(entry["justification"]),
        owner=str(entry["owner"]),
        expires=expires,
        resource=str(resource) if resource not in (None, "") else None,
    )


def load_waivers(path: str | Path) -> list[Waiver]:
    """Load and validate waivers from a JSON file. Fail-closed on any problem."""

    p = Path(path)
    try:
        document = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise WaiverError(f"cannot read waivers file {p}: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("waivers"), list):
        raise WaiverError(f"waivers file {p} must be an object with a 'waivers' array")
    return [_parse_waiver(entry, index=i) for i, entry in enumerate(document["waivers"])]


@dataclass
class WaiverOutcome:
    """Result of applying waivers to a :class:`FindingsReport`."""

    kept: FindingsReport
    suppressed: list[tuple[Finding, Waiver]] = field(default_factory=list)
    expired: list[Waiver] = field(default_factory=list)
    unused: list[Waiver] = field(default_factory=list)


def apply_waivers(
    report: FindingsReport,
    waivers: list[Waiver],
    *,
    today: date | None = None,
) -> WaiverOutcome:
    """Apply ``waivers`` to ``report``, returning the kept findings + bookkeeping.

    Active (unexpired) waivers suppress whole findings (finding-level) or
    specific flagged resources (resource-level); a finding whose every flagged
    resource is waived is dropped. Expired waivers that *would* have matched are
    reported in ``expired`` but never suppress. Waivers that match nothing are
    reported in ``unused``.
    """

    today = today or date.today()
    active = [w for w in waivers if not w.is_expired(today)]
    expired_waivers = [w for w in waivers if w.is_expired(today)]
    matched: set[int] = set()
    matched_expired: set[int] = set()

    kept_findings: list[Finding] = []
    suppressed: list[tuple[Finding, Waiver]] = []

    for finding in report.findings:
        # Flag any expired waiver that would have applied to this finding.
        for w in expired_waivers:
            if w.matches_rule(finding) and (
                w.is_finding_level or any(w.matches_resource(i) for i in finding.items)
            ):
                matched_expired.add(id(w))

        rule_active = [w for w in active if w.matches_rule(finding)]
        finding_level = next((w for w in rule_active if w.is_finding_level), None)
        if finding_level is not None:
            matched.add(id(finding_level))
            suppressed.append((finding, finding_level))
            continue

        if finding.items and rule_active:
            kept_items: list[str] = []
            waiver_for_item: Waiver | None = None
            for item in finding.items:
                hit = next((w for w in rule_active if w.matches_resource(item)), None)
                if hit is None:
                    kept_items.append(item)
                else:
                    matched.add(id(hit))
                    waiver_for_item = hit
            if not kept_items:
                # Every flagged resource waived -> finding fully suppressed.
                suppressed.append((finding, waiver_for_item))  # type: ignore[arg-type]
                continue
            if len(kept_items) != len(finding.items):
                finding = replace(finding, items=tuple(kept_items), flagged_items=len(kept_items))
        kept_findings.append(finding)

    unused = [w for w in waivers if id(w) not in matched and id(w) not in matched_expired]
    return WaiverOutcome(
        kept=FindingsReport(findings=kept_findings, providers=list(report.providers)),
        suppressed=suppressed,
        expired=[w for w in expired_waivers if id(w) in matched_expired],
        unused=unused,
    )


def summarize_outcome(outcome: WaiverOutcome) -> list[str]:
    """Human-readable lines describing a :class:`WaiverOutcome` (no I/O).

    Returned for a CLI to print to stderr: a suppression count, plus fail-closed
    warnings for expired waivers (which no longer hide anything) and waivers that
    matched nothing (stale).
    """

    messages: list[str] = []
    if outcome.suppressed:
        messages.append(f"waivers: suppressed {len(outcome.suppressed)} finding(s)")
    for w in outcome.expired:
        messages.append(
            f"warning: expired waiver for {w.rule} (owner {w.owner}, expired {w.expires}) "
            "— finding NOT suppressed"
        )
    for w in outcome.unused:
        messages.append(f"warning: waiver for {w.rule} matched no current finding (stale)")
    return messages
