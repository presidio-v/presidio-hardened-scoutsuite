"""Post-run integrity and sanitization checks on the generated report.

ScoutSuite renders a static HTML report (plus ``inc-*`` assets and the raw
``scoutsuite-results`` data). This guard:

* injects a strict Content-Security-Policy ``<meta>`` into each HTML file so the
  static viewer can't load remote/inline script if a finding string ever
  contained markup;
* adds Subresource Integrity (``integrity="sha384-…"``) to each local
  ``<script>``/stylesheet ``<link>`` so the browser refuses to execute a
  tampered local asset — defence-in-depth alongside the ``script-src 'self'``
  CSP;
* flags any reference that would reach the network (so the report is provably an
  *offline* viewer);
* scans the whole tree for leaked secrets (fail-closed option);
* writes a signed-able SHA-256 integrity manifest so a report can be verified
  later, offline, by :mod:`presidio_scoutsuite.verify`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

from . import manifest, redact
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

_SCRIPT_TAG_RE = re.compile(r"<script\b[^>]*>", re.IGNORECASE)
_LINK_TAG_RE = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(r"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")
#: A URL that fetches over the network: an explicit http(s) scheme or a
#: protocol-relative ``//host/…`` reference. ``data:``/relative paths are local.
_REMOTE_URL_RE = re.compile(r"^(?:https?:)?//", re.IGNORECASE)
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")


@dataclass
class GuardResult:
    """Summary of a :func:`guard_report` run."""

    report_dir: Path
    html_hardened: list[str] = field(default_factory=list)
    sri_hardened: list[str] = field(default_factory=list)
    remote_refs: list[str] = field(default_factory=list)
    secret_findings: dict[str, list[str]] = field(default_factory=dict)
    manifest: dict[str, str] = field(default_factory=dict)
    manifest_document: dict = field(default_factory=dict)
    manifest_path: Path | None = None

    @property
    def has_secrets(self) -> bool:
        return bool(self.secret_findings)

    @property
    def has_remote_refs(self) -> bool:
        return bool(self.remote_refs)


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


def _parse_attrs(tag: str) -> dict[str, str]:
    """Map lower-cased attribute names to values for a single start tag."""

    return {m.group(1).lower(): (m.group(2) or m.group(3) or "") for m in _ATTR_RE.finditer(tag)}


def _is_remote(url: str) -> bool:
    return bool(_REMOTE_URL_RE.match(url))


def _is_local_asset(url: str) -> bool:
    """True for a same-document relative path (no scheme, not network/anchor)."""

    if not url or url.startswith("#"):
        return False
    if _is_remote(url):
        return False
    # Any other explicit scheme (data:, javascript:, mailto:, file:…) is not a
    # local file we can hash and pin.
    return not _SCHEME_RE.match(url)


def _sri_hash(path: Path) -> str:
    """Compute the ``sha384-<base64>`` Subresource-Integrity value for a file."""

    digest = hashlib.sha384()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return "sha384-" + base64.b64encode(digest.digest()).decode("ascii")


def _local_target(url: str, *, base_dir: Path, root: Path) -> Path | None:
    """Resolve a local asset URL to a file inside ``root``, or ``None``.

    Strips any query/fragment, URL-decodes the path, and rejects anything that
    escapes the report directory (path traversal) or does not exist.
    """

    clean = unquote(url.split("#", 1)[0].split("?", 1)[0])
    if not clean:
        return None
    target = (base_dir / clean).resolve()
    root_resolved = root.resolve()
    if target != root_resolved and root_resolved not in target.parents:
        return None
    return target if target.is_file() else None


def _add_integrity(tag: str, integrity: str) -> str:
    inject = f' integrity="{integrity}" crossorigin="anonymous"'
    if tag.endswith("/>"):
        return tag[:-2] + inject + "/>"
    return tag[:-1] + inject + ">"


def inject_sri(html: str, *, base_dir: Path, root: Path) -> tuple[str, list[str], list[str]]:
    """Pin local ``<script>``/stylesheet ``<link>`` assets with SRI hashes.

    Returns ``(html, pinned, remote)`` where ``pinned`` lists the local asset
    URLs that gained an ``integrity`` attribute and ``remote`` lists any
    network-fetching references seen (which the CSP already blocks, but are
    surfaced so an operator knows the report isn't fully self-contained).
    Idempotent: a tag that already carries ``integrity`` is left untouched.
    """

    pinned: list[str] = []
    remote: list[str] = []

    def _rewrite(tag: str, url_attr: str, *, require_stylesheet: bool) -> str:
        attrs = _parse_attrs(tag)
        if require_stylesheet and "stylesheet" not in attrs.get("rel", "").lower().split():
            return tag
        url = attrs.get(url_attr, "")
        if not url:
            return tag
        if _is_remote(url):
            remote.append(url)
            return tag
        if "integrity" in attrs or not _is_local_asset(url):
            return tag
        target = _local_target(url, base_dir=base_dir, root=root)
        if target is None:
            return tag
        pinned.append(url)
        return _add_integrity(tag, _sri_hash(target))

    html = _SCRIPT_TAG_RE.sub(lambda m: _rewrite(m.group(0), "src", require_stylesheet=False), html)
    html = _LINK_TAG_RE.sub(lambda m: _rewrite(m.group(0), "href", require_stylesheet=True), html)
    return html, pinned, remote


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
    fail_on_remote_ref: bool = False,
    write_manifest: bool = True,
    sign_key: bytes | None = None,
) -> GuardResult:
    """Harden and verify a finished report directory.

    Injects CSP and Subresource Integrity into HTML files, flags any
    network-reaching references, scans the tree for secrets, and writes a
    SHA-256 integrity manifest (computed *after* hardening so the hashes match
    what a user will open). The manifest file itself is excluded from the
    inventory it records.

    ``fail_on_secret`` / ``fail_on_remote_ref`` turn a surviving secret or a
    remote reference into a :class:`ReportGuardError`. ``sign_key`` (defaulting
    to the :data:`~presidio_scoutsuite.manifest.HMAC_ENV_VAR` environment key)
    attaches an HMAC signature to the manifest.
    """

    root = Path(report_dir)
    if not root.is_dir():
        raise ReportGuardError(f"report dir {root} does not exist")

    result = GuardResult(report_dir=root)
    seen_remote: set[str] = set()

    for html_file in sorted([*root.rglob("*.html"), *root.rglob("*.htm")]):
        text = html_file.read_text(encoding="utf-8", errors="replace")
        hardened, csp_changed = inject_csp(text)
        hardened, pinned, remote = inject_sri(hardened, base_dir=html_file.parent, root=root)
        rel = str(html_file.relative_to(root))
        if csp_changed:
            result.html_hardened.append(rel)
        if pinned:
            result.sri_hardened.append(rel)
        for url in remote:
            if url not in seen_remote:
                seen_remote.add(url)
                result.remote_refs.append(url)
        if hardened != text:
            html_file.write_text(hardened, encoding="utf-8")

    if sign_key is None:
        sign_key = manifest.hmac_key_from_env()

    for file in sorted(root.rglob("*")):
        if not file.is_file():
            continue
        rel = str(file.relative_to(root))
        if rel == manifest.MANIFEST_FILENAME:
            continue
        try:
            findings = redact.scan(file.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, OSError):
            findings = []
        if findings:
            result.secret_findings[rel] = findings
        result.manifest[rel] = _sha256(file)

    result.manifest_document = manifest.build_manifest(result.manifest, sign_key=sign_key)
    if write_manifest:
        manifest_path = root / manifest.MANIFEST_FILENAME
        manifest_path.write_text(
            json.dumps(result.manifest_document, indent=2) + "\n", encoding="utf-8"
        )
        result.manifest_path = manifest_path

    if fail_on_secret and result.has_secrets:
        files = ", ".join(sorted(result.secret_findings))
        raise ReportGuardError(f"secrets present in report after redaction: {files}")
    if fail_on_remote_ref and result.has_remote_refs:
        refs = ", ".join(sorted(set(result.remote_refs)))
        raise ReportGuardError(f"report references remote resources: {refs}")

    return result
