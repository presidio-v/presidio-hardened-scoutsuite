# Presidio-Hardened ScoutSuite – Requirements & Deliberation Log

## Overview

Build a Presidio security-hardened **distribution of ScoutSuite** (NCC Group's
multi-cloud security auditing tool). Operators run their normal cloud audit but
get hardened defaults, automatic report redaction, supply-chain integrity, and a
least-privilege deployment model — without trusting a modified ScoutSuite.

---

## Approach deliberation (2026-06-05)

The requester asked to weigh **fork vs. drop-in vs. distribution** and to scope
what "hardened" means. Key facts and decisions:

### Why not the single-import wrapper pattern (MIT, drop-in client)?

Several sibling projects harden an **API client**: swap one import and outbound
HTTP is hardened. That pattern doesn't transfer to ScoutSuite for two reasons:

1. **License.** ScoutSuite is **GPL-2.0-only**
   (<https://github.com/nccgroup/ScoutSuite/blob/master/LICENSE>). Forking or
   importing it makes a derivative work that must ship GPL-2.0 — it cannot be
   relicensed MIT. The only way to keep *our* additions independently licensed is
   to stay **out of process** (drive `scout` as a subprocess; never import it).
2. **Shape.** ScoutSuite is an end-user CLI app (authenticate → collect via
   provider SDKs → rule engine → HTML report), not a library with a stable import
   surface. "Single import → hardened transport" has nothing to attach to.

### Decision — Out-of-process distribution (chosen)

| Option | Verdict |
|---|---|
| **Out-of-process distribution** | **Chosen.** Subprocess `scout`; wrapper stays non-derivative → **MIT**; lowest maintenance; closest to the family's "drop-in" ethos. |
| Soft fork / overlay (import ScoutSuite) | Rejected for 0.1: makes the wrapper a GPL derivative; ScoutSuite has no stable import API. |
| Hard fork | Rejected: inherits a large transitive SDK tree to maintain; GPL-2.0; highest burden. |
| Upstream-first + thin distro | Deferred: good long-term hygiene but gated on NCC Group's acceptance cadence. |

### Scope — what "hardened" means (all four axes, requester-selected)

1. **Runtime credential & data safety** — env scrubbed to cloud creds only; 0700
   report dir + `umask 0077`; report/log secret redaction; `--fail-on-secret`.
2. **Secure-by-default policy** — curated, CIS-aligned **AWS** baseline ruleset
   forcing high-impact controls to `danger`.
3. **Supply-chain & build integrity** — hash-pinned lockfile, SBOM, CodeQL,
   Dependabot, cosign-signed images + provenance; release blocked if unpinned.
4. **Hardened deployment** — distroless/non-root/read-only container; bundled
   least-privilege AWS audit role (read-only + explicit `Deny`, MFA + ExternalId).

**Lead cloud = AWS** (largest ScoutSuite user base / richest rules). Azure & GCP
rulesets + IAM deferred to 0.2.0.

---

## Technical Requirements

- Python 3.9+; `pyproject.toml` + `hatchling`; `src/presidio_scoutsuite/` layout.
- **No runtime dependency on ScoutSuite** — invoked as a subprocess. Optional
  `[scoutsuite]` extra pins it for convenience (documented GPL implication).
- `pytest` + `pytest-cov` (≥ 90% gate); tests run **without ScoutSuite installed**
  (the subprocess boundary is injected).
- `ruff` lint + format enforced in CI.
- Full GitHub security posture: CI, CodeQL, Dependabot, SBOM, signed release.
- Wrapper license = **MIT**; bundled ScoutSuite = **GPL-2.0** (notice in
  `LICENSES/README.md`).

---

## v0.1.0 — Initial scaffold (2026-06-05)

**Design decisions:**

- **`launcher` fail-closed allowlist.** Pass-through flags are validated against
  an explicit allowlist; an unknown/new ScoutSuite flag is **rejected**, not
  forwarded, so upstream additions can't silently weaken a run until vetted.
  Launcher-owned flags (`--report-dir`, `--ruleset`, `--no-browser`) cannot be
  overridden from the command line.
- **Environment scrubbing over passthrough.** The child gets only cloud-cred vars
  (by known prefix) + a short runtime allowlist. Fail-closed: a new credential
  family must be added to `_CLOUD_ENV_PREFIXES` to reach the child.
- **Report dir is 0700 + `umask 0077`.** ScoutSuite writes raw account config;
  it must not be group/world readable, and is `.gitignore`d.
- **Redaction is deterministic.** Specific regexes (AWS/Azure/GCP keys, private-key
  blocks, bearer/Authorization) — no entropy heuristics — so results are
  reproducible and auditable. `--fail-on-secret` turns a surviving secret into a
  non-zero exit (exit 3).
- **Report guard injects CSP + integrity manifest.** Findings can echo
  attacker-influenced resource names; the CSP (`default-src 'none'`, no inline
  script) limits blast radius. SHA-256 manifest is computed post-hardening.
- **Curated AWS ruleset is the default**, opt-out via `--no-baseline`. Rule
  filenames track the pinned ScoutSuite version; **0.2.0 will validate them in
  CI** against the pinned upstream (until then they're a documented assumption).
- **Supply chain.** `requirements.lock` is the pinned tree; CI *warns* if it's not
  hash-pinned, the **release pipeline hard-fails**. Release builds a distroless
  image, attaches provenance + SBOM, and **cosign-signs** it.
- **Least-privilege IAM ships as data**, not code: managed read-only policies +
  a supplemental policy whose `Deny` blocks any non-read action, + MFA/ExternalId
  trust policy.

**Delivered:**
- `launcher.py` (build/run, validate, scrub, harden dir), `redact.py`,
  `report_guard.py`, `cli.py` (`presidio-scout`), `errors.py`
- Curated `policy/aws-cis.json`; `iam/aws/` role + trust + README
- `Dockerfile` (distroless/non-root), `requirements.lock` (placeholder, pinned
  version; hashes added before first release)
- CI / CodeQL / Dependabot / SBOM / signed-release workflows
- README, SECURITY.md, LICENSE (MIT) + GPL notice
- Test suite (launcher/redact/report_guard/cli), coverage-gated, ruff clean

---

## v0.2.0 — Multi-cloud baselines + rule-name validation (2026-06-06)

**Design decisions:**

- **Curated baselines for Azure & GCP.** `policy/azure-cis.json` and
  `policy/gcp-cis.json` follow the AWS pattern: a CIS-aligned subset with
  high-impact storage/SQL/network/identity controls forced to `danger`. The CLI
  now applies them by default (`_BUNDLED_RULESETS` covers aws/azure/gcp);
  remaining providers still warn and fall back to ScoutSuite's default.
- **Rule-name validation closes a silent-failure gap.** A ruleset's keys are the
  *filenames* of finding rules inside ScoutSuite. A typo or an upstream rename
  makes ScoutSuite **silently ignore** the rule — the control vanishes with no
  error. New `ruleset.py` validates that every referenced rule exists.
- **Two inventory sources, fail-closed.** *manifest* (default): a checked-in
  `policy/<provider>.rules.txt` inventory of the pinned ScoutSuite's finding
  rules, so CI validates on every push **without installing GPL ScoutSuite**.
  *installed*: discovered from an actually-installed ScoutSuite, run at release
  to catch manifest drift. `installed_rules` raises (never returns empty) when
  ScoutSuite is absent, so a missing dependency can't pass the check.
- **Validation wired into both pipelines.** `presidio-scout-validate` console
  script; `ci.yml` runs `--source manifest`; a new `verify-rulesets` release gate
  installs the pinned ScoutSuite and runs `--source installed` before any image
  is built/signed.
- **Least-privilege IAM for Azure & GCP, as data.** `iam/azure/` (built-in
  `Reader`+`Security Reader`, or a custom `*/read` role with **empty
  `dataActions`** so secret/key *values* stay unreadable; minimal directory read
  for AAD). `iam/gcp/` (`roles/viewer`+`roles/iam.securityReviewer`, or a custom
  role of `*.list`/`*.get`/`*.getIamPolicy` only; service-account impersonation
  preferred over downloaded keys).

**Delivered:**
- `policy/azure-cis.json`, `policy/gcp-cis.json`; `policy/{aws,azure,gcp}.rules.txt`
- `ruleset.py` + `RulesetValidationError`; `presidio-scout-validate` script
- `iam/azure/` and `iam/gcp/` (custom role data + README each)
- CI offline-validation step; release `verify-rulesets` hard gate
- `test_ruleset.py`; coverage maintained (95%, ≥90% gate); ruff clean

**Assumption (documented):** the rule manifests are seeded for ScoutSuite 5.14.0;
because `requirements.lock` is still a placeholder, the manifests are regenerated
from the installed package (`ruleset.installed_rules`) and the release-time
`--source installed` gate is the authority that keeps them honest.

---

## v0.3.0 — Deeper report guard: SRI, offline viewer, signed manifests (2026-06-16)

**Design decisions:**

- **The integrity manifest is now persisted, not just computed.** 0.1/0.2
  hashed every report file but kept the manifest in memory. 0.3 writes
  `presidio-report-manifest.json` into the report dir, so a report can be
  integrity-checked long after the run. The manifest **excludes itself** (a file
  can't hash itself) and is re-runnable: a prior manifest is skipped on a second
  guard pass.
- **Tamper-evidence in two independent layers.** A `content_digest` (SHA-256
  over the canonical, sorted file→hash map) makes edits to the recorded hashes
  detectable on their own. An **optional HMAC-SHA256 signature**
  (`PRESIDIO_MANIFEST_HMAC_KEY`) proves the manifest came from a holder of the
  shared pipeline key. Both cover only the security-relevant content (algorithm
  + file hashes), never the informational timestamp/generator — so verification
  is independent of *when/where* the report was guarded. HMAC is symmetric by
  design (pipeline integrity, not non-repudiation); for distribution the
  manifest *blob* is signed out of band with **cosign `sign-blob`**, reusing the
  release pipeline's existing keyless signing rather than inventing a runtime
  asymmetric-key story (no runtime crypto deps).
- **Offline verification, fail-closed.** New `verify.py` /
  `presidio-scout-verify` re-hashes the tree and reports **modified / missing /
  added** files, recomputes the self-digest, and checks the HMAC when a key is
  present. A present-but-unverifiable signature (no key) does **not** fail —
  the hashes already establish integrity — but a *bad* signature does. Exit
  `0` verified · `3` mismatch · `2` no usable manifest. A malformed/missing
  manifest raises rather than silently passing.
- **Subresource Integrity closes the local-asset gap.** The CSP already pins
  scripts to `'self'`; SRI goes further by pinning each local `<script>` /
  stylesheet `<link>` to a `sha384` hash so the browser refuses a *tampered*
  local asset. Injection is idempotent (skips tags that already carry
  `integrity`), resolves hrefs relative to the HTML file, and **rejects path
  traversal** (only files inside the report dir are hashed).
- **Offline-viewer enforcement.** Any network-reaching reference (`http(s):` or
  protocol-relative `//`) is detected and surfaced; `--fail-on-remote-ref`
  turns one into a non-zero exit. Combined with `connect-src 'none'`, the
  report is provably self-contained.

**Delivered:**
- `manifest.py` (shape, canonicalization, self-digest, HMAC signing)
- `verify.py` + `ReportVerificationError`; `presidio-scout-verify` console script
- `report_guard.py`: SRI injection, remote-ref detection, manifest persistence,
  `--fail-on-remote-ref`; `cli.py` surfaces the manifest path + SRI/remote counts
- `test_manifest.py`, `test_verify.py`, extended `test_report_guard.py`/`test_cli.py`;
  coverage 95% (≥90% gate); ruff clean

---

## Roadmap

| Version | Planned |
|---|---|
| **0.1.0** | Out-of-process hardened launcher + redaction/guard + AWS ruleset/IAM + container + supply-chain posture |
| **0.2.0** | Azure & GCP curated baselines + least-privilege roles; **rule-name validation** against the pinned ScoutSuite (offline manifest in CI, installed-source drift gate at release) ✓ |
| **0.3.0** | Deeper report guard (SRI, offline viewer), signed report manifests ✓ |
| **0.4.0** | SLSA provenance verification on install; reproducible-build attestation |

---

## SDLC

Delivered under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
