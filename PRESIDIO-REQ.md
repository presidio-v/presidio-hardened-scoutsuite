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

## v0.4.0 — SLSA provenance verification + reproducible builds (2026-06-16)

**Design decisions:**

- **Separate *policy* verification from *signature* verification.** `cosign
  verify-attestation` already does the hard cryptographic part (Fulcio cert +
  Rekor transparency log); re-implementing that in-tree would mean bundling
  sigstore + a trust-root and would be easy to get subtly wrong. What cosign
  does *not* do is tell you the provenance says the *right* thing — a valid
  signature on an attestation for the *wrong* source/builder/digest still
  passes. `provenance.py` owns exactly that gap: a fail-closed **policy gate**
  run on the already-verified statement. This mirrors the project's existing
  split (heavy work out of process; the *policy* owned here, pure-stdlib,
  deterministic, offline-testable).
- **Understand both SLSA v0.2 and v1.** The container build emits buildx
  `slsa/provenance/v0.2`; slsa-github-generator and PyPI attestations emit
  `v1`. The parser extracts builder id, source URI, and subject digests across
  both layouts, and accepts a bare in-toto statement, a DSSE envelope, or a line
  of cosign's JSON-Lines output — so it drops straight onto real tool output.
- **URI normalization, not string equality.** SLSA tools spell the same repo
  many ways (`git+https://…​.git@refs/tags/v1`, `https://…/`, `…#main`).
  `_normalize_uri` strips the `git+` scheme, `@ref`/`#ref` suffix, `.git`, and
  trailing slash so comparisons are robust without being permissive about the
  actual host/path.
- **Collect all violations, fail closed.** `verify` reports every policy
  mismatch (predicate type, builder, source, digest) rather than the first, and
  is `ok` only if none fired. Bundled policy data (`policy/provenance-policy.json`)
  with `--source-uri` / `--builder-id-prefix` overrides — same data-not-code
  pattern as the curated rulesets.
- **Reproducible builds make provenance *useful*.** If you can't rebuild the
  artifact bit-for-bit, you can't independently confirm what shipped. Builds are
  pinned to the tagged commit's `SOURCE_DATE_EPOCH` (publish.yml) and a new
  `reproducible-build` CI job builds twice and **hard-fails on any difference**.
  The wheel is compared byte-for-byte; the sdist is compared at the
  *decompressed-tar* level, because a gzip container embeds an mtime that is not
  part of the archived content (the reproducible-builds.org convention) — this
  surfaced as a real CI failure when a freshly-resolved hatchling didn't pin the
  gzip mtime, and the content-level check is the correct, robust assertion.

**Delivered:**
- `provenance.py` + `ProvenanceVerificationError`; `presidio-scout-verify-provenance`
  console script; bundled `policy/provenance-policy.json`
- `reproducible-build` CI gate; `SOURCE_DATE_EPOCH` wired into publish.yml
- Public API exports (`Provenance`, `ProvenancePolicy`, `load_statement`)
- `test_provenance.py` (v0.2/v1/DSSE, field extraction, policy, CLI); coverage
  96% (≥90% gate); ruff clean
- README *Verifying what you pull* section, SECURITY.md, this log

---

## v0.5.0 — ScoutSuite install-integrity gate + real lockfile (2026-06-16)

**Design decisions:**

- **Verify *what runs*, out of process.** The wrapper drives `scout` as a
  subprocess and never imports it, so it can't assume the `scout` on PATH is the
  version we pinned and vetted — a newer/older/modified ScoutSuite can ship
  different rules and silently weaken an audit. `scout_integrity` runs a
  fail-closed preflight before any credentials are handed over: resolve the
  executable, read `scout --version` out of process, and require it to equal the
  pinned version. Mismatch / not-found / undeterminable → exit 2, unless
  `--allow-unverified-scout` downgrades it to a warning.
- **Two complementary integrity layers, at the right layers.** Artifact-hash
  integrity (the *installed files* are the exact PyPI artifacts) belongs at
  install time — `pip install --require-hashes -r requirements.lock`. The
  runtime gate confirms the *executed* scout is that pinned version, which also
  covers the case where ScoutSuite lives in a separate env or is supplied via
  `--scout-bin`. We deliberately did **not** try to re-hash installed files at
  runtime (fragile, and meaningless when scout is a separate install).
- **Single source of truth for the pinned version.** `pinned_version()` reads
  the `ScoutSuite==` pin from our *own* package metadata (the `scoutsuite`
  extra), so the gate can't drift from what the extra/lockfile install; a
  constant is the fallback for odd installs.
- **Real hash-pinned `requirements.lock`.** Replaced the un-hashed placeholder
  with the full transitive tree (130 packages) pinned + SHA-256-hashed via
  `pip-compile --generate-hashes --allow-unsafe --extra scoutsuite`. Validated
  with `pip install --require-hashes --dry-run` (129 packages resolve + verify,
  incl. ScoutSuite 5.14.0). This satisfies the release `verify-lock` hard gate
  for the first time.
- **Pinned build backend + Python alignment.** `requires = ["hatchling==1.27.0"]`
  so the wheel/sdist build is deterministic across environments (the
  reproducible-build gate depends on it). Pinned to 1.27.0 — the last hatchling
  that still supports Python 3.9 (1.28+ requires ≥3.10); 1.30.1 broke the 3.9 CI
  job's editable install and was rolled back. The lock is resolved under Python 3.11
  to match the distroless runtime (`python3-debian12` = 3.11); the Dockerfile
  builder was moved from 3.12 to **3.11** so the venv matches both the runtime
  and the lock (it was a latent mismatch).

**Delivered:**
- `scout_integrity.py` + `ScoutIntegrityError`; CLI preflight + `--allow-unverified-scout`
- Real hash-pinned `requirements.lock` (130 pkgs); pinned `hatchling`; Dockerfile → py3.11
- Public API exports (`verify_scout`, `ScoutIntegrityResult`, `pinned_version`)
- `test_scout_integrity.py` + CLI gate tests; coverage 95% (≥90% gate); ruff clean
- README (preflight in the flow, CLI flag, exit codes), SECURITY.md, this log

---

## v0.6.0 — Findings model + severity gate (2026-06-16)

**Design decisions:**

- **Read results as *data*, never import ScoutSuite.** ScoutSuite writes
  `scoutsuite_results*.js` (a `scoutsuite_results = {…}` JS wrapper around a JSON
  object) next to the report. `findings.py` strips the wrapper (`raw_decode` from
  the first `{`, tolerant of trailing JS) and flattens
  `services.<svc>.findings.<rule>` into a model — staying out-of-process and
  GPL-clean.
- **Only *flagged* findings count.** A finding exists for every rule in the
  ruleset; it "fires" only when `flagged_items > 0`. The model excludes the rest,
  so counts reflect real problems. Parsing is defensive about malformed shapes
  (non-dict services/findings, bad `flagged_items`) — a weird results file
  yields fewer findings, never a crash.
- **Severity gate, fail-closed.** Levels rank `danger > warning`; `--fail-on
  <level>` trips on anything at or above it (exit **4**, a new code distinct from
  guard failure). If the results data is missing or unparseable the gate
  **errors (exit 2)** rather than passing — a gate that can't read the audit must
  not green-light it.
- **Inline gate + standalone tool.** `presidio-scout --fail-on-finding` evaluates
  after redaction/guard during a run; `presidio-scout-findings` summarizes/gates
  an existing report offline (text or JSON), for use after the fact or in a
  separate CI step. Same model and exit codes behind both.

**Delivered:**
- `findings.py` (`Finding`, `FindingsReport`, `load_report`) + `FindingsError`;
  `presidio-scout-findings` console script; `--fail-on-finding` on the main CLI
- Public API exports (`Finding`, `FindingsReport`, `load_report`)
- `test_findings.py` + CLI gate tests (danger trips, under-threshold passes,
  missing results fails closed); coverage 96% (≥90% gate); ruff clean
- README *Gating a pipeline on findings* section, exit-code 4, SECURITY.md, this log

---

## v0.7.0 — SARIF export + GitHub code scanning (2026-06-16)

**Design decisions:**

- **Reuse the 0.6.0 findings model; add SARIF as a pure projection.** `sarif.py`
  builds a SARIF 2.1.0 document straight from the in-memory `FindingsReport` — no
  re-parsing, no ScoutSuite import. `Finding` gained an `items` tuple (the flagged
  resource paths ScoutSuite lists) so results can be **per-resource**.
- **Documented, auditable mapping.** rule id = `<service>/<key without .json>`;
  ScoutSuite `danger`→SARIF `error` + `security-severity` 8.0 (high), `warning`→
  `warning` + 4.0 (medium); unknown levels → `note`/0.0. Rules carry the
  `security` tag so GitHub classifies them as security alerts.
- **Cloud findings have no source file — be honest about it.** Each result gets a
  *synthetic* physical location (`<provider>/<service>`, line 1) so GitHub
  accepts it, plus a `logicalLocations` entry naming the actual resource, and a
  deterministic `partialFingerprints` (sha256 of rule+resource) so the same alert
  is tracked across runs rather than churning.
- **Two entry points + CI-friendly inline emit.** `presidio-scout-export`
  converts an existing report (stdout or `-o`); `presidio-scout --sarif PATH`
  emits during a run. SARIF is written **even when `--fail-on-finding` trips**, so
  a gated pipeline still uploads the alerts.

**Delivered:**
- `sarif.py` (`to_sarif`) + `presidio-scout-export` console script; `--sarif PATH`
  on the main CLI; `Finding.items`
- Public API export (`to_sarif`)
- `test_sarif.py` + findings/CLI tests (per-resource results, severity mapping,
  fingerprints, inline emit + gate); coverage 96% (≥90% gate); ruff clean
- README *GitHub code scanning (SARIF)* section with an upload-sarif Action
  snippet, SECURITY.md, this log

---

## v0.8.0 — Waivers / exceptions framework (2026-06-16)

**Design decisions:**

- **Exceptions as expiring, attributable data — not ruleset edits.** Hiding an
  accepted finding by weakening the curated baseline is dangerous and invisible;
  `waivers.py` instead takes a checked-in JSON file where every entry carries a
  **justification**, an **owner**, and a mandatory **expiry**. A waived finding
  is documented and time-boxed.
- **Whole-finding *and* per-resource granularity.** A waiver with no `resource`
  (or `"*"`) suppresses the finding; a resource pattern (`fnmatch`) waives only
  matching flagged resources, and the finding survives with a *reduced* count if
  any resource is left unwaived (built on 0.7.0's `Finding.items`). Count-only
  findings (no item list) are only ever suppressed finding-level.
- **Fail-closed in every direction.** A missing/malformed waiver file, or one
  missing a required field, **errors** (never silently "waive nothing" — or,
  worse, be misread as "waive everything"). An **expired** waiver does not
  suppress; the finding resurfaces and the expired waiver is reported, so risk
  can't be hidden past its review date. Stale waivers (matching nothing) are
  surfaced too.
- **One model, applied everywhere findings are consumed.** `apply_waivers`
  returns the kept `FindingsReport` plus bookkeeping (suppressed/expired/unused);
  `--waivers` is wired into the severity gate, `presidio-scout-findings`, and the
  SARIF export, so waived findings never reach a gate *or* a code-scanning alert.
  Rule ids match the SARIF/`service/key` forms for consistency.

**Delivered:**
- `waivers.py` (`Waiver`, `load_waivers`, `apply_waivers`, `summarize_outcome`) +
  `WaiverError`; `--waivers` on `presidio-scout`, `presidio-scout-findings`,
  `presidio-scout-export`
- Public API exports (`Waiver`, `load_waivers`, `apply_waivers`)
- `test_waivers.py` + CLI tests (suppression, resource reduction, expired
  resurfacing, malformed→exit 2); coverage 96% (≥90% gate); ruff clean
- README *Waiving accepted findings* section, SECURITY.md, this log

---

## v0.9.0 — Signed run attestation (2026-06-16)

**Design decisions:**

- **One statement about the *run*, chaining the existing layers.** 0.3 records
  what the report contains (manifest) and verifies it; 0.4 verifies how
  *artifacts* were built; 0.5 checks *which* ScoutSuite ran. `attestation.py`
  ties these together: an in-toto v1 statement whose **subject is the report's
  integrity manifest** (by SHA-256) and whose predicate records provider, the
  curated ruleset's digest, the verified ScoutSuite version, the wrapper
  version, the manifest's own content digest, and optional finding counts. The
  chain — report files → manifest (verified by `presidio-scout-verify`) →
  attestation subject → cosign signature — is what makes it meaningful.
- **Build/verify here; sign with cosign.** Same split as 0.4's provenance gate:
  the heavy crypto (sign-blob, Fulcio/Rekor) stays in cosign; this module
  produces the statement and `verify_attestation` does the *binding* check
  (predicate type, subject digest == on-disk manifest, recorded content digest
  == manifest's). No runtime crypto deps.
- **Written even when the findings gate trips.** In a run, `--attest` is emitted
  alongside `--sarif` *before* the `--fail-on-finding` exit, so a gated pipeline
  still produces the signed record of what it audited. The integrity preflight's
  detected ScoutSuite version is captured and recorded.
- **Standalone generate/verify too.** `presidio-scout-attest generate|verify`
  works against any guarded report offline (`--scout-version` defaults to the
  pinned version; `--ruleset` recorded by digest).

**Delivered:**
- `attestation.py` (`build_attestation`, `attest_report`, `verify_attestation`,
  `AttestationResult`) + `AttestationError`; `presidio-scout-attest` console
  script; `--attest PATH` on the main CLI (captures scout version + ruleset)
- Public API exports (`build_attestation`, `attest_report`, `verify_attestation`)
- `test_attestation.py` + CLI tests (emitted during run, emitted even when gate
  trips, tamper detection); coverage 96% (≥90% gate); ruff clean
- README *Signed run attestation* section, SECURITY.md, this log

---

## v0.10.0 — Drift detection / run diff (2026-06-16)

**Design decisions:**

- **Gate on *change*, not the absolute set.** A mature account has a triaged
  backlog; failing on every finding is noise. `diff.py` compares a baseline
  `FindingsReport` to a current one and reports only the delta, so a pipeline can
  block *regressions* while ignoring pre-existing findings.
- **Resource-granular occurrences.** Diffing on `(service, key, resource)`
  occurrences (count-only findings use a single `None` occurrence) cleanly
  distinguishes a brand-new finding (`whole_finding`) from an existing finding
  that began flagging an additional resource — both are "new", but reported
  separately — and likewise for resolved findings vs resolved resources.
- **Severity-scoped fail gate.** `--fail-on-new-finding {any,warning,danger}`
  trips (exit 4, consistent with the findings gate) only when a *newly added*
  occurrence is at or above the threshold, so new warnings needn't block a
  danger-only gate.
- **Standalone, reusing the findings model.** `presidio-scout-diff OLD NEW`
  loads both reports with `findings.load_report` (fail-closed on a missing
  report) and diffs them; no new parsing, no ScoutSuite import. JSON output
  carries the full structured delta for downstream tooling.

**Delivered:**
- `diff.py` (`FindingChange`, `DiffResult`, `diff_reports`, `load_and_diff`,
  `summarize`); `presidio-scout-diff` console script
- Public API exports (`DiffResult`, `diff_reports`, `load_and_diff`)
- `test_diff.py` (new/resolved findings + resources, severity thresholds, count-only
  findings, provider union, CLI text/json/gate); coverage 96% (≥90% gate); ruff clean
- README *Tracking drift between runs* section, SECURITY.md, this log

---

## v0.11.0 — Reproducible multi-arch image + E2E image provenance (2026-06-16)

**Design decisions:**

- **Consume 0.4 against the *real* published artifact.** The release pipeline now
  has a `verify-image` job (gated after build) that re-verifies the freshly
  pushed image end to end: `cosign verify` for the signature (keyless, this
  repo's `release.yml` identity), then `gh attestation verify` for the
  GitHub-signed SLSA provenance, piped into `presidio-scout-verify-provenance`
  for the policy check (builder / source / this exact digest). The release run
  only goes green once the published image verifies — closing the loop from
  "we sign" to "what we shipped verifies."
- **Signed, gh-verifiable provenance.** Added `actions/attest-build-provenance`
  (push-to-registry) so the image carries a sigstore-signed SLSA provenance
  attestation, verifiable with the standard `gh attestation verify` rather than
  bespoke extraction of unsigned buildx metadata.
- **`load_statement` made robust to real verifier output (the testable core).**
  Refactored to locate the in-toto statement in a bare statement, a DSSE
  envelope, cosign JSON-Lines, *or* the nested array `gh attestation verify
  --format json` emits — so the gate is a clean `gh … | presidio-scout-verify-
  provenance -`. Preserved the existing error semantics (empty / invalid JSON /
  undecodable DSSE payload / no predicateType).
- **Multi-arch + reproducible image.** Build `linux/amd64,linux/arm64` (QEMU),
  with `SOURCE_DATE_EPOCH` pinned to the tagged commit so buildkit rewrites
  timestamps to a deterministic digest. Both base images (`python:3.11-slim`,
  distroless `python3-debian12`) are multi-arch.

**Delivered:**
- `release.yml`: QEMU + `platforms: linux/amd64,linux/arm64`; `SOURCE_DATE_EPOCH`;
  `actions/attest-build-provenance`; new `verify-image` end-to-end gate (new
  actions SHA-pinned)
- `provenance.load_statement` + `_extract_statement` handle gh/cosign/DSSE/bare
  forms; README image-verification commands, SECURITY.md, this log
- `test_provenance.py`: gh-array + container-image-provenance fixtures; coverage
  96% (≥90% gate); ruff clean
- Note: release-workflow changes are tag-triggered and validated by YAML + review
  (not executed by the PR's CI), following standard GitHub Artifact Attestations
  + cosign patterns.

---

## v0.12.0 — Keyless / short-lived credentials (2026-06-16)

**Deliberation (A vs B):** the roadmap framed 0.12.0 as *auto-assuming the audit
role via the cloud CLI as a subprocess* (**Direction A**). On inspection that
conflicts with the project's invariants:

- ScoutSuite's bundled SDKs (boto3, azure-identity, google-auth) **already**
  resolve assumed roles, OIDC web identity, impersonation, and managed identity.
  Brokering in the wrapper would **duplicate** that with a new, security-sensitive
  responsibility (handling temp secrets / session tokens / MFA).
- It would require **either** a runtime dependency on `aws`/`gcloud`/`az`
  (which the distroless image ships none of → de-hardening/bloat) **or**
  hand-rolling SigV4 STS + GCP impersonation + Azure token flows across three
  clouds in stdlib (large, must track three providers, only mock-testable —
  the worst place to have only mock coverage).

**Direction B (chosen):** keep credential *resolution* in the SDKs; the wrapper
adds a deterministic, dependency-free, fail-closed **preflight** over the
credential *shape* plus keyless setup docs. It hits the same goal ("no long-lived
keys reach the audit") while preserving every invariant (zero runtime deps,
out-of-process, minimal secret-handling surface, distroless unchanged) and
reusing the SDKs' battle-tested resolution. Rejected A (active brokering) and
A-lite (opt-in CLI brokering) for the reasons above.

**Design decisions:**

- **Classify, don't broker.** `credentials.inspect_credentials(provider, env)`
  returns `short-lived` / `static` / `unknown` from variable presence (and, for
  GCP, only the non-secret `type` field of the credential file — never secret
  values). `--require-short-lived-creds` fails closed (exit 2) on `static`;
  without it, `static` warns. `unknown` (e.g. `AWS_PROFILE`, CLI/ADC login)
  **never** blocks — the gate only trips on an unambiguous long-lived secret.
- **Per-provider signals.** AWS: session token / OIDC web-identity → short-lived;
  access key without a session token → static. Azure: federation / managed
  identity → short-lived; client secret / certificate → static. GCP:
  impersonation / `external_account` → short-lived; downloaded `service_account`
  key → static.
- **Keyless env survives the scrub.** Added the non-prefixed managed-identity
  endpoints (`IDENTITY_ENDPOINT`, `IDENTITY_HEADER`, `MSI_ENDPOINT`, `MSI_SECRET`)
  to the launcher's env allowlist so Azure managed identity works in the child
  without any stored secret.

**Delivered:**
- `credentials.py` (`inspect_credentials`, `assert_short_lived`, `CredentialCheck`)
  + `CredentialError`; `--require-short-lived-creds` on the CLI (default-warn);
  launcher keyless-env passthrough
- Public API exports (`inspect_credentials`, `assert_short_lived`, `CredentialCheck`)
- `test_credentials.py` + CLI tests (strict block / default warn / short-lived
  silent) + launcher scrub test; coverage 96% (≥90% gate); ruff clean
- README *Keyless / short-lived credentials* section (per-cloud + OIDC CI),
  SECURITY.md, this log

---

## v0.13.0 — Kubernetes deployment (2026-06-16)

**Design decisions:**

- **Ships as data, like `iam/`.** A `deploy/kubernetes/` set (Job, CronJob,
  ServiceAccount, NetworkPolicy + README) and a `deploy/helm/presidio-scout`
  chart — no package code, not in the wheel. Pairs the signed multi-arch image
  (0.11), keyless credentials (0.12), and the findings gate (0.6).
- **Hardened by construction.** Pod/container security context: `runAsNonRoot`
  (uid/gid 65532), `readOnlyRootFilesystem` (writable `emptyDir` for `/tmp` and
  `/report`), `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`,
  `seccompProfile: RuntimeDefault`. `automountServiceAccountToken: false` — the
  audit pod never calls the K8s API.
- **Workload identity, not keys.** The ServiceAccount carries (exactly one)
  IRSA / GKE WI / Azure WI annotation; the invocation adds
  `--require-short-lived-creds` so a static secret can't sneak in. The Azure WI
  pod label and projected-token volume are accounted for; the GKE-WI metadata
  dependency is documented so the NetworkPolicy doesn't break it.
- **Default-deny network.** No ingress; egress only DNS + 443 (cloud APIs),
  containing blast radius. README explains tightening the CIDR and blocking the
  metadata IP on EKS/AKS (but not GKE).
- **Testable without a YAML/helm dependency.** `test_deploy_manifests.py` does
  string-presence assertions on the manifests + Helm defaults, failing closed if
  a control is removed — a regression guard for data the wheel can't exercise.

**Delivered:**
- `deploy/kubernetes/{job,cronjob,serviceaccount,networkpolicy}.yaml` + README
- `deploy/helm/presidio-scout/` chart (Chart/values/templates/NOTES; Job↔CronJob
  on `schedule`, hardening via `values.yaml`)
- `test_deploy_manifests.py`; coverage 96% (≥90% gate); ruff clean
- README *Run in Kubernetes* section + table/structure, SECURITY.md, this log

---

## Roadmap

Delivered (0.1.0–0.13.0) and planned (0.14.0–0.15.0). The arc: **0.5** hardens
*what runs*; **0.6–0.8** turn findings into an enforceable, waiver-aware policy
gate; **0.9–0.10** make every run attested and comparable over time; **0.11–0.14**
harden how it's built and deployed; **0.15** makes it configurable for an org.
Every item keeps the project's invariants — out-of-process, never import GPL
ScoutSuite, MIT wrapper, stdlib runtime, fail-closed, offline-testable.

| Version | Planned | Axis · depends on |
|---|---|---|
| **0.1.0** | Out-of-process hardened launcher + redaction/guard + AWS ruleset/IAM + container + supply-chain posture | all ✓ |
| **0.2.0** | Azure & GCP curated baselines + least-privilege roles; **rule-name validation** against the pinned ScoutSuite (offline manifest in CI, installed-source drift gate at release) | policy ✓ |
| **0.3.0** | Deeper report guard (SRI, offline viewer), signed report manifests | report integrity ✓ |
| **0.4.0** | SLSA provenance verification on pull; reproducible-build attestation | supply-chain ✓ |
| **0.5.0** | **ScoutSuite install-integrity gate** — fail-closed preflight that the `scout` on PATH is the pinned, vetted version before running (`--allow-unverified-scout` to override); real hash-pinned `requirements.lock`; pinned `hatchling` build backend. ✓ | supply-chain + runtime trust · lockfile |
| **0.6.0** | **Findings model + severity gate** — parse the `scoutsuite-results` data off disk into a deterministic findings summary; `--fail-on-finding danger\|warning` + standalone `presidio-scout-findings` (fail-closed, exit 4). ✓ | secure-by-default policy |
| **0.7.0** | **SARIF export + code-scanning** — `presidio-scout-export` + `presidio-scout --sarif PATH` emit SARIF 2.1.0 (severity-mapped, per-resource, stable fingerprints); documented `upload-sarif` Action. ✓ | policy / integration · 0.6 |
| **0.8.0** | **Waivers / exceptions framework** — checked-in JSON waivers (rule + resource + justification + owner + **expiry**); applied to the gate/SARIF via `--waivers`; **expired/malformed waivers fail closed**. ✓ | policy · 0.6 |
| **0.9.0** | **Signed run attestation** — an in-toto statement binding inputs (provider, ruleset digest, verified ScoutSuite version) → output (report-manifest digest); `presidio-scout --attest` + `presidio-scout-attest generate/verify`, cosign-signable. ✓ | supply-chain integrity · 0.3, 0.4, 0.5 |
| **0.10.0** | **Drift detection / run diff** — `presidio-scout-diff` over two reports at resource granularity (new vs resolved findings/resources); `--fail-on-new-finding {any,warning,danger}`. ✓ | policy / operational · 0.6, 0.9 |
| **0.11.0** | **Reproducible, multi-arch container + image provenance E2E** — `amd64`+`arm64`, reproducible digests, GitHub-signed provenance; release `verify-image` gate re-verifies the published image (cosign + `gh attestation verify` + `presidio-scout-verify-provenance`). ✓ | supply-chain + deployment · 0.4 |
| **0.12.0** | **Keyless / short-lived credentials** — chose configuration + a fail-closed `--require-short-lived-creds` preflight (reject long-lived static secrets) + keyless-env passthrough + OIDC/assume-role/impersonation docs, over in-wrapper brokering (see deliberation). ✓ | runtime credential safety · iam/ |
| **0.13.0** | **Kubernetes deployment** — hardened `Job`/`CronJob` manifests + Helm chart (IRSA / GKE WI / Azure WI; read-only rootfs, dropped caps, seccomp, default-deny `NetworkPolicy`) under `deploy/`. ✓ | hardened deployment · 0.11, 0.12 |
| **0.14.0** | **Vulnerability-scan gate + SBOM/vuln attestations** — Grype/Trivy gate on fixable criticals; SBOM and vuln report attached as **signed attestations** and verified alongside provenance. | supply-chain · 0.11 |
| **0.15.0** | **Org policy profiles / config** — `.presidio-scout.toml` for org defaults (provider, ruleset, gates, waiver/redaction paths, named profiles) + `presidio-scout-policy` to validate it. | usability / policy · most prior |

**Open design questions (revisit when the version lands):**

- **0.12.0** — resolved: chose configuration + fail-closed preflight (Direction B)
  over in-wrapper brokering. See the v0.12.0 deliberation above.
- **0.15.0** needs `tomllib` (stdlib ≥3.11) or a small `tomli` backport for 3.9/3.10
  — the one place a runtime dependency would creep in.

---

## SDLC

Delivered under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
