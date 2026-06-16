# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.22.x  | ✅ Yes (current) |
| <0.22   | Best-effort security fixes only |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security
Advisory (via the **Security** tab → **Report a vulnerability**) rather than a
public issue.

Include: a description, steps to reproduce, potential impact, and a suggested
fix if you have one. You will receive an acknowledgement within 5 business days;
we aim to ship a patch within 30 days of a confirmed vulnerability.

> Vulnerabilities in **ScoutSuite itself** (the upstream tool we package) should
> also be reported to [NCC Group / ScoutSuite](https://github.com/nccgroup/ScoutSuite).
> We will pull in fixed upstream versions and re-pin `requirements.lock`.

## What this project is

`presidio-hardened-scoutsuite` is a **hardened distribution** of NCC Group's
ScoutSuite. It does **not** modify or import ScoutSuite; it drives the upstream
`scout` CLI **out of process** and wraps it with hardened defaults, report
redaction, supply-chain controls, and a least-privilege deployment model.

## Security Features

- **Hardened invocation (`launcher`)** — provider allowlist; a **fail-closed
  allowlist** of pass-through flags (an unknown/new ScoutSuite flag is rejected,
  not forwarded); forced `--no-browser`; a fixed, **0700** report directory; a
  restrictive `umask` (0077) on the child process.
- **Environment scrubbing** — the ScoutSuite subprocess receives **only** cloud
  credential variables (by known prefix) and a short allowlist of runtime
  essentials. Unrelated secrets in the parent environment never reach the child
  or its logs.
- **Report redaction (`redact`)** — the generated report (`*.js`/`*.json`/
  `*.html`) and ScoutSuite's own stderr are scanned for AWS/Azure/GCP keys,
  private-key blocks, bearer/`Authorization` tokens, etc., and redacted in
  place. `--fail-on-secret` makes a surviving secret a non-zero exit.
- **Report guard (`report_guard`)** — a strict **Content-Security-Policy** is
  injected into every HTML report file (no remote/inline scripts), each local
  `<script>`/stylesheet gets a **Subresource Integrity** (`sha384`) hash so the
  browser refuses a tampered local asset, and any network-reaching reference is
  flagged (`--fail-on-remote-ref` makes one a non-zero exit). A SHA-256
  **integrity manifest** (`presidio-report-manifest.json`) is written for the
  rendered report — self-digested, optionally HMAC-signed
  (`PRESIDIO_MANIFEST_HMAC_KEY`) — and verified offline with
  **`presidio-scout-verify`**, which flags any modified/missing/added file.
- **Secure-by-default rulesets** — curated, CIS-aligned **AWS, Azure, and GCP**
  baselines are applied by default (`--ruleset`), forcing high-impact
  identity/logging/network/storage controls to `danger`. Opt out with
  `--no-baseline`.
- **Ruleset rule-name validation (`ruleset`)** — a baseline references finding
  rules by *filename*; a typo or an upstream rename would make ScoutSuite
  **silently drop** that control. `presidio-scout-validate` checks every
  referenced rule against the pinned ScoutSuite's inventory — offline against a
  checked-in manifest in CI, and against the **installed** ScoutSuite as a
  hard release gate (`verify-rulesets`) so the manifest can't drift unnoticed.
- **Short-lived-credential preflight** — `--require-short-lived-creds` inspects
  the scrubbed environment's credential *shape* and **fails closed** on a
  long-lived static secret (AWS access key without a session token, downloaded
  GCP service-account key, Azure client secret), steering operators onto
  assumed-role / OIDC / impersonation / managed identity. The wrapper does not
  broker credentials itself (it would expand the trusted surface and bloat the
  distroless image) — it relies on ScoutSuite's SDKs for resolution and only
  gates the inputs; the keyless/managed-identity env vars are passed through to
  the child so federated auth works with no stored secret.
- **Least-privilege deployment** — bundled read-only audit identities per cloud:
  AWS (`iam/aws/`: managed read-only policies + supplemental policy with an
  explicit **`Deny` on any non-read action** + **MFA/`ExternalId`** trust),
  Azure (`iam/azure/`: `Reader`+`Security Reader` or a custom `*/read` role with
  **empty `dataActions`** so secret/key values stay unreadable), and GCP
  (`iam/gcp/`: `viewer`+`securityReviewer` or a `*.list`/`*.get`-only custom
  role, via service-account **impersonation** over downloaded keys).
- **Supply-chain integrity** — hash-pinned `requirements.lock`
  (`--require-hashes`), CycloneDX **SBOM**, CodeQL, Dependabot, and
  **cosign-signed** release images with **SLSA build-provenance** attestation.
  The release pipeline **refuses to publish** an image whose lockfile isn't
  hash-pinned. The wheel/sdist build is **reproducible** (pinned
  `SOURCE_DATE_EPOCH`), enforced by a `reproducible-build` CI gate that builds
  twice and requires byte-identical digests.
- **Findings severity gate** — `presidio-scout --fail-on-finding danger|warning`
  (and the standalone `presidio-scout-findings`) reads ScoutSuite's results data
  off disk and exits non-zero (4) when any *flagged* finding is at or above the
  chosen severity, so an audit can block a CI pipeline. Fail-closed: missing or
  unparseable results error out rather than passing a report never evaluated.
- **SARIF export for code scanning** — `presidio-scout --sarif PATH` (and
  `presidio-scout-export`) emits SARIF 2.1.0 so findings become GitHub
  code-scanning alerts; severity-mapped (`danger`→error/8.0, `warning`→warning/4.0)
  with per-resource results and stable fingerprints for cross-run alert tracking.
- **Findings waivers (`--waivers`)** — accepted findings are checked in as data
  with a justification, owner, and mandatory expiry; matching findings are
  suppressed before the gate/SARIF (whole-finding or per-resource). Fail-closed:
  a malformed/missing waiver file errors, and an **expired** waiver stops
  suppressing so the finding resurfaces — exceptions can't silently hide risk
  forever, and every suppression is attributable.
- **Signed run attestation (`--attest`, `presidio-scout-attest`)** — emits an
  in-toto statement whose subject is the report's integrity manifest and whose
  predicate records the run's inputs (provider, ruleset digest, verified
  ScoutSuite version, wrapper version, manifest content digest). Signed as a
  blob with cosign, it is a portable, verifiable record that *this* report was
  produced by *that* provider/ruleset/ScoutSuite; `verify` re-checks the binding
  to the on-disk report.
- **Drift gate (`presidio-scout-diff`)** — diffs a baseline report against a new
  one at resource granularity; `--fail-on-new-finding {any,warning,danger}`
  blocks a pipeline on *newly introduced* findings/resources while ignoring the
  pre-existing, already-triaged backlog — so regressions can't slip in unnoticed.
- **Image build/release integrity** — the release image is multi-arch with
  timestamps pinned to the tagged commit (reproducible digests), `cosign`-signed,
  and carries **GitHub-signed SLSA build provenance**. A `verify-image` release
  gate independently re-verifies the freshly published image end-to-end — the
  signature *and* the provenance (cryptographically, then against this
  distribution's `presidio-scout-verify-provenance` policy) — before the release
  run is allowed to succeed.
- **Posture-regression gate** — `presidio-scout-trend` records each run's flagged
  findings to an append-only history and compares the latest run to the previous
  one; `--fail-on-regression danger|warning` exits non-zero when a *new* finding
  at or above that severity appears, so a pipeline blocks when posture worsens
  even if the absolute count is within an existing waiver budget. Fail-closed: a
  run whose results can't be read is never recorded as clean, and a malformed
  history store errors rather than silently resetting the baseline.
- **Config-driven redaction & baseline composition** — `[redaction].extra-patterns`
  in `.presidio-scout.toml` add org-specific secret redactors that run *alongside*
  the built-ins during report redaction; `[baseline]` composes the ruleset from a
  bundled baseline (raise/lower/add a rule's severity, disable rules). Both are
  **fail-closed**: an uncompilable regex, an unknown baseline rule (not in the
  pinned ScoutSuite's manifest), or a bad severity is rejected by
  `presidio-scout-policy` (and again when a run applies them), so a typo can't
  silently weaken redaction or drop a control.
- **Redaction-aware notification sinks** — `presidio-scout-notify` pushes an
  audit summary to a file, a generic JSON webhook, or Slack. Before anything
  leaves the process the payload is run through the **same secret scanner the
  report redaction uses**; if a secret survives into the message it is **not
  transmitted** (fail-closed). Webhooks use stdlib `urllib` only (non-HTTP(S)
  schemes are refused), so the sink adds no dependency and no new trusted code.
- **Org-wide fleet orchestration** — `presidio-scout-orchestrate` fans the audit
  across a declared `.presidio-scout-targets.toml` matrix, running each account as
  a **separate out-of-process `presidio-scout`** invocation with its own scrubbed
  environment (no ScoutSuite state shared between accounts). It **does not broker
  credentials** (the 0.12.0 decision) — it only selects each target's read-only
  identity via that target's credential-resolution env. **Fail-closed:** a target
  that can't be audited, or whose results can't be read for the aggregated gate,
  fails the fleet run rather than being silently skipped.
- **Compliance mapping (CIS / NIST 800-53 / SOC 2)** — `presidio-scout-compliance`
  expresses flagged findings as **control** failures using curated, checked-in
  rule→control mappings (`policy/<provider>.controls.json`). The mappings are
  validated **fail-closed** against the rule manifest (a mapping that names a rule
  the pinned ScoutSuite doesn't ship errors in CI), and a flagged finding with no
  mapping is surfaced as `unmapped` (`--fail-on-unmapped` makes it a non-zero
  exit) rather than silently dropped — so a control view can't quietly omit risk.
- **AWS Security Hub (ASFF) export** — `presidio-scout-asff` (and `--asff`) emit
  findings in AWS Security Hub Finding Format, enriched with the mapped controls
  as `Compliance.RelatedRequirements`, so the audit feeds Security Hub alongside
  the SARIF code-scanning path. Required identifiers (account id, region) are
  validated fail-closed so a malformed batch can't be emitted.
- **Pinned-version coherence gate + upgrade automation** — the pinned ScoutSuite
  version is declared in several files that must agree (the `scoutsuite` extra,
  `requirements.lock`, the install-integrity fallback constant); drift would let
  a gate silently check against the wrong version. `presidio-scout-upgrade check`
  is a **fail-closed** gate (run on every push by the `pin-coherence` CI job)
  that errors on any disagreement, and `plan`/`apply` make a version bump a
  deterministic, reviewable operation. A scheduled workflow bumps the pin,
  regenerates the hash-pinned lockfile and the rule manifests
  (`presidio-scout-validate --regenerate`), runs every gate, and opens a PR —
  so staying current is reviewed, not silent drift, and never auto-merged.
- **ScoutSuite install-integrity gate** — before any cloud credentials are
  handed to ScoutSuite, a fail-closed preflight (`scout_integrity`) confirms the
  `scout` on PATH is the **pinned, vetted version** this distribution ships;
  an unexpected, newer, or modified ScoutSuite (which could carry different
  rules or behaviour) is refused (exit 2) unless `--allow-unverified-scout` is
  given. Complements the install-time artifact-hash guarantee from
  `pip install --require-hashes -r requirements.lock`.
- **Vulnerability-scan gate** — before a release is accepted, the locked runtime
  tree is audited (`pip-audit`) and the published image is scanned (Trivy); the
  scan is gated by `presidio-scout-vuln-gate`, which **fails closed** on any
  *fixable* vulnerability at or above a chosen severity (Trivy *or* Grype JSON).
  A **signed CycloneDX SBOM** is attached to the image (GitHub attestation) and
  re-verified alongside the provenance in the `verify-image` gate — so the
  release records, and re-checks, exactly what shipped and that it was scanned.
- **Provenance policy verification** — `presidio-scout-verify-provenance` checks
  a *cryptographically verified* SLSA provenance statement (from `cosign
  verify-attestation`) against this distribution's policy: the expected builder
  identity, source repository, predicate type, and the specific artifact digest.
  It is a fail-closed **policy gate**, not signature verification — so an
  authentic-but-wrong attestation (right signer, wrong source/builder/digest) is
  still rejected.
- **Hardened container** — distroless, **non-root**, designed to run with
  `--read-only --tmpfs /tmp`; ships no shell or package manager.
- **Hardened Kubernetes deployment** ([`deploy/`](./deploy/)) — `Job`/`CronJob`
  manifests and a Helm chart that run the signed image as a least-privilege
  **workload-identity** ServiceAccount (no long-lived keys), with
  `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`,
  `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`,
  `automountServiceAccountToken: false`, and a default-deny `NetworkPolicy`
  (egress limited to DNS + 443). A guardrail test fails closed if any of these
  controls is dropped from the manifests.

## Data Handling & Trust Boundaries

- **Collected cloud configuration is sensitive.** ScoutSuite pulls real account
  configuration into the report directory. We lock that directory to `0700`,
  redact secrets out of it, and `.gitignore` `scoutsuite-report/` /
  `scoutsuite-results/` so it is never accidentally committed. Treat the report
  as confidential.
- **Cloud credentials come from the environment only** — never the command line,
  never logged. Use the bundled least-privilege **read-only** audit role; the
  role's explicit `Deny` ensures ScoutSuite can never mutate your account.
- **The HTML report is treated as untrusted output.** Finding strings can echo
  attacker-influenced resource names/tags; the injected CSP and the secret scan
  reduce the blast radius of opening a report in a browser.
- **No telemetry.** Nothing phones home. The only outbound traffic is
  ScoutSuite's authenticated calls to your cloud provider's APIs.

## Licensing note

This wrapper is **MIT**; ScoutSuite is **GPL-2.0-only** and is installed
separately (or bundled into the container image). See
[`LICENSES/README.md`](./LICENSES/README.md) for redistribution obligations.

## Dependency Management

- Dependabot keeps Python, GitHub Actions, and Docker base images current.
- CodeQL (`security-extended`) runs on every push and pull request.
- The container/runtime lockfile is audited with `pip-audit` before image
  release; new images are not published while known vulnerabilities remain in
  the bundled ScoutSuite dependency tree.
- A checked-in `.presidio-scout.toml` (defaults + named profiles) lets a team
  enforce the hardened gates by default across every pipeline;
  `presidio-scout-policy validate` fail-closed-checks it so a typo in org policy
  errors rather than silently disabling a control.
- All changes require passing CI (pytest + ruff) before merge.

## Responsible Disclosure

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure)
and will credit researchers who report responsibly (with permission).

## Software Development Lifecycle

Developed under the Presidio hardened-family SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
