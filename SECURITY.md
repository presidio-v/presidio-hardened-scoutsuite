# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | ✅ Yes (current) |
| 0.1.x   | ✅ Yes |

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
- **Provenance policy verification** — `presidio-scout-verify-provenance` checks
  a *cryptographically verified* SLSA provenance statement (from `cosign
  verify-attestation`) against this distribution's policy: the expected builder
  identity, source repository, predicate type, and the specific artifact digest.
  It is a fail-closed **policy gate**, not signature verification — so an
  authentic-but-wrong attestation (right signer, wrong source/builder/digest) is
  still rejected.
- **Hardened container** — distroless, **non-root**, designed to run with
  `--read-only --tmpfs /tmp`; ships no shell or package manager.

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
- All changes require passing CI (pytest + ruff) before merge.

## Responsible Disclosure

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure)
and will credit researchers who report responsibly (with permission).

## Software Development Lifecycle

Developed under the Presidio hardened-family SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
