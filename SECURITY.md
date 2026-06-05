# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅ Yes (current) |

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
  injected into every HTML report file (no remote/inline scripts), and a
  SHA-256 **integrity manifest** is recorded for the rendered report.
- **Secure-by-default ruleset** — a curated, CIS-aligned AWS baseline is applied
  by default (`--ruleset`), forcing high-impact IAM/logging/network controls to
  `danger`. Opt out with `--no-baseline`.
- **Least-privilege deployment** — bundled AWS audit role (`iam/aws/`): the two
  managed read-only policies plus a supplemental policy with an explicit
  **`Deny` on any non-read action**, and a trust policy requiring **MFA + a
  random `ExternalId`**.
- **Supply-chain integrity** — hash-pinned `requirements.lock`
  (`--require-hashes`), CycloneDX **SBOM**, CodeQL, Dependabot, and
  **cosign-signed** release images with build **provenance** attestation. The
  release pipeline **refuses to publish** an image whose lockfile isn't
  hash-pinned.
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
