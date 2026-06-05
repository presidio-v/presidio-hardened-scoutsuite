# presidio-hardened-scoutsuite

[![CI](https://github.com/presidio-v/presidio-hardened-scoutsuite/actions/workflows/ci.yml/badge.svg)](https://github.com/presidio-v/presidio-hardened-scoutsuite/actions/workflows/ci.yml)
[![CodeQL](https://github.com/presidio-v/presidio-hardened-scoutsuite/actions/workflows/codeql.yml/badge.svg)](https://github.com/presidio-v/presidio-hardened-scoutsuite/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

A Presidio security-hardened **distribution of [ScoutSuite](https://github.com/nccgroup/ScoutSuite)**,
NCC Group's multi-cloud security auditing tool.

> **Wrapper, not a fork.** ScoutSuite is **GPL-2.0**. Rather than fork or import
> it, this project drives the upstream `scout` CLI **out of process** and wraps
> it with hardened defaults, report redaction, supply-chain integrity, and a
> least-privilege deployment model. That keeps the wrapper a separate,
> non-derivative work — so *this* code is **MIT** — while you still run stock,
> trusted-upstream ScoutSuite underneath. See
> [`LICENSES/README.md`](./LICENSES/README.md).

---

## What "hardened" means here

| Axis | What you get |
|---|---|
| **Runtime credential & data safety** | Env scrubbed to cloud creds only; 0700 report dir + `umask 0077`; secrets redacted out of the report and ScoutSuite's logs; `--fail-on-secret` gate |
| **Secure-by-default policy** | Curated, CIS-aligned **AWS baseline ruleset** applied by default (high-impact IAM/logging/network controls forced to `danger`) |
| **Supply-chain & build integrity** | Hash-pinned `requirements.lock`, CycloneDX SBOM, CodeQL, Dependabot, **cosign-signed** images + build provenance; release blocked if the lock isn't pinned |
| **Hardened deployment** | Distroless, non-root, `--read-only` container; bundled **least-privilege AWS audit role** (read-only + explicit `Deny`, MFA + `ExternalId` trust) |

---

## How it works

```
presidio-scout aws ──▶ launcher ──▶ [ scout aws … ] ──▶ redact ──▶ report_guard ──▶ report/
                       (validate     (subprocess;       (scrub      (CSP + integrity
                        + harden)     env-scoped)        secrets)     manifest)
```

1. **launcher** — validates the provider + pass-through flags (fail-closed
   allowlist), forces `--no-browser` and a locked-down `--report-dir`, wires in
   the curated ruleset, and scrubs the environment.
2. **subprocess** — stock ScoutSuite runs with only the cloud credentials it
   needs.
3. **redact** — credentials are scrubbed out of the report files and ScoutSuite's
   own output.
4. **report_guard** — a strict CSP is injected into the HTML report and a
   SHA-256 integrity manifest is recorded.

---

## Install

The wrapper has **no runtime dependencies** and never imports ScoutSuite. You
supply `scout` yourself (recommended: a pinned virtualenv or the container).

```bash
pip install presidio-hardened-scoutsuite          # wrapper only (MIT)

# Convenience extra that also installs ScoutSuite (GPL-2.0) into your env:
pip install 'presidio-hardened-scoutsuite[scoutsuite]'
```

Or use the hardened container (bundles a pinned ScoutSuite):

```bash
docker run --rm --read-only --tmpfs /tmp \
  -e AWS_PROFILE=auditor \
  -v "$HOME/.aws:/tmp/.aws:ro" \
  -v "$PWD/scoutsuite-report:/report" \
  ghcr.io/presidio-v/presidio-hardened-scoutsuite:latest \
  aws --report-dir /report
```

---

## CLI usage

```bash
presidio-scout aws                          # audit AWS with the hardened defaults
presidio-scout aws --report-dir ./out       # choose the (0700) report directory
presidio-scout aws -- --profile auditor     # pass-through flags after '--' (allowlisted)
presidio-scout aws --fail-on-secret         # non-zero exit if a secret survives redaction
presidio-scout aws --no-baseline            # use ScoutSuite's default ruleset instead
presidio-scout aws --dry-run                # print the hardened command, run nothing
presidio-scout azure                        # other providers (no curated baseline yet → warns)
```

Anything after `--` is forwarded to ScoutSuite **only if it's on the
pass-through allowlist** (`--profile`, `--region(s)`, `--services`, `--skip`,
`--max-rate`, …). Flags the launcher owns (`--report-dir`, `--ruleset`,
`--no-browser`) and unknown flags are rejected with exit code 2 — a new upstream
flag can't silently weaken a run until it's vetted and added.

Exit codes: `0` ok · `2` invalid invocation / `scout` not found · `3` report
guard failure (e.g. `--fail-on-secret`).

---

## Library usage

```python
from presidio_scoutsuite import build_plan, run, redact_report_dir, guard_report

plan = build_plan("aws", "scoutsuite-report", ruleset="src/presidio_scoutsuite/policy/aws-cis.json")
print(plan.redacted_command())          # scout aws --no-browser --report-dir … --ruleset …

result = run(plan)                      # subprocess.CompletedProcess
redact_report_dir(plan.report_dir)      # scrub secrets out of the report
guard = guard_report(plan.report_dir)   # inject CSP + build integrity manifest
print(len(guard.manifest), "files;", len(guard.html_hardened), "HTML hardened")
```

---

## Least-privilege AWS role

ScoutSuite needs broad **read-only** access. The bundled role under
[`iam/aws/`](./iam/aws/) grants exactly that and **nothing else**: the two AWS
managed read-only policies, a supplemental read policy with an explicit `Deny`
on any non-read action, and a trust policy requiring MFA + a random `ExternalId`.
See [`iam/aws/README.md`](./iam/aws/README.md).

---

## Curated ruleset

The default AWS baseline lives at
[`src/presidio_scoutsuite/policy/aws-cis.json`](./src/presidio_scoutsuite/policy/aws-cis.json).
It enables a CIS-aligned subset of ScoutSuite's AWS findings and elevates the
high-impact ones to `danger`. Rule filenames track the **pinned** upstream
ScoutSuite version in `requirements.lock`. Override with `--ruleset PATH` or opt
out with `--no-baseline`.

---

## Roadmap

| Version | Highlights |
|---|---|
| **0.1.0** | Out-of-process hardened launcher, report redaction + guard, AWS-first curated ruleset + least-privilege IAM, hardened container, full supply-chain posture |
| **0.2.0** _(planned)_ | Azure + GCP curated rulesets & IAM; ruleset rule-name validation against the pinned ScoutSuite in CI |
| **0.3.0** _(planned)_ | Deeper report guard (subresource integrity, offline viewer), signed report manifests |
| **0.4.0** _(planned)_ | SLSA provenance verification on pull; reproducible-build attestation |

---

## Running tests

```bash
pip install -e ".[dev]"
pytest --cov=presidio_scoutsuite --cov-report=term-missing
ruff check . && ruff format --check .
```

Tests run **without ScoutSuite installed** — the subprocess boundary is injected.

---

## Project structure

```
presidio-hardened-scoutsuite/
├── src/presidio_scoutsuite/
│   ├── launcher.py        # build/run the hardened scout subprocess
│   ├── redact.py          # secret detection + in-place redaction
│   ├── report_guard.py    # CSP injection + integrity manifest
│   ├── cli.py             # presidio-scout entrypoint
│   ├── errors.py          # exception hierarchy
│   └── policy/aws-cis.json   # curated AWS baseline ruleset
├── iam/aws/               # least-privilege audit role + trust policy
├── tests/
├── Dockerfile             # distroless, non-root
├── requirements.lock      # hash-pinned runtime tree (incl. ScoutSuite)
├── .github/workflows/     # ci, codeql, sbom, release (cosign + provenance)
├── LICENSE                # MIT (this wrapper)
└── LICENSES/README.md     # GPL-2.0 notice for bundled ScoutSuite
```

---

## License

MIT for this wrapper — see [LICENSE](./LICENSE). It bundles/installs ScoutSuite
(GPL-2.0-only) separately; see [LICENSES/README.md](./LICENSES/README.md).

## Security

See [SECURITY.md](./SECURITY.md).

## SDLC

Developed under the Presidio hardened-family SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
