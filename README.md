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
| **Report integrity & isolation** | Strict CSP + **Subresource Integrity** on local report assets; remote-reference detection (`--fail-on-remote-ref`); a signed-able **SHA-256 integrity manifest** verified offline with `presidio-scout-verify` |
| **Secure-by-default policy** | Curated, CIS-aligned **AWS baseline ruleset** applied by default (high-impact IAM/logging/network controls forced to `danger`) |
| **Supply-chain & build integrity** | Hash-pinned `requirements.lock`, pinned build backend, CycloneDX SBOM, CodeQL, Dependabot, **cosign-signed** images + SLSA build provenance, **reproducible** wheel/sdist, a `presidio-scout-verify-provenance` policy gate for what you pull, and a **fail-closed preflight that the `scout` you run is the pinned, vetted ScoutSuite version** |
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
2. **preflight** — before any credentials are handed over, a fail-closed gate
   confirms the `scout` on PATH is the **pinned, vetted ScoutSuite version**; an
   unexpected/modified ScoutSuite is refused (override: `--allow-unverified-scout`).
3. **subprocess** — stock ScoutSuite runs with only the cloud credentials it
   needs.
4. **redact** — credentials are scrubbed out of the report files and ScoutSuite's
   own output.
5. **report_guard** — a strict CSP and per-asset Subresource Integrity hashes
   are injected into the HTML report, network-reaching references are flagged,
   and a SHA-256 integrity manifest (`presidio-report-manifest.json`,
   optionally HMAC-signed) is written so the report can be verified later with
   `presidio-scout-verify`.

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
presidio-scout aws --fail-on-remote-ref     # non-zero exit if the report references a remote resource
presidio-scout aws --no-baseline            # use ScoutSuite's default ruleset instead
presidio-scout aws --allow-unverified-scout # run even if scout isn't the pinned version (warns)
presidio-scout aws --dry-run                # print the hardened command, run nothing
presidio-scout azure                        # Azure audit with the hardened Azure baseline
presidio-scout gcp                          # GCP audit with the hardened GCP baseline
```

AWS, Azure, and GCP each ship a curated baseline; other providers fall back to
ScoutSuite's default ruleset (with a warning) until their baselines land.

Anything after `--` is forwarded to ScoutSuite **only if it's on the
pass-through allowlist** (`--profile`, `--region(s)`, `--services`, `--skip`,
`--max-rate`, …). Flags the launcher owns (`--report-dir`, `--ruleset`,
`--no-browser`) and unknown flags are rejected with exit code 2 — a new upstream
flag can't silently weaken a run until it's vetted and added.

Exit codes: `0` ok · `2` invalid invocation / `scout` not found / unverified
ScoutSuite · `3` report guard failure (e.g. `--fail-on-secret`).

---

## Library usage

```python
from presidio_scoutsuite import build_plan, run, redact_report_dir, guard_report

plan = build_plan("aws", "scoutsuite-report", ruleset="src/presidio_scoutsuite/policy/aws-cis.json")
print(plan.redacted_command())          # scout aws --no-browser --report-dir … --ruleset …

result = run(plan)                      # subprocess.CompletedProcess
redact_report_dir(plan.report_dir)      # scrub secrets out of the report
guard = guard_report(plan.report_dir)   # CSP + SRI + write integrity manifest
print(len(guard.manifest), "files;", len(guard.sri_hardened), "SRI-pinned")
```

---

## Report integrity & verification

Every guarded report carries `presidio-report-manifest.json`: a SHA-256 over
each file plus a self-digest of those hashes. Verify a report offline — no
ScoutSuite, no network — at any later point:

```bash
presidio-scout-verify ./scoutsuite-report
# ok   verified 214 file(s) in scoutsuite-report
```

The verifier re-hashes the tree and reports any **modified**, **missing**, or
**added** file, and detects edits to the manifest's own recorded hashes. Exit
codes: `0` verified · `3` tampered/mismatch · `2` no usable manifest.

**Signing.** Two layers, both optional and independent of the always-on hashes:

- **HMAC (pipeline integrity).** Set `PRESIDIO_MANIFEST_HMAC_KEY` and the
  manifest gains an HMAC-SHA256 signature; verification on a host with the same
  key confirms the manifest came from your pipeline. Symmetric — proves
  provenance within a trust boundary you control, not non-repudiation.
- **Detached cosign (distribution).** For third-party verification, sign the
  manifest *blob* out of band exactly as the release pipeline signs images:
  `cosign sign-blob scoutsuite-report/presidio-report-manifest.json`.

Beyond the manifest, the guard makes the static report **safe to open and fully
offline**: a strict CSP (`default-src 'none'`, no remote/inline script),
Subresource Integrity on every local `<script>`/stylesheet (the browser refuses
a tampered local asset), and detection of any network-reaching reference
(`--fail-on-remote-ref` turns one into a non-zero exit).

---

## Verifying what you pull

Release artifacts carry **SLSA build provenance** (the container image is
`cosign`-signed with `provenance: mode=max`; the PyPI wheel ships attestations),
and the wheel/sdist are a **reproducible** function of the source.

A signature only proves an attestation is *authentic* — you still have to check
it *says the right thing*. `presidio-scout-verify-provenance` is that policy
gate, run **after** `cosign` has cryptographically verified the attestation:

```bash
# 1. cosign verifies the signature + transparency-log entry (crypto + network)
cosign verify-attestation --type slsaprovenance \
  --certificate-identity-regexp '^https://github.com/presidio-v/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/presidio-v/presidio-hardened-scoutsuite@sha256:DIGEST \
  --output text > prov.jsonl

# 2. presidio enforces the policy: built by this repo's CI, from this source,
#    for this exact digest (exit 0 verified · 3 policy mismatch · 2 unparseable)
presidio-scout-verify-provenance prov.jsonl --digest sha256:DIGEST
```

It understands both SLSA provenance `v0.2` (buildx) and `v1` (slsa-github-generator)
predicates, and checks the **builder identity**, **source repository**,
**predicate type**, and that the **artifact digest** is actually attested.
Override the expected source/builder with `--source-uri` / `--builder-id-prefix`.

**Reproducible build.** Builds are pinned to the tagged commit's timestamp
(`SOURCE_DATE_EPOCH`), so anyone can rebuild from the same commit and confirm
the **wheel** is byte-identical to what was published — and CI fails the
`reproducible-build` job if two builds diverge:

```bash
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) python -m build
sha256sum dist/*.whl          # compare against the published wheel's digest
```

(The `.tar.gz` sdist is reproducible at the *content* level; its gzip container
carries an mtime that isn't part of the archived files, so compare it with
`gzip -dc dist/*.tar.gz | sha256sum` rather than the raw bytes — which is exactly
what the CI gate does.)

---

## Least-privilege audit identities

ScoutSuite needs broad **read-only** access. Bundled, ready-to-apply identities
grant exactly that and nothing else, per cloud:

- **AWS** ([`iam/aws/`](./iam/aws/)) — the two managed read-only policies, a
  supplemental read policy with an explicit `Deny` on any non-read action, and a
  trust policy requiring MFA + a random `ExternalId`.
- **Azure** ([`iam/azure/`](./iam/azure/)) — `Reader` + `Security Reader` (or a
  custom `*/read` role with **no `dataActions`**, so secret/key values stay
  unreadable), plus minimal directory read for the Azure AD findings.
- **GCP** ([`iam/gcp/`](./iam/gcp/)) — `roles/viewer` +
  `roles/iam.securityReviewer` (or a custom role listing only `*.list`/`*.get`
  permissions), assumed via service-account **impersonation** over a downloaded
  key.

---

## Curated rulesets

Curated baselines ship for **AWS, Azure, and GCP** under
[`src/presidio_scoutsuite/policy/`](./src/presidio_scoutsuite/policy/)
(`aws-cis.json`, `azure-cis.json`, `gcp-cis.json`). Each enables a CIS-aligned
subset of ScoutSuite's findings and elevates the high-impact ones to `danger`.
Override with `--ruleset PATH` or opt out with `--no-baseline`.

A ruleset's keys are the **filenames** of finding rules that live inside
ScoutSuite. If a baseline names a rule the pinned ScoutSuite doesn't ship (a typo
or an upstream rename), ScoutSuite silently drops that control. To catch that,
each provider ships a rule-name inventory (`policy/<provider>.rules.txt`) tracking
the pinned upstream version, and a validator checks the baselines against it:

```bash
presidio-scout-validate                  # offline: baselines ⊆ checked-in manifests (runs in CI)
presidio-scout-validate --source installed   # release: baselines ⊆ the installed ScoutSuite
```

CI runs the offline check on every push; the release pipeline runs the
`installed` check against the pinned ScoutSuite so the manifest can't drift from
upstream unnoticed. Regenerate a manifest with
`ruleset.installed_rules("<provider>")` (see the header of each `.rules.txt`).

---

## Roadmap

| Version | Highlights |
|---|---|
| **0.1.0** | Out-of-process hardened launcher, report redaction + guard, AWS-first curated ruleset + least-privilege IAM, hardened container, full supply-chain posture |
| **0.2.0** | Azure + GCP curated baselines & least-privilege IAM; ruleset rule-name validation against the pinned ScoutSuite (offline manifest in CI, installed-source drift check at release) |
| **0.3.0** | Deeper report guard — Subresource Integrity on local assets, offline-viewer (remote-reference) enforcement, and a signed-able, offline-verifiable report manifest (`presidio-scout-verify`) |
| **0.4.0** | SLSA build-provenance policy verification (`presidio-scout-verify-provenance`, v0.2 + v1) and a reproducible wheel/sdist with a `reproducible-build` CI gate |
| **0.5.0** | ScoutSuite install-integrity gate — fail-closed preflight that the `scout` you run is the pinned, vetted version (`--allow-unverified-scout` to override); real hash-pinned `requirements.lock`; pinned build backend |
| **0.6.0** _(planned)_ | Findings model + severity gate (`--fail-on-finding danger\|warning`) parsed from the report data |
| **0.7.0** _(planned)_ | SARIF export + GitHub code-scanning integration (`presidio-scout-export`) |
| **0.8.0** _(planned)_ | Waivers / exceptions framework with justification + owner + expiry (expired waivers fail closed) |
| **0.9.0** _(planned)_ | Signed run attestation — in-toto statement binding run inputs to the report-manifest digest |
| **0.10.0** _(planned)_ | Drift detection / run diff (`presidio-scout-diff`, `--fail-on-new-finding`) |
| **0.11.0** _(planned)_ | Reproducible, multi-arch container + end-to-end image provenance verification at release |
| **0.12.0** _(planned)_ | Credential brokering / keyless auth — auto-assume the bundled least-privilege audit role; OIDC in CI |
| **0.13.0** _(planned)_ | Kubernetes deployment — least-privilege Job/CronJob + Helm (IRSA / Workload Identity), seccomp, egress policy |
| **0.14.0** _(planned)_ | Vulnerability-scan gate + signed SBOM/vuln attestations verified alongside provenance |
| **0.15.0** _(planned)_ | Org policy profiles / config (`.presidio-scout.toml`, `presidio-scout-policy`) |

See [`PRESIDIO-REQ.md`](./PRESIDIO-REQ.md) for the per-version rationale,
dependencies, and open design questions.

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
│   ├── report_guard.py    # CSP + SRI injection, remote-ref detection, manifest write
│   ├── manifest.py        # integrity-manifest shape, self-digest, HMAC signing
│   ├── verify.py          # offline report verification (presidio-scout-verify)
│   ├── provenance.py      # SLSA provenance policy gate (presidio-scout-verify-provenance)
│   ├── ruleset.py         # baseline rule-name validation (presidio-scout-validate)
│   ├── cli.py             # presidio-scout entrypoint
│   ├── errors.py          # exception hierarchy
│   └── policy/            # curated baselines + rule manifests + provenance-policy.json
├── iam/{aws,azure,gcp}/   # least-privilege audit identities per cloud
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
