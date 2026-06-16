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
| **Supply-chain & build integrity** | Hash-pinned `requirements.lock`, pinned build backend, CycloneDX SBOM, CodeQL, Dependabot, **cosign-signed** images + SLSA build provenance, **reproducible** wheel/sdist, a `presidio-scout-verify-provenance` policy gate for what you pull, a **fail-closed preflight that the `scout` you run is the pinned, vetted ScoutSuite version**, and a release **vulnerability-scan gate** (`pip-audit` + Trivy + `presidio-scout-vuln-gate`) with **signed SBOM/provenance attestations** |
| **Hardened deployment** | Distroless, non-root, `--read-only` container; bundled **least-privilege AWS audit role** (read-only + explicit `Deny`, MFA + `ExternalId` trust); hardened Kubernetes `Job`/`CronJob` + Helm chart (workload identity, read-only rootfs, dropped caps, seccomp, default-deny `NetworkPolicy`) |

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
presidio-scout aws --fail-on-finding danger # exit 4 if any flagged finding is danger (gate a pipeline)
presidio-scout aws --sarif results.sarif    # also emit SARIF for GitHub code scanning
presidio-scout aws --waivers waivers.json --fail-on-finding danger  # suppress accepted findings
presidio-scout aws --attest run.intoto.json # emit a signed-able run attestation
presidio-scout aws --require-short-lived-creds  # refuse to run with long-lived static keys
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
ScoutSuite · `3` report guard failure (e.g. `--fail-on-secret`) · `4` findings
severity threshold exceeded (`--fail-on-finding`).

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

### Signed run attestation

`presidio-scout aws --attest run.intoto.json` (or `presidio-scout-attest
generate`) emits an **in-toto statement about the run itself**: its subject is
the report's integrity manifest (by SHA-256), and its predicate records the
inputs — provider, the curated ruleset's digest, the verified ScoutSuite
version, this wrapper's version, the manifest's content digest, and finding
counts. Sign it as a blob for a complete, portable record:

```bash
cosign sign-blob run.intoto.json --output-signature run.intoto.json.sig
presidio-scout-attest verify ./scoutsuite-report run.intoto.json  # binding check
```

This chains the layers: report files → manifest (`presidio-scout-verify`) →
attestation subject (this) → signature. `presidio-scout-attest verify` confirms
the statement still describes the report on disk (subject + manifest digest
match); cosign confirms the signature. Together they prove *this exact report
was produced by this provider, with this ruleset, by this vetted ScoutSuite.*

---

## Gating a pipeline on findings

ScoutSuite writes machine-readable results next to the report; the wrapper reads
that data (it's data, not ScoutSuite code) and turns the **flagged** findings
(`flagged_items > 0`) into a severity-ranked model. Use it to fail a pipeline on
the audit result — inline during a run, or after the fact:

```bash
presidio-scout aws --fail-on-finding danger      # exit 4 if any danger-level finding fired
presidio-scout-findings ./scoutsuite-report      # summarize an existing report
presidio-scout-findings ./scoutsuite-report --fail-on warning --format json
# findings [aws]: 7 flagged (danger=2, warning=5)
```

Levels rank `danger > warning`; `--fail-on <level>` trips on anything **at or
above** it. The gate is **fail-closed**: if the results data is missing or
unparseable it errors (exit 2) rather than passing a report it never evaluated.

### Waiving accepted findings

Findings an org has reviewed and consciously accepted are checked in as data —
each with a **justification**, an **owner**, and a mandatory **expiry** — instead
of being hidden by weakening the ruleset:

```json
{
  "waivers": [
    { "rule": "s3/s3-bucket-world-acl", "resource": "s3.buckets.public-assets",
      "justification": "Public static-site bucket, reviewed in TICKET-123",
      "owner": "web-platform@example.com", "expires": "2026-12-31" }
  ]
}
```

`presidio-scout aws --waivers waivers.json` (also on `presidio-scout-findings`
and `presidio-scout-export`) suppresses matching findings before the gate and
SARIF output. Omit `resource` (or use `"*"`) to waive the whole finding; a
resource pattern (`fnmatch`) waives only those resources and the finding
survives with a reduced count if any flagged resource is left unwaived.
**Fail-closed:** a malformed/missing waiver file errors, and an **expired**
waiver stops suppressing — the finding resurfaces (and is reported) — so risk
can't be hidden indefinitely.

### GitHub code scanning (SARIF)

Export the flagged findings as **SARIF 2.1.0** so they surface as code-scanning
**alerts** (tracked and triageable in the Security tab) — inline during a run
(`--sarif PATH`) or from an existing report (`presidio-scout-export`):

```yaml
# .github/workflows/cloud-audit.yml (excerpt)
- run: presidio-scout aws --report-dir ./report --sarif results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

`danger` maps to SARIF `error` (`security-severity` 8.0 / high), `warning` to
`warning` (4.0 / medium); each flagged resource becomes a result with a stable
fingerprint so GitHub tracks the same alert across runs.

### Tracking drift between runs

Gating on the absolute set of findings is noisy when there's a known,
already-triaged backlog. `presidio-scout-diff` compares a **baseline** report to
a **current** one and reports only what *changed* — so a pipeline can block
*regressions* while ignoring pre-existing findings:

```bash
presidio-scout-diff ./baseline-report ./scoutsuite-report --fail-on-new-finding danger
# drift: +1 new finding(s), +2 new resource(s); -3 resolved finding(s), -0 resolved resource(s)
```

It diffs at **resource granularity**, distinguishing a brand-new finding from an
existing finding that started flagging an additional resource, and from
resolved findings/resources. `--fail-on-new-finding {any,warning,danger}` exits
`4` when a *newly* flagged occurrence is at or above the chosen severity
(`--format json` for the full structured delta).

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
predicates — and reads a bare statement, a DSSE envelope, cosign's JSON-Lines, or
the output of `gh attestation verify --format json` — and checks the **builder
identity**, **source repository**, **predicate type**, and that the **artifact
digest** is actually attested. Override the expected source/builder with
`--source-uri` / `--builder-id-prefix`.

**Container image.** The released image is **multi-arch** (`linux/amd64` +
`linux/arm64`) with timestamps pinned to the tagged commit (reproducible
digests), `cosign`-signed, and carries GitHub-signed SLSA build provenance. The
release pipeline re-verifies the freshly published image end-to-end before the
run is marked good; you can do the same:

```bash
cosign verify ghcr.io/presidio-v/presidio-hardened-scoutsuite@sha256:DIGEST \
  --certificate-identity-regexp '^https://github.com/presidio-v/.*release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/presidio-v/presidio-hardened-scoutsuite@sha256:DIGEST \
  --repo presidio-v/presidio-hardened-scoutsuite --format json \
  | presidio-scout-verify-provenance - --digest sha256:DIGEST
# a signed CycloneDX SBOM is attached too:
gh attestation verify oci://ghcr.io/presidio-v/presidio-hardened-scoutsuite@sha256:DIGEST \
  --repo presidio-v/presidio-hardened-scoutsuite --predicate-type https://cyclonedx.org/bom
```

**Vulnerability gate.** Before a release is accepted, the locked dependency tree
is audited (`pip-audit`) and the published image is scanned (Trivy); the scan is
gated by `presidio-scout-vuln-gate`, which fails closed on any **fixable**
vulnerability at or above a chosen severity. It reads a Trivy *or* Grype JSON
report, so you can run the same gate locally:

```bash
trivy image --format json ghcr.io/presidio-v/presidio-hardened-scoutsuite:vX > scan.json
presidio-scout-vuln-gate scan.json --fail-on critical --ignore-unfixed   # exit 4 if any remain
```

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

## Keyless / short-lived credentials

The wrapper doesn't broker credentials itself — ScoutSuite's bundled cloud SDKs
already resolve assumed roles, OIDC, impersonation, and managed identity. What it
adds is a **fail-closed preflight**: `presidio-scout … --require-short-lived-creds`
refuses to run when the (scrubbed) environment carries a **long-lived static
secret** — an AWS access key with no session token, a downloaded GCP
service-account key, or an Azure client secret — pushing you onto short-lived
credentials that pair with the bundled audit roles. Without the flag, a static
secret is allowed but **warned** about. (An "unknown" posture — e.g. an
`AWS_PROFILE` that may itself assume a role — never blocks.)

Recommended keyless setups:

- **AWS** — a profile that assumes the audit role (`role_arn` + `source_profile`
  + `mfa_serial` + `external_id`) so the SDK vends temporary creds; or, in CI,
  GitHub OIDC → `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE` (no stored keys).
- **GCP** — service-account **impersonation**
  (`CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT`) or Workload Identity Federation
  (`external_account`), never a downloaded key.
- **Azure** — **managed identity** (`IDENTITY_ENDPOINT`/`MSI_ENDPOINT`, passed
  through to the child) or workload-identity federation
  (`AZURE_FEDERATED_TOKEN_FILE`), not a client secret.

```yaml
# CI: GitHub OIDC → assume the AWS audit role, then run with no long-lived keys
permissions: { id-token: write, contents: read }
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::<acct>:role/presidio-scoutsuite-auditor
      aws-region: us-east-1
  - run: presidio-scout aws --report-dir ./report --require-short-lived-creds
```

---

## Run in Kubernetes

Hardened in-cluster manifests and a Helm chart live under
[`deploy/`](./deploy/): a one-shot `Job` or scheduled `CronJob` that runs the
signed image as a least-privilege **workload-identity** ServiceAccount (no
long-lived keys), with `readOnlyRootFilesystem`, all capabilities dropped,
`seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`, a
default-deny `NetworkPolicy` (egress only DNS + 443), and `--fail-on-finding
danger` so a finding fails the Job.

```bash
kubectl apply -f deploy/kubernetes/          # annotate serviceaccount.yaml for your cloud first
# or, with Helm:
helm install nightly deploy/helm/presidio-scout \
  --set provider=aws --set schedule="0 6 * * *" \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::<acct>:role/presidio-scoutsuite-auditor
```

See [`deploy/kubernetes/README.md`](./deploy/kubernetes/README.md) for per-cloud
workload-identity annotations (IRSA / GKE WI / Azure WI) and NetworkPolicy
tightening.

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
| **0.6.0** | Findings model + severity gate — `presidio-scout --fail-on-finding danger\|warning` and the standalone `presidio-scout-findings`, parsed from the report data (fail-closed; exit 4) |
| **0.7.0** | SARIF export + GitHub code-scanning — `presidio-scout-export` and `presidio-scout --sarif PATH` emit SARIF 2.1.0 (severity-mapped, per-resource, stable fingerprints) |
| **0.8.0** | Waivers / exceptions framework — checked-in JSON waivers (justification + owner + expiry; resource-level globs), applied to the gate/SARIF via `--waivers`; expired/malformed waivers fail closed |
| **0.9.0** | Signed run attestation — in-toto statement binding run inputs (provider, ruleset digest, ScoutSuite version) to the report-manifest digest; `presidio-scout --attest` + `presidio-scout-attest generate/verify` |
| **0.10.0** | Drift detection / run diff — `presidio-scout-diff` compares two reports at resource granularity (new vs resolved findings), with `--fail-on-new-finding {any,warning,danger}` |
| **0.11.0** | Reproducible, multi-arch (`amd64`+`arm64`) container; GitHub-signed image provenance; a release `verify-image` gate that re-checks the signature + provenance (cosign + `presidio-scout-verify-provenance`) end-to-end |
| **0.12.0** | Keyless / short-lived credentials — a fail-closed `--require-short-lived-creds` preflight that rejects long-lived static secrets, keyless/managed-identity env passthrough, and OIDC/assume-role/impersonation setup docs (chose configuration + preflight over in-wrapper brokering) |
| **0.13.0** | Kubernetes deployment — hardened `Job`/`CronJob` + Helm chart (workload identity, read-only rootfs, dropped caps, seccomp, default-deny `NetworkPolicy`) under `deploy/` |
| **0.14.0** | Vulnerability-scan gate (`pip-audit` + Trivy + `presidio-scout-vuln-gate`, fail-closed on fixable findings) + signed CycloneDX SBOM attestation verified alongside provenance at release |
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
│   ├── scout_integrity.py # pinned-ScoutSuite preflight gate
│   ├── findings.py        # findings model + severity gate (presidio-scout-findings)
│   ├── sarif.py           # SARIF 2.1.0 export for code scanning (presidio-scout-export)
│   ├── waivers.py         # expiring findings waivers / exceptions (--waivers)
│   ├── attestation.py     # in-toto run attestation (presidio-scout-attest)
│   ├── diff.py            # drift detection between two runs (presidio-scout-diff)
│   ├── credentials.py     # short-lived-credential preflight (--require-short-lived-creds)
│   ├── vuln.py            # Trivy/Grype vulnerability gate (presidio-scout-vuln-gate)
│   ├── ruleset.py         # baseline rule-name validation (presidio-scout-validate)
│   ├── cli.py             # presidio-scout entrypoint
│   ├── errors.py          # exception hierarchy
│   └── policy/            # curated baselines + rule manifests + provenance-policy.json
├── iam/{aws,azure,gcp}/   # least-privilege audit identities per cloud
├── deploy/                # hardened Kubernetes manifests + Helm chart
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
