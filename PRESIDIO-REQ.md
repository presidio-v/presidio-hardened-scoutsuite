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

### Why not the AngelList pattern (MIT, single-import wrapper)?

The sibling `presidio-hardened-angellist` hardens an **API client**: swap one
import and outbound HTTP is hardened. That doesn't transfer to ScoutSuite for two
reasons:

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

## Roadmap

| Version | Planned |
|---|---|
| **0.1.0** | Out-of-process hardened launcher + redaction/guard + AWS ruleset/IAM + container + supply-chain posture |
| **0.2.0** | Azure & GCP curated rulesets + least-privilege roles; **CI validation of ruleset rule names** against the pinned ScoutSuite |
| **0.3.0** | Deeper report guard (SRI, offline viewer), signed report manifests |
| **0.4.0** | SLSA provenance verification on install; reproducible-build attestation |

---

## SDLC

Delivered under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
