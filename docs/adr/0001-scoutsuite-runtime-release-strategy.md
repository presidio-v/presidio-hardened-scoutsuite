# ADR-0001: Separate wrapper releases from ScoutSuite runtime releases

## Status

Accepted, 2026-06-18.

## Context

`presidio-hardened-scoutsuite` deliberately keeps the MIT wrapper separate from
ScoutSuite. The wrapper drives ScoutSuite out of process, never imports it, and
the base package has no runtime dependency on ScoutSuite.

The container image and `[scoutsuite]` extra are different: they bundle the full
ScoutSuite runtime tree for operator convenience. That runtime tree inherits
ScoutSuite's GPL-2.0 license obligations and ScoutSuite's dependency constraints.
When `pip-audit -r requirements.lock` reports vulnerabilities in ScoutSuite or
its cloud SDK transitive dependencies, those are real findings in the bundled
runtime even when the wrapper itself is clean.

The immediate pressure is release reliability: wrapper-only PyPI releases can be
clean and useful while the bundled ScoutSuite image remains blocked by upstream
dependencies that this wrapper does not directly control.

## Decision

We will keep two release tracks:

1. **Wrapper release track**: the MIT wrapper package. This may be tagged and
   published to PyPI when the wrapper's own checks pass, even if the optional
   ScoutSuite runtime lockfile remains blocked.
2. **ScoutSuite runtime release track**: the bundled ScoutSuite container and any
   hash-locked full runtime. This must remain blocked while known vulnerabilities
   are present in the installed runtime tree, unless an exception is explicitly
   documented with evidence and an expiry date.

We will not hide ScoutSuite runtime CVEs by weakening `pip-audit` or keeping a
permanent ignore list. Long-term fixes must come from one of these paths:

- upstream ScoutSuite or its SDK dependencies publish compatible fixed versions,
  and we regenerate the hash-pinned lockfile;
- Presidio carries a reviewed patched ScoutSuite runtime or patched dependency
  wheel, with corresponding source/provenance and provider compatibility tests;
- the affected dependency is proven unreachable in the shipped runtime, accepted
  as a temporary exception, and assigned an expiry date.

The preferred future direction is a separate GPL-compliant hardened ScoutSuite
runtime artifact, potentially split by provider (`aws`, `azure`, `gcp`, `aliyun`,
`oci`, and `full`) to reduce installed dependency surface and avoid blocking an
AWS-only image on Azure-only dependencies.

## Options considered

### Option A: Suppress inherited ScoutSuite CVEs in release gates

Rejected. This would make the release green while still shipping a vulnerable
runtime. It also trains operators to distrust the project's hardening claims.

### Option B: Publish only the wrapper and never ship a bundled runtime

Rejected as the only long-term path. It is safe and remains acceptable as a
fallback, but it reduces operator ergonomics and leaves each team to assemble its
own ScoutSuite runtime.

### Option C: Override dependencies with `pip install --no-deps`

Rejected as a default release method. It can produce a working container, but it
creates metadata drift: ScoutSuite may still declare incompatible requirements
while the image contains different packages. That is not a stable provenance
story unless it is converted into a reviewed patched package/fork.

### Option D: Maintain a separate hardened ScoutSuite runtime

Accepted as the long-term path. It makes ownership explicit, preserves the MIT
wrapper boundary, satisfies GPL redistribution obligations, and gives the
container release a real place to carry patched metadata, compatibility tests,
SBOMs, signatures, and vulnerability policy.

## Consequences

- Wrapper PyPI releases can continue while the ScoutSuite container is blocked.
- Container/image release status must be reported separately from wrapper
  release status.
- Any patched ScoutSuite runtime is GPL-covered and must publish corresponding
  source and notices.
- Provider-split images become an architectural goal because they reduce blast
  radius and inherited CVE noise.
- `pip-audit` remains a hard gate for the bundled runtime.

## Operational policy

Before tagging a wrapper release:

- run the wrapper lint/test/packaging checks;
- verify the base package dependency surface remains clean;
- document any blocked ScoutSuite runtime findings as runtime-track blockers.

Before publishing a ScoutSuite runtime image:

- regenerate the full hash-pinned lockfile;
- run `pip-audit -r requirements.lock`;
- run provider smoke tests against the installed ScoutSuite runtime;
- generate and sign SBOM/provenance;
- sign the image and verify the signature/attestations before declaring the
  runtime release complete.
