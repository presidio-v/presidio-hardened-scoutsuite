# ScoutSuite dependency vulnerability policy

`presidio-hardened-scoutsuite` has two dependency surfaces:

- the MIT wrapper package, which intentionally has no runtime dependency on ScoutSuite;
- the optional full ScoutSuite runtime tree in `requirements.lock` and the container image.

The release split and long-term runtime strategy are recorded in
[`docs/adr/0001-scoutsuite-runtime-release-strategy.md`](./docs/adr/0001-scoutsuite-runtime-release-strategy.md).

When `pip-audit -r requirements.lock` reports a vulnerability in a transitive dependency
owned by ScoutSuite or its cloud SDK stack, do not suppress it by default. The runtime image
must stay blocked until one of these paths is true:

1. Upstream ScoutSuite or the affected SDK publishes a compatible fixed dependency tree, and
   `requirements.lock` is regenerated with hashes.
2. We carry a reviewed Presidio patch or fork for the affected package, with provenance and
   a narrow compatibility test proving ScoutSuite still works for the provider surface that
   imports it.
3. The vulnerable dependency is proven unreachable in the shipped runtime, documented here,
   and accepted with an expiry date. This is a temporary exception, not a permanent release
   bypass.

PyPI releases of the wrapper may continue independently when the wrapper itself has a clean
runtime audit, because installing the base package does not install ScoutSuite. Container
releases and `[scoutsuite]` lockfile refreshes remain subject to the hard audit gate.

## AWS-only runtime (since 2026-10-22, ScoutSuite 5.14.0)

The runtime is AWS-only ([ADR-0002](./docs/adr/0002-aws-only-runtime.md)).
`requirements-aws.overrides` lists every ScoutSuite dependency that serves only the
Azure, GCP, Aliyun, OCI, Kubernetes or DigitalOcean providers, and the lock is
generated without them. That removed the two former runtime-track blockers, which
had no fix within ScoutSuite's pins:

| Package | Advisory | Status |
|---|---|---|
| `azure-identity==1.5.0` | CVE-2024-35255 (PYSEC-2026-1209) | Not in the lock |
| `protobuf==3.20.3` | CVE-2025-4565 (PYSEC-2026-1806), CVE-2026-0994 (PYSEC-2026-1805) | Not in the lock |

There are no runtime-track blockers. The lock is installed with `--no-deps`, and
`scripts/runtime_smoke.py` checks the installed tree: every AWS provider module
imports, every other provider fails to load, and ScoutSuite's declared
dependencies equal the lock plus the exclusion list.

## Accepted exceptions (path 3)

| Package | Advisory | Expires | Why it is unreachable |
|---|---|---|---|
| `sqlitedict==2.1.0` | CVE-2024-35515 (PYSEC-2026-1939), no fixed release | 2027-04-22 | ScoutSuite 5.14.0 opens a `SqliteDict` (which unpickles the database) only in `SqlLiteEncoder`, selected by `--result-format sqlite`, and in `core/server.py`, started by `--serve`. Since 2026-10-22 the launcher accepts `--result-format json` only (`RESTRICTED_VALUES`, with tests), and `--serve` was never on the pass-through allowlist. The module is still imported at startup, but no database is opened. Running the image with `--entrypoint scout` bypasses the wrapper and all of its controls. |

## How the gates use this

`requirements.lock.audit-exceptions` lists every advisory ID above with its kind:

- The **CI `lock-audit` job** (every PR and push to `main`) ignores the accepted exceptions
  and the runtime-track blockers, so any *new* advisory in the lock fails CI when it appears.
- The **release gate** (`release.yml`) ignores only unexpired accepted exceptions. The
  blockers keep the image release blocked.
- Both fail once an accepted exception passes its expiry date.

A new blocker would be cleared by the paths listed above and in ADR-0001, or for a
provider-specific SDK by keeping it out of the AWS-only runtime (ADR-0002).

The GCP, Kubernetes and Aliyun import failures noted during the 2026-10-18 refresh no
longer apply: those providers are not part of the runtime.
