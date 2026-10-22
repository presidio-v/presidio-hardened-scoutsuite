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

## Current runtime-track blockers (as of 2026-10-18, ScoutSuite 5.14.0)

The lock was regenerated on 2026-10-18; every finding with a fix the ScoutSuite
5.14.0 metadata allows is fixed. These remain, and keep the image release blocked.
Neither meets the "proven unreachable" bar, so neither is ignored in the release gate:

| Package | Advisory | Why it can't be bumped | Reachable in the shipped runtime |
|---|---|---|---|
| `azure-identity==1.5.0` | CVE-2024-35255 (PYSEC-2026-1209), fixed in 1.16.1 | ScoutSuite pins `azure-identity==1.5.0` exactly (also on upstream `master`/`develop`) | Yes: ScoutSuite's Azure `--msi` path uses `ManagedIdentityCredential`, and the wrapper supports managed identity |
| `protobuf==3.20.3` | CVE-2025-4565 (PYSEC-2026-1806), CVE-2026-0994 (PYSEC-2026-1805) | ScoutSuite pins `google-cloud-kms==1.3.0` and `google-cloud-monitoring==1.1.0`, which need `google-api-core<2`, which caps `protobuf<4` | Yes: the GCP provider parses API responses with it (DoS class) |

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

Paths to clear them are those listed above and in ADR-0001: an upstream ScoutSuite release
with modern pins, or a reviewed Presidio-patched runtime (for example an AWS-only
provider split that drops the Azure/GCP SDKs). Dropping only the Azure SDK would not
unblock the image, because `protobuf` (GCP) would still block it.

Separate pre-existing defect, found during the 2026-10-18 refresh and present in the
previous lock as well: on the locked tree, the GCP and Kubernetes providers fail to import
(`No module named 'pkg_resources'`, which setuptools >= 82 no longer ships) and the Aliyun
ActionTrail resources fail to import (`aliyunsdkactiontrail.request.v20171204` missing).
Run the provider smoke tests that ADR-0001 requires before publishing an image.
