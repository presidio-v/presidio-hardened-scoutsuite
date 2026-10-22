# ADR-0002: AWS-only ScoutSuite runtime with a reviewed dependency exclusion list

## Status

Accepted, 2026-10-22. Supersedes the Option C rejection in
[ADR-0001](./0001-scoutsuite-runtime-release-strategy.md) for the AWS-only
runtime described here. The rest of ADR-0001 stands.

## Context

ScoutSuite 5.14.0 is still the latest release, and upstream `develop` keeps the
same pins. Its metadata pins `azure-identity==1.5.0` exactly, and its pinned
`google-cloud-kms==1.3.0` and `google-cloud-monitoring==1.1.0` cap protobuf below
4. That left three advisories with no fix ScoutSuite allows:

- azure-identity 1.5.0: PYSEC-2026-1209 (CVE-2024-35255), fixed in 1.16.1;
- protobuf 3.20.3: PYSEC-2026-1805 (CVE-2026-0994) and PYSEC-2026-1806
  (CVE-2025-4565).

Both were reachable (Azure `--msi`, GCP response parsing), so they could not be
accepted as unreachable, and they blocked every image release. Dropping Azure
alone would not help, because protobuf comes from the GCP stack.

The operator decision (2026-10-22) is to keep only the AWS provider.

ScoutSuite loads providers lazily: `ScoutSuite.providers.get_provider_object()`
imports `ScoutSuite.providers.<name>.provider` only for the provider a run asks
for. ScoutSuite's core and its AWS provider import only `boto3`, `botocore`,
`netaddr`, `policyuniverse`, `sqlitedict`, `cherrypy`, `cherrypy-cors`,
`coloredlogs`, `python-dateutil` and `asyncio-throttle`. Nothing on that path
imports an Azure, Google, Aliyun, OCI, Kubernetes or DigitalOcean module.

## Decision

The bundled runtime (container image and `requirements.lock`) is AWS-only.

1. **Exclusion list.** `requirements-aws.overrides` lists every ScoutSuite
   dependency that only serves a non-AWS provider, each as a uv override with a
   never-true marker. `uv pip compile --override requirements-aws.overrides`
   resolves ScoutSuite without them and writes the hash-pinned lock
   (132 → 37 packages). The exact command is in the lock header and in
   `presidio_scoutsuite.upgrade.LOCK_CMD`.
2. **Constrained install.** The image, CI and the release gate install the lock
   with `pip install --no-deps --require-hashes -r requirements.lock`. The lock
   is the complete runtime set, so `--no-deps` only stops pip from following
   ScoutSuite's metadata to the excluded SDKs.
3. **Explicit drift check.** ADR-0001 rejected `--no-deps` because ScoutSuite's
   metadata would silently disagree with what is installed. Here the
   disagreement is written down and enforced: `scripts/runtime_smoke.py` fails
   if ScoutSuite declares a dependency that is neither installed nor in the
   exclusion list, or if an excluded package is installed or no longer declared.
   A ScoutSuite upgrade that adds a dependency therefore stops the upgrade
   workflow until a reviewer decides which side it belongs on.
4. **Provider smoke test.** The same script imports every module under
   `ScoutSuite.providers.aws` (159 in 5.14.0), runs `scout aws --help`, and
   requires every other provider to fail to load. It runs in the `runtime-smoke`
   CI job, in the release `verify-rulesets` gate and in the image build, which
   meets ADR-0001's "run provider smoke tests" requirement.
5. **Wrapper refusal.** `presidio-scout` accepts only `aws`. `azure`, `gcp`,
   `aliyun` and `oci` fail with exit code 2 and the reason, whether they come
   from the command line, `.presidio-scout.toml` or an orchestration target,
   before any ScoutSuite process starts.

## Why this is not the Option C that ADR-0001 rejected

Option C was an unreviewed `--no-deps` install whose metadata drift nobody
tracked. This one keeps the drift explicit and tested: a reviewed, checked-in
exclusion list, a lock generated from it, and a fail-closed check that ScoutSuite's
declared dependencies equal the lock plus the list. The excluded code is never
imported, the providers that would import it are refused by the wrapper, and the
smoke test proves both on the installed tree.

## Consequences

- The release gate passes with only the accepted sqlitedict exception
  (PYSEC-2026-1939, expires 2027-04-22); there are no runtime-track blockers.
- Azure, GCP, Alibaba Cloud and Oracle Cloud audits are no longer available
  through this distribution. Operators run upstream ScoutSuite for those clouds.
  The bundled least-privilege identities and baselines for those clouds stay,
  and the offline report tools still read reports from any provider.
- The `[scoutsuite]` extra still installs stock ScoutSuite with all its
  dependencies; only the lock and the image are AWS-only.
- Restoring a provider means removing its lines from the exclusion list, which
  brings its advisories back into the audit.
