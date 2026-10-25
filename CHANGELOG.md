# Changelog

Notable changes to presidio-hardened-scoutsuite. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). Earlier releases are summarised in
the roadmap tables in `README.md` and `PRESIDIO-REQ.md`.

## [Unreleased]

### Security

- Container image: `setuptools` 84.0.0 → 84.2.1 in `requirements.lock`
  (GHSA-xmj3-9gf7-h52w). It is pulled in by ScoutSuite through `zc-lockfile`;
  only that pin changed.
- Container image: `certifi` 2026.7.22 → 2026.10.19 in `requirements.lock`. The new
  bundle drops emSign ECC Root CA - G3, the root behind the eight eMudhra
  intermediates whose private keys were trivially recoverable (Mozilla bug
  2083449). The scanner's cloud API clients trust certifi and do not check
  revocation, so browser-side blocks did not cover them.
- `--result-format` now accepts only `json`. ScoutSuite's `sqlite` format opens
  its results with `sqlitedict`, which unpickles the database (CVE-2024-35515 /
  PYSEC-2026-1939, no fixed release). With `--serve` already off the
  allowlist, that path is now unreachable through the wrapper. The advisory is
  an accepted exception that expires on 2027-04-22.
- New blocking `lock-audit` CI job runs `pip-audit -r requirements.lock` on every
  pull request and push to `main`, not only on release tags. It ignores exactly
  the IDs in `requirements.lock.audit-exceptions`. The release gate ignores only
  the accepted exceptions, so the azure-identity and protobuf blockers still
  block the image release.

### Changed

- **Breaking for `--result-format sqlite` users:** the wrapper rejects it with
  exit code 2. Use the default `json`.

## [0.30.0] - 2026-10-18

### Fixed

- Evidence signatures now conform to the family evidence contract: each
  `evidence-ref@2` ref is signed over the canonical JSON of
  `{"content_hash", "signer"}` only, the message ikigov-assess and the family
  verifier check. Refs emitted by v0.29.x and earlier were signed over every
  field except `signature` and never verified outside this repo (#79).
- The canonical JSON encoder rejects floats (and so NaN/Infinity) anywhere in a
  payload and encodes with `allow_nan=False`, matching the contract's strict
  profile.
- Conformance tests now run against vendored copies of the family evidence
  contract test vectors (`tests/vectors/`) instead of a self-generated vector,
  and the interop envelope in `tests/interop/` is regenerated with the contract
  message and checked by an independent re-implementation of the family
  verifier.

### Added

- `presidio-scout-evidence resign` re-signs legacy refs over the contract
  message. It re-signs only refs that already verify against the trust store,
  checks every new signature against the signer's trust entry, and never prints
  or logs key material.
- `verify_ref_detailed()` returns a `VerifyResult` with `ok` and
  `legacy_signature`; `verify_ref()` keeps returning a bool.

### Deprecated

- Acceptance of legacy (pre-0.30.0) full-document signatures. `verify` tries the
  contract message first and falls back to the legacy message; a legacy match
  succeeds with `legacy_signature=True`, is marked `[legacy signature]` and logs
  a WARNING. Support will be removed in v0.32.0 or 90 days after the v0.30.0
  release, whichever is later. Run `presidio-scout-evidence resign` before then.
