# Changelog

Notable changes to presidio-hardened-scoutsuite. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). Earlier releases are summarised in
the roadmap tables in `README.md` and `PRESIDIO-REQ.md`.

## [Unreleased]

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
