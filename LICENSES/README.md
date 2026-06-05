# Licensing & third-party notices

This project has **two distinct licensing surfaces**. Read this before
redistributing.

## 1. This wrapper — MIT

All code in `src/presidio_scoutsuite/`, the policies in `iam/` and
`src/presidio_scoutsuite/policy/`, the tests, and the docs are **original work**
licensed under the [MIT License](../LICENSE).

The wrapper **does not import, link, or vendor ScoutSuite**. It invokes the
upstream `scout` executable as a separate process (see
`presidio_scoutsuite/launcher.py`). Driving a program over a process boundary
does not create a derivative work, so this wrapper is **not** subject to
ScoutSuite's GPL-2.0 terms and may ship under MIT.

## 2. ScoutSuite — GPL-2.0-only

[ScoutSuite](https://github.com/nccgroup/ScoutSuite) (© NCC Group) is licensed
**GPL-2.0-only**. This repository does **not** contain ScoutSuite's source.

- When you `pip install 'presidio-hardened-scoutsuite[scoutsuite]'` or build the
  container image, ScoutSuite is fetched and installed alongside the wrapper.
- **The published container image therefore *distributes* GPL-2.0 software.**
  Anyone redistributing that image must comply with GPL-2.0 §3 (provide, or
  offer, the corresponding source). The pinned version is recorded in
  `requirements.lock`; the source is available from the upstream repository at
  the matching tag.

If you only `pip install presidio-hardened-scoutsuite` (no `[scoutsuite]` extra)
and supply your own `scout` binary, you are not redistributing ScoutSuite and
only the MIT terms apply to what you received here.
