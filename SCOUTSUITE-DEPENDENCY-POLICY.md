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
