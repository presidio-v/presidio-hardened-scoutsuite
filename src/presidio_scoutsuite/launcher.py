"""Build and run a hardened ScoutSuite invocation **out of process**.

This module never imports ScoutSuite. It constructs an argv for the upstream
``scout`` CLI, validates every caller-supplied flag against a fail-closed
allowlist, scrubs the child environment down to the variables ScoutSuite
actually needs, and runs the result in a locked-down report directory.

Keeping ScoutSuite at arm's length (a subprocess, not an import) is deliberate:
ScoutSuite is GPL-2.0, so this wrapper stays a separate, non-derivative work.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .errors import LauncherError

#: Cloud providers ScoutSuite supports and that we accept as the first argument.
PROVIDERS: tuple[str, ...] = ("aws", "azure", "gcp", "aliyun", "oci")

#: Flags the launcher owns. A caller must not set these — we control them so the
#: hardened posture (no browser, fixed report dir, curated ruleset) can't be
#: quietly undone from the command line.
LAUNCHER_OWNED: frozenset[str] = frozenset(
    {"--report-dir", "--ruleset", "--ruleset-name", "--no-browser", "--report-name"}
)

#: Fail-closed allowlist of ScoutSuite flags a caller may pass through, mapped to
#: whether the flag consumes the following token as its value. Anything not in
#: this table is rejected, so a new/unknown upstream flag can never silently
#: weaken a run until we vet it and add it here.
ALLOWED_PASSTHROUGH: dict[str, bool] = {
    "--profile": True,
    "--access-keys": False,
    "--user-account": False,
    "--all-regions": False,
    "--region": True,
    "--regions": True,
    "--services": True,
    "--skip": True,
    "--exceptions": True,
    "--max-rate": True,
    "--max-workers": True,
    "--result-format": True,
    "--debug": False,
}

#: Environment-variable name prefixes that carry legitimate cloud credentials /
#: SDK configuration and must reach the child process.
_CLOUD_ENV_PREFIXES: tuple[str, ...] = (
    "AWS_",
    "AZURE_",
    "GOOGLE_",
    "GCP_",
    "CLOUDSDK_",
    "GOOGLE_CLOUD_",
    "ALIBABA_",
    "ALICLOUD_",
    "ALIYUN_",
    "OCI_",
)

#: Non-credential environment variables the child still needs to run correctly.
_ALLOWED_ENV_NAMES: frozenset[str] = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "TERM",
        "LANG",
        "TZ",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "PYTHONUTF8",
        # Keyless / managed-identity endpoints that aren't covered by a cloud
        # prefix above but must reach the child so federated auth works without
        # any long-lived secret (Azure App Service / Functions managed identity).
        "IDENTITY_ENDPOINT",
        "IDENTITY_HEADER",
        "MSI_ENDPOINT",
        "MSI_SECRET",
    }
)


@dataclass(frozen=True)
class LaunchPlan:
    """A validated, ready-to-run ScoutSuite invocation."""

    provider: str
    argv: list[str]
    report_dir: Path
    env: dict[str, str]

    def redacted_command(self) -> str:
        """A shell-ish rendering of :attr:`argv` safe to print/log.

        The argv itself never contains secrets (credentials come from the
        environment, not the command line), so this is the full command — but
        we route it through one place so callers don't hand-roll logging.
        """

        return " ".join(self.argv)


def validate_passthrough(extra_args: Sequence[str]) -> list[str]:
    """Validate caller-supplied ScoutSuite flags against the allowlist.

    Returns the args unchanged if every one is permitted; otherwise raises
    :class:`LauncherError`. Fail-closed: an unrecognised ``--flag`` is rejected
    rather than forwarded.
    """

    args = list(extra_args)
    i = 0
    while i < len(args):
        token = args[i]
        if token in LAUNCHER_OWNED:
            raise LauncherError(
                f"{token!r} is managed by the hardened launcher and cannot be passed through"
            )
        if token.startswith("-"):
            if token not in ALLOWED_PASSTHROUGH:
                raise LauncherError(f"flag {token!r} is not on the hardened pass-through allowlist")
            if ALLOWED_PASSTHROUGH[token]:
                value = args[i + 1] if i + 1 < len(args) else None
                if value is None or value.startswith("-"):
                    raise LauncherError(f"flag {token!r} requires a value")
                i += 2
                continue
        else:
            raise LauncherError(f"unexpected positional argument {token!r}")
        i += 1
    return args


def scrub_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a minimal child environment.

    Only cloud-credential variables (by prefix) and a short allowlist of
    runtime essentials survive. Everything else is dropped so unrelated secrets
    sitting in the parent environment can never leak into ScoutSuite's logs or
    report output.
    """

    source = os.environ if base is None else base
    out: dict[str, str] = {}
    for name, value in source.items():
        if name in _ALLOWED_ENV_NAMES or name.startswith(_CLOUD_ENV_PREFIXES):
            out[name] = value
    return out


def harden_report_dir(report_dir: str | os.PathLike[str]) -> Path:
    """Create (if needed) and lock down the report directory to 0700.

    ScoutSuite writes the raw collected cloud configuration here, so it must not
    be world/group readable. Refuses a path that already exists as a non-dir.
    """

    path = Path(report_dir)
    if path.exists() and not path.is_dir():
        raise LauncherError(f"report dir {path} exists and is not a directory")
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def build_plan(
    provider: str,
    report_dir: str | os.PathLike[str],
    *,
    ruleset: str | os.PathLike[str] | None = None,
    extra_args: Iterable[str] = (),
    scout_bin: str = "scout",
    base_env: Mapping[str, str] | None = None,
) -> LaunchPlan:
    """Assemble a validated :class:`LaunchPlan`.

    Forces ``--no-browser`` and a fixed ``--report-dir``, wires in the curated
    ``--ruleset`` when one is supplied, validates pass-through flags, and scrubs
    the environment. Does not run anything — see :func:`run`.
    """

    if provider not in PROVIDERS:
        raise LauncherError(
            f"unknown provider {provider!r}; expected one of {', '.join(PROVIDERS)}"
        )

    safe_extra = validate_passthrough(list(extra_args))
    hardened_dir = harden_report_dir(report_dir)

    argv: list[str] = [scout_bin, provider, "--no-browser", "--report-dir", str(hardened_dir)]
    if ruleset is not None:
        argv += ["--ruleset", str(ruleset)]
    argv += safe_extra

    return LaunchPlan(
        provider=provider,
        argv=argv,
        report_dir=hardened_dir,
        env=scrub_env(base_env),
    )


def run(
    plan: LaunchPlan,
    *,
    runner=subprocess.run,
    timeout: float | None = None,
) -> subprocess.CompletedProcess:
    """Execute a :class:`LaunchPlan`.

    Sets a restrictive umask so any files ScoutSuite creates are owner-only,
    then runs the child with the scrubbed environment. ``runner`` is injectable
    so the whole launch path is unit-testable without ScoutSuite installed.
    Output is captured (text) and never auto-printed — redaction happens before
    anything is surfaced.
    """

    previous_umask = os.umask(0o077)
    try:
        return runner(
            plan.argv,
            env=plan.env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    finally:
        os.umask(previous_umask)
