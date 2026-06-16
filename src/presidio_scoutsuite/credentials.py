"""Classify the credential posture of a run and gate out long-lived secrets.

The wrapper never *brokers* credentials — ScoutSuite's bundled cloud SDKs already
resolve assumed roles, OIDC web identity, service-account impersonation and
managed identity natively, and re-implementing that would expand the trusted
surface and bloat the distroless image for no gain (see the 0.12.0 deliberation
in ``PRESIDIO-REQ.md``). What the wrapper *can* do cheaply and safely is inspect
the (already env-scrubbed) credential **shape** and refuse, fail-closed, to hand
ScoutSuite a long-lived static secret when the operator asked for short-lived
only.

The check is deterministic, dependency-free, and never logs secret *values* — it
keys off variable presence (and, for GCP, only the non-secret ``type`` field of
the credential file). Postures:

* ``short-lived`` — assumed/temporary, OIDC/federated, impersonated, or managed
  identity;
* ``static`` — a long-lived access key / client secret / downloaded SA key;
* ``unknown`` — can't be determined from the environment alone (e.g. an AWS
  profile that may itself assume a role, or CLI/ADC login) — never failed on.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .errors import CredentialError

SHORT_LIVED = "short-lived"
STATIC = "static"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class CredentialCheck:
    """The detected credential posture for one provider."""

    provider: str
    posture: str
    detail: str

    @property
    def is_static(self) -> bool:
        return self.posture == STATIC


def _aws(env: Mapping[str, str]) -> CredentialCheck:
    if env.get("AWS_SESSION_TOKEN"):
        return CredentialCheck(
            "aws", SHORT_LIVED, "AWS_SESSION_TOKEN present (temporary credentials)"
        )
    if env.get("AWS_WEB_IDENTITY_TOKEN_FILE") and env.get("AWS_ROLE_ARN"):
        return CredentialCheck("aws", SHORT_LIVED, "OIDC web-identity role assumption")
    if env.get("AWS_ACCESS_KEY_ID"):
        return CredentialCheck(
            "aws", STATIC, "AWS_ACCESS_KEY_ID without a session token (long-lived access key)"
        )
    if env.get("AWS_PROFILE"):
        return CredentialCheck(
            "aws", UNKNOWN, "AWS_PROFILE set (the profile may assume a role; can't tell from env)"
        )
    return CredentialCheck("aws", UNKNOWN, "no AWS credentials in the scrubbed environment")


def _azure(env: Mapping[str, str]) -> CredentialCheck:
    if env.get("AZURE_FEDERATED_TOKEN_FILE"):
        return CredentialCheck(
            "azure", SHORT_LIVED, "workload-identity federation (OIDC token file)"
        )
    if env.get("IDENTITY_ENDPOINT") or env.get("MSI_ENDPOINT"):
        return CredentialCheck("azure", SHORT_LIVED, "managed identity")
    if env.get("AZURE_CLIENT_SECRET"):
        return CredentialCheck("azure", STATIC, "AZURE_CLIENT_SECRET (long-lived client secret)")
    if env.get("AZURE_CLIENT_CERTIFICATE_PATH"):
        return CredentialCheck(
            "azure", STATIC, "AZURE_CLIENT_CERTIFICATE_PATH (long-lived certificate credential)"
        )
    return CredentialCheck(
        "azure", UNKNOWN, "no static Azure secret in env (CLI / DefaultAzureCredential resolves)"
    )


def _gcp_credential_type(path: str) -> str | None:
    """Return only the non-secret ``type`` field of a GCP credential file."""

    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data.get("type") if isinstance(data, dict) else None


def _gcp(env: Mapping[str, str]) -> CredentialCheck:
    if env.get("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT"):
        return CredentialCheck("gcp", SHORT_LIVED, "service-account impersonation")
    gac = env.get("GOOGLE_APPLICATION_CREDENTIALS")
    if gac:
        cred_type = _gcp_credential_type(gac)
        if cred_type == "service_account":
            return CredentialCheck(
                "gcp", STATIC, "GOOGLE_APPLICATION_CREDENTIALS is a downloaded service-account key"
            )
        if cred_type in {"external_account", "impersonated_service_account"}:
            return CredentialCheck("gcp", SHORT_LIVED, f"federated credentials ({cred_type})")
        return CredentialCheck(
            "gcp", UNKNOWN, f"GOOGLE_APPLICATION_CREDENTIALS of type {cred_type!r}"
        )
    return CredentialCheck(
        "gcp", UNKNOWN, "no GOOGLE_APPLICATION_CREDENTIALS in env (ADC resolves)"
    )


_INSPECTORS = {"aws": _aws, "azure": _azure, "gcp": _gcp}


def inspect_credentials(provider: str, env: Mapping[str, str] | None = None) -> CredentialCheck:
    """Classify the credential posture for ``provider`` from the environment."""

    source = os.environ if env is None else env
    inspector = _INSPECTORS.get(provider.lower())
    if inspector is None:
        return CredentialCheck(provider, UNKNOWN, f"no credential heuristics for {provider!r}")
    return inspector(source)


def assert_short_lived(provider: str, env: Mapping[str, str] | None = None) -> CredentialCheck:
    """Raise :class:`CredentialError` if static long-lived credentials are present.

    An ``unknown`` posture never raises — the check only fails on an
    unambiguously static secret, so it can't block legitimate
    profile/CLI/managed-identity setups it can't introspect.
    """

    check = inspect_credentials(provider, env)
    if check.is_static:
        raise CredentialError(
            f"{provider}: {check.detail}; supply short-lived credentials — assume the bundled "
            "audit role, or use OIDC / impersonation / managed identity (see the README)"
        )
    return check
