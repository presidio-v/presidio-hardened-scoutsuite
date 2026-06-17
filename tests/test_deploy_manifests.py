"""Guardrail tests for the bundled Kubernetes deployment data.

The manifests ship as data (like ``iam/`` and ``policy/``), so there's no Python
to unit-test — but a hardened pod spec is easy to weaken by accident. These
string-presence checks fail closed if a key control is dropped from the manifests
or the Helm defaults. They avoid a YAML dependency on purpose (the Helm templates
aren't valid standalone YAML anyway).
"""

from __future__ import annotations

from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9 / 3.10
    import tomli as tomllib  # type: ignore[no-redef]

_ROOT = Path(__file__).resolve().parents[1]
_K8S = _ROOT / "deploy" / "kubernetes"
_CHART = _ROOT / "deploy" / "helm" / "presidio-scout"

#: Hardening lines every audit pod spec must carry.
_POD_HARDENING = (
    "runAsNonRoot: true",
    "readOnlyRootFilesystem: true",
    "allowPrivilegeEscalation: false",
    'drop: ["ALL"]',
    "seccompProfile",
    "type: RuntimeDefault",
    "automountServiceAccountToken: false",
)


@pytest.mark.parametrize("name", ["job.yaml", "cronjob.yaml"])
def test_workload_manifests_are_hardened(name):
    text = (_K8S / name).read_text()
    for needle in _POD_HARDENING:
        assert needle in text, f"{name} missing hardening: {needle}"
    # short-lived creds + findings gate are wired into the invocation
    assert "--require-short-lived-creds" in text
    assert "--fail-on-finding" in text


def test_networkpolicy_default_deny():
    text = (_K8S / "networkpolicy.yaml").read_text()
    assert "ingress: []" in text  # deny all ingress
    assert "- Egress" in text and "- Ingress" in text
    assert "port: 443" in text  # only HTTPS egress (+ DNS)
    assert "port: 53" in text


def test_serviceaccount_no_api_token():
    text = (_K8S / "serviceaccount.yaml").read_text()
    assert "automountServiceAccountToken: false" in text


def test_deploy_image_tags_match_project_version():
    version = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    for name in ("job.yaml", "cronjob.yaml"):
        assert f"presidio-hardened-scoutsuite:v{version}" in (_K8S / name).read_text()
    chart = (_CHART / "Chart.yaml").read_text()
    assert f"version: {version}" in chart
    assert f'appVersion: "{version}"' in chart


def test_helm_values_hardened_by_default():
    text = (_CHART / "values.yaml").read_text()
    for needle in (
        "readOnlyRootFilesystem: true",
        "allowPrivilegeEscalation: false",
        "RuntimeDefault",
        'drop: ["ALL"]',
    ):
        assert needle in text, f"helm values.yaml missing hardening: {needle}"


def test_helm_chart_layout():
    assert (_CHART / "Chart.yaml").is_file()
    for template in ("workload.yaml", "serviceaccount.yaml", "networkpolicy.yaml", "_helpers.tpl"):
        assert (_CHART / "templates" / template).is_file(), f"missing helm template {template}"


def test_helm_pod_template_hardened_and_no_api_token():
    text = (_CHART / "templates" / "_helpers.tpl").read_text()
    assert "automountServiceAccountToken: false" in text
    assert "podSecurityContext" in text and "containerSecurityContext" in text
    assert "--require-short-lived-creds" in text
