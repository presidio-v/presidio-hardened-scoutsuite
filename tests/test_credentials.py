from __future__ import annotations

import json

import pytest

from presidio_scoutsuite import credentials as C
from presidio_scoutsuite.errors import CredentialError

# --- AWS ---------------------------------------------------------------------


def test_aws_session_token_is_short_lived():
    c = C.inspect_credentials("aws", {"AWS_ACCESS_KEY_ID": "ASIA", "AWS_SESSION_TOKEN": "t"})
    assert c.posture == C.SHORT_LIVED


def test_aws_oidc_web_identity_is_short_lived():
    c = C.inspect_credentials(
        "aws", {"AWS_WEB_IDENTITY_TOKEN_FILE": "/t", "AWS_ROLE_ARN": "arn:aws:iam::1:role/x"}
    )
    assert c.posture == C.SHORT_LIVED


def test_aws_static_key_without_session_token():
    c = C.inspect_credentials("aws", {"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE"})
    assert c.posture == C.STATIC
    assert c.is_static


def test_aws_profile_is_unknown():
    assert C.inspect_credentials("aws", {"AWS_PROFILE": "auditor"}).posture == C.UNKNOWN


def test_aws_empty_is_unknown():
    assert C.inspect_credentials("aws", {}).posture == C.UNKNOWN


# --- Azure -------------------------------------------------------------------


def test_azure_client_secret_is_static():
    assert C.inspect_credentials("azure", {"AZURE_CLIENT_SECRET": "s"}).is_static


def test_azure_certificate_is_static():
    assert C.inspect_credentials("azure", {"AZURE_CLIENT_CERTIFICATE_PATH": "/c.pem"}).is_static


def test_azure_federation_is_short_lived():
    assert (
        C.inspect_credentials("azure", {"AZURE_FEDERATED_TOKEN_FILE": "/t"}).posture
        == C.SHORT_LIVED
    )


def test_azure_managed_identity_is_short_lived():
    for var in ("IDENTITY_ENDPOINT", "MSI_ENDPOINT"):
        assert C.inspect_credentials("azure", {var: "http://x"}).posture == C.SHORT_LIVED


def test_azure_empty_is_unknown():
    assert C.inspect_credentials("azure", {}).posture == C.UNKNOWN


# --- GCP ---------------------------------------------------------------------


def _cred_file(tmp_path, payload):
    p = tmp_path / "cred.json"
    p.write_text(json.dumps(payload))
    return str(p)


def test_gcp_service_account_key_is_static(tmp_path):
    gac = _cred_file(tmp_path, {"type": "service_account", "private_key": "X"})
    assert C.inspect_credentials("gcp", {"GOOGLE_APPLICATION_CREDENTIALS": gac}).is_static


def test_gcp_external_account_is_short_lived(tmp_path):
    gac = _cred_file(tmp_path, {"type": "external_account"})
    assert (
        C.inspect_credentials("gcp", {"GOOGLE_APPLICATION_CREDENTIALS": gac}).posture
        == C.SHORT_LIVED
    )


def test_gcp_impersonation_is_short_lived():
    c = C.inspect_credentials("gcp", {"CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT": "sa@p.iam"})
    assert c.posture == C.SHORT_LIVED


def test_gcp_unreadable_cred_file_is_unknown(tmp_path):
    assert (
        C.inspect_credentials(
            "gcp", {"GOOGLE_APPLICATION_CREDENTIALS": str(tmp_path / "nope.json")}
        ).posture
        == C.UNKNOWN
    )


def test_gcp_empty_is_unknown():
    assert C.inspect_credentials("gcp", {}).posture == C.UNKNOWN


# --- generic + assert --------------------------------------------------------


def test_unknown_provider():
    assert C.inspect_credentials("oci", {}).posture == C.UNKNOWN


def test_assert_short_lived_raises_on_static():
    with pytest.raises(CredentialError, match="long-lived access key"):
        C.assert_short_lived("aws", {"AWS_ACCESS_KEY_ID": "AKIA"})


def test_assert_short_lived_allows_unknown():
    # An unknown posture must not raise (can't prove it's static).
    assert C.assert_short_lived("aws", {"AWS_PROFILE": "auditor"}).posture == C.UNKNOWN


def test_assert_short_lived_allows_short_lived():
    assert C.assert_short_lived("aws", {"AWS_SESSION_TOKEN": "t"}).posture == C.SHORT_LIVED
