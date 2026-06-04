"""Tests for Phase 3.4 Auto-Remediation.

Covers:
- File discovery: finding -> file resolution for K8s and Terraform
- Deterministic K8s fixers across every category the rule engine raises
- Deterministic Terraform fixers across categories
- Patch validation: every patched file re-parses cleanly
- Unified diff generation
- LLM fallback path (mocked) with retry on validation failure
- Error paths: missing resource, unsupported file kind, malformed bundle
"""
from __future__ import annotations

import json

import pytest

from app.agents.remediator import (
    NonPatchableFinding,
    PatchValidationError,
    RemediationError,
    _find_tf_block_span,
    _is_cosmetic_drift,
    _locate_file_for_finding,
    _strip_cosmetic_drift,
    _validate_patch,
    is_non_patchable,
    remediate,
    remediate_sync,
)
from app.models import Finding, Severity
from app.parsers.kubernetes import parse_kubernetes_yaml
from app.parsers.terraform import extract_tf_resources, parse_terraform


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _f(
    *,
    category: str,
    title: str,
    resource: str,
    description: str = "",
    severity: Severity = Severity.HIGH,
    agent: str = "Security Agent",
    recommendation: str = "Fix it.",
) -> Finding:
    return Finding(
        agent=agent,
        category=category,
        severity=severity,
        title=title,
        description=description or title,
        resource=resource,
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def test_locate_terraform_file_finds_aws_resource():
    bundle = {
        "infra.tf": '''
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
}
''',
        "irrelevant.yaml": "apiVersion: v1\nkind: Service\nmetadata: { name: foo }\n",
    }
    finding = _f(category="encryption", title="X", resource="aws_s3_bucket.data")
    fname, kind, content = _locate_file_for_finding(finding, bundle)
    assert fname == "infra.tf"
    assert kind == "terraform_hcl"
    assert "aws_s3_bucket" in content


def test_locate_kubernetes_file_finds_named_deployment():
    bundle = {
        "deploy.yaml": '''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:latest
''',
        "infra.tf": 'resource "aws_s3_bucket" "data" { bucket = "x" }\n',
    }
    finding = _f(category="image-tag", title="latest", resource="Deployment/default/api-server")
    fname, kind, _ = _locate_file_for_finding(finding, bundle)
    assert fname == "deploy.yaml"
    assert kind == "kubernetes_yaml"


def test_locate_raises_when_resource_missing():
    bundle = {"infra.tf": 'resource "aws_s3_bucket" "data" { bucket = "x" }\n'}
    finding = _f(category="encryption", title="X", resource="aws_s3_bucket.NOPE")
    with pytest.raises(RemediationError):
        _locate_file_for_finding(finding, bundle)


def test_locate_raises_on_empty_resource():
    bundle = {"infra.tf": 'resource "aws_s3_bucket" "x" {}\n'}
    finding = _f(category="encryption", title="X", resource="")
    with pytest.raises(RemediationError):
        _locate_file_for_finding(finding, bundle)


# ---------------------------------------------------------------------------
# Deterministic K8s fixers
# ---------------------------------------------------------------------------


def _k8s_bundle(yaml_body: str) -> dict[str, str]:
    return {"manifest.yaml": yaml_body}


def test_k8s_privileged_fixer(mock_llm):
    bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
          securityContext:
            privileged: true
''')
    finding = _f(
        category="privileged",
        title="Privileged container",
        resource="Deployment/default/bad",
        description="Container 'app' in Deployment/default/bad runs in privileged mode.",
        severity=Severity.CRITICAL,
    )
    patch = remediate_sync(finding, 0, bundle)
    assert patch.strategy == "deterministic"
    assert patch.validation_status == "valid"
    docs = parse_kubernetes_yaml(patch.patched_content)
    sec_ctx = docs[0]["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    assert sec_ctx["privileged"] is False
    assert patch.unified_diff  # non-empty diff


def test_k8s_run_as_root_fixer(mock_llm):
    bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
''')
    finding = _f(
        category="run-as-root",
        title="Container may run as root",
        resource="Deployment/default/bad",
        description="Container 'app' in Deployment/default/bad has no runAsNonRoot.",
    )
    patch = remediate_sync(finding, 0, bundle)
    docs = parse_kubernetes_yaml(patch.patched_content)
    sec_ctx = docs[0]["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    assert sec_ctx["runAsNonRoot"] is True


def test_k8s_filesystem_fixer_warns_about_volumes(mock_llm):
    bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
''')
    finding = _f(
        category="filesystem",
        title="Writable root filesystem",
        resource="Deployment/default/bad",
        description="Container 'app' in Deployment/default/bad has writable root filesystem.",
        severity=Severity.MEDIUM,
    )
    patch = remediate_sync(finding, 0, bundle)
    docs = parse_kubernetes_yaml(patch.patched_content)
    assert docs[0]["spec"]["template"]["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"] is True
    assert any("emptyDir" in w or "PVC" in w for w in patch.warnings)


def test_k8s_resource_limits_fixer(mock_llm):
    bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
''')
    finding = _f(
        category="resource-limits",
        title="No resource limits",
        resource="Deployment/default/bad",
        description="Container 'app' in Deployment/default/bad has no resource limits.",
    )
    patch = remediate_sync(finding, 0, bundle)
    docs = parse_kubernetes_yaml(patch.patched_content)
    res = docs[0]["spec"]["template"]["spec"]["containers"][0]["resources"]
    assert "requests" in res and "limits" in res
    assert res["limits"]["cpu"] == "500m"


def test_k8s_image_tag_fixer(mock_llm):
    bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:latest
''')
    finding = _f(
        category="image-tag",
        title="Using latest or untagged image",
        resource="Deployment/default/bad",
        description="Container 'app' in Deployment/default/bad uses image 'nginx:latest'.",
        severity=Severity.MEDIUM,
    )
    patch = remediate_sync(finding, 0, bundle)
    docs = parse_kubernetes_yaml(patch.patched_content)
    image = docs[0]["spec"]["template"]["spec"]["containers"][0]["image"]
    assert "CHANGE_ME" in image
    assert image.startswith("nginx:")


def test_k8s_host_namespace_fixer(mock_llm):
    bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
  namespace: default
spec:
  template:
    spec:
      hostPID: true
      containers:
        - name: app
          image: app:1.0
''')
    finding = _f(
        category="host-namespace",
        title="hostPID enabled",
        resource="Deployment/default/bad",
        description="bad has hostPID=true.",
        severity=Severity.CRITICAL,
    )
    patch = remediate_sync(finding, 0, bundle)
    docs = parse_kubernetes_yaml(patch.patched_content)
    pod_spec = docs[0]["spec"]["template"]["spec"]
    assert "hostPID" not in pod_spec


def test_k8s_loadbalancer_to_clusterip(mock_llm):
    bundle = _k8s_bundle('''
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: default
spec:
  type: LoadBalancer
  selector:
    app: web
  ports:
    - port: 80
''')
    finding = _f(
        category="public-exposure",
        title="Public LoadBalancer service",
        resource="Service/default/web",
        severity=Severity.HIGH,
    )
    patch = remediate_sync(finding, 0, bundle)
    docs = parse_kubernetes_yaml(patch.patched_content)
    assert docs[0]["spec"]["type"] == "ClusterIP"


def test_k8s_cluster_admin_binding_fixer(mock_llm):
    bundle = _k8s_bundle('''
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bad-bind
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: app
    namespace: default
''')
    finding = _f(
        category="rbac",
        title="cluster-admin binding",
        resource="ClusterRoleBinding/default/bad-bind",
        severity=Severity.CRITICAL,
    )
    # Note: get_resource_name builds Kind/namespace/name even though
    # ClusterRoleBinding is non-namespaced — the helper still fills in 'default'.
    patch = remediate_sync(finding, 0, bundle)
    docs = parse_kubernetes_yaml(patch.patched_content)
    assert docs[0]["roleRef"]["name"] == "CHANGE_ME_LEAST_PRIVILEGE_ROLE"


def test_k8s_hardcoded_secret_fixer(mock_llm):
    bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: db-app
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.0
          env:
            - name: DB_PASSWORD
              value: hunter2
''')
    finding = _f(
        category="hardcoded-secret",
        title="Hardcoded secret in environment variable",
        resource="Deployment/default/db-app",
        description="Container 'app' in db-app has secret 'DB_PASSWORD' hardcoded in plain text.",
        severity=Severity.CRITICAL,
    )
    patch = remediate_sync(finding, 0, bundle)
    docs = parse_kubernetes_yaml(patch.patched_content)
    env = docs[0]["spec"]["template"]["spec"]["containers"][0]["env"][0]
    assert "value" not in env
    assert env["valueFrom"]["secretKeyRef"]["name"] == "CHANGE_ME_SECRET_NAME"


# ---------------------------------------------------------------------------
# Deterministic Terraform fixers
# ---------------------------------------------------------------------------


def _tf_bundle(hcl: str) -> dict[str, str]:
    return {"main.tf": hcl}


def test_tf_block_span_balanced_braces():
    content = '''
resource "aws_s3_bucket" "data" {
  bucket = "x"
  tags = {
    Env = "prod"
  }
}

resource "aws_s3_bucket" "other" {
  bucket = "y"
}
'''
    span = _find_tf_block_span(content, "aws_s3_bucket", "data")
    assert span is not None
    s, e = span
    assert content[s:e].count("{") == content[s:e].count("}")
    assert "data" in content[s:e]
    assert "other" not in content[s:e]


def test_tf_security_group_open_ingress_fixer(mock_llm):
    bundle = _tf_bundle('''
resource "aws_security_group" "open" {
  name = "open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''')
    finding = _f(
        category="network",
        title="Security group open to 0.0.0.0/0",
        resource="aws_security_group.open",
        severity=Severity.CRITICAL,
    )
    patch = remediate_sync(finding, 0, bundle)
    assert patch.strategy == "deterministic"
    assert "0.0.0.0/0" not in patch.patched_content
    assert "10.0.0.0/8" in patch.patched_content
    parse_terraform(patch.patched_content)  # must reparse


def test_tf_s3_encryption_companion(mock_llm):
    bundle = _tf_bundle('''
resource "aws_s3_bucket" "data" {
  bucket = "data"
}
''')
    finding = _f(
        category="encryption",
        title="S3 bucket without encryption",
        resource="aws_s3_bucket.data",
    )
    patch = remediate_sync(finding, 0, bundle)
    assert "aws_s3_bucket_server_side_encryption_configuration" in patch.patched_content
    parsed = parse_terraform(patch.patched_content)
    types = {r["type"] for r in extract_tf_resources(parsed)}
    assert "aws_s3_bucket_server_side_encryption_configuration" in types


def test_tf_s3_acl_set_to_private(mock_llm):
    bundle = _tf_bundle('''
resource "aws_s3_bucket" "data" {
  bucket = "data"
  acl    = "public-read"
}
''')
    finding = _f(
        category="public-exposure",
        title="Public S3 bucket",
        resource="aws_s3_bucket.data",
        severity=Severity.CRITICAL,
    )
    patch = remediate_sync(finding, 0, bundle)
    assert '"private"' in patch.patched_content
    assert '"public-read"' not in patch.patched_content


def test_tf_rds_storage_encrypted(mock_llm):
    bundle = _tf_bundle('''
resource "aws_db_instance" "main" {
  identifier     = "main"
  engine         = "postgres"
  instance_class = "db.t3.micro"
  username       = "admin"
  password       = "var.db_password"
}
''')
    finding = _f(
        category="encryption",
        title="RDS storage not encrypted",
        resource="aws_db_instance.main",
    )
    patch = remediate_sync(finding, 0, bundle)
    assert "storage_encrypted = true" in patch.patched_content


def test_tf_imdsv2_required(mock_llm):
    bundle = _tf_bundle('''
resource "aws_instance" "app" {
  ami           = "ami-123"
  instance_type = "t3.micro"
}
''')
    finding = _f(
        category="instance-metadata",
        title="EC2 instance without IMDSv2",
        resource="aws_instance.app",
        severity=Severity.MEDIUM,
    )
    patch = remediate_sync(finding, 0, bundle)
    assert 'http_tokens' in patch.patched_content
    assert '"required"' in patch.patched_content
    parse_terraform(patch.patched_content)


def test_tf_kms_rotation_enabled(mock_llm):
    bundle = _tf_bundle('''
resource "aws_kms_key" "main" {
  description = "main"
}
''')
    finding = _f(
        category="encryption",
        title="KMS key rotation not enabled",
        resource="aws_kms_key.main",
        severity=Severity.MEDIUM,
    )
    patch = remediate_sync(finding, 0, bundle)
    assert "enable_key_rotation = true" in patch.patched_content


def test_tf_azure_storage_https_only(mock_llm):
    bundle = _tf_bundle('''
resource "azurerm_storage_account" "data" {
  name                       = "data"
  resource_group_name        = "rg"
  location                   = "eastus"
  account_tier               = "Standard"
  account_replication_type   = "LRS"
  enable_https_traffic_only  = false
}
''')
    finding = _f(
        category="encryption-in-transit",
        title="Azure storage allows non-HTTPS traffic",
        resource="azurerm_storage_account.data",
    )
    patch = remediate_sync(finding, 0, bundle)
    assert "enable_https_traffic_only  = true" in patch.patched_content or \
           "enable_https_traffic_only = true" in patch.patched_content


def test_tf_azure_keyvault_purge_protection(mock_llm):
    bundle = _tf_bundle('''
resource "azurerm_key_vault" "main" {
  name                = "main"
  location            = "eastus"
  resource_group_name = "rg"
  tenant_id           = "x"
  sku_name            = "standard"
}
''')
    finding = _f(
        category="encryption",
        title="Key Vault without purge protection",
        resource="azurerm_key_vault.main",
        severity=Severity.MEDIUM,
    )
    patch = remediate_sync(finding, 0, bundle)
    assert "purge_protection_enabled = true" in patch.patched_content


def test_tf_gcp_firewall_open(mock_llm):
    bundle = _tf_bundle('''
resource "google_compute_firewall" "open" {
  name          = "open"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
''')
    finding = _f(
        category="network",
        title="GCP firewall open to 0.0.0.0/0",
        resource="google_compute_firewall.open",
        severity=Severity.CRITICAL,
    )
    patch = remediate_sync(finding, 0, bundle)
    assert "0.0.0.0/0" not in patch.patched_content
    parse_terraform(patch.patched_content)


def test_tf_gcs_uniform_access(mock_llm):
    bundle = _tf_bundle('''
resource "google_storage_bucket" "data" {
  name     = "data"
  location = "US"
}
''')
    finding = _f(
        category="public-exposure",
        title="GCS bucket without uniform access",
        resource="google_storage_bucket.data",
        severity=Severity.MEDIUM,
    )
    patch = remediate_sync(finding, 0, bundle)
    assert "uniform_bucket_level_access = true" in patch.patched_content


def test_tf_hardcoded_password_externalized(mock_llm):
    bundle = _tf_bundle('''
resource "aws_db_instance" "main" {
  identifier     = "main"
  engine         = "postgres"
  instance_class = "db.t3.micro"
  username       = "admin"
  password       = "Pl4inT3xt!"
}
''')
    finding = _f(
        category="hardcoded-secret",
        title="Hardcoded database password in Terraform",
        resource="aws_db_instance.main",
        severity=Severity.CRITICAL,
    )
    patch = remediate_sync(finding, 0, bundle)
    assert "Pl4inT3xt!" not in patch.patched_content
    assert "var.db_password" in patch.patched_content


def test_tf_iam_policy_annotation_only(mock_llm):
    """Policy wildcards can't be safely auto-narrowed; we annotate with TODO."""
    bundle = _tf_bundle('''
resource "aws_iam_policy" "wide" {
  name   = "wide"
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}
''')
    finding = _f(
        category="iam",
        title="Overly permissive IAM policy",
        resource="aws_iam_policy.wide",
    )
    patch = remediate_sync(finding, 0, bundle)
    assert "TODO(governance)" in patch.patched_content
    parse_terraform(patch.patched_content)


# ---------------------------------------------------------------------------
# Validation behavior
# ---------------------------------------------------------------------------


def test_validate_rejects_unparseable_yaml():
    with pytest.raises(PatchValidationError):
        _validate_patch("x.yaml", "kubernetes_yaml", "this: is\n  : not valid: yaml: ::")


def test_validate_rejects_empty_patched_content():
    with pytest.raises(PatchValidationError):
        _validate_patch("x.yaml", "kubernetes_yaml", "   \n\n")


def test_validate_passes_for_well_formed_terraform():
    _validate_patch("x.tf", "terraform_hcl", 'resource "aws_s3_bucket" "x" { bucket = "y" }\n')


def test_validate_rejects_unparseable_terraform():
    with pytest.raises(PatchValidationError):
        _validate_patch("x.tf", "terraform_hcl", 'resource "aws_s3_bucket" "x" { bucket =\n')


# ---------------------------------------------------------------------------
# LLM fallback
# ---------------------------------------------------------------------------


def test_llm_fallback_for_ai_analysis_finding(mock_llm):
    """When category isn't covered by deterministic fixers, the LLM is invoked."""
    bundle = _tf_bundle('''
resource "aws_s3_bucket" "data" {
  bucket = "data"
}
''')
    fixed = '''
resource "aws_s3_bucket" "data" {
  bucket = "data"
  versioning { enabled = true }
}
'''
    mock_llm.set("remediator", {"patched_content": fixed, "explanation": "Enabled versioning."})

    finding = _f(
        category="ai-analysis",  # no deterministic fixer for this
        title="S3 bucket missing versioning",
        resource="aws_s3_bucket.data",
        agent="Reliability Agent",
    )
    patch = remediate_sync(finding, 0, bundle)
    assert patch.strategy == "llm"
    assert "versioning" in patch.patched_content
    assert any("LLM" in w for w in patch.warnings)


def test_llm_fallback_retries_on_invalid_output(mock_llm):
    """First LLM response is unparseable HCL; second succeeds."""
    bundle = _tf_bundle('''
resource "aws_s3_bucket" "data" {
  bucket = "data"
}
''')
    # Override the fake to return bad-then-good. We do this by stuffing a list
    # into the response_map and consuming it in a custom subclass.
    call_count = {"n": 0}
    good = 'resource "aws_s3_bucket" "data" { bucket = "data"\n  versioning { enabled = true }\n}\n'
    bad = 'resource "aws_s3_bucket" "data" { bucket = "data" missing brace\n'

    # We can't easily mutate the fake mid-test for this scenario, so we
    # monkeypatch the LLM call directly via mock_llm.set with a sentinel that
    # toggles. The simplest approach: set to bad, then in a second pass,
    # override to good. But the remediator runs both attempts inside one call.
    #
    # Instead, simulate by patching get_llm to return a custom Runnable.
    import json as _json

    class _ToggleRunnable:
        async def ainvoke(self, *args, **kwargs):
            call_count["n"] += 1
            payload = bad if call_count["n"] == 1 else good
            class _R:
                content = _json.dumps({"patched_content": payload, "explanation": "Versioning."})
            return _R()

        def invoke(self, *args, **kwargs):
            import asyncio as _a
            return _a.run(self.ainvoke(*args, **kwargs))

    # Patch right where remediator looks it up
    import app.agents.remediator as rem
    orig = rem.get_llm
    rem.get_llm = lambda *a, **k: _ToggleRunnable()
    try:
        finding = _f(
            category="ai-analysis",
            title="X",
            resource="aws_s3_bucket.data",
        )
        patch = remediate_sync(finding, 0, bundle)
    finally:
        rem.get_llm = orig

    assert call_count["n"] == 2, "LLM should have been retried after invalid first response"
    assert "versioning" in patch.patched_content
    assert patch.strategy == "llm"


def test_llm_fallback_fails_when_both_attempts_invalid(mock_llm):
    bundle = _tf_bundle('''
resource "aws_s3_bucket" "data" {
  bucket = "data"
}
''')
    mock_llm.set("remediator", {"patched_content": "garbage HCL { broken", "explanation": "x"})
    finding = _f(
        category="ai-analysis",
        title="X",
        resource="aws_s3_bucket.data",
    )
    with pytest.raises(RemediationError):
        remediate_sync(finding, 0, bundle)


# ---------------------------------------------------------------------------
# End-to-end: diff content + warnings
# ---------------------------------------------------------------------------


def test_patch_unified_diff_is_well_formed(mock_llm):
    bundle = _tf_bundle('''
resource "aws_kms_key" "main" {
  description = "main"
}
''')
    finding = _f(
        category="encryption",
        title="KMS key rotation not enabled",
        resource="aws_kms_key.main",
    )
    patch = remediate_sync(finding, 0, bundle)
    assert patch.unified_diff.startswith("--- a/main.tf")
    assert "+++ b/main.tf" in patch.unified_diff
    assert "+  enable_key_rotation = true" in patch.unified_diff


def test_warnings_list_is_populated_when_placeholder_introduced(mock_llm):
    bundle = _tf_bundle('''
resource "aws_security_group" "open" {
  ingress { cidr_blocks = ["0.0.0.0/0"] }
}
''')
    finding = _f(
        category="network",
        title="Security group open to 0.0.0.0/0",
        resource="aws_security_group.open",
        severity=Severity.CRITICAL,
    )
    patch = remediate_sync(finding, 0, bundle)
    assert any("CHANGE_ME" in w or "10.0.0.0/8" in w or "trusted CIDR" in w for w in patch.warnings)


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_empty_bundle_raises():
    finding = _f(category="encryption", title="X", resource="aws_s3_bucket.data")
    with pytest.raises(RemediationError):
        remediate_sync(finding, 0, {})


def test_finding_referencing_unknown_resource(mock_llm):
    bundle = _tf_bundle('resource "aws_s3_bucket" "data" { bucket = "x" }\n')
    finding = _f(category="encryption", title="X", resource="aws_s3_bucket.does_not_exist")
    with pytest.raises(RemediationError):
        remediate_sync(finding, 0, bundle)


def test_unsupported_category_falls_back_to_llm_then_fails(mock_llm):
    """A finding with no deterministic fixer triggers the LLM. With the
    default mock returning empty patched_content, the LLM path also fails."""
    bundle = _tf_bundle('resource "aws_s3_bucket" "data" { bucket = "x" }\n')
    finding = _f(
        category="reliability-policy",
        title="No backup policy",
        resource="aws_s3_bucket.data",
    )
    # Default remediator mock has empty patched_content -> validation fails
    with pytest.raises(RemediationError):
        remediate_sync(finding, 0, bundle)


# ---------------------------------------------------------------------------
# K8s edge cases
# ---------------------------------------------------------------------------


def test_k8s_multi_doc_yaml_preserves_other_documents(mock_llm):
    bundle = _k8s_bundle('''
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
data:
  key: value
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: c
          image: c:1.0
          securityContext:
            privileged: true
''')
    finding = _f(
        category="privileged",
        title="Privileged container",
        resource="Deployment/default/app",
        description="Container 'c' in Deployment/default/app runs in privileged mode.",
        severity=Severity.CRITICAL,
    )
    patch = remediate_sync(finding, 0, bundle)
    docs = parse_kubernetes_yaml(patch.patched_content)
    assert len(docs) == 2
    assert docs[0]["kind"] == "ConfigMap"
    assert docs[1]["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] is False


def test_k8s_finding_against_init_container_falls_back_to_first(mock_llm):
    """When the description names an initContainer, the fixer matches it."""
    bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: default
spec:
  template:
    spec:
      initContainers:
        - name: setup
          image: setup:1.0
      containers:
        - name: main
          image: main:1.0
          securityContext:
            privileged: true
''')
    finding = _f(
        category="privileged",
        title="Privileged container",
        resource="Deployment/default/app",
        description="Container 'main' in Deployment/default/app runs in privileged mode.",
        severity=Severity.CRITICAL,
    )
    patch = remediate_sync(finding, 0, bundle)
    docs = parse_kubernetes_yaml(patch.patched_content)
    main_container = next(c for c in docs[0]["spec"]["template"]["spec"]["containers"] if c["name"] == "main")
    assert main_container["securityContext"]["privileged"] is False
    init_container = docs[0]["spec"]["template"]["spec"]["initContainers"][0]
    assert "securityContext" not in init_container


# ---------------------------------------------------------------------------
# TF edge cases
# ---------------------------------------------------------------------------


def test_tf_block_span_with_braces_in_strings():
    """Strings containing { or } must not confuse the brace counter."""
    content = '''
resource "aws_iam_policy" "alpha" {
  policy = "{\\"Version\\":\\"2012-10-17\\"}"
}
resource "aws_iam_policy" "bravo" {
  description = "z"
}
'''
    span = _find_tf_block_span(content, "aws_iam_policy", "alpha")
    assert span is not None
    s, e = span
    block = content[s:e]
    assert '"alpha"' in block
    assert '"bravo"' not in block
    # Block braces balance
    assert block.count("{") == block.count("}")


def test_tf_block_span_with_nested_blocks():
    content = '''
resource "aws_security_group" "main" {
  ingress {
    from_port = 80
    to_port = 80
    protocol = "tcp"
  }
  egress {
    from_port = 0
  }
}
resource "aws_s3_bucket" "other" {
  bucket = "x"
}
'''
    span = _find_tf_block_span(content, "aws_security_group", "main")
    assert span is not None
    s, e = span
    assert "ingress" in content[s:e]
    assert "egress" in content[s:e]
    assert "aws_s3_bucket" not in content[s:e]


def test_tf_set_argument_replaces_existing(mock_llm):
    """Setting an existing key should overwrite, not duplicate."""
    bundle = _tf_bundle('''
resource "aws_kms_key" "main" {
  description         = "main"
  enable_key_rotation = false
}
''')
    finding = _f(
        category="encryption",
        title="KMS key rotation not enabled",
        resource="aws_kms_key.main",
        severity=Severity.MEDIUM,
    )
    patch = remediate_sync(finding, 0, bundle)
    # Should have ONE enable_key_rotation line, set to true
    occurrences = patch.patched_content.count("enable_key_rotation")
    assert occurrences == 1
    assert "enable_key_rotation = true" in patch.patched_content
    assert "enable_key_rotation = false" not in patch.patched_content


# ---------------------------------------------------------------------------
# Whitespace-tolerant filter for LLM patches
# ---------------------------------------------------------------------------


class TestCosmeticDriftFilter:
    """The filter strips dash-rule comment drift and trailing-whitespace
    drift from LLM patches, while preserving real edits."""

    def test_dash_count_change_is_cosmetic(self):
        assert _is_cosmetic_drift("# ----------------\n", "# ------\n") is True

    def test_dash_count_change_no_newline_still_cosmetic(self):
        assert _is_cosmetic_drift("# --------", "# -----") is True

    def test_trailing_whitespace_only_is_cosmetic(self):
        assert _is_cosmetic_drift("foo\n", "foo   \n") is True
        assert _is_cosmetic_drift("foo  \n", "foo\n") is True

    def test_identical_lines_not_drift(self):
        # _is_cosmetic_drift returns False for identical lines (caller checks first)
        assert _is_cosmetic_drift("# --------\n", "# --------\n") is False

    def test_real_comment_text_change_is_not_cosmetic(self):
        assert _is_cosmetic_drift("# SECURITY GROUP\n", "# SECURITY\n") is False
        assert _is_cosmetic_drift("# foo bar\n", "# foo baz\n") is False

    def test_dash_to_equals_is_not_cosmetic(self):
        """Different decoration character means it's an intentional change."""
        assert _is_cosmetic_drift("# --------\n", "# ========\n") is False

    def test_code_line_change_is_not_cosmetic(self):
        assert _is_cosmetic_drift("foo = 1\n", "foo = 2\n") is False
        assert _is_cosmetic_drift("storage_encrypted = true\n",
                                  "storage_encrypted = false\n") is False

    def test_strip_cosmetic_drift_reverts_dash_rewrites(self):
        original = (
            "# -------------------------------------------------\n"
            "# SECURITY GROUP\n"
            "# -------------------------------------------------\n"
            'resource "aws_security_group" "x" {\n'
            "  name = \"x\"\n"
            "}\n"
        )
        # LLM emitted shorter dashes around the comment but added a real edit
        patched = (
            "# -----------------\n"          # cosmetic drift (shorter)
            "# SECURITY GROUP\n"
            "# -----------------\n"          # cosmetic drift
            'resource "aws_security_group" "x" {\n'
            "  name = \"x\"\n"
            "  description = \"managed\"\n"  # real edit
            "}\n"
        )
        cleaned = _strip_cosmetic_drift(original, patched)
        # Original dash lines preserved
        assert "# -------------------------------------------------\n" in cleaned
        assert "# -----------------\n" not in cleaned
        # Real edit retained
        assert "description = \"managed\"" in cleaned

    def test_strip_cosmetic_drift_leaves_real_edits_alone(self):
        original = "foo = 1\nbar = 2\n"
        patched = "foo = 1\nbar = 99\n"
        assert _strip_cosmetic_drift(original, patched) == "foo = 1\nbar = 99\n"

    def test_strip_cosmetic_drift_handles_pure_inserts(self):
        """Inserted lines (no original counterpart) flow through unchanged."""
        original = "a\nb\n"
        patched = "a\nINSERTED\nb\n"
        assert _strip_cosmetic_drift(original, patched) == patched

    def test_strip_cosmetic_drift_identical_returns_original(self):
        original = "x = 1\n"
        assert _strip_cosmetic_drift(original, original) == original

    def test_filter_applied_in_llm_path_end_to_end(self, mock_llm):
        """End-to-end: LLM emits a patch with dash-line drift; the cleaned
        diff has no hunks for the cosmetic lines."""
        original = (
            'provider "aws" {\n'
            '  region = "us-east-1"\n'
            '}\n'
            '\n'
            "# -------------------------------------------------\n"
            "# S3\n"
            "# -------------------------------------------------\n"
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "data"\n'
            '}\n'
        )
        # LLM "fix": adds a real versioning block but rewrites the dash rules
        llm_patched = (
            'provider "aws" {\n'
            '  region = "us-east-1"\n'
            '}\n'
            '\n'
            "# -----------\n"                # drift
            "# S3\n"
            "# -----------\n"                # drift
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "data"\n'
            '  versioning {\n'
            '    enabled = true\n'
            '  }\n'
            '}\n'
        )
        mock_llm.set("remediator", {
            "patched_content": llm_patched,
            "explanation": "Enabled versioning.",
        })

        bundle = {"main.tf": original}
        finding = _f(
            category="ai-analysis",
            title="S3 bucket missing versioning",
            resource="aws_s3_bucket.data",
            agent="Reliability Agent",
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "llm"
        # The cleaned output keeps the original dash lines intact
        assert "# -------------------------------------------------\n" in patch.patched_content
        assert "# -----------\n" not in patch.patched_content
        # Real edit survives the filter
        assert "versioning {" in patch.patched_content
        # The unified diff shows no hunks touching the dash-rule lines
        assert "# -------------" not in patch.unified_diff or all(
            "# -------------" not in line
            for line in patch.unified_diff.splitlines()
            if line.startswith(("-", "+")) and not line.startswith(("---", "+++"))
        )


# ---------------------------------------------------------------------------
# Egress fixer (deterministic, was previously LLM-only)
# ---------------------------------------------------------------------------


class TestEgressFixer:
    """The 'Overly Permissive Egress on Security Group' finding (LLM-emitted
    title) now flows through the deterministic fixer instead of falling back
    to the LLM, just like the rule-based ingress finding."""

    def test_overly_permissive_egress_is_deterministic(self, mock_llm):
        bundle = {
            "main.tf": (
                'resource "aws_security_group" "app_sg" {\n'
                '  name = "app-sg"\n'
                '  ingress {\n'
                '    from_port   = 22\n'
                '    to_port     = 22\n'
                '    protocol    = "tcp"\n'
                '    cidr_blocks = ["10.0.0.0/8"]\n'
                '  }\n'
                '  egress {\n'
                '    from_port   = 0\n'
                '    to_port     = 0\n'
                '    protocol    = "-1"\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                '  }\n'
                '}\n'
            )
        }
        finding = _f(
            category="network",
            title="Overly Permissive Egress on Security Group",
            resource="aws_security_group.app_sg",
            severity=Severity.MEDIUM,
            agent="Security Agent",
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic", (
            f"Egress should be deterministic, got {patch.strategy}"
        )
        assert "0.0.0.0/0" not in patch.patched_content
        assert "10.0.0.0/8" in patch.patched_content
        # Ingress wasn't touched (still has its 10.0.0.0/8 from the start)
        assert patch.patched_content.count("10.0.0.0/8") >= 2
        # Validates as TF
        from app.parsers.terraform import parse_terraform
        parse_terraform(patch.patched_content)
        # Direction reported as egress in the explanation
        assert "egress" in patch.explanation.lower()

    def test_ingress_finding_still_works(self, mock_llm):
        """The rule-based 'Security group open to 0.0.0.0/0' finding (which
        is ingress) continues to work via the same deterministic fixer."""
        bundle = {
            "main.tf": (
                'resource "aws_security_group" "open" {\n'
                '  ingress {\n'
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                '  }\n'
                '}\n'
            )
        }
        finding = _f(
            category="network",
            title="Security group open to 0.0.0.0/0",
            resource="aws_security_group.open",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert "0.0.0.0/0" not in patch.patched_content
        assert "10.0.0.0/8" in patch.patched_content
        assert "ingress" in patch.explanation.lower()

    def test_sg_without_literal_zero_cidr_falls_back_to_llm(self, mock_llm):
        """If the SG has no literal 0.0.0.0/0 (e.g. it uses var.allowed_cidrs),
        the deterministic fixer raises and the LLM gets the call."""
        bundle = {
            "main.tf": (
                'resource "aws_security_group" "app_sg" {\n'
                '  name = "app-sg"\n'
                '  egress {\n'
                '    from_port = 0\n'
                '    to_port = 0\n'
                '    protocol = "-1"\n'
                '    cidr_blocks = var.allowed_egress_cidrs\n'
                '  }\n'
                '}\n'
            )
        }
        # LLM returns a no-op so the LLM path will fail validation and the
        # whole call should raise — proving we did try the LLM path.
        mock_llm.set("remediator", {"patched_content": "", "explanation": "x"})
        finding = _f(
            category="network",
            title="Overly Permissive Egress on Security Group",
            resource="aws_security_group.app_sg",
            severity=Severity.MEDIUM,
        )
        with pytest.raises(RemediationError):
            remediate_sync(finding, 0, bundle)


# ---------------------------------------------------------------------------
# Advisory / non-patchable findings
# ---------------------------------------------------------------------------


class TestNonPatchableFindings:
    """Findings whose resource is N/A, empty, or a whole-infrastructure
    sentinel cannot be remediated by a code patch. The remediator must
    surface this clearly instead of mis-classifying them as Kubernetes
    resources or returning a misleading 'file not found' error."""

    def test_is_non_patchable_for_na(self):
        f = _f(category="ai-analysis", title="x", resource="N/A")
        assert is_non_patchable(f) is True

    def test_is_non_patchable_for_empty(self):
        f = _f(category="ai-analysis", title="x", resource="")
        assert is_non_patchable(f) is True

    def test_is_non_patchable_for_infrastructure_sentinel(self):
        f = _f(category="monitoring", title="x", resource="infrastructure")
        assert is_non_patchable(f) is True

    def test_is_non_patchable_handles_case_and_whitespace(self):
        for r in ("n/a", "  N/A  ", "None", "GLOBAL", "Various"):
            f = _f(category="ai-analysis", title="x", resource=r)
            assert is_non_patchable(f) is True, f"{r!r} should be non-patchable"

    def test_is_patchable_for_real_resource(self):
        for r in ("aws_s3_bucket.data", "Deployment/default/api",
                  "azurerm_storage_account.x", "google_compute_firewall.allow"):
            f = _f(category="encryption", title="x", resource=r)
            assert is_non_patchable(f) is False, f"{r!r} should be patchable"

    def test_advisory_finding_raises_non_patchable_not_locate_error(self, mock_llm):
        """The bug from the screenshot: 'Lack of Commitment Discounts' with
        resource='N/A' was returning 'Could not locate Kubernetes resource'
        — wrong AND misleading. Now it raises NonPatchableFinding with a
        clear advisory message, and never tries to locate or call the LLM."""
        bundle = {
            "main.tf": (
                'resource "aws_s3_bucket" "data" { bucket = "x" }\n'
            )
        }
        finding = _f(
            category="ai-analysis",
            title="Lack of Commitment Discounts",
            resource="N/A",
            severity=Severity.INFO,
            agent="Cost Agent",
        )
        with pytest.raises(NonPatchableFinding) as exc_info:
            remediate_sync(finding, 0, bundle)
        msg = str(exc_info.value).lower()
        assert "advisory" in msg
        assert "kubernetes" not in msg, (
            "Error must not mention Kubernetes for an AWS-only advisory"
        )

    def test_non_patchable_is_subclass_of_remediation_error(self):
        """Existing API code that catches RemediationError still catches
        the new NonPatchableFinding — backwards compatible."""
        assert issubclass(NonPatchableFinding, RemediationError)

    def test_empty_resource_raises_non_patchable(self):
        bundle = {"main.tf": "resource \"aws_s3_bucket\" \"x\" { bucket = \"y\" }\n"}
        finding = _f(category="ai-analysis", title="x", resource="")
        with pytest.raises(NonPatchableFinding):
            remediate_sync(finding, 0, bundle)


# ---------------------------------------------------------------------------
# Bug fixes (post-Helm-chart user testing)
# ---------------------------------------------------------------------------


class TestRuamelMinimalDiff:
    """Bug 1: deterministic K8s fixers must produce minimal diffs.

    Before the ruamel.yaml round-trip migration, fixing a single env var
    in a multi-document Helm-rendered YAML caused PyYAML to renormalize
    quote style, indentation, flow style, and drop ``# Source:`` comments,
    producing 80+ lines of cosmetic diff for a 4-line edit. ruamel
    round-trip mode preserves all of that.
    """

    def test_helm_rendered_yaml_minimal_diff_for_secret_fix(self, mock_llm):
        # Realistic Helm-rendered shape: source comments, double-quoted
        # version strings, list indentation under containers, flow style
        # preserved. Loosely mirrors samples/my-chart-1.0.0.tgz output.
        original = (
            "---\n"
            "# Source: my-chart/templates/service.yaml\n"
            "apiVersion: v1\n"
            "kind: Service\n"
            "metadata:\n"
            "  name: release-my-chart\n"
            "  labels:\n"
            '    app.kubernetes.io/version: "2.1.0"\n'
            "---\n"
            "# Source: my-chart/templates/deployment.yaml\n"
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: release-my-chart\n"
            "  namespace: default\n"
            "  labels:\n"
            '    app.kubernetes.io/version: "2.1.0"\n'
            "spec:\n"
            "  replicas: 2\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: my-chart\n"
            '          image: "my-org/web-api:2.1.0"\n'
            "          env:\n"
            "            - name: APP_ENV\n"
            '              value: "production"\n'
            "            - name: DB_PASSWORD\n"
            '              value: "supersecret123"\n'
            "            - name: LOG_LEVEL\n"
            '              value: "info"\n'
        )
        bundle = {"my-chart-rendered.yaml": original}
        finding = _f(
            agent="Security Agent",
            category="hardcoded-secret",
            title="Hardcoded secret in environment variable",
            resource="Deployment/default/release-my-chart",
            description="Container 'my-chart' in Deployment/default/release-my-chart has secret 'DB_PASSWORD' hardcoded in plain text.",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        # Sanity: the actual fix landed
        assert "secretKeyRef" in patch.patched_content
        assert "supersecret123" not in patch.patched_content

        # Critical assertion: only the env var lines should differ.
        # Source comments and version quotes must survive untouched.
        assert "# Source: my-chart/templates/service.yaml" in patch.patched_content
        assert "# Source: my-chart/templates/deployment.yaml" in patch.patched_content
        assert '"2.1.0"' in patch.patched_content, (
            "ruamel must preserve double-quoted version strings"
        )

        # Diff hunk count: a single-key replacement should produce one
        # small hunk. Count `+` and `-` content lines (ignoring file headers).
        added = [
            ln for ln in patch.unified_diff.splitlines()
            if ln.startswith("+") and not ln.startswith("+++")
        ]
        removed = [
            ln for ln in patch.unified_diff.splitlines()
            if ln.startswith("-") and not ln.startswith("---")
        ]
        # A reasonable upper bound: secretKeyRef adds 3 lines, removes 1.
        # Allow some headroom for indentation but reject the old PyYAML
        # blowup of 50+ lines.
        assert len(added) + len(removed) <= 12, (
            f"Diff too noisy ({len(added)} added + {len(removed)} removed). "
            f"ruamel round-trip should keep the patch surgical. "
            f"Diff:\n{patch.unified_diff}"
        )

    def test_quoted_strings_survive_round_trip(self, mock_llm):
        """Single-quoted, double-quoted, and bare strings must keep their
        quoting style after a deterministic K8s fix."""
        original = (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: app\n"
            "  namespace: default\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: app\n"
            '          image: "app:1.0"\n'
            "          env:\n"
            "            - name: KEY\n"
            "              value: 'plain-text'\n"
            "          securityContext:\n"
            "            privileged: true\n"
        )
        bundle = {"deploy.yaml": original}
        finding = _f(
            category="privileged",
            title="Privileged container",
            resource="Deployment/default/app",
            description="Container 'app' in Deployment/default/app runs in privileged mode.",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        # Both quote styles preserved
        assert '"app:1.0"' in patch.patched_content
        assert "'plain-text'" in patch.patched_content


class TestLLMJsonParsing:
    """Bug 2: the local LLM emits JSON with literal newlines inside string
    values. Strict ``json.loads`` rejects those; we now have multi-strategy
    parsing that survives the common failure modes."""

    def test_strict_json_still_works(self):
        from app.agents.remediator import _parse_llm_json_response
        text = '{"patched_content": "hello", "explanation": "x"}'
        patched, expl = _parse_llm_json_response(text)
        assert patched == "hello"
        assert expl == "x"

    def test_unescaped_newlines_in_patched_content_recovered(self):
        """The exact failure mode you saw: 'Invalid control character at: line 1 column 25'.
        Gemma emitted the patched content with literal \\n bytes inside
        the string value. strict=False rescues."""
        from app.agents.remediator import _parse_llm_json_response
        # Note: literal newline inside the JSON string value
        text = (
            '{"patched_content": "apiVersion: v1\nkind: Service\nmetadata:\n  name: x\n", '
            '"explanation": "Set service type."}'
        )
        patched, expl = _parse_llm_json_response(text)
        assert "apiVersion: v1" in patched
        assert "kind: Service" in patched
        assert expl == "Set service type."

    def test_markdown_fenced_json_recovered(self):
        from app.agents.remediator import _parse_llm_json_response
        text = '```json\n{"patched_content": "hello", "explanation": "x"}\n```'
        patched, expl = _parse_llm_json_response(text)
        assert patched == "hello"

    def test_response_with_prose_around_json_via_regex(self):
        """The LLM rambles before the JSON. Regex extraction rescues."""
        from app.agents.remediator import _parse_llm_json_response
        text = (
            "Sure, here is the patch:\n"
            '{"patched_content": "fixed: yes\nworking: true\n", "explanation": "ok"}\n'
            "Hope that helps!"
        )
        patched, _ = _parse_llm_json_response(text)
        assert "fixed: yes" in patched

    def test_empty_response_raises(self):
        from app.agents.remediator import _parse_llm_json_response
        with pytest.raises(ValueError):
            _parse_llm_json_response("")
        with pytest.raises(ValueError):
            _parse_llm_json_response("   \n  ")

    def test_non_object_response_raises(self):
        from app.agents.remediator import _parse_llm_json_response
        with pytest.raises(ValueError):
            _parse_llm_json_response('"just a string"')
        with pytest.raises(ValueError):
            _parse_llm_json_response('[1, 2, 3]')


class TestTemplatePathDetection:
    """Bug 3: LLM emits Helm template paths in resource field. The
    locator now treats those as non-patchable rather than mis-routing
    them through the K8s file matcher."""

    def test_helm_template_path_is_non_patchable(self, mock_llm):
        bundle = {
            "rendered.yaml": (
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n  name: app\n  namespace: default\n"
                "spec:\n  template:\n    spec:\n      containers:\n"
                "        - name: c\n          image: c:1.0\n"
            )
        }
        finding = _f(
            category="ai-analysis",
            title="Image Tagging",
            resource="my-chart/templates/deployment.yaml",
            severity=Severity.INFO,
        )
        with pytest.raises(NonPatchableFinding) as exc:
            remediate_sync(finding, 0, bundle)
        msg = str(exc.value).lower()
        assert "template" in msg or "file" in msg
        # Make sure the OLD wrong message is gone
        assert "could not locate kubernetes resource" not in msg

    def test_yaml_file_extension_resource_is_non_patchable(self, mock_llm):
        bundle = {"foo.yaml": "apiVersion: v1\nkind: Service\nmetadata:\n  name: x\n"}
        finding = _f(
            category="ai-analysis",
            title="X",
            resource="some-chart-file.yaml",
            severity=Severity.LOW,
        )
        with pytest.raises(NonPatchableFinding):
            remediate_sync(finding, 0, bundle)

    def test_real_kubernetes_resource_still_locates(self, mock_llm):
        """Sanity: don't false-positive on legitimate Kind/ns/name."""
        bundle = {
            "rendered.yaml": (
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n  name: app\n  namespace: default\n"
                "spec:\n  template:\n    spec:\n      containers:\n"
                "        - name: c\n          image: c:1.0\n"
                "          securityContext:\n            privileged: true\n"
            )
        }
        finding = _f(
            category="privileged",
            title="Privileged container",
            resource="Deployment/default/app",
            description="Container 'c' in Deployment/default/app runs in privileged mode.",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert "privileged: false" in patch.patched_content

    def test_terraform_resource_still_locates(self, mock_llm):
        """Sanity: aws_*.foo doesn't match the file-path heuristic."""
        bundle = {"main.tf": 'resource "aws_kms_key" "main" {\n  description = "x"\n}\n'}
        finding = _f(
            category="encryption",
            title="KMS key rotation not enabled",
            resource="aws_kms_key.main",
            severity=Severity.MEDIUM,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert "enable_key_rotation = true" in patch.patched_content


# ---------------------------------------------------------------------------
# Fuzzy K8s resource matching (Cost Agent emits chart-style names)
# ---------------------------------------------------------------------------


class TestFuzzyKubernetesMatching:
    """The Cost-Agent LLM occasionally emits 2-segment Kind/name resources
    (no namespace) and chart-style names that don't exactly match the
    rendered Helm release name. The locator and fix path now tolerate
    these via a layered match strategy that only resolves when the
    ambiguity is naturally bounded.
    """

    def test_two_segment_resource_resolves(self, mock_llm):
        """Kind/name (no namespace) — match via exact name + Kind."""
        bundle = {
            "rendered.yaml": (
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n"
                "  name: release-my-chart\n"
                "  namespace: default\n"
                "spec:\n"
                "  template:\n"
                "    spec:\n"
                "      containers:\n"
                "        - name: c\n"
                "          image: c:1.0\n"
                "          securityContext:\n"
                "            privileged: true\n"
            )
        }
        finding = _f(
            category="privileged",
            title="Privileged container",
            resource="Deployment/release-my-chart",  # 2-segment
            description="Container 'c' in Deployment/default/release-my-chart runs in privileged mode.",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert "privileged: false" in patch.patched_content

    def test_chart_name_resolves_to_rendered_release_name(self, mock_llm):
        """Bug from the screenshot: the Cost LLM emitted
        ``Deployment/my-chart`` against a Helm-rendered Deployment named
        ``release-my-chart`` (chart name + release prefix). Substring
        match should resolve unambiguously when there's only one
        Deployment of that name shape.
        """
        bundle = {
            "rendered.yaml": (
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n"
                "  name: release-my-chart\n"
                "  namespace: default\n"
                "spec:\n"
                "  template:\n"
                "    spec:\n"
                "      containers:\n"
                "        - name: c\n"
                "          image: c:1.0\n"
                "          securityContext:\n"
                "            privileged: true\n"
            )
        }
        finding = _f(
            category="privileged",
            title="Privileged container",
            resource="Deployment/my-chart",  # chart name, not rendered name
            description="Container 'c' in Deployment/default/release-my-chart runs in privileged mode.",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert "privileged: false" in patch.patched_content

    def test_single_workload_of_kind_fallback(self, mock_llm):
        """If the bundle has exactly ONE Deployment, even a name that
        doesn't match by substring resolves to it (last-resort fallback).
        """
        bundle = {
            "rendered.yaml": (
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n"
                "  name: completely-different-name\n"
                "  namespace: default\n"
                "spec:\n"
                "  template:\n"
                "    spec:\n"
                "      containers:\n"
                "        - name: c\n"
                "          image: c:1.0\n"
                "          securityContext:\n"
                "            privileged: true\n"
            )
        }
        finding = _f(
            category="privileged",
            title="Privileged container",
            resource="Deployment/something-else",
            description="Container 'c' runs in privileged mode.",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert "privileged: false" in patch.patched_content

    def test_ambiguous_substring_does_not_silently_pick(self, mock_llm):
        """Two Deployments both contain 'app' in their name — the locator
        must NOT pick one silently. It should fall through to the kind-only
        fallback, which also fails because there are 2 of the same Kind."""
        bundle = {
            "rendered.yaml": (
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n  name: app-frontend\n  namespace: default\n"
                "spec:\n  template:\n    spec:\n      containers:\n"
                "        - name: c\n          image: c:1.0\n"
                "          securityContext:\n            privileged: true\n"
                "---\n"
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n  name: app-backend\n  namespace: default\n"
                "spec:\n  template:\n    spec:\n      containers:\n"
                "        - name: c\n          image: c:1.0\n"
                "          securityContext:\n            privileged: true\n"
            )
        }
        finding = _f(
            category="privileged",
            title="Privileged container",
            resource="Deployment/app",  # substring-matches BOTH
            description="x",
            severity=Severity.CRITICAL,
        )
        # Substring match has 2 candidates; kind-only fallback also has 2;
        # locator should raise rather than guess.
        with pytest.raises(RemediationError) as exc:
            remediate_sync(finding, 0, bundle)
        msg = str(exc.value).lower()
        assert "could not locate" in msg or "ambiguous" in msg

    def test_exact_three_segment_still_matches_priority(self, mock_llm):
        """When two Deployments exist but one matches Kind/ns/name exactly,
        layer 1 wins and we don't fall back to ambiguous substring.
        """
        bundle = {
            "rendered.yaml": (
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n  name: app\n  namespace: prod\n"
                "spec:\n  template:\n    spec:\n      containers:\n"
                "        - name: c\n          image: c:1.0\n"
                "          securityContext:\n            privileged: true\n"
                "---\n"
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n  name: app\n  namespace: dev\n"
                "spec:\n  template:\n    spec:\n      containers:\n"
                "        - name: c\n          image: c:1.0\n"
            )
        }
        finding = _f(
            category="privileged",
            title="Privileged container",
            resource="Deployment/prod/app",  # exact 3-segment
            description="Container 'c' in Deployment/prod/app runs in privileged mode.",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        # The prod one was patched, dev one was untouched
        docs = parse_kubernetes_yaml(patch.patched_content)
        prod_doc = next(d for d in docs if d["metadata"]["namespace"] == "prod")
        dev_doc = next(d for d in docs if d["metadata"]["namespace"] == "dev")
        assert prod_doc["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] is False
        # dev had no securityContext to begin with — must remain absent
        assert "securityContext" not in dev_doc["spec"]["template"]["spec"]["containers"][0]

    def test_two_segment_with_ambiguous_namespaces(self, mock_llm):
        """Kind/name resolves UNAMBIGUOUSLY when only one workload has
        that exact name across all namespaces."""
        bundle = {
            "rendered.yaml": (
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n  name: web\n  namespace: prod\n"
                "spec:\n  template:\n    spec:\n      containers:\n"
                "        - name: c\n          image: c:1.0\n"
                "          securityContext:\n            privileged: true\n"
                "---\n"
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n  name: db\n  namespace: dev\n"
                "spec:\n  template:\n    spec:\n      containers:\n"
                "        - name: c\n          image: c:1.0\n"
            )
        }
        finding = _f(
            category="privileged",
            title="Privileged container",
            resource="Deployment/web",
            description="Container 'c' runs in privileged mode.",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"

    def test_canonical_three_segment_still_works(self, mock_llm):
        """Sanity: don't break the original happy path."""
        bundle = {
            "rendered.yaml": (
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n  name: api\n  namespace: default\n"
                "spec:\n  template:\n    spec:\n      containers:\n"
                "        - name: c\n          image: c:1.0\n"
                "          securityContext:\n            privileged: true\n"
            )
        }
        finding = _f(
            category="privileged",
            title="Privileged container",
            resource="Deployment/default/api",
            description="Container 'c' in Deployment/default/api runs in privileged mode.",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert "privileged: false" in patch.patched_content


# ---------------------------------------------------------------------------
# K8s JSON manifest round-trip
# ---------------------------------------------------------------------------


class TestK8sJsonRoundTrip:
    """Bug from k8s-api-deployment.json: a Kubernetes manifest uploaded as
    .json was loaded by ruamel YAML, mutated, then dumped as YAML — but
    the validator (correctly) tried to parse the patched output as JSON.
    Result: 'Patched content failed to parse: Expecting property name
    enclosed in double quotes'.

    Fix: when the source file is kubernetes_json, dump back as JSON.
    """

    def test_k8s_json_run_as_root_fix_emits_json(self, mock_llm):
        import json as _json
        original = _json.dumps({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "payments-api", "namespace": "production"},
            "spec": {
                "replicas": 2,
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "payments-api", "image": "x:1.0"},
                        ]
                    }
                },
            },
        }, indent=2) + "\n"
        bundle = {"k8s.json": original}
        finding = _f(
            agent="Security Agent",
            category="run-as-root",
            title="Container may run as root",
            resource="Deployment/production/payments-api",
            description="Container 'payments-api' in Deployment/production/payments-api has no runAsNonRoot.",
            severity=Severity.HIGH,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert patch.validation_status == "valid"

        # Output MUST parse as JSON — not YAML
        out = _json.loads(patch.patched_content)
        assert out["kind"] == "Deployment"
        sec = out["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        assert sec["runAsNonRoot"] is True
        assert sec["runAsUser"] == 1000

        # Sanity: output should look like JSON (curly braces, double quotes),
        # not like YAML (no leading "{", uses unquoted keys).
        assert patch.patched_content.lstrip().startswith("{")
        assert '"kind": "Deployment"' in patch.patched_content

    def test_k8s_json_filesystem_fix_emits_json(self, mock_llm):
        import json as _json
        original = _json.dumps({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "api", "namespace": "default"},
            "spec": {
                "template": {
                    "spec": {"containers": [{"name": "api", "image": "x:1.0"}]}
                }
            },
        }, indent=2)
        bundle = {"deploy.json": original}
        finding = _f(
            agent="Security Agent",
            category="filesystem",
            title="Writable root filesystem",
            resource="Deployment/default/api",
            description="Container 'api' in Deployment/default/api has writable root filesystem.",
            severity=Severity.MEDIUM,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.validation_status == "valid"
        out = _json.loads(patch.patched_content)
        assert out["spec"]["template"]["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"] is True

    def test_k8s_json_preserves_indent_width(self, mock_llm):
        """A 4-space-indented input should round-trip with 4 spaces."""
        import json as _json
        body = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "x", "namespace": "default"},
            "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "i"}]}}},
        }
        original = _json.dumps(body, indent=4) + "\n"
        bundle = {"x.json": original}
        finding = _f(
            agent="Security Agent",
            category="run-as-root",
            title="Container may run as root",
            resource="Deployment/default/x",
            description="Container 'c' in Deployment/default/x has no runAsNonRoot.",
            severity=Severity.HIGH,
        )
        patch = remediate_sync(finding, 0, bundle)
        # Find any indented line — should use 4 spaces, not 2
        for line in patch.patched_content.splitlines():
            stripped = line.lstrip(" ")
            if stripped and stripped != line:
                indent = len(line) - len(stripped)
                if indent > 0:
                    assert indent in (4, 8, 12, 16, 20), (
                        f"Expected 4-space indent, got {indent} on line: {line!r}"
                    )
                    break

    def test_k8s_json_secret_fix_emits_json(self, mock_llm):
        """Hardcoded-secret fix on a JSON manifest: the env section is
        rewritten and the output stays JSON."""
        import json as _json
        body = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "api", "namespace": "default"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "api",
                            "image": "x:1.0",
                            "env": [{"name": "DB_PASSWORD", "value": "hunter2"}],
                        }]
                    }
                }
            },
        }
        bundle = {"x.json": _json.dumps(body, indent=2)}
        finding = _f(
            agent="Security Agent",
            category="hardcoded-secret",
            title="Hardcoded secret in environment variable",
            resource="Deployment/default/api",
            description="Container 'api' in Deployment/default/api has secret 'DB_PASSWORD' hardcoded in plain text.",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        out = _json.loads(patch.patched_content)
        env = out["spec"]["template"]["spec"]["containers"][0]["env"][0]
        assert "value" not in env
        assert env["valueFrom"]["secretKeyRef"]["name"] == "CHANGE_ME_SECRET_NAME"


# ---------------------------------------------------------------------------
# Companion-resource categories (HPA, PDB, NetworkPolicy)
# ---------------------------------------------------------------------------


from app.agents.remediator import CompanionResourceRequired


class TestCompanionResourceRequired:
    """Bug from k8s-api-deployment.json: clicking Generate fix on
    'No HorizontalPodAutoscaler' wasted two LLM calls and ended in
    'Patched content failed to parse: Expecting value: line 1 column 1'.
    Root cause: HPA is a NEW resource, can't be patched into the
    existing single-doc JSON. Now we detect this category up-front and
    surface a clean YAML template instead.
    """

    def test_hpa_finding_returns_companion_template(self, mock_llm):
        bundle = {"k8s.json": '{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "api"}, "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "x"}]}}}}'}
        finding = _f(
            agent="Reliability Agent",
            category="autoscaling",
            title="No HorizontalPodAutoscaler",
            resource="Deployment/production/payments-api",
            severity=Severity.LOW,
        )
        with pytest.raises(CompanionResourceRequired) as exc:
            remediate_sync(finding, 0, bundle)
        # Template includes the canonical HPA shape with the workload bound
        assert "HorizontalPodAutoscaler" in exc.value.template
        assert "scaleTargetRef" in exc.value.template
        assert "payments-api" in exc.value.template
        assert "production" in exc.value.template
        # Suggested filename is workload-derived
        assert exc.value.filename == "payments-api-hpa.yaml"

    def test_pdb_finding_returns_companion_template(self, mock_llm):
        bundle = {"k8s.json": '{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "api"}, "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "x"}]}}}}'}
        finding = _f(
            agent="Reliability Agent",
            category="pdb",
            title="No PodDisruptionBudget",
            resource="Deployment/default/api",
            severity=Severity.MEDIUM,
        )
        with pytest.raises(CompanionResourceRequired) as exc:
            remediate_sync(finding, 0, bundle)
        assert "PodDisruptionBudget" in exc.value.template
        assert "minAvailable" in exc.value.template
        assert exc.value.filename == "api-pdb.yaml"

    def test_network_policy_finding_returns_companion_template(self, mock_llm):
        bundle = {"k8s.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n  namespace: default\nspec:\n  template:\n    spec:\n      containers:\n        - name: c\n          image: c:1\n"}
        finding = _f(
            agent="Security Agent",
            category="network-policy",
            title="No NetworkPolicy defined",
            resource="Deployment/default/api",
            severity=Severity.HIGH,
        )
        with pytest.raises(CompanionResourceRequired) as exc:
            remediate_sync(finding, 0, bundle)
        assert "NetworkPolicy" in exc.value.template
        assert "podSelector" in exc.value.template
        assert exc.value.filename == "api-netpol.yaml"

    def test_companion_required_is_caught_by_nonpatchable_handler(self, mock_llm):
        """The API endpoint catches NonPatchableFinding for 409.
        CompanionResourceRequired must subclass NonPatchableFinding so
        the existing handler still works without modification."""
        from app.agents.remediator import CompanionResourceRequired, NonPatchableFinding
        assert issubclass(CompanionResourceRequired, NonPatchableFinding)

    def test_companion_short_circuits_before_file_locator(self, mock_llm):
        """An empty bundle with an HPA finding still raises
        CompanionResourceRequired (not 'bundle is empty'). This proves
        we detect companion categories BEFORE attempting to locate a
        file — the LLM is never called either."""
        finding = _f(
            agent="Reliability Agent",
            category="autoscaling",
            title="No HorizontalPodAutoscaler",
            resource="Deployment/default/api",
            severity=Severity.LOW,
        )
        with pytest.raises(CompanionResourceRequired):
            remediate_sync(finding, 0, {"x.yaml": "kind: Pod\napiVersion: v1\nmetadata:\n  name: x\n"})

    def test_non_companion_reliability_finding_still_remediates(self, mock_llm):
        """Probes findings ARE in-place patches (add to container spec) —
        they should NOT be treated as companion-resource. They go through
        the LLM path normally."""
        bundle = {"deploy.yaml": (
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n  namespace: default\n"
            "spec:\n  template:\n    spec:\n      containers:\n        - name: c\n          image: c:1\n"
        )}
        finding = _f(
            agent="Reliability Agent",
            category="probes",
            title="Missing liveness probe",
            resource="Deployment/default/api",
            severity=Severity.HIGH,
        )
        # Configure the LLM to return a valid patched file. If we wrongly
        # short-circuited probes as companion-resource, this would raise
        # CompanionResourceRequired before reaching the LLM.
        patched_yaml = (
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n  namespace: default\n"
            "spec:\n  template:\n    spec:\n      containers:\n        - name: c\n          image: c:1\n"
            "          livenessProbe:\n            tcpSocket:\n              port: 8080\n"
        )
        mock_llm.set("remediator", {"patched_content": patched_yaml, "explanation": "Added liveness."})
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "llm"
        assert "livenessProbe" in patch.patched_content

    def test_hpa_template_renders_default_namespace_when_missing(self, mock_llm):
        """Resource with only Kind/name (no namespace) still produces a
        valid HPA template with namespace defaulting to 'default'."""
        finding = _f(
            agent="Reliability Agent",
            category="autoscaling",
            title="No HorizontalPodAutoscaler",
            resource="Deployment/api",  # 2-segment
            severity=Severity.LOW,
        )
        with pytest.raises(CompanionResourceRequired) as exc:
            remediate_sync(finding, 0, {"k8s.yaml": "kind: Deployment\nmetadata:\n  name: api\n"})
        assert "namespace: default" in exc.value.template
        assert "name: api-hpa" in exc.value.template


# ---------------------------------------------------------------------------
# Terraform JSON deterministic fixers (samples/terraform-serverless.json)
# ---------------------------------------------------------------------------


class TestTerraformJsonFixers:
    """Bug from terraform-serverless.json: clicking Generate fix on
    'S3 bucket without encryption' wasted two LLM calls and ended with
    'Invalid control character at: line 60 column 182'. Root cause: the
    LLM is unreliable on multi-hundred-line JSON.

    Phase 3.4 fix: deterministic JSON-tree fixers for every category the
    rule engine actually emits on Terraform JSON files.
    """

    @staticmethod
    def _bundle(json_body: str) -> dict[str, str]:
        return {"infra.json": json_body}

    @staticmethod
    def _minimal_tf_json(resource_type: str, resource_name: str, config: dict) -> str:
        import json as _j
        return _j.dumps({
            "terraform": {"required_providers": {"aws": {"source": "hashicorp/aws"}}},
            "resource": {resource_type: {resource_name: config}},
        }, indent=2)

    def test_s3_encryption_companion_added_to_json(self, mock_llm):
        import json as _j
        bundle = self._bundle(self._minimal_tf_json(
            "aws_s3_bucket", "uploads", {"bucket": "x"}
        ))
        finding = _f(
            agent="Security Agent",
            category="encryption",
            title="S3 bucket without encryption",
            resource="aws_s3_bucket.uploads",
            severity=Severity.HIGH,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert patch.validation_status == "valid"
        out = _j.loads(patch.patched_content)
        # Companion resource present
        assert "aws_s3_bucket_server_side_encryption_configuration" in out["resource"]
        sse = out["resource"]["aws_s3_bucket_server_side_encryption_configuration"]
        assert "uploads" in sse
        # Original bucket untouched
        assert out["resource"]["aws_s3_bucket"]["uploads"]["bucket"] == "x"

    def test_s3_public_access_block_companion(self, mock_llm):
        import json as _j
        bundle = self._bundle(self._minimal_tf_json(
            "aws_s3_bucket", "data", {"bucket": "y"}
        ))
        finding = _f(
            agent="Security Agent",
            category="public-exposure",
            title="S3 bucket without public access block",
            resource="aws_s3_bucket.data",
            severity=Severity.MEDIUM,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        out = _j.loads(patch.patched_content)
        pab = out["resource"]["aws_s3_bucket_public_access_block"]["data"]
        assert pab["block_public_acls"] is True
        assert pab["block_public_policy"] is True
        assert pab["ignore_public_acls"] is True
        assert pab["restrict_public_buckets"] is True

    def test_kms_rotation_scalar(self, mock_llm):
        import json as _j
        bundle = self._bundle(self._minimal_tf_json(
            "aws_kms_key", "main", {"description": "main"}
        ))
        finding = _f(
            agent="Security Agent",
            category="encryption",
            title="KMS key rotation not enabled",
            resource="aws_kms_key.main",
            severity=Severity.MEDIUM,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        out = _j.loads(patch.patched_content)
        assert out["resource"]["aws_kms_key"]["main"]["enable_key_rotation"] is True

    def test_imdsv2_metadata_options(self, mock_llm):
        import json as _j
        bundle = self._bundle(self._minimal_tf_json(
            "aws_instance", "app", {"ami": "ami-1", "instance_type": "t3.micro"}
        ))
        finding = _f(
            agent="Security Agent",
            category="instance-metadata",
            title="EC2 instance without IMDSv2",
            resource="aws_instance.app",
            severity=Severity.MEDIUM,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        out = _j.loads(patch.patched_content)
        meta = out["resource"]["aws_instance"]["app"]["metadata_options"]
        assert meta["http_tokens"] == "required"
        assert meta["http_endpoint"] == "enabled"

    def test_dynamodb_point_in_time_recovery(self, mock_llm):
        import json as _j
        bundle = self._bundle(self._minimal_tf_json(
            "aws_dynamodb_table", "sessions",
            {"name": "sessions", "hash_key": "id", "billing_mode": "PAY_PER_REQUEST"},
        ))
        finding = _f(
            agent="Reliability Agent",
            category="backup",
            title="DynamoDB without point-in-time recovery",
            resource="aws_dynamodb_table.sessions",
            severity=Severity.HIGH,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        out = _j.loads(patch.patched_content)
        pitr = out["resource"]["aws_dynamodb_table"]["sessions"]["point_in_time_recovery"]
        assert pitr["enabled"] is True

    def test_lambda_dead_letter_config(self, mock_llm):
        import json as _j
        bundle = self._bundle(self._minimal_tf_json(
            "aws_lambda_function", "api",
            {"function_name": "api", "runtime": "nodejs20.x", "handler": "index.handler"},
        ))
        finding = _f(
            agent="Reliability Agent",
            category="error-handling",
            title="Lambda without dead letter queue",
            resource="aws_lambda_function.api",
            severity=Severity.MEDIUM,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        out = _j.loads(patch.patched_content)
        dlc = out["resource"]["aws_lambda_function"]["api"]["dead_letter_config"]
        assert dlc["target_arn"] == "CHANGE_ME_SQS_OR_SNS_ARN"
        # Warning surfaced so the user knows they must fill in the ARN
        assert any("SQS" in w or "SNS" in w for w in patch.warnings)

    def test_lambda_vpc_config_added(self, mock_llm):
        import json as _j
        bundle = self._bundle(self._minimal_tf_json(
            "aws_lambda_function", "api",
            {"function_name": "api", "runtime": "nodejs20.x", "handler": "index.handler"},
        ))
        finding = _f(
            agent="Security Agent",
            category="network",
            title="Lambda function not in VPC",
            resource="aws_lambda_function.api",
            severity=Severity.LOW,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        out = _j.loads(patch.patched_content)
        vpc = out["resource"]["aws_lambda_function"]["api"]["vpc_config"]
        assert "subnet_ids" in vpc
        assert "security_group_ids" in vpc

    def test_cloudwatch_log_retention(self, mock_llm):
        import json as _j
        bundle = self._bundle(self._minimal_tf_json(
            "aws_cloudwatch_log_group", "lambda_logs",
            {"name": "/aws/lambda/api"},
        ))
        finding = _f(
            agent="Cost Agent",
            category="storage",
            title="CloudWatch logs with unlimited retention",
            resource="aws_cloudwatch_log_group.lambda_logs",
            severity=Severity.MEDIUM,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        out = _j.loads(patch.patched_content)
        assert out["resource"]["aws_cloudwatch_log_group"]["lambda_logs"]["retention_in_days"] == 30

    def test_rds_storage_encrypted_scalar(self, mock_llm):
        import json as _j
        bundle = self._bundle(self._minimal_tf_json(
            "aws_db_instance", "main",
            {"identifier": "main", "engine": "postgres", "instance_class": "db.t3.micro"},
        ))
        finding = _f(
            agent="Security Agent",
            category="encryption",
            title="RDS storage not encrypted",
            resource="aws_db_instance.main",
            severity=Severity.HIGH,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        out = _j.loads(patch.patched_content)
        assert out["resource"]["aws_db_instance"]["main"]["storage_encrypted"] is True

    def test_rds_multi_az_scalar(self, mock_llm):
        import json as _j
        bundle = self._bundle(self._minimal_tf_json(
            "aws_db_instance", "main",
            {"identifier": "main", "engine": "postgres", "instance_class": "db.t3.micro"},
        ))
        finding = _f(
            agent="Reliability Agent",
            category="high-availability",
            title="RDS instance not Multi-AZ",
            resource="aws_db_instance.main",
            severity=Severity.HIGH,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        out = _j.loads(patch.patched_content)
        assert out["resource"]["aws_db_instance"]["main"]["multi_az"] is True

    def test_rds_deletion_protection(self, mock_llm):
        import json as _j
        bundle = self._bundle(self._minimal_tf_json(
            "aws_db_instance", "main",
            {"identifier": "main", "engine": "postgres", "instance_class": "db.t3.micro"},
        ))
        finding = _f(
            agent="Reliability Agent",
            category="protection",
            title="RDS without deletion protection",
            resource="aws_db_instance.main",
            severity=Severity.MEDIUM,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        out = _j.loads(patch.patched_content)
        assert out["resource"]["aws_db_instance"]["main"]["deletion_protection"] is True

    def test_companion_refuses_to_overwrite(self, mock_llm):
        """If a companion resource of the same name already exists, we
        refuse to silently overwrite. Caller falls back to LLM."""
        import json as _j
        # Pre-existing companion with the same name
        body = _j.dumps({
            "resource": {
                "aws_s3_bucket": {"uploads": {"bucket": "x"}},
                "aws_s3_bucket_server_side_encryption_configuration": {
                    "uploads": {"bucket": "different", "rule": {}}
                },
            },
        }, indent=2)
        bundle = self._bundle(body)
        finding = _f(
            agent="Security Agent",
            category="encryption",
            title="S3 bucket without encryption",
            resource="aws_s3_bucket.uploads",
            severity=Severity.HIGH,
        )
        # Mock LLM so the fallback path also fails — proves we tried and gave up
        mock_llm.set("remediator", {"patched_content": "", "explanation": "x"})
        with pytest.raises(RemediationError):
            remediate_sync(finding, 0, bundle)

    def test_unknown_category_falls_back_to_llm(self, mock_llm):
        """Categories without a deterministic JSON fixer flow to LLM
        cleanly (no crash). We verify the fallback path is actually
        reached by setting a mock that returns valid output."""
        import json as _j
        body = self._minimal_tf_json("aws_s3_bucket", "data", {"bucket": "x"})
        bundle = self._bundle(body)
        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",  # no deterministic JSON fixer for this
            title="Some advisory",
            resource="aws_s3_bucket.data",
            severity=Severity.LOW,
        )
        # Mock returns the original unchanged — LLM "patches" nothing
        # but produces valid output, proving the LLM path was reached.
        mock_llm.set("remediator", {"patched_content": body, "explanation": "noop"})
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "llm"

    def test_real_serverless_sample_s3_encryption(self, mock_llm):
        """End-to-end on the actual samples/terraform-serverless.json."""
        import json as _j
        from pathlib import Path
        sample_path = Path(__file__).parent.parent / "samples" / "terraform-serverless.json"
        if not sample_path.exists():
            pytest.skip("sample not found")
        content = sample_path.read_text()
        bundle = {"terraform-serverless.json": content}
        finding = _f(
            agent="Security Agent",
            category="encryption",
            title="S3 bucket without encryption",
            resource="aws_s3_bucket.uploads",
            severity=Severity.HIGH,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert patch.validation_status == "valid"
        # Patched content is valid JSON and includes the SSE companion
        out = _j.loads(patch.patched_content)
        assert "aws_s3_bucket_server_side_encryption_configuration" in out["resource"]
        # All other resources from the original survived untouched
        assert "aws_lambda_function" in out["resource"]
        assert "aws_dynamodb_table" in out["resource"]
        assert out["resource"]["aws_s3_bucket"]["uploads"]["bucket"] == "myapp-user-uploads-prod"


# ---------------------------------------------------------------------------
# Advisory-language detection (the DynamoDB billing-mode bug)
# ---------------------------------------------------------------------------


from app.agents.remediator import _is_advisory_language


class TestAdvisoryLanguageDetection:
    """Bug from terraform-serverless.json's "DynamoDB Billing Mode" finding:
    Cost Agent (LLM) produced an INFO finding with a real resource
    (aws_dynamodb_table.sessions) but a recommendation that READS like a
    decision task: 'Analyze historical read/write throughput to determine
    if moving to Provisioned Capacity offers a cost saving...'.

    The remediator wasted two LLM calls trying to patch this — and failed
    with 'Invalid control character at: line 52 column 182'. The honest
    fix: detect this language pattern up-front and route to NonPatchable.
    """

    def test_dynamodb_billing_mode_advisory_caught(self, mock_llm):
        bundle = {"infra.json": '{"resource": {"aws_dynamodb_table": {"sessions": {"name": "x", "billing_mode": "PAY_PER_REQUEST"}}}}'}
        finding = _f(
            agent="Cost Agent",
            category="ai-analysis",
            title="DynamoDB Billing Mode",
            resource="aws_dynamodb_table.sessions",
            description="The DynamoDB table 'sessions' is using PAY_PER_REQUEST billing.",
            recommendation=(
                "Analyze historical read/write throughput to determine if moving "
                "to Provisioned Capacity offers a cost saving."
            ),
            severity=Severity.INFO,
        )
        with pytest.raises(NonPatchableFinding) as exc:
            remediate_sync(finding, 0, bundle)
        msg = str(exc.value).lower()
        assert "advisory" in msg
        assert "decision" in msg or "evaluate" in msg or "analyze" in msg

    @pytest.mark.parametrize("verb", [
        "Analyze", "Monitor", "Consider", "Evaluate", "Review",
        "Determine", "Investigate", "Audit", "Assess",
    ])
    def test_each_advisory_verb_is_detected(self, mock_llm, verb):
        bundle = {"infra.json": '{"resource": {"aws_s3_bucket": {"data": {"bucket": "x"}}}}'}
        finding = _f(
            agent="Cost Agent",
            category="ai-analysis",
            title="X",
            resource="aws_s3_bucket.data",
            recommendation=f"{verb} the actual usage and adjust accordingly.",
            severity=Severity.LOW,
        )
        with pytest.raises(NonPatchableFinding):
            remediate_sync(finding, 0, bundle)

    def test_concrete_fix_recommendation_still_works(self, mock_llm):
        """A real fixable finding whose recommendation starts with an
        imperative verb ('Set...', 'Add...', 'Enable...') must NOT be
        marked advisory. Use a deterministic-fixer-eligible category
        and resource so we can confirm the fix actually runs."""
        import json as _j
        bundle = {"infra.json": _j.dumps({
            "terraform": {"required_providers": {"aws": {"source": "hashicorp/aws"}}},
            "resource": {"aws_kms_key": {"main": {"description": "main"}}},
        }, indent=2)}
        finding = _f(
            agent="Security Agent",
            category="encryption",
            title="KMS key rotation not enabled",
            resource="aws_kms_key.main",
            recommendation="Set enable_key_rotation = true for key management best practices.",
            severity=Severity.MEDIUM,
        )
        # Should NOT raise — should produce a deterministic patch
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert "enable_key_rotation" in patch.patched_content

    def test_rule_engine_finding_with_advisory_verb_in_recommendation_not_caught(self, mock_llm):
        """Critical: only LLM-produced (category='ai-analysis') findings
        are eligible for advisory-language detection. A rule-engine
        finding (e.g. category='encryption') with the word 'Consider'
        somewhere must NOT be misclassified as advisory."""
        import json as _j
        bundle = {"infra.json": _j.dumps({
            "resource": {"aws_kms_key": {"main": {"description": "main"}}},
        }, indent=2)}
        # Category=encryption (rule-engine), recommendation starts with "Consider"
        # — this is hypothetical; real rule recommendations don't start this
        # way, but we want to be defensive.
        finding = _f(
            agent="Security Agent",
            category="encryption",  # NOT ai-analysis
            title="KMS key rotation not enabled",
            resource="aws_kms_key.main",
            recommendation="Consider enabling key rotation for compliance.",
            severity=Severity.MEDIUM,
        )
        # Should NOT raise NonPatchable — rule engine has a deterministic
        # fixer for encryption + aws_kms_key.
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"

    def test_advisory_detector_unit(self):
        """Unit test for _is_advisory_language."""
        # ai-analysis + decision verb → True
        f = _f(
            category="ai-analysis", title="X", resource="aws_x.y",
            recommendation="Analyze the usage pattern.",
        )
        assert _is_advisory_language(f) is True
        # rule-engine category + decision verb → False (only LLM findings filter)
        f = _f(
            category="encryption", title="X", resource="aws_x.y",
            recommendation="Analyze the usage pattern.",
        )
        assert _is_advisory_language(f) is False
        # ai-analysis + concrete verb → False
        f = _f(
            category="ai-analysis", title="X", resource="aws_x.y",
            recommendation="Set the encryption flag to true.",
        )
        assert _is_advisory_language(f) is False
        # Empty recommendation → False
        f = _f(
            category="ai-analysis", title="X", resource="aws_x.y",
            recommendation="",
        )
        assert _is_advisory_language(f) is False
        # Verb with trailing punctuation still detected
        f = _f(
            category="ai-analysis", title="X", resource="aws_x.y",
            recommendation="Analyze, then decide.",
        )
        assert _is_advisory_language(f) is True

    def test_advisory_short_circuits_before_llm(self, mock_llm):
        """Critical efficiency check: advisory-language findings must NEVER
        reach the LLM. We set a mock that would return invalid output —
        if remediate_sync were calling the LLM, it would raise
        RemediationError, not NonPatchableFinding."""
        bundle = {"infra.json": '{"resource": {"aws_dynamodb_table": {"sessions": {}}}}'}
        finding = _f(
            agent="Cost Agent",
            category="ai-analysis",
            title="X",
            resource="aws_dynamodb_table.sessions",
            recommendation="Analyze and decide.",
            severity=Severity.INFO,
        )
        # Configure LLM mock to fail loudly. If we reach the LLM, the test
        # would raise RemediationError after 2 attempts (different exc type).
        mock_llm.set("remediator", {"patched_content": "", "explanation": "noop"})
        with pytest.raises(NonPatchableFinding):
            remediate_sync(finding, 0, bundle)


# ---------------------------------------------------------------------------
# Phase 3.4 — Helm "filename (chart-name)" detection + praise-finding routing
# ---------------------------------------------------------------------------


from app.agents.remediator import _looks_like_file_path


class TestHelmAnnotatedPathDetection:
    """Bug from samples/good-chart-1.1.0.tgz: the Security Agent's LLM
    emitted resource = 'deployment.yaml (good-chart)' for INFO findings.
    The original _looks_like_file_path only checked endsWith, so the
    annotated form slipped through and triggered 'Could not locate
    Kubernetes resource' errors.
    """

    @pytest.mark.parametrize("resource", [
        "deployment.yaml (good-chart)",
        "deployment.yaml (chart-1.0.0)",
        "deployment.yaml (release-name)",
        "configmap.yaml (my-chart-1.2.3)",
        "service.yml (chart-name)",
        "manifests.json (project)",
        "main.tf (terraform-aws)",
        "infra.hcl (mod)",
    ])
    def test_filename_with_annotation_detected(self, resource):
        assert _looks_like_file_path(resource) is True, (
            f"{resource!r} should be detected as a file path"
        )

    @pytest.mark.parametrize("resource", [
        "templates/deployment.yaml (chart)",
        "my-chart/templates/svc.yaml (release)",
    ])
    def test_template_path_with_annotation_detected(self, resource):
        assert _looks_like_file_path(resource) is True

    @pytest.mark.parametrize("resource", [
        "Deployment/default/api",
        "aws_s3_bucket.data",
        "Service/release-good-chart",  # real K8s resource, no parens
        "azurerm_storage_account.x",
    ])
    def test_real_resources_not_flagged(self, resource):
        assert _looks_like_file_path(resource) is False, (
            f"{resource!r} is a real resource and must NOT be flagged"
        )

    def test_helm_annotated_path_raises_non_patchable(self, mock_llm):
        """End-to-end: the exact bug from the screenshot."""
        bundle = {
            "good-chart-1.1.0-rendered.yaml": (
                "apiVersion: apps/v1\nkind: Deployment\n"
                "metadata:\n  name: release-good-chart\n  namespace: default\n"
                "spec:\n  template:\n    spec:\n      containers:\n"
                "        - name: c\n          image: c:1.0\n"
            )
        }
        finding = _f(
            agent="Security Agent",
            category="ai-analysis",
            title="Secure Container Configuration",
            resource="deployment.yaml (good-chart)",
            recommendation="No immediate action required.",
            severity=Severity.INFO,
        )
        with pytest.raises(NonPatchableFinding) as exc:
            remediate_sync(finding, 0, bundle)
        msg = str(exc.value).lower()
        # Should mention path/template/file (or at least be non-patchable),
        # not the misleading "could not locate kubernetes resource"
        assert "kubernetes resource" not in msg


class TestPraiseFindings:
    """Bug from good-chart-1.1.0.tgz: the LLM emitted INFO findings
    congratulating the user on already-secure configurations:
        'No immediate action required. This configuration adheres to...'
        'Maintain this setting. This is a recommended security practice.'
        'Continue using Secret references for sensitive data.'

    These have no fix because there's nothing to fix. Generate-fix used
    to either error or time out trying to patch them. Now we detect them
    upfront and surface a clean 'no action needed' caption.
    """

    @pytest.mark.parametrize("recommendation", [
        "No immediate action required. This configuration adheres to best practices.",
        "No action needed.",
        "No change needed — already correct.",
        "No changes required.",
        "This is already configured correctly.",
        "This is a recommended security practice.",
        "This is best practice and should be maintained.",
        "This is correct as-is.",
        "This is the recommended setting.",
        "Already configured per CIS guidance.",
        "Already enabled.",
        "Already in place — no further action.",
        "Already meets compliance requirements.",
        "Already follows security best practices.",
        "The current configuration is correct.",
        "The configuration is already secure.",
    ])
    def test_no_action_recommendation_detected(self, mock_llm, recommendation):
        bundle = {"deploy.yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n"}
        finding = _f(
            agent="Security Agent",
            category="ai-analysis",
            title="Praise finding",
            resource="Deployment/default/api",
            recommendation=recommendation,
            severity=Severity.INFO,
        )
        with pytest.raises(NonPatchableFinding):
            remediate_sync(finding, 0, bundle)

    @pytest.mark.parametrize("verb", ["Maintain", "Continue", "Keep"])
    def test_keep_doing_verbs_detected(self, mock_llm, verb):
        bundle = {"deploy.yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n"}
        finding = _f(
            agent="Cost Agent",
            category="ai-analysis",
            title="Service Type Efficiency",
            resource="Service/release-good-chart",
            recommendation=f"{verb} ClusterIP type unless external exposure is required.",
            severity=Severity.INFO,
        )
        with pytest.raises(NonPatchableFinding):
            remediate_sync(finding, 0, bundle)

    def test_concrete_fix_with_keep_word_in_middle_not_caught(self, mock_llm):
        """Keep/Maintain only fire when they're the FIRST word of the
        recommendation. A real fix that mentions 'keep' later must NOT
        be misclassified."""
        import json as _j
        bundle = {"infra.json": _j.dumps({
            "terraform": {"required_providers": {"aws": {"source": "hashicorp/aws"}}},
            "resource": {"aws_kms_key": {"main": {"description": "main"}}},
        }, indent=2)}
        finding = _f(
            agent="Security Agent",
            category="encryption",  # rule-engine, not ai-analysis
            title="KMS key rotation not enabled",
            resource="aws_kms_key.main",
            recommendation="Set enable_key_rotation = true to keep keys rotated.",
            severity=Severity.MEDIUM,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"

    def test_no_action_short_circuits_before_llm(self, mock_llm):
        """Critical efficiency check — praise findings must never reach
        the LLM. Set the LLM mock to fail loudly; if we reach it, the
        wrong exception type would surface."""
        bundle = {"deploy.yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n"}
        finding = _f(
            agent="Security Agent",
            category="ai-analysis",
            title="Secret Management",
            resource="Deployment/default/api",
            recommendation="Continue using Secret references for sensitive data.",
            severity=Severity.INFO,
        )
        mock_llm.set("remediator", {"patched_content": "garbage", "explanation": "x"})
        with pytest.raises(NonPatchableFinding):
            remediate_sync(finding, 0, bundle)


# ---------------------------------------------------------------------------
# Update-strategy fixer (good-chart-1.1.0.tgz "No update strategy specified")
# ---------------------------------------------------------------------------


class TestUpdateStrategyFixer:
    """Bug from samples/good-chart-1.1.0.tgz: the Reliability Agent's
    rule-engine 'No update strategy specified' finding had no
    deterministic fixer. The LLM fallback returned an empty
    patched_content twice in a row, ending in 'LLM remediation failed
    after 2 attempts: LLM returned empty patched_content'.

    Phase 3.4 fix: deterministic injection of a RollingUpdate strategy
    block. Same transformation every time, no LLM needed.
    """

    def test_strategy_added_to_deployment_yaml(self, mock_llm):
        bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: default
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: c
          image: c:1.0
''')
        finding = _f(
            agent="Reliability Agent",
            category="strategy",
            title="No update strategy specified",
            resource="Deployment/default/api",
            severity=Severity.LOW,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert patch.validation_status == "valid"
        docs = parse_kubernetes_yaml(patch.patched_content)
        strategy = docs[0]["spec"]["strategy"]
        assert strategy["type"] == "RollingUpdate"
        assert strategy["rollingUpdate"]["maxSurge"] == "25%"
        assert strategy["rollingUpdate"]["maxUnavailable"] == 0

    def test_strategy_added_to_deployment_json(self, mock_llm):
        import json as _j
        body = _j.dumps({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "api", "namespace": "default"},
            "spec": {
                "replicas": 2,
                "template": {"spec": {"containers": [{"name": "c", "image": "x"}]}},
            },
        }, indent=2)
        bundle = {"deploy.json": body}
        finding = _f(
            agent="Reliability Agent",
            category="strategy",
            title="No update strategy specified",
            resource="Deployment/default/api",
            severity=Severity.LOW,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert patch.validation_status == "valid"
        # Must be valid JSON (not YAML)
        out = _j.loads(patch.patched_content)
        assert out["spec"]["strategy"]["type"] == "RollingUpdate"

    def test_statefulset_uses_updateStrategy_field(self, mock_llm):
        bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
  namespace: default
spec:
  replicas: 3
  serviceName: db
  template:
    spec:
      containers:
        - name: c
          image: c:1.0
''')
        finding = _f(
            agent="Reliability Agent",
            category="strategy",
            title="No update strategy specified",
            resource="StatefulSet/default/db",
            severity=Severity.LOW,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        docs = parse_kubernetes_yaml(patch.patched_content)
        # StatefulSet uses "updateStrategy", NOT "strategy"
        assert docs[0]["spec"]["updateStrategy"]["type"] == "RollingUpdate"
        assert "strategy" not in docs[0]["spec"]

    def test_existing_strategy_not_clobbered(self, mock_llm):
        """If the deployment already has a strategy block, the fixer
        refuses to overwrite — falls through and the LLM is asked
        instead. This is the safety rail."""
        bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: default
spec:
  replicas: 2
  strategy:
    type: Recreate
  template:
    spec:
      containers:
        - name: c
          image: c:1.0
''')
        finding = _f(
            agent="Reliability Agent",
            category="strategy",
            title="No update strategy specified",
            resource="Deployment/default/api",
            severity=Severity.LOW,
        )
        # Make the LLM also fail so the test surfaces a clear error
        mock_llm.set("remediator", {"patched_content": "", "explanation": "noop"})
        with pytest.raises(RemediationError):
            remediate_sync(finding, 0, bundle)

    def test_strategy_fix_rejected_for_non_workload_kinds(self, mock_llm):
        """Pods don't have an update strategy. If the LLM somehow emits
        a strategy finding against a Pod, we refuse cleanly."""
        bundle = _k8s_bundle('''
apiVersion: v1
kind: Pod
metadata:
  name: api
  namespace: default
spec:
  containers:
    - name: c
      image: c:1.0
''')
        finding = _f(
            agent="Reliability Agent",
            category="strategy",
            title="No update strategy specified",
            resource="Pod/default/api",
            severity=Severity.LOW,
        )
        # Configure LLM to also fail so the bundle reports a clear error
        mock_llm.set("remediator", {"patched_content": "", "explanation": "noop"})
        with pytest.raises(RemediationError):
            remediate_sync(finding, 0, bundle)

    def test_strategy_warning_about_default_values(self, mock_llm):
        """The fixer adds default 25%/0 values — must surface a warning
        so the user knows to tune them for their workload."""
        bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: default
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: c
          image: c:1.0
''')
        finding = _f(
            agent="Reliability Agent",
            category="strategy",
            title="No update strategy specified",
            resource="Deployment/default/api",
            severity=Severity.LOW,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert any("tune" in w.lower() or "25%" in w for w in patch.warnings), (
            f"Expected a warning about default values, got: {patch.warnings}"
        )

    def test_strategy_short_circuits_no_llm_call(self, mock_llm):
        """End-to-end efficiency: strategy fixer must NEVER reach the
        LLM. Set the LLM mock to return invalid content; if we reached
        it, the patch would fail validation."""
        bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: default
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: c
          image: c:1.0
''')
        finding = _f(
            agent="Reliability Agent",
            category="strategy",
            title="No update strategy specified",
            resource="Deployment/default/api",
            severity=Severity.LOW,
        )
        mock_llm.set("remediator", {"patched_content": "GARBAGE", "explanation": "noop"})
        patch = remediate_sync(finding, 0, bundle)
        # Strategy must be 'deterministic', proving the LLM was never called
        assert patch.strategy == "deterministic"


# ---------------------------------------------------------------------------
# Termination grace period fixer + structural-preservation safety net
# ---------------------------------------------------------------------------


from app.agents.remediator import (
    PatchValidationError,
    _count_resources,
    _verify_no_resources_dropped,
)


class TestTerminationGracePeriodFixer:
    """Bug from samples/critical-security-failure.yaml: the LLM's
    'Missing Termination Grace Period' INFO finding was sent to LLM
    fallback. Local Gemma added the field but DELETED the Service and
    ClusterRoleBinding documents. Validator only checked YAML parses,
    not that documents survived.

    Phase 3.4 fix has TWO parts:
      1. Deterministic fixer for this finding — never reaches LLM
      2. Structural-preservation check — rejects ANY LLM patch that
         drops resources from multi-resource files
    """

    def test_termination_grace_period_deterministic(self, mock_llm):
        bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: node-debugger
  namespace: kube-system
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: c
          image: c:1.0
---
apiVersion: v1
kind: Service
metadata:
  name: debugger-service
  namespace: kube-system
spec:
  type: LoadBalancer
  selector:
    app: node-debugger
  ports:
    - port: 22
      targetPort: 22
''')
        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",
            title="Missing Termination Grace Period",
            resource="Deployment/kube-system/node-debugger",
            recommendation="Explicitly set terminationGracePeriodSeconds in the container specification.",
            severity=Severity.INFO,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert patch.validation_status == "valid"
        docs = parse_kubernetes_yaml(patch.patched_content)
        # All 2 docs preserved
        assert len(docs) == 2
        assert {d["kind"] for d in docs} == {"Deployment", "Service"}
        # Fix landed in the right place
        deploy = next(d for d in docs if d["kind"] == "Deployment")
        assert deploy["spec"]["template"]["spec"]["terminationGracePeriodSeconds"] == 30

    def test_termination_grace_period_short_circuits_llm(self, mock_llm):
        """The LLM mock is set to drop documents — but we never reach
        it because the deterministic fixer handles this finding."""
        bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: default
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: c
          image: c:1.0
''')
        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",
            title="Missing Termination Grace Period",
            resource="Deployment/default/api",
            recommendation="Explicitly set terminationGracePeriodSeconds.",
            severity=Severity.INFO,
        )
        # Set LLM to fail loudly — proves we never called it
        mock_llm.set("remediator", {"patched_content": "GARBAGE", "explanation": "x"})
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"

    def test_termination_already_set_refuses(self, mock_llm):
        """Won't clobber an existing value."""
        bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: default
spec:
  replicas: 1
  template:
    spec:
      terminationGracePeriodSeconds: 60
      containers:
        - name: c
          image: c:1.0
''')
        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",
            title="Missing Termination Grace Period",
            resource="Deployment/default/api",
            recommendation="Explicitly set terminationGracePeriodSeconds.",
            severity=Severity.INFO,
        )
        mock_llm.set("remediator", {"patched_content": "", "explanation": "noop"})
        with pytest.raises(RemediationError):
            remediate_sync(finding, 0, bundle)

    def test_real_critical_security_failure_sample(self, mock_llm):
        """End-to-end on the actual failing sample. Critical assertion:
        Service AND ClusterRoleBinding survive the patch."""
        from pathlib import Path
        sample = Path(__file__).parent.parent / "samples" / "critical-security-failure.yaml"
        if not sample.exists():
            pytest.skip("sample not present")
        bundle = {"critical-security-failure.yaml": sample.read_text()}
        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",
            title="Missing Termination Grace Period",
            resource="Deployment/node-debugger",
            recommendation="Explicitly set terminationGracePeriodSeconds in the container specification.",
            severity=Severity.INFO,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        docs = parse_kubernetes_yaml(patch.patched_content)
        kinds = [d["kind"] for d in docs]
        # ALL THREE documents survive — Service and ClusterRoleBinding
        # were the ones the LLM was deleting before this fix.
        assert "Deployment" in kinds
        assert "Service" in kinds
        assert "ClusterRoleBinding" in kinds


class TestStructuralPreservationCheck:
    """Higher-leverage protection: ANY LLM patch that drops resources
    from a multi-resource file is rejected, regardless of the finding
    category. Defends against the entire class of 'silent data loss'
    bugs the LLM is prone to."""

    def test_count_resources_yaml_multi_doc(self):
        content = (
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\n"
            "---\n"
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: b\n"
            "---\n"
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: c\n"
        )
        assert _count_resources(content, "kubernetes_yaml") == 3

    def test_count_resources_terraform_json(self):
        import json as _j
        content = _j.dumps({
            "resource": {
                "aws_s3_bucket": {"a": {}, "b": {}},
                "aws_kms_key": {"c": {}},
            }
        })
        assert _count_resources(content, "terraform_json") == 3

    def test_count_resources_empty_returns_zero(self):
        assert _count_resources("", "kubernetes_yaml") == 0

    def test_count_resources_unparseable_returns_minus_one(self):
        assert _count_resources("{not valid yaml: : :", "terraform_json") == -1

    def test_dropped_resources_rejected(self):
        """The exact attack vector: LLM kept doc 1, dropped docs 2 and 3."""
        before = (
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\n"
            "spec:\n  replicas: 1\n"
            "---\n"
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: b\n"
            "---\n"
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: c\n"
        )
        after = (
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\n"
            "spec:\n  replicas: 1\n  template:\n    spec:\n      terminationGracePeriodSeconds: 30\n"
        )
        with pytest.raises(PatchValidationError) as exc:
            _verify_no_resources_dropped(before, after, "kubernetes_yaml")
        msg = str(exc.value).lower()
        assert "dropped" in msg
        assert "2" in str(exc.value)  # specifically: dropped 2 of 3

    def test_added_resources_allowed(self):
        """Adding resources (e.g., an HPA companion) is fine."""
        before = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\nspec:\n  replicas: 1\n"
        after = (
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\nspec:\n  replicas: 1\n"
            "---\n"
            "apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\nmetadata:\n  name: a-hpa\n"
        )
        # Should not raise
        _verify_no_resources_dropped(before, after, "kubernetes_yaml")

    def test_same_count_allowed(self):
        before = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\nspec:\n  replicas: 1\n"
        after = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\nspec:\n  replicas: 2\n"
        _verify_no_resources_dropped(before, after, "kubernetes_yaml")

    def test_unknown_count_falls_through(self):
        """When either side is unparseable (-1), skip the check rather
        than false-fail. The parser-level _validate_patch is a separate
        safety layer that catches actual broken output."""
        before = "valid: yaml\n"
        after = "{[broken garbage"
        # Should not raise — count is -1, inconclusive
        _verify_no_resources_dropped(before, after, "terraform_json")

    def test_llm_dropping_resources_blocked_end_to_end(self, mock_llm):
        """The whole point of this safety net. LLM returns a
        'fixed' file that's missing two resources — must be rejected
        and surface as a clear LLM remediation error."""
        # Use a non-deterministic-fixer category (ai-analysis) so we
        # actually go through the LLM path
        bundle = _k8s_bundle('''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: a
  namespace: default
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: c
          image: c:1.0
---
apiVersion: v1
kind: Service
metadata:
  name: b
  namespace: default
spec:
  type: ClusterIP
  selector:
    app: a
  ports:
    - port: 80
''')
        # LLM "fix" drops the Service
        evil_response = (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n  name: a\n  namespace: default\n"
            "spec:\n  replicas: 1\n  template:\n    spec:\n"
            "      terminationGracePeriodSeconds: 30\n"
            "      containers:\n        - name: c\n          image: c:1.0\n"
        )
        mock_llm.set("remediator", {"patched_content": evil_response, "explanation": "x"})
        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",
            title="Some custom advisory",  # Not termination grace period — forces LLM path
            resource="Deployment/default/a",
            recommendation="Add some custom field for reasons.",
            severity=Severity.INFO,
        )
        with pytest.raises(RemediationError) as exc:
            remediate_sync(finding, 0, bundle)
        # Error message should mention the safety check
        msg = str(exc.value).lower()
        assert "drop" in msg or "remediation failed" in msg


class TestAiAnalysisCategoryInference:
    """The Reliability/Cost agents emit findings with category="ai-analysis"
    that frequently mirror rule-engine findings (e.g. "Publicly Accessible
    Database" == public-exposure on aws_db_instance). Without inference,
    these fall through to the slow LLM path. With inference, they hit the
    deterministic fixer instantly.
    """

    def test_publicly_accessible_database_routed_to_public_exposure(self, mock_llm):
        """Real failure mode from samples/vulnerable-infra.tf: Reliability
        Agent emits 'Publicly Accessible Database' as ai-analysis. Should
        route to the public-exposure deterministic fixer for aws_db_instance.
        """
        bundle = _tf_bundle('''
resource "aws_db_instance" "main_db" {
  identifier         = "main"
  publicly_accessible = true
}
''')
        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",
            title="Publicly Accessible Database",
            resource="aws_db_instance.main_db",
            recommendation="Restrict access to the database.",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert "publicly_accessible = false" in patch.patched_content

    def test_unencrypted_ebs_volume_routed_to_encryption(self, mock_llm):
        bundle = _tf_bundle('''
resource "aws_ebs_volume" "data_vol" {
  availability_zone = "us-east-1a"
  size              = 10
}
''')
        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",
            title="Unencrypted EBS Volume",
            resource="aws_ebs_volume.data_vol",
            recommendation="Enable encryption.",
            severity=Severity.HIGH,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert "encrypted = true" in patch.patched_content

    def test_hardcoded_password_routed_to_hardcoded_secret(self, mock_llm):
        bundle = _tf_bundle('''
resource "aws_db_instance" "main_db" {
  identifier = "main"
  password   = "hunter2"
}
''')
        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",
            title="Hardcoded Password",
            resource="aws_db_instance.main_db",
            recommendation="Use a secrets manager.",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        # Hardcoded-secret fixer replaces literal value with var reference
        assert '"hunter2"' not in patch.patched_content

    def test_cloudtrail_logging_disabled_routed_to_logging(self, mock_llm):
        bundle = _tf_bundle('''
resource "aws_cloudtrail" "main_trail" {
  name           = "main"
  s3_bucket_name = "logs"
  enable_logging = false
}
''')
        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",
            title="CloudTrail Logging Disabled",
            resource="aws_cloudtrail.main_trail",
            recommendation="Enable logging.",
            severity=Severity.HIGH,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert "enable_logging = true" in patch.patched_content

    def test_imdsv2_routed_to_instance_metadata(self, mock_llm):
        bundle = _tf_bundle('''
resource "aws_instance" "app_server" {
  ami           = "ami-123"
  instance_type = "t3.micro"
}
''')
        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",
            title="No IMDSv2 for EC2 Instance",
            resource="aws_instance.app_server",
            recommendation="Enforce IMDSv2.",
            severity=Severity.MEDIUM,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert "http_tokens" in patch.patched_content
        assert '"required"' in patch.patched_content

    def test_inference_does_not_apply_to_rule_engine_findings(self, mock_llm):
        """The inference helper must be a no-op for findings with a real
        rule-engine category — those already route correctly. This test
        confirms inference doesn't accidentally re-route a security-network
        finding (which already works) into a different category.
        """
        bundle = _tf_bundle('''
resource "aws_security_group" "open" {
  name = "open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''')
        finding = _f(
            agent="Security Agent",
            category="network",  # NOT ai-analysis
            title="Security group open to 0.0.0.0/0",
            resource="aws_security_group.open",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "deterministic"
        assert "0.0.0.0/0" not in patch.patched_content

    def test_uninferable_ai_analysis_falls_through_to_llm(self, mock_llm):
        """When the inference table doesn't match (novel title, unknown
        resource type), the finding must still fall through to the LLM
        path — preserving the existing fallback behavior.
        """
        bundle = _tf_bundle('''
resource "aws_kinesis_stream" "events" {
  name        = "events"
  shard_count = 1
}
''')
        # Mock LLM returns a valid patched file
        mock_llm.set("remediator", {
            "patched_content": (
                'terraform {\n  required_version = ">= 1.0"\n}\n\n'
                'resource "aws_kinesis_stream" "events" {\n'
                '  name             = "events"\n'
                '  shard_count      = 1\n'
                '  retention_period = 24\n'
                '}\n'
            ),
            "explanation": "Added retention_period.",
        })
        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",
            title="Kinesis Stream Without Retention Tuning",  # Not in inference table
            resource="aws_kinesis_stream.events",
            recommendation="Add a retention_period appropriate to your replay needs.",
            severity=Severity.LOW,
        )
        patch = remediate_sync(finding, 0, bundle)
        assert patch.strategy == "llm"

    def test_inference_requires_resource_prefix_match(self, mock_llm):
        """Title keywords match but resource prefix doesn't — must NOT
        route to the deterministic fixer (would break on the wrong
        resource type).
        """
        from app.agents.remediator import _infer_rule_category

        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",
            title="Publicly Accessible Database",
            resource="aws_dynamodb_table.events",  # Wrong resource type
            severity=Severity.HIGH,
        )
        # Title keywords match "publicly,accessible" but resource prefix
        # is aws_dynamodb_table, not aws_db_instance — must return None.
        assert _infer_rule_category(finding) is None

    def test_inference_returns_none_for_non_ai_analysis(self, mock_llm):
        from app.agents.remediator import _infer_rule_category

        finding = _f(
            agent="Security Agent",
            category="public-exposure",  # Real rule-engine category
            title="RDS instance publicly accessible",
            resource="aws_db_instance.main_db",
        )
        # Even though title matches, category != ai-analysis means
        # inference is a no-op — caller routes via existing category.
        assert _infer_rule_category(finding) is None

    def test_inference_short_circuits_llm_call(self, mock_llm):
        """Confirm the inference path doesn't invoke the LLM — the whole
        point is to avoid the slow round-trip. We prove this by setting
        the mock LLM to return an INVALID patch: if the deterministic
        path were skipped, the test would fail validation. With inference
        working, the LLM is never called and the test passes.
        """
        bundle = _tf_bundle('''
resource "aws_db_instance" "main_db" {
  identifier         = "main"
  publicly_accessible = true
}
''')
        # Sabotage the LLM — if it gets called, the patch would be garbage.
        mock_llm.set("remediator", {
            "patched_content": "INVALID HCL THAT WOULD FAIL VALIDATION {{{",
            "explanation": "should never be used",
        })
        finding = _f(
            agent="Reliability Agent",
            category="ai-analysis",
            title="Publicly Accessible Database",
            resource="aws_db_instance.main_db",
            severity=Severity.CRITICAL,
        )
        patch = remediate_sync(finding, 0, bundle)
        # Deterministic strategy means the LLM was bypassed entirely
        assert patch.strategy == "deterministic"
        assert "publicly_accessible = false" in patch.patched_content
        assert "INVALID" not in patch.patched_content
