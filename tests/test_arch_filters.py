"""Tests for the three architecture-reviewer gap filters.

Reference: app/agents/architecture_reviewer.py
- _filter_k8s_platform_gaps  (line 61)
- _filter_terraform_speculative_gaps  (line 92)
- _filter_terraform_secrets_gap  (line 106)
"""
from __future__ import annotations

from app.agents.architecture_reviewer import (
    _filter_k8s_platform_gaps,
    _filter_terraform_secrets_gap,
    _filter_terraform_speculative_gaps,
)
from app.models import Severity

from tests.fixtures.findings import make_gap


# ---------------------------------------------------------------------------
# _filter_k8s_platform_gaps
#
# Drops gaps containing keywords from _K8S_PLATFORM_GAP_KEYWORDS (external
# secrets, observability stack, DR/multi-region) UNLESS infra_type == "terraform".
# ---------------------------------------------------------------------------


class TestK8sPlatformGapFilter:
    def test_terraform_passes_through_unchanged(self):
        gaps = [
            make_gap(title="Disaster recovery missing"),
            make_gap(title="External secrets manager not configured"),
        ]
        result = _filter_k8s_platform_gaps(gaps, "terraform")
        assert result == gaps  # untouched

    def test_drops_disaster_recovery_for_kubernetes(self):
        gaps = [make_gap(title="Disaster recovery plan missing for chart")]
        assert _filter_k8s_platform_gaps(gaps, "kubernetes") == []

    def test_drops_external_secrets_for_kubernetes(self):
        gaps = [make_gap(
            title="External secrets manager",
            description="Chart should integrate with Vault or AWS Secrets Manager.",
        )]
        assert _filter_k8s_platform_gaps(gaps, "kubernetes") == []

    def test_drops_observability_stack_for_kubernetes(self):
        gaps = [make_gap(
            title="Comprehensive observability stack missing",
            description="No centralized logging, metrics, or distributed tracing.",
        )]
        assert _filter_k8s_platform_gaps(gaps, "kubernetes") == []

    def test_drops_multi_region_for_kubernetes(self):
        gaps = [make_gap(title="Multi-region deployment recommended")]
        assert _filter_k8s_platform_gaps(gaps, "kubernetes") == []

    def test_drops_jaeger_specifically(self):
        gaps = [make_gap(
            title="Tracing missing",
            description="Deploy Jaeger for distributed tracing.",
        )]
        assert _filter_k8s_platform_gaps(gaps, "kubernetes") == []

    def test_keeps_chart_level_gaps(self):
        # NetworkPolicy, RBAC, etc. are chart-level concerns — must NOT be filtered.
        gaps = [
            make_gap(title="NetworkPolicy missing", description="No ingress/egress rules."),
            make_gap(title="RBAC overly permissive"),
        ]
        result = _filter_k8s_platform_gaps(gaps, "kubernetes")
        assert len(result) == 2

    def test_mixed_gaps_only_platform_dropped(self):
        gaps = [
            make_gap(title="NetworkPolicy missing"),
            make_gap(title="Disaster recovery plan missing"),  # drop
            make_gap(title="Resource limits not enforced"),
        ]
        result = _filter_k8s_platform_gaps(gaps, "kubernetes")
        titles = [g.title for g in result]
        assert "NetworkPolicy missing" in titles
        assert "Resource limits not enforced" in titles
        assert "Disaster recovery plan missing" not in titles

    def test_mixed_infra_type_treated_as_kubernetes(self):
        """Non-'terraform' infra_type follows the K8s filtering path."""
        gaps = [make_gap(title="Disaster recovery plan missing")]
        # 'mixed' is not 'terraform', so K8s filter applies
        assert _filter_k8s_platform_gaps(gaps, "mixed") == []


# ---------------------------------------------------------------------------
# _filter_terraform_speculative_gaps
#
# Drops Terraform gaps that flag absence of strategies (DR, multi-region,
# zero-trust, chaos engineering) — these are design choices, not misconfigs.
# ---------------------------------------------------------------------------


class TestTerraformSpeculativeGapFilter:
    def test_kubernetes_passes_through_unchanged(self):
        gaps = [make_gap(title="Disaster recovery missing")]
        result = _filter_terraform_speculative_gaps(gaps, "kubernetes")
        assert result == gaps

    def test_drops_disaster_recovery_for_terraform(self):
        gaps = [make_gap(title="Disaster recovery plan missing")]
        assert _filter_terraform_speculative_gaps(gaps, "terraform") == []

    def test_drops_zero_trust_for_terraform(self):
        gaps = [make_gap(
            title="Zero-trust architecture not implemented",
            description="System lacks zero-trust controls.",
        )]
        assert _filter_terraform_speculative_gaps(gaps, "terraform") == []

    def test_drops_chaos_engineering_for_terraform(self):
        gaps = [make_gap(title="Chaos engineering practice missing")]
        assert _filter_terraform_speculative_gaps(gaps, "terraform") == []

    def test_drops_service_mesh_for_terraform(self):
        gaps = [make_gap(title="Service mesh integration missing")]
        assert _filter_terraform_speculative_gaps(gaps, "terraform") == []

    def test_keeps_concrete_misconfig_gaps(self):
        gaps = [
            make_gap(title="RDS not encrypted"),
            make_gap(title="IAM policy too permissive"),
        ]
        result = _filter_terraform_speculative_gaps(gaps, "terraform")
        assert len(result) == 2


# ---------------------------------------------------------------------------
# _filter_terraform_secrets_gap
#
# Drops gaps containing "secret" + ("management" or "credential") if the
# Terraform code uses var refs, manage_master_user_password, or aws_secretsmanager_secret.
# ---------------------------------------------------------------------------


class TestTerraformSecretsGapFilter:
    def test_kubernetes_passes_through_unchanged(self):
        gaps = [make_gap(title="Secrets management strategy missing")]
        result = _filter_terraform_secrets_gap(gaps, "kubernetes", {"a.tf": "..."})
        assert result == gaps

    def test_no_file_contents_passes_through(self):
        gaps = [make_gap(title="Secrets management strategy missing")]
        result = _filter_terraform_secrets_gap(gaps, "terraform", None)
        assert result == gaps

    def test_no_secrets_evidence_passes_through(self):
        # File doesn't reference any of: var.db_password, manage_master_user_password,
        # aws_secretsmanager_secret → filter doesn't apply.
        gaps = [make_gap(title="Secrets management strategy missing")]
        result = _filter_terraform_secrets_gap(
            gaps, "terraform", {"a.tf": 'resource "aws_db_instance" "x" { engine = "postgres" }'},
        )
        assert result == gaps

    def test_drops_when_secretsmanager_secret_present(self):
        gaps = [make_gap(
            title="Secrets management",
            description="No external secrets management strategy.",
        )]
        result = _filter_terraform_secrets_gap(
            gaps, "terraform",
            {"a.tf": 'resource "aws_secretsmanager_secret" "db" { name = "db" }'},
        )
        assert result == []

    def test_drops_when_managed_master_password_present(self):
        gaps = [make_gap(
            title="Secrets credential rotation",
            description="No credential management process.",
        )]
        result = _filter_terraform_secrets_gap(
            gaps, "terraform",
            {"a.tf": "resource \"aws_db_instance\" \"x\" { manage_master_user_password = true }"},
        )
        assert result == []

    def test_drops_when_var_db_password_used(self):
        gaps = [make_gap(
            title="Secrets management",
            description="Plain-text credential storage.",
        )]
        result = _filter_terraform_secrets_gap(
            gaps, "terraform",
            {"a.tf": "resource \"aws_db_instance\" \"x\" { password = var.db_password }"},
        )
        assert result == []

    def test_keeps_non_secrets_gaps(self):
        gaps = [
            make_gap(title="RDS not encrypted at rest"),
            make_gap(title="Secrets management missing"),  # would drop
        ]
        result = _filter_terraform_secrets_gap(
            gaps, "terraform",
            {"a.tf": 'resource "aws_secretsmanager_secret" "db" {}'},
        )
        titles = [g.title for g in result]
        assert "RDS not encrypted at rest" in titles
        assert "Secrets management missing" not in titles

    def test_filter_requires_secret_AND_management_or_credential(self):
        """A gap with 'secret' alone but neither 'management' nor 'credential' is kept."""
        gaps = [make_gap(title="Secret values exposed in logs",
                         description="Verbose logging may leak secrets.")]
        result = _filter_terraform_secrets_gap(
            gaps, "terraform",
            {"a.tf": 'resource "aws_secretsmanager_secret" "db" {}'},
        )
        # No 'management' or 'credential' in text → kept
        assert len(result) == 1
