"""Tests for cost rule-based checks (run_cost_rules + run_terraform_cost_rules).

Reference: app/agents/cost.py
"""
from __future__ import annotations

from app.agents.cost import (
    run_cost_rules,
    run_terraform_cost_rules,
)
from app.models import Severity

from tests.fixtures.findings import (
    minimal_container,
    minimal_deployment,
    tf_resource,
)


def has_finding_with(findings, *, title=None, category=None, severity=None) -> bool:
    for f in findings:
        if title is not None and title not in f.title:
            continue
        if category is not None and f.category != category:
            continue
        if severity is not None and f.severity != severity:
            continue
        return True
    return False


# ===========================================================================
# Kubernetes
# ===========================================================================


class TestKubernetesCostRules:
    def test_no_resources_at_all_flagged_high(self):
        depl = minimal_deployment(containers=[minimal_container()])
        findings = run_cost_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="No resource requests or limits",
                                severity=Severity.HIGH)

    def test_overprovisioned_cpu_flagged_when_5x(self):
        depl = minimal_deployment(
            containers=[minimal_container(
                cpu_request="100m", cpu_limit="2000m",
                mem_request="128Mi", mem_limit="256Mi",
            )],
        )
        findings = run_cost_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="Overprovisioned cpu", severity=Severity.MEDIUM)

    def test_overprovisioned_memory_flagged_when_5x(self):
        depl = minimal_deployment(
            containers=[minimal_container(
                cpu_request="500m", cpu_limit="1000m",
                mem_request="128Mi", mem_limit="2Gi",
            )],
        )
        findings = run_cost_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="Overprovisioned memory", severity=Severity.MEDIUM)

    def test_balanced_resources_no_finding(self):
        depl = minimal_deployment(
            containers=[minimal_container(
                cpu_request="500m", cpu_limit="1000m",
                mem_request="256Mi", mem_limit="512Mi",
            )],
        )
        findings = run_cost_rules({"Deployment": [depl]})
        assert not has_finding_with(findings, title="Overprovisioned cpu")
        assert not has_finding_with(findings, title="Overprovisioned memory")

    def test_excessive_replicas_flagged_low(self):
        depl = minimal_deployment(
            replicas=10,
            containers=[minimal_container(cpu_request="100m", cpu_limit="200m")],
        )
        findings = run_cost_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="High replica count", severity=Severity.LOW)

    def test_loadbalancer_service_flagged_medium(self):
        svc = {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "api", "namespace": "default"},
            "spec": {"type": "LoadBalancer"},
        }
        findings = run_cost_rules({"Service": [svc]})
        assert has_finding_with(findings, title="LoadBalancer service", severity=Severity.MEDIUM)


# ===========================================================================
# Terraform
# ===========================================================================


class TestTerraformCostRules:
    # ----- CloudWatch retention -----

    def test_cloudwatch_log_group_no_retention_flagged(self):
        tf = [tf_resource("aws_cloudwatch_log_group", "lambda_logs",
                          name="/aws/lambda/api")]
        findings = run_terraform_cost_rules(tf)
        assert has_finding_with(findings, title="unlimited retention", severity=Severity.MEDIUM)

    def test_cloudwatch_log_group_with_retention_no_flag(self):
        tf = [tf_resource(
            "aws_cloudwatch_log_group", "lambda_logs",
            name="/aws/lambda/api", retention_in_days=90,
        )]
        findings = run_terraform_cost_rules(tf)
        assert not has_finding_with(findings, title="unlimited retention")

    def test_cloudwatch_zero_retention_flagged(self):
        """retention_in_days=0 means never expire — should still flag."""
        tf = [tf_resource(
            "aws_cloudwatch_log_group", "lambda_logs",
            name="/aws/lambda/api", retention_in_days=0,
        )]
        findings = run_terraform_cost_rules(tf)
        assert has_finding_with(findings, title="unlimited retention")

    # ----- S3 lifecycle (Phase 2 companion-aware) -----

    def test_s3_without_lifecycle_flagged(self):
        tf = [tf_resource("aws_s3_bucket", "data", bucket="my-bucket")]
        findings = run_terraform_cost_rules(tf)
        assert has_finding_with(findings, title="S3 bucket without lifecycle rules")

    def test_s3_with_companion_lifecycle_no_flag(self):
        tf = [
            tf_resource("aws_s3_bucket", "data", bucket="my-bucket"),
            tf_resource(
                "aws_s3_bucket_lifecycle_configuration", "data_lc",
                bucket="${aws_s3_bucket.data.id}",
                rule=[{"id": "expire-old", "status": "Enabled",
                       "expiration": {"days": 365}}],
            ),
        ]
        findings = run_terraform_cost_rules(tf)
        assert not has_finding_with(findings, title="S3 bucket without lifecycle rules")

    def test_s3_with_inline_lifecycle_no_flag(self):
        """Pre-v4 inline lifecycle_rule also suppresses."""
        tf = [tf_resource(
            "aws_s3_bucket", "data", bucket="my-bucket",
            lifecycle_rule=[{"id": "expire", "enabled": True,
                             "expiration": {"days": 365}}],
        )]
        findings = run_terraform_cost_rules(tf)
        assert not has_finding_with(findings, title="S3 bucket without lifecycle rules")

    # ----- DynamoDB billing mode -----

    def test_dynamodb_provisioned_high_capacity_flagged(self):
        """PROVISIONED with high capacity should flag."""
        tf = [tf_resource(
            "aws_dynamodb_table", "sessions",
            name="sessions", hash_key="id",
            billing_mode="PROVISIONED",
            read_capacity=200, write_capacity=200,
        )]
        findings = run_terraform_cost_rules(tf)
        assert has_finding_with(findings, title="DynamoDB high provisioned capacity")

    def test_dynamodb_pay_per_request_no_flag(self):
        tf = [tf_resource(
            "aws_dynamodb_table", "sessions",
            name="sessions", hash_key="id",
            billing_mode="PAY_PER_REQUEST",
        )]
        findings = run_terraform_cost_rules(tf)
        assert not has_finding_with(findings, title="DynamoDB high provisioned capacity")
