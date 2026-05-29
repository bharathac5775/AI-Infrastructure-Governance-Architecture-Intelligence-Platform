"""Tests for reliability rule-based checks (run_reliability_rules + run_terraform_reliability_rules).

Reference: app/agents/reliability.py
"""
from __future__ import annotations

from app.agents.reliability import (
    run_reliability_rules,
    run_terraform_reliability_rules,
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


class TestKubernetesReliabilityRules:
    def test_missing_readiness_probe_flagged_high(self):
        depl = minimal_deployment(containers=[minimal_container(liveness=True)])
        findings = run_reliability_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="Missing readiness probe", severity=Severity.HIGH)

    def test_missing_liveness_probe_flagged_high(self):
        depl = minimal_deployment(containers=[minimal_container(readiness=True)])
        findings = run_reliability_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="Missing liveness probe", severity=Severity.HIGH)

    def test_both_probes_present_no_finding(self):
        depl = minimal_deployment(
            containers=[minimal_container(liveness=True, readiness=True)],
        )
        findings = run_reliability_rules({"Deployment": [depl]})
        assert not has_finding_with(findings, title="Missing readiness probe")
        assert not has_finding_with(findings, title="Missing liveness probe")

    def test_no_resource_requests_flagged_medium(self):
        depl = minimal_deployment(containers=[minimal_container()])
        findings = run_reliability_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="No resource requests", severity=Severity.MEDIUM)

    def test_resource_requests_present_no_finding(self):
        depl = minimal_deployment(
            containers=[minimal_container(cpu_request="100m", mem_request="128Mi")],
        )
        findings = run_reliability_rules({"Deployment": [depl]})
        assert not has_finding_with(findings, title="No resource requests")

    def test_single_replica_deployment_flagged(self):
        # No HPA, no replicas (defaults to 1)
        depl = minimal_deployment(replicas=1)
        findings = run_reliability_rules({"Deployment": [depl]})
        # The single-replica rule has its own title
        assert any("replica" in f.title.lower() for f in findings)

    def test_hpa_suppresses_single_replica_finding(self):
        """Phase 2 regression: HPA targeting a Deployment suppresses SPOF finding."""
        depl = minimal_deployment(name="api", namespace="default", replicas=1)
        # Remove explicit replicas so HPA is "managing" it. The rule logic expects
        # replicas <= 1 AND no HPA target. With HPA, the single-replica rule should NOT fire.
        hpa = {
            "apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler",
            "metadata": {"name": "api-hpa", "namespace": "default"},
            "spec": {
                "scaleTargetRef": {"kind": "Deployment", "name": "api"},
                "minReplicas": 2, "maxReplicas": 10,
            },
        }
        findings = run_reliability_rules({"Deployment": [depl], "HorizontalPodAutoscaler": [hpa]})
        # No "Single replica" finding because HPA targets this Deployment
        single_replica_findings = [f for f in findings if "single replica" in f.title.lower()
                                   or "single-replica" in f.title.lower()]
        assert len(single_replica_findings) == 0

    def test_no_pdb_with_multiple_replicas_flagged(self):
        depl = minimal_deployment(name="api", replicas=3)
        findings = run_reliability_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="No PodDisruptionBudget", severity=Severity.MEDIUM)

    def test_no_update_strategy_flagged_low(self):
        depl = minimal_deployment()
        findings = run_reliability_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="No update strategy", severity=Severity.LOW)


# ===========================================================================
# Terraform
# ===========================================================================


class TestTerraformReliabilityRules:
    # ----- DynamoDB PITR (Phase 2 fix) -----

    def test_dynamodb_without_pitr_flagged_high(self):
        tf = [tf_resource("aws_dynamodb_table", "sessions",
                          name="sessions", hash_key="id")]
        findings = run_terraform_reliability_rules(tf)
        assert has_finding_with(findings, title="DynamoDB without point-in-time recovery",
                                severity=Severity.HIGH)

    def test_dynamodb_with_pitr_enabled_no_flag(self):
        tf = [tf_resource(
            "aws_dynamodb_table", "sessions",
            name="sessions", hash_key="id",
            point_in_time_recovery={"enabled": True},
        )]
        findings = run_terraform_reliability_rules(tf)
        assert not has_finding_with(findings, title="DynamoDB without point-in-time recovery")

    def test_dynamodb_pitr_as_list_format_handled(self):
        """HCL2 sometimes wraps single-instance config in a list."""
        tf = [tf_resource(
            "aws_dynamodb_table", "sessions",
            name="sessions", hash_key="id",
            point_in_time_recovery=[{"enabled": True}],
        )]
        findings = run_terraform_reliability_rules(tf)
        assert not has_finding_with(findings, title="DynamoDB without point-in-time recovery")

    def test_dynamodb_pitr_explicit_false_flagged(self):
        tf = [tf_resource(
            "aws_dynamodb_table", "sessions",
            name="sessions", hash_key="id",
            point_in_time_recovery={"enabled": False},
        )]
        findings = run_terraform_reliability_rules(tf)
        assert has_finding_with(findings, title="DynamoDB without point-in-time recovery")

    # ----- Lambda DLQ (Phase 2 fix) -----

    def test_lambda_without_dlq_flagged_medium(self):
        tf = [tf_resource(
            "aws_lambda_function", "api",
            function_name="api", handler="index.handler", runtime="nodejs20.x",
        )]
        findings = run_terraform_reliability_rules(tf)
        assert has_finding_with(findings, title="Lambda without dead letter queue",
                                severity=Severity.MEDIUM)

    def test_lambda_with_dlq_no_flag(self):
        tf = [tf_resource(
            "aws_lambda_function", "api",
            function_name="api", handler="index.handler", runtime="nodejs20.x",
            dead_letter_config={"target_arn": "arn:aws:sqs:us-east-1:1234:dlq"},
        )]
        findings = run_terraform_reliability_rules(tf)
        assert not has_finding_with(findings, title="Lambda without dead letter queue")

    # ----- SQS DLQ name skip (Phase 2 fix) -----

    def test_sqs_named_lambda_dlq_not_flagged(self):
        """Phase 2 regression: queue named *_dlq must NOT flag for missing DLQ."""
        tf = [tf_resource("aws_sqs_queue", "lambda_dlq", name="myapp-lambda-dlq")]
        findings = run_terraform_reliability_rules(tf)
        assert not has_finding_with(findings, title="SQS queue without dead letter queue")

    def test_sqs_named_dead_letter_not_flagged(self):
        tf = [tf_resource("aws_sqs_queue", "dead_letter_queue",
                          name="myapp-dead-letter-queue")]
        findings = run_terraform_reliability_rules(tf)
        assert not has_finding_with(findings, title="SQS queue without dead letter queue")

    def test_sqs_normal_queue_without_dlq_flagged(self):
        tf = [tf_resource("aws_sqs_queue", "main", name="myapp-events")]
        findings = run_terraform_reliability_rules(tf)
        assert has_finding_with(findings, title="SQS queue without dead letter queue")

    def test_sqs_with_redrive_policy_no_flag(self):
        tf = [tf_resource(
            "aws_sqs_queue", "main", name="myapp-events",
            redrive_policy='{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:1234:dlq","maxReceiveCount":5}',
        )]
        findings = run_terraform_reliability_rules(tf)
        assert not has_finding_with(findings, title="SQS queue without dead letter queue")

    # ----- ElastiCache failover -----

    def test_elasticache_without_failover_flagged(self):
        tf = [tf_resource("aws_elasticache_replication_group", "redis",
                          replication_group_id="redis", description="cache")]
        findings = run_terraform_reliability_rules(tf)
        assert has_finding_with(findings, title="ElastiCache without automatic failover")

    def test_elasticache_with_failover_no_flag(self):
        tf = [tf_resource(
            "aws_elasticache_replication_group", "redis",
            replication_group_id="redis", description="cache",
            automatic_failover_enabled=True,
        )]
        findings = run_terraform_reliability_rules(tf)
        assert not has_finding_with(findings, title="ElastiCache without automatic failover")
