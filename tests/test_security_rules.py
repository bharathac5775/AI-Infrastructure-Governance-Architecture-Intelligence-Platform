"""Tests for security rule-based checks (run_security_rules + run_terraform_security_rules).

Reference: app/agents/security.py
"""
from __future__ import annotations

import json

from app.agents.security import (
    run_security_rules,
    run_terraform_security_rules,
)
from app.models import Severity

from tests.fixtures.findings import (
    minimal_container,
    minimal_deployment,
    tf_resource,
)


# ---------------------------------------------------------------------------
# Helpers — assertions readable
# ---------------------------------------------------------------------------


def has_finding_with(findings, *, title: str | None = None,
                     category: str | None = None,
                     severity: Severity | None = None) -> bool:
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


class TestKubernetesSecurityRules:
    def test_privileged_container_flagged_critical(self):
        depl = minimal_deployment(containers=[minimal_container(privileged=True)])
        findings = run_security_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="Privileged container", severity=Severity.CRITICAL)

    def test_host_network_flagged_critical(self):
        depl = minimal_deployment(host_network=True)
        findings = run_security_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="hostNetwork", severity=Severity.CRITICAL)

    def test_host_pid_flagged_critical(self):
        depl = minimal_deployment(host_pid=True)
        findings = run_security_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="hostPID", severity=Severity.CRITICAL)

    def test_run_as_root_flagged_when_no_securitycontext(self):
        depl = minimal_deployment()  # no runAsNonRoot anywhere
        findings = run_security_rules({"Deployment": [depl]})
        assert has_finding_with(findings, category="run-as-root", severity=Severity.HIGH)

    def test_run_as_non_root_at_pod_level_suppresses_finding(self):
        """Phase 1 regression: pod-level runAsNonRoot should suppress per-container finding."""
        depl = minimal_deployment(
            pod_run_as_non_root=True,
            containers=[minimal_container()],  # no per-container runAsNonRoot
        )
        findings = run_security_rules({"Deployment": [depl]})
        assert not has_finding_with(findings, category="run-as-root")

    def test_run_as_non_root_at_container_level_suppresses_finding(self):
        depl = minimal_deployment(
            containers=[minimal_container(run_as_non_root=True)],
        )
        findings = run_security_rules({"Deployment": [depl]})
        assert not has_finding_with(findings, category="run-as-root")

    def test_writable_root_filesystem_flagged_medium(self):
        depl = minimal_deployment()  # no readOnlyRootFilesystem
        findings = run_security_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="Writable root filesystem", severity=Severity.MEDIUM)

    def test_read_only_root_fs_suppresses_finding(self):
        depl = minimal_deployment(
            containers=[minimal_container(read_only_root_fs=True)],
        )
        findings = run_security_rules({"Deployment": [depl]})
        assert not has_finding_with(findings, title="Writable root filesystem")

    def test_no_resource_limits_flagged(self):
        depl = minimal_deployment()  # no resources
        findings = run_security_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="No resource limits", severity=Severity.HIGH)

    def test_resource_limits_present_no_finding(self):
        depl = minimal_deployment(
            containers=[minimal_container(cpu_limit="500m", mem_limit="256Mi")],
        )
        findings = run_security_rules({"Deployment": [depl]})
        assert not has_finding_with(findings, title="No resource limits")

    def test_latest_image_tag_flagged(self):
        depl = minimal_deployment(
            containers=[minimal_container(image="app:latest")],
        )
        findings = run_security_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="latest or untagged image")

    def test_untagged_image_flagged(self):
        depl = minimal_deployment(
            containers=[minimal_container(image="app")],
        )
        findings = run_security_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="latest or untagged image")

    def test_specific_tag_no_finding(self):
        depl = minimal_deployment(
            containers=[minimal_container(image="app:1.2.3")],
        )
        findings = run_security_rules({"Deployment": [depl]})
        assert not has_finding_with(findings, title="latest or untagged image")

    def test_loadbalancer_service_flagged(self):
        svc = {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "api", "namespace": "default"},
            "spec": {"type": "LoadBalancer"},
        }
        findings = run_security_rules({"Service": [svc]})
        assert has_finding_with(findings, title="Public LoadBalancer service")

    def test_clusterip_service_no_finding(self):
        svc = {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "api", "namespace": "default"},
            "spec": {"type": "ClusterIP"},
        }
        findings = run_security_rules({"Service": [svc]})
        assert not has_finding_with(findings, title="Public LoadBalancer service")

    def test_cluster_admin_binding_flagged_critical(self):
        binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "admin-binding", "namespace": "default"},
            "roleRef": {"name": "cluster-admin", "apiGroup": "rbac.authorization.k8s.io"},
        }
        findings = run_security_rules({"ClusterRoleBinding": [binding]})
        assert has_finding_with(findings, title="cluster-admin binding", severity=Severity.CRITICAL)

    def test_wildcard_rbac_flagged(self):
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "wide", "namespace": "default"},
            "rules": [{"verbs": ["*"], "resources": ["*"]}],
        }
        findings = run_security_rules({"ClusterRole": [role]})
        assert has_finding_with(findings, title="Wildcard RBAC permissions")

    def test_hardcoded_secret_in_env_flagged_critical(self):
        depl = minimal_deployment(
            containers=[{
                **minimal_container(),
                "env": [{"name": "DB_PASSWORD", "value": "supersecret"}],
            }],
        )
        findings = run_security_rules({"Deployment": [depl]})
        assert has_finding_with(findings, title="Hardcoded secret", severity=Severity.CRITICAL)

    def test_secret_via_valuefrom_no_finding(self):
        depl = minimal_deployment(
            containers=[{
                **minimal_container(),
                "env": [{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "creds", "key": "pw"}}}],
            }],
        )
        findings = run_security_rules({"Deployment": [depl]})
        assert not has_finding_with(findings, title="Hardcoded secret")


# ===========================================================================
# Terraform — Phase 2 regression sentinels
# ===========================================================================


class TestTerraformSecurityRules:
    # ----- IAM wildcard rule (Phase 2 fix) -----

    def test_iam_xray_wildcard_not_flagged(self):
        """Phase 2 regression: AWS-required wildcard actions must be exempt."""
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow",
                 "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords"],
                 "Resource": "*"},
            ],
        }
        tf = [tf_resource("aws_iam_role_policy", "xray", policy=json.dumps(policy_doc))]
        findings = run_terraform_security_rules(tf)
        assert not has_finding_with(findings, title="Overly permissive IAM policy")

    def test_iam_ec2_eni_wildcard_not_flagged(self):
        """Phase 2 regression: EC2 ENI actions also exempt (Lambda VPC requirement)."""
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow",
                 "Action": ["ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces",
                            "ec2:DeleteNetworkInterface"],
                 "Resource": "*"},
            ],
        }
        tf = [tf_resource("aws_iam_role_policy", "lambda_eni", policy=json.dumps(policy_doc))]
        findings = run_terraform_security_rules(tf)
        assert not has_finding_with(findings, title="Overly permissive IAM policy")

    def test_iam_s3_wildcard_resource_flagged(self):
        """Counterpart: arbitrary action with Resource:'*' must still flag."""
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"},
            ],
        }
        tf = [tf_resource("aws_iam_role_policy", "broad", policy=json.dumps(policy_doc))]
        findings = run_terraform_security_rules(tf)
        assert has_finding_with(findings, title="Overly permissive IAM policy", severity=Severity.HIGH)

    def test_iam_action_wildcard_admin_flagged(self):
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ],
        }
        tf = [tf_resource("aws_iam_role_policy", "admin", policy=json.dumps(policy_doc))]
        findings = run_terraform_security_rules(tf)
        assert has_finding_with(findings, title="Overly permissive IAM policy")

    def test_iam_unparseable_policy_with_action_wildcard_flagged(self):
        """Terraform interpolations make JSON unparseable; fall back to substring match."""
        policy_str = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action": "*","Resource":"${aws_s3_bucket.foo.arn}"}]}'
        tf = [tf_resource("aws_iam_role_policy", "interp", policy=policy_str)]
        findings = run_terraform_security_rules(tf)
        assert has_finding_with(findings, title="Overly permissive IAM policy")

    def test_iam_specific_actions_no_flag(self):
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow",
                 "Action": ["s3:GetObject", "s3:PutObject"],
                 "Resource": "arn:aws:s3:::mybucket/*"},
            ],
        }
        tf = [tf_resource("aws_iam_role_policy", "narrow", policy=json.dumps(policy_doc))]
        findings = run_terraform_security_rules(tf)
        assert not has_finding_with(findings, title="Overly permissive IAM policy")

    def test_iam_mixed_xray_and_arbitrary_action_flagged(self):
        """Mixed statement: xray exempt + s3:* on Resource:* → still flag because of s3:*."""
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow",
                 "Action": ["xray:PutTraceSegments", "s3:*"],
                 "Resource": "*"},
            ],
        }
        tf = [tf_resource("aws_iam_role_policy", "mixed", policy=json.dumps(policy_doc))]
        findings = run_terraform_security_rules(tf)
        assert has_finding_with(findings, title="Overly permissive IAM policy")

    # ----- Security Group open to internet -----

    def test_security_group_open_to_world_flagged(self):
        tf = [tf_resource("aws_security_group", "web", ingress=[{
            "from_port": 22, "to_port": 22, "protocol": "tcp",
            "cidr_blocks": ["0.0.0.0/0"],
        }])]
        findings = run_terraform_security_rules(tf)
        assert has_finding_with(findings, title="Security group open to 0.0.0.0/0",
                                severity=Severity.CRITICAL)

    def test_security_group_restricted_no_flag(self):
        tf = [tf_resource("aws_security_group", "internal", ingress=[{
            "from_port": 22, "to_port": 22, "protocol": "tcp",
            "cidr_blocks": ["10.0.0.0/8"],
        }])]
        findings = run_terraform_security_rules(tf)
        assert not has_finding_with(findings, title="Security group open to 0.0.0.0/0")

    # ----- S3 encryption (Phase 2 companion-resource awareness) -----

    def test_s3_without_encryption_flagged_when_no_companion(self):
        tf = [tf_resource("aws_s3_bucket", "data", bucket="my-bucket")]
        findings = run_terraform_security_rules(tf)
        assert has_finding_with(findings, title="S3 bucket without encryption", severity=Severity.HIGH)

    def test_s3_with_companion_encryption_no_flag(self):
        """Phase 2: AWS provider v4+ encryption companion suppresses the finding."""
        tf = [
            tf_resource("aws_s3_bucket", "data", bucket="my-bucket"),
            tf_resource(
                "aws_s3_bucket_server_side_encryption_configuration",
                "data_enc",
                bucket="${aws_s3_bucket.data.id}",
                rule={"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}},
            ),
        ]
        findings = run_terraform_security_rules(tf)
        assert not has_finding_with(findings, title="S3 bucket without encryption")

    def test_s3_with_inline_encryption_no_flag(self):
        """Pre-v4 inline server_side_encryption_configuration also suppresses."""
        tf = [tf_resource(
            "aws_s3_bucket", "data", bucket="my-bucket",
            server_side_encryption_configuration={
                "rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}},
            },
        )]
        findings = run_terraform_security_rules(tf)
        assert not has_finding_with(findings, title="S3 bucket without encryption")

    def test_s3_public_acl_flagged_critical(self):
        tf = [tf_resource("aws_s3_bucket", "data", bucket="my-bucket", acl="public-read")]
        findings = run_terraform_security_rules(tf)
        assert has_finding_with(findings, title="Public S3 bucket", severity=Severity.CRITICAL)

    # ----- RDS public access -----

    def test_rds_publicly_accessible_flagged_critical(self):
        tf = [tf_resource(
            "aws_db_instance", "main",
            engine="postgres", publicly_accessible=True,
        )]
        findings = run_terraform_security_rules(tf)
        assert has_finding_with(findings, title="RDS instance publicly accessible",
                                severity=Severity.CRITICAL)

    def test_rds_private_no_flag(self):
        tf = [tf_resource(
            "aws_db_instance", "main",
            engine="postgres", publicly_accessible=False,
        )]
        findings = run_terraform_security_rules(tf)
        assert not has_finding_with(findings, title="RDS instance publicly accessible")
