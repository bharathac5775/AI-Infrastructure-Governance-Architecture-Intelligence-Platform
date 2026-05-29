"""Tests for parsers — K8s YAML/JSON and Terraform HCL/JSON.

Reference:
- app/parsers/kubernetes.py
- app/parsers/terraform.py
"""
from __future__ import annotations

from app.parsers.kubernetes import (
    extract_k8s_resources,
    get_containers,
    get_pod_spec,
    get_resource_name,
    parse_kubernetes_yaml,
)
from app.parsers.terraform import (
    extract_tf_resources,
    parse_terraform,
    resources_with_companion,
)


# ===========================================================================
# Kubernetes parser
# ===========================================================================


class TestKubernetesParser:
    def test_single_doc_yaml(self):
        content = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
"""
        docs = parse_kubernetes_yaml(content)
        assert len(docs) == 1
        assert docs[0]["kind"] == "Deployment"

    def test_multi_doc_yaml(self):
        content = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
---
apiVersion: v1
kind: Service
metadata:
  name: app-svc
"""
        docs = parse_kubernetes_yaml(content)
        assert len(docs) == 2
        assert docs[0]["kind"] == "Deployment"
        assert docs[1]["kind"] == "Service"

    def test_invalid_yaml_raises_value_error(self):
        import pytest
        with pytest.raises(ValueError):
            parse_kubernetes_yaml("not: valid: yaml: at all:")

    def test_empty_string_returns_empty_list(self):
        assert parse_kubernetes_yaml("") == []

    def test_extract_groups_by_kind(self):
        docs = [
            {"kind": "Deployment", "metadata": {"name": "a"}},
            {"kind": "Deployment", "metadata": {"name": "b"}},
            {"kind": "Service", "metadata": {"name": "svc"}},
        ]
        resources = extract_k8s_resources(docs)
        assert len(resources["Deployment"]) == 2
        assert len(resources["Service"]) == 1

    def test_get_pod_spec_for_deployment(self):
        depl = {
            "kind": "Deployment",
            "spec": {"template": {"spec": {"containers": [{"name": "x"}]}}},
        }
        assert get_pod_spec(depl) == {"containers": [{"name": "x"}]}

    def test_get_pod_spec_for_pod(self):
        pod = {"kind": "Pod", "spec": {"containers": [{"name": "x"}]}}
        assert get_pod_spec(pod) == {"containers": [{"name": "x"}]}

    def test_get_pod_spec_for_cronjob(self):
        cj = {
            "kind": "CronJob",
            "spec": {
                "jobTemplate": {
                    "spec": {"template": {"spec": {"containers": [{"name": "x"}]}}},
                },
            },
        }
        assert get_pod_spec(cj) == {"containers": [{"name": "x"}]}

    def test_get_containers_includes_init_containers(self):
        spec = {
            "template": {
                "spec": {
                    "containers": [{"name": "main"}],
                    "initContainers": [{"name": "init"}],
                },
            },
        }
        containers = get_containers(spec)
        names = [c["name"] for c in containers]
        assert "main" in names
        assert "init" in names

    def test_get_resource_name_format(self):
        r = {"kind": "Deployment", "metadata": {"name": "api", "namespace": "prod"}}
        assert get_resource_name(r) == "Deployment/prod/api"

    def test_get_resource_name_default_namespace(self):
        r = {"kind": "Deployment", "metadata": {"name": "api"}}
        assert get_resource_name(r) == "Deployment/default/api"

    def test_list_kind_not_currently_expanded(self):
        """Documents the CURRENT behavior — kind:List is NOT expanded into items.

        This is a known limitation. When fixed, the resulting `kinds` set should
        contain the underlying resource types (Deployment, Service, etc.) instead
        of just 'List'.
        """
        list_doc = {
            "kind": "List",
            "items": [
                {"kind": "Deployment", "metadata": {"name": "a"}},
                {"kind": "Service", "metadata": {"name": "svc"}},
            ],
        }
        resources = extract_k8s_resources([list_doc])
        assert "List" in resources
        # When List expansion is implemented, this assertion should be inverted.
        assert "Deployment" not in resources


# ===========================================================================
# Terraform parser
# ===========================================================================


class TestTerraformParser:
    def test_parse_hcl_single_resource(self):
        content = '''
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}
'''
        parsed = parse_terraform(content)
        resources = extract_tf_resources(parsed)
        assert len(resources) == 1
        assert resources[0]["type"] == "aws_s3_bucket"
        assert resources[0]["name"] == "data"
        # config.bucket is wrapped in a list by hcl2 typically; parser unwraps via [0]
        assert resources[0]["config"].get("bucket") == "my-bucket"

    def test_parse_hcl_multiple_resources(self):
        content = '''
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}
resource "aws_dynamodb_table" "sessions" {
  name = "sessions"
  hash_key = "id"
  attribute {
    name = "id"
    type = "S"
  }
}
'''
        parsed = parse_terraform(content)
        resources = extract_tf_resources(parsed)
        types = {r["type"] for r in resources}
        assert "aws_s3_bucket" in types
        assert "aws_dynamodb_table" in types

    def test_parse_terraform_json_format(self):
        """Phase 2 regression: extract_tf_resources must handle JSON dict format.

        Before the parser fix, JSON-format Terraform silently produced zero
        resources because the function expected HCL2's list-of-dicts shape.
        """
        json_format = {
            "resource": {
                "aws_s3_bucket": {
                    "data": {"bucket": "my-bucket"},
                },
                "aws_dynamodb_table": {
                    "sessions": {"name": "sessions", "hash_key": "id"},
                },
            },
        }
        resources = extract_tf_resources(json_format)
        types = {r["type"] for r in resources}
        assert "aws_s3_bucket" in types
        assert "aws_dynamodb_table" in types

    def test_parse_empty_terraform(self):
        parsed = parse_terraform("")
        resources = extract_tf_resources(parsed)
        assert resources == []

    def test_invalid_hcl_raises_value_error(self):
        import pytest
        # Truly malformed input that hcl2 cannot lex
        with pytest.raises(ValueError):
            parse_terraform("@@@@ NOT VALID HCL @@@@")


class TestResourcesWithCompanion:
    def test_finds_companion_via_bucket_field(self):
        tf = [
            {"type": "aws_s3_bucket", "name": "data", "config": {"bucket": "mb"}},
            {"type": "aws_s3_bucket_versioning", "name": "data_v",
             "config": {"bucket": "${aws_s3_bucket.data.id}"}},
        ]
        result = resources_with_companion(tf, "aws_s3_bucket_versioning")
        assert "data" in result

    def test_finds_companion_via_other_string_field(self):
        """When the bucket field isn't standard, scan all string values."""
        tf = [
            {"type": "aws_s3_bucket", "name": "data", "config": {"bucket": "mb"}},
            {"type": "aws_s3_bucket_lifecycle_configuration", "name": "lc",
             "config": {"some_ref": "${aws_s3_bucket.data.arn}"}},
        ]
        result = resources_with_companion(tf, "aws_s3_bucket_lifecycle_configuration")
        assert "data" in result

    def test_no_companion_returns_empty_set(self):
        tf = [
            {"type": "aws_s3_bucket", "name": "data", "config": {"bucket": "mb"}},
        ]
        result = resources_with_companion(tf, "aws_s3_bucket_versioning")
        assert result == set()

    def test_companion_missing_reference_returns_empty(self):
        tf = [
            {"type": "aws_s3_bucket", "name": "data", "config": {"bucket": "mb"}},
            {"type": "aws_s3_bucket_versioning", "name": "v",
             "config": {"bucket": "literal-bucket-name"}},  # no aws_s3_bucket. ref
        ]
        result = resources_with_companion(tf, "aws_s3_bucket_versioning")
        assert result == set()

    def test_handles_list_value(self):
        """HCL2 sometimes wraps single string values in lists."""
        tf = [
            {"type": "aws_s3_bucket", "name": "data", "config": {"bucket": "mb"}},
            {"type": "aws_s3_bucket_versioning", "name": "v",
             "config": {"bucket": ["${aws_s3_bucket.data.id}"]}},
        ]
        result = resources_with_companion(tf, "aws_s3_bucket_versioning")
        assert "data" in result
