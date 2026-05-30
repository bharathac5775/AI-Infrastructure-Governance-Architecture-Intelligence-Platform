"""Test fixture builders for Findings, CrossCuttingGaps, and AgentReports.

Defaults are chosen so each builder call is minimal — pass only what
the test actually cares about.
"""
from app.models import (
    AgentReport,
    CrossCuttingGap,
    Finding,
    Severity,
)


def make_finding(
    agent: str = "Security Agent",
    category: str = "test",
    severity: Severity = Severity.HIGH,
    title: str = "Test finding",
    description: str = "Test description.",
    resource: str = "test/resource",
    recommendation: str = "Fix it.",
    compliance_controls: list[str] | None = None,
) -> Finding:
    return Finding(
        agent=agent,
        category=category,
        severity=severity,
        title=title,
        description=description,
        resource=resource,
        recommendation=recommendation,
        compliance_controls=compliance_controls or [],
    )


def make_gap(
    title: str = "Test gap",
    severity: Severity = Severity.MEDIUM,
    description: str = "Test gap description.",
    recommendation: str = "Fix the gap.",
) -> CrossCuttingGap:
    return CrossCuttingGap(
        title=title,
        severity=severity,
        description=description,
        recommendation=recommendation,
    )


def make_report(
    agent_name: str,
    findings: list[Finding] | None = None,
    score: float = 80.0,
    summary: str = "Test summary.",
) -> AgentReport:
    return AgentReport(
        agent_name=agent_name,
        findings=findings or [],
        score=score,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Kubernetes resource builders
# ---------------------------------------------------------------------------


def minimal_container(
    name: str = "main",
    image: str = "app:1.0",
    privileged: bool = False,
    run_as_non_root: bool | None = None,
    read_only_root_fs: bool | None = None,
    liveness: bool = False,
    readiness: bool = False,
    cpu_request: str | None = None,
    cpu_limit: str | None = None,
    mem_request: str | None = None,
    mem_limit: str | None = None,
) -> dict:
    sec_ctx: dict = {}
    if privileged:
        sec_ctx["privileged"] = True
    if run_as_non_root is not None:
        sec_ctx["runAsNonRoot"] = run_as_non_root
    if read_only_root_fs is not None:
        sec_ctx["readOnlyRootFilesystem"] = read_only_root_fs

    container: dict = {"name": name, "image": image}
    if sec_ctx:
        container["securityContext"] = sec_ctx
    if liveness:
        container["livenessProbe"] = {"httpGet": {"path": "/health", "port": 8080}}
    if readiness:
        container["readinessProbe"] = {"httpGet": {"path": "/ready", "port": 8080}}

    resources: dict = {}
    if cpu_request or mem_request:
        resources["requests"] = {}
        if cpu_request:
            resources["requests"]["cpu"] = cpu_request
        if mem_request:
            resources["requests"]["memory"] = mem_request
    if cpu_limit or mem_limit:
        resources["limits"] = {}
        if cpu_limit:
            resources["limits"]["cpu"] = cpu_limit
        if mem_limit:
            resources["limits"]["memory"] = mem_limit
    if resources:
        container["resources"] = resources

    return container


def minimal_deployment(
    name: str = "app",
    namespace: str = "default",
    replicas: int = 1,
    containers: list[dict] | None = None,
    pod_run_as_non_root: bool | None = None,
    host_network: bool = False,
    host_pid: bool = False,
    service_account: str | None = None,
) -> dict:
    """Return a Deployment dict shaped like extract_k8s_resources output."""
    pod_spec: dict = {
        "containers": containers or [minimal_container()],
    }
    if host_network:
        pod_spec["hostNetwork"] = True
    if host_pid:
        pod_spec["hostPID"] = True
    if service_account is not None:
        pod_spec["serviceAccountName"] = service_account
    if pod_run_as_non_root is not None:
        pod_spec["securityContext"] = {"runAsNonRoot": pod_run_as_non_root}

    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "replicas": replicas,
            "template": {"spec": pod_spec},
        },
    }


# ---------------------------------------------------------------------------
# Terraform resource builders
# ---------------------------------------------------------------------------


def tf_resource(rtype: str, resource_name: str = "test", **config) -> dict:
    """Build a parsed-Terraform resource dict shaped like extract_tf_resources output.

    `resource_name` is the Terraform local name (e.g., `aws_s3_bucket.<this>`).
    Pass `name=...` in **config to set the AWS-side `name` attribute.
    """
    return {"type": rtype, "name": resource_name, "config": config}
