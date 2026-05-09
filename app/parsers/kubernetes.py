import yaml
from typing import Any


def parse_kubernetes_yaml(content: str) -> list[dict[str, Any]]:
    """Parse Kubernetes YAML (supports multi-document YAML)."""
    documents = []
    try:
        for doc in yaml.safe_load_all(content):
            if doc and isinstance(doc, dict):
                documents.append(doc)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}")
    return documents


def extract_k8s_resources(documents: list[dict]) -> dict[str, list[dict]]:
    """Group parsed K8s documents by resource kind."""
    resources: dict[str, list[dict]] = {}
    for doc in documents:
        kind = doc.get("kind", "Unknown")
        resources.setdefault(kind, []).append(doc)
    return resources


def get_containers(spec: dict) -> list[dict]:
    """Extract containers from a pod spec."""
    containers = []
    pod_spec = spec
    # Handle Deployment/StatefulSet/DaemonSet -> spec.template.spec
    if "template" in spec:
        pod_spec = spec.get("template", {}).get("spec", {})
    elif "spec" in spec:
        pod_spec = spec.get("spec", {})

    containers.extend(pod_spec.get("containers", []))
    containers.extend(pod_spec.get("initContainers", []))
    return containers


def get_pod_spec(resource: dict) -> dict:
    """Get pod spec from various resource types."""
    kind = resource.get("kind", "")
    spec = resource.get("spec", {})

    if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job"):
        return spec.get("template", {}).get("spec", {})
    elif kind in ("Pod", "CronJob"):
        if kind == "CronJob":
            return (
                spec.get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
            )
        return spec
    return spec


def get_resource_name(resource: dict) -> str:
    """Get the name of a K8s resource."""
    metadata = resource.get("metadata", {})
    name = metadata.get("name", "unnamed")
    namespace = metadata.get("namespace", "default")
    kind = resource.get("kind", "Unknown")
    return f"{kind}/{namespace}/{name}"
