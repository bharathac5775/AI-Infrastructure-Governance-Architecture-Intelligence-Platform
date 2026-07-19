"""Resource dependency graph (Phase 4.1).

Builds a directed dependency graph over the resources extracted from an upload,
regardless of source format. All six supported input types converge into the two
structures this module consumes:

- Kubernetes (``.yaml`` / ``.yml`` / K8s-``.json`` / rendered ``.tgz`` Helm charts)
  → ``k8s_resources``: ``dict[kind -> list[manifest dict]]`` from
  ``extract_k8s_resources``.
- Terraform (``.tf`` / ``.hcl`` / Terraform-``.json``)
  → ``tf_resources``: ``list[{type, name, config}]`` from ``extract_tf_resources``.

Edge direction convention: ``A --depends_on--> B`` means "A needs B" (A is the
dependent, B is the dependency). Blast radius later walks the *reverse* direction
("what breaks if B disappears" = everything that depends on B).

Node IDs are namespaced so a mixed K8s+Terraform upload never collides:
- Kubernetes: ``get_resource_name`` form ``Kind/namespace/name`` (e.g. ``Deployment/prod/api``).
- Terraform:  ``type.name`` (e.g. ``aws_db_instance.default``).

The builder is pure and deterministic (no LLM, no I/O). NetworkX (BSD licence)
is the only new dependency.
"""

from __future__ import annotations

import re
from typing import Any

import networkx as nx

from app.parsers.kubernetes import get_containers, get_pod_spec, get_resource_name
from app.models import (
    DependencyGraph,
    Finding,
    GraphEdge,
    GraphNode,
    Severity,
    Spof,
)

# ---------------------------------------------------------------------------
# Terraform reference extraction
# ---------------------------------------------------------------------------

# Matches a Terraform resource address inside an interpolation, e.g.
#   ${aws_kms_key.main.arn}  -> ("aws_kms_key", "main")
#   ${aws_subnet.main.id}    -> ("aws_subnet", "main")
#   ${aws_db_instance.default} (depends_on form, no attribute) -> ("aws_db_instance", "default")
# Also matches bare (non-${}) addresses that HCL2 occasionally leaves unwrapped.
# A TF resource type is one or more `word` segments joined by underscores and
# must contain at least one underscore-or-provider prefix; we accept any
# ``ident.ident`` where the first ident looks like a provider resource type
# (contains an underscore) to avoid matching things like ``var.foo`` or
# ``local.bar`` which are NOT resources.
_TF_REF_RE = re.compile(r"([a-zA-Z][\w-]*_[\w-]+)\.([a-zA-Z_][\w-]*)")

# Interpolation prefixes that are NOT resource references and must be ignored.
_TF_NON_RESOURCE_PREFIXES = ("var", "local", "module", "data", "each", "count", "self", "path", "terraform")


def _iter_strings(value: Any):
    """Yield every string found anywhere inside a nested dict/list structure."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _iter_strings(v)
    # ints/floats/bools/None: nothing to yield


def extract_tf_references(config: dict[str, Any]) -> set[str]:
    """Return the set of Terraform resource addresses (``type.name``) this
    config references, via ``${...}`` interpolations or ``depends_on``.

    Handles nested blocks, list-wrapped values, and both attribute references
    (``aws_kms_key.main.arn``) and bare ones (``aws_db_instance.default``).
    Filters out ``var.``/``local.``/``module.``/``data.`` which are not
    resource-to-resource edges.
    """
    refs: set[str] = set()
    for s in _iter_strings(config):
        for m in _TF_REF_RE.finditer(s):
            rtype, rname = m.group(1), m.group(2)
            # Guard 1: the matched type must not itself be a non-resource prefix.
            if rtype in _TF_NON_RESOURCE_PREFIXES:
                continue
            # Guard 2: the match must not be the MIDDLE of a longer path like
            # ``data.aws_ami.ubuntu`` (which would otherwise yield a spurious
            # ``aws_ami.ubuntu`` resource edge) or ``module.x.aws_foo.bar``.
            # Look at the token immediately preceding the match.
            preceding = s[max(0, m.start() - 40):m.start()]
            pm = re.search(r"([A-Za-z_][\w-]*)\.\s*$", preceding)
            if pm and pm.group(1) in _TF_NON_RESOURCE_PREFIXES:
                continue
            refs.add(f"{rtype}.{rname}")
    return refs


# ---------------------------------------------------------------------------
# Kubernetes helpers
# ---------------------------------------------------------------------------

def _expand_k8s_lists(k8s_resources: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """Return a copy of ``k8s_resources`` with any ``kind: List`` documents
    expanded into their inner items grouped by real kind.

    The base parser stores a ``List`` manifest under the ``"List"`` key without
    expanding ``.items`` (documented limitation). For a dependency graph we want
    the real resources, so we expand them here without touching the parser.
    """
    expanded: dict[str, list[dict]] = {}
    for kind, items in k8s_resources.items():
        if kind == "List":
            for lst in items:
                for inner in lst.get("items", []):
                    if isinstance(inner, dict):
                        inner_kind = inner.get("kind", "Unknown")
                        expanded.setdefault(inner_kind, []).append(inner)
            continue
        expanded.setdefault(kind, []).extend(items)
    return expanded


def _pod_labels(workload: dict) -> dict[str, str]:
    """Labels on the pod template (what a Service selector matches against)."""
    spec = workload.get("spec", {}) or {}
    template = spec.get("template", {}) or {}
    meta = template.get("metadata", {}) or {}
    labels = meta.get("labels", {}) or {}
    # Fall back to top-level metadata labels for bare Pods.
    if not labels:
        labels = (workload.get("metadata", {}) or {}).get("labels", {}) or {}
    return labels if isinstance(labels, dict) else {}


def _selector_matches(selector: dict, labels: dict[str, str]) -> bool:
    """True if a Service ``spec.selector`` (plain label map) matches ``labels``."""
    if not selector or not labels:
        return False
    return all(labels.get(k) == v for k, v in selector.items())


_K8S_WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod")
_K8S_NAMESPACED_DEFAULT = "default"


def _k8s_namespace(resource: dict) -> str:
    return (resource.get("metadata", {}) or {}).get("namespace", _K8S_NAMESPACED_DEFAULT)


def _k8s_ref_node_id(kind: str, namespace: str, name: str) -> str:
    """Node id for a referenced-but-maybe-not-uploaded K8s resource."""
    return f"{kind}/{namespace}/{name}"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_dependency_graph(
    k8s_resources: dict[str, list[dict]] | None = None,
    tf_resources: list[dict] | None = None,
) -> nx.DiGraph:
    """Build a directed dependency graph from parsed resources.

    Every node carries attributes: ``kind`` (K8s kind or TF type), ``platform``
    (``kubernetes`` | ``terraform``), and ``present`` (True if the resource was
    actually in the upload, False if it is only referenced by another resource).

    Edge ``A -> B`` means "A depends on B".
    """
    g = nx.DiGraph()
    k8s_resources = k8s_resources or {}
    tf_resources = tf_resources or []

    _add_k8s_nodes_and_edges(g, k8s_resources)
    _add_tf_nodes_and_edges(g, tf_resources)
    return g


def _add_k8s_nodes_and_edges(g: nx.DiGraph, k8s_resources: dict[str, list[dict]]) -> None:
    resources = _expand_k8s_lists(k8s_resources)

    # First pass: add every present resource as a node, and index workloads by
    # (namespace -> [(node_id, pod_labels)]) for selector matching.
    workloads_by_ns: dict[str, list[tuple[str, dict]]] = {}
    for kind, items in resources.items():
        for res in items:
            node_id = get_resource_name(res)
            g.add_node(node_id, kind=kind, platform="kubernetes", present=True)
            if kind in _K8S_WORKLOAD_KINDS:
                workloads_by_ns.setdefault(_k8s_namespace(res), []).append(
                    (node_id, _pod_labels(res))
                )

    # Second pass: edges.
    for kind, items in resources.items():
        for res in items:
            node_id = get_resource_name(res)
            ns = _k8s_namespace(res)

            # Service --selects--> workload(s): Service depends on the pods it targets.
            if kind == "Service":
                selector = (res.get("spec", {}) or {}).get("selector", {}) or {}
                if isinstance(selector, dict) and selector:
                    for wl_id, wl_labels in workloads_by_ns.get(ns, []):
                        if _selector_matches(selector, wl_labels):
                            g.add_edge(node_id, wl_id, relation="selects")

            # Workload --uses--> Secret / ConfigMap / ServiceAccount.
            if kind in _K8S_WORKLOAD_KINDS:
                _add_k8s_workload_refs(g, res, node_id, ns)


def _ensure_ref_node(g: nx.DiGraph, node_id: str, kind: str) -> None:
    """Add a referenced node if absent, marking it as not-present (external)."""
    if node_id not in g:
        g.add_node(node_id, kind=kind, platform="kubernetes", present=False)
    # If it exists (was uploaded), leave its attributes as-is.


def _add_k8s_workload_refs(g: nx.DiGraph, workload: dict, node_id: str, ns: str) -> None:
    pod = get_pod_spec(workload)
    if not isinstance(pod, dict):
        return

    # serviceAccountName
    sa = pod.get("serviceAccountName") or pod.get("serviceAccount")
    if isinstance(sa, str) and sa:
        target = _k8s_ref_node_id("ServiceAccount", ns, sa)
        _ensure_ref_node(g, target, "ServiceAccount")
        g.add_edge(node_id, target, relation="serviceAccount")

    # env valueFrom secretKeyRef / configMapKeyRef, and envFrom
    for container in get_containers(workload.get("spec", {}) or {}):
        for env in container.get("env", []) or []:
            value_from = (env or {}).get("valueFrom", {}) or {}
            skr = value_from.get("secretKeyRef", {}) or {}
            if isinstance(skr, dict) and skr.get("name"):
                target = _k8s_ref_node_id("Secret", ns, skr["name"])
                _ensure_ref_node(g, target, "Secret")
                g.add_edge(node_id, target, relation="secretKeyRef")
            cmr = value_from.get("configMapKeyRef", {}) or {}
            if isinstance(cmr, dict) and cmr.get("name"):
                target = _k8s_ref_node_id("ConfigMap", ns, cmr["name"])
                _ensure_ref_node(g, target, "ConfigMap")
                g.add_edge(node_id, target, relation="configMapKeyRef")
        for env_from in container.get("envFrom", []) or []:
            ef = env_from or {}
            sref = ef.get("secretRef", {}) or {}
            if isinstance(sref, dict) and sref.get("name"):
                target = _k8s_ref_node_id("Secret", ns, sref["name"])
                _ensure_ref_node(g, target, "Secret")
                g.add_edge(node_id, target, relation="secretRef")
            cref = ef.get("configMapRef", {}) or {}
            if isinstance(cref, dict) and cref.get("name"):
                target = _k8s_ref_node_id("ConfigMap", ns, cref["name"])
                _ensure_ref_node(g, target, "ConfigMap")
                g.add_edge(node_id, target, relation="configMapRef")

    # volumes: secret / configMap / persistentVolumeClaim
    for vol in pod.get("volumes", []) or []:
        v = vol or {}
        sec = v.get("secret", {}) or {}
        if isinstance(sec, dict) and sec.get("secretName"):
            target = _k8s_ref_node_id("Secret", ns, sec["secretName"])
            _ensure_ref_node(g, target, "Secret")
            g.add_edge(node_id, target, relation="volumeSecret")
        cm = v.get("configMap", {}) or {}
        if isinstance(cm, dict) and cm.get("name"):
            target = _k8s_ref_node_id("ConfigMap", ns, cm["name"])
            _ensure_ref_node(g, target, "ConfigMap")
            g.add_edge(node_id, target, relation="volumeConfigMap")
        pvc = v.get("persistentVolumeClaim", {}) or {}
        if isinstance(pvc, dict) and pvc.get("claimName"):
            target = _k8s_ref_node_id("PersistentVolumeClaim", ns, pvc["claimName"])
            _ensure_ref_node(g, target, "PersistentVolumeClaim")
            g.add_edge(node_id, target, relation="volumePVC")


def _add_tf_nodes_and_edges(g: nx.DiGraph, tf_resources: list[dict]) -> None:
    # First pass: every present resource is a node.
    present_addrs: set[str] = set()
    for res in tf_resources:
        rtype, rname = res.get("type"), res.get("name")
        if not rtype or not rname:
            continue
        addr = f"{rtype}.{rname}"
        present_addrs.add(addr)
        g.add_node(addr, kind=rtype, platform="terraform", present=True)

    # Second pass: edges from interpolations + depends_on.
    for res in tf_resources:
        rtype, rname = res.get("type"), res.get("name")
        if not rtype or not rname:
            continue
        addr = f"{rtype}.{rname}"
        for ref in extract_tf_references(res.get("config", {}) or {}):
            if ref == addr:
                continue  # ignore self-references
            if ref not in g:
                # Referenced resource not in the upload (e.g. in another module).
                rt = ref.split(".", 1)[0]
                g.add_node(ref, kind=rt, platform="terraform", present=False)
            g.add_edge(addr, ref, relation="reference")


# ---------------------------------------------------------------------------
# SPOF detection (Phase 4.5)
# ---------------------------------------------------------------------------

# A resource is a high-fan-in SPOF when at least this many other resources
# depend on it. Roadmap specifies ">5 dependents"; we use >= HIGH_FANIN_THRESHOLD.
HIGH_FANIN_THRESHOLD = 5

SPOF_AGENT_NAME = "Architecture Agent"
SPOF_CATEGORY = "architecture"


def dependents_of(g: nx.DiGraph, node: str) -> list[str]:
    """Every resource that (transitively) depends on ``node``.

    Edges point dependent -> dependency, so dependents are found by walking
    *predecessors*. This is the blast-radius set (Phase 4.2 will reuse it).
    """
    if node not in g:
        return []
    # Reverse the graph so descendants(reverse, node) = ancestors(g, node).
    return sorted(nx.descendants(g.reverse(copy=False), node))


def find_spofs(g: nx.DiGraph) -> list[dict[str, Any]]:
    """Identify single points of failure in the dependency graph.

    Two independent signals, unioned:
    1. **High fan-in** — a node with >= HIGH_FANIN_THRESHOLD transitive
       dependents. Its loss cascades widely.
    2. **Articulation point** — a node whose removal disconnects the
       (undirected) graph, splitting the system into isolated islands.

    Returns a list of dicts: ``{node, kind, platform, dependents (list),
    dependent_count, reasons (list), is_articulation}`` sorted by
    dependent_count desc.
    """
    if g.number_of_nodes() == 0:
        return []

    # Articulation points operate on the undirected view.
    undirected = g.to_undirected()
    try:
        articulation = set(nx.articulation_points(undirected))
    except Exception:
        articulation = set()

    spofs: list[dict[str, Any]] = []
    for node in g.nodes():
        deps = dependents_of(g, node)
        count = len(deps)
        reasons: list[str] = []
        if count >= HIGH_FANIN_THRESHOLD:
            reasons.append("high-fan-in")
        is_artic = node in articulation
        # Only treat an articulation point as a SPOF if it actually has
        # dependents (a leaf articulation point that nothing relies on isn't a
        # meaningful single point of failure for blast-radius purposes).
        if is_artic and count >= 1:
            reasons.append("articulation-point")
        if not reasons:
            continue
        attrs = g.nodes[node]
        spofs.append({
            "node": node,
            "kind": attrs.get("kind", "Unknown"),
            "platform": attrs.get("platform", "unknown"),
            "dependents": deps,
            "dependent_count": count,
            "reasons": reasons,
            "is_articulation": is_artic,
        })

    spofs.sort(key=lambda s: (-s["dependent_count"], s["node"]))
    return spofs


def _spof_severity(dependent_count: int) -> Severity:
    if dependent_count >= 8:
        return Severity.HIGH
    if dependent_count >= 3:
        return Severity.MEDIUM
    return Severity.LOW


def spof_findings(g: nx.DiGraph) -> list[Finding]:
    """Turn detected SPOFs into architecture-category Findings.

    Deterministic — no LLM. Emitted under the "Architecture Agent" so they sit
    naturally alongside the existing architecture review in the report.
    """
    findings: list[Finding] = []
    for spof in find_spofs(g):
        count = spof["dependent_count"]
        node = spof["node"]
        reason_txt = " and ".join(spof["reasons"])
        sample = ", ".join(spof["dependents"][:5])
        more = "" if count <= 5 else f" (+{count - 5} more)"
        findings.append(Finding(
            agent=SPOF_AGENT_NAME,
            category=SPOF_CATEGORY,
            severity=_spof_severity(count),
            title=f"Single point of failure: {node}",
            description=(
                f"{node} ({spof['kind']}) is a single point of failure "
                f"({reason_txt}). {count} resource(s) depend on it"
                + (f": {sample}{more}." if sample else ".")
                + (" Removing it would partition the architecture into disconnected"
                   " components." if spof["is_articulation"] else "")
            ),
            resource=node,
            recommendation=(
                "Add redundancy for this resource (e.g. replicas / Multi-AZ / a "
                "standby or read replica) or decouple dependents so its loss does "
                "not cascade across the system."
            ),
        ))
    return findings


# ---------------------------------------------------------------------------
# Serialization (Phase 4.1 — persist on the report)
# ---------------------------------------------------------------------------

def to_dependency_graph_model(g: nx.DiGraph) -> DependencyGraph:
    """Serialize a NetworkX graph + its SPOFs into the persistable pydantic model.

    Node/edge ordering is sorted for deterministic output (stable diffs, stable
    tests). Returns an empty model for an empty graph.
    """
    nodes = [
        GraphNode(
            id=n,
            kind=attrs.get("kind", "Unknown"),
            platform=attrs.get("platform", "unknown"),
            present=attrs.get("present", True),
        )
        for n, attrs in sorted(g.nodes(data=True))
    ]
    edges = [
        GraphEdge(source=a, target=b, relation=attrs.get("relation", "reference"))
        for a, b, attrs in sorted(g.edges(data=True), key=lambda e: (e[0], e[1], e[2].get("relation", "")))
    ]
    spofs = [
        Spof(
            node=s["node"],
            kind=s["kind"],
            platform=s["platform"],
            dependent_count=s["dependent_count"],
            dependents=s["dependents"],
            reasons=s["reasons"],
            is_articulation=s["is_articulation"],
        )
        for s in find_spofs(g)
    ]
    return DependencyGraph(nodes=nodes, edges=edges, spofs=spofs)


def build_dependency_graph_model(
    k8s_resources: dict[str, list[dict]] | None = None,
    tf_resources: list[dict] | None = None,
) -> DependencyGraph:
    """Convenience: build the graph and return the serialized model in one call."""
    g = build_dependency_graph(k8s_resources=k8s_resources, tf_resources=tf_resources)
    return to_dependency_graph_model(g)
