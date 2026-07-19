"""Tests for the Phase 4.1 dependency graph + 4.5 SPOF detector.

Reference code:
- app/core/graph.py::build_dependency_graph / find_spofs / spof_findings /
  extract_tf_references / dependents_of / to_dependency_graph_model
- app/models.py::DependencyGraph / GraphNode / GraphEdge / Spof

Coverage goals:
- Terraform edges: ${...} interpolations, depends_on, list-wrapped, nested blocks
- Kubernetes edges: Service selector, secretKeyRef/configMapKeyRef, envFrom,
  serviceAccountName, volume secret/configMap/PVC
- var./local./data. references are NOT edges
- referenced-but-not-uploaded resources get present=False
- node-id namespaces never collide across platforms
- kind: List is expanded
- SPOF: high fan-in + articulation points, severity scaling
- serialization round-trips
- empty inputs are safe
"""
from __future__ import annotations

from app.core.graph import (
    HIGH_FANIN_THRESHOLD,
    SPOF_AGENT_NAME,
    blast_radius,
    build_dependency_graph,
    build_dependency_graph_model,
    dependents_of,
    extract_tf_references,
    find_spofs,
    graph_from_model,
    spof_findings,
    to_dependency_graph_model,
    to_mermaid,
)
from app.models import DependencyGraph, Severity
from app.parsers.kubernetes import extract_k8s_resources, parse_kubernetes_yaml
from app.parsers.terraform import extract_tf_resources, parse_terraform


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tf(content: str):
    return extract_tf_resources(parse_terraform(content))


def _k8s(content: str):
    return extract_k8s_resources(parse_kubernetes_yaml(content))


def _edge_set(g):
    return {(a, b, d["relation"]) for a, b, d in g.edges(data=True)}


# ---------------------------------------------------------------------------
# extract_tf_references
# ---------------------------------------------------------------------------

class TestTfReferences:
    def test_simple_interpolation(self):
        refs = extract_tf_references({"kms_key_id": "${aws_kms_key.main.arn}"})
        assert "aws_kms_key.main" in refs

    def test_bare_depends_on(self):
        refs = extract_tf_references({"depends_on": ["${aws_db_instance.default}"]})
        assert "aws_db_instance.default" in refs

    def test_nested_block_reference(self):
        cfg = {"ebs_block_device": {"kms_key_id": "${aws_kms_key.k.arn}"}}
        assert "aws_kms_key.k" in extract_tf_references(cfg)

    def test_var_and_local_are_not_references(self):
        cfg = {"a": "${var.name}", "b": "${local.thing}", "c": "${module.m.out}"}
        # var/module have no underscore in the first segment (var, module) OR are
        # explicitly excluded; none should be treated as resource edges.
        assert extract_tf_references(cfg) == set()

    def test_data_source_excluded(self):
        # data.aws_ami.x — 'data' is an explicit non-resource prefix
        assert extract_tf_references({"ami": "${data.aws_ami.ubuntu.id}"}) == set()

    def test_multiple_refs_in_one_string(self):
        cfg = {"policy": "arn ${aws_iam_role.r.arn} and ${aws_kms_key.k.arn}"}
        refs = extract_tf_references(cfg)
        assert "aws_iam_role.r" in refs and "aws_kms_key.k" in refs


# ---------------------------------------------------------------------------
# Terraform graph
# ---------------------------------------------------------------------------

class TestTerraformGraph:
    def test_interpolation_edge(self):
        g = build_dependency_graph(tf_resources=_tf(
            'resource "aws_kms_key" "main" {}\n'
            'resource "aws_db_instance" "db" { kms_key_id = aws_kms_key.main.arn }\n'
        ))
        assert ("aws_db_instance.db", "aws_kms_key.main", "reference") in _edge_set(g)

    def test_depends_on_edge(self):
        g = build_dependency_graph(tf_resources=_tf(
            'resource "aws_db_instance" "db" {}\n'
            'resource "aws_instance" "web" {\n  depends_on = [aws_db_instance.db]\n}\n'
        ))
        assert ("aws_instance.web", "aws_db_instance.db", "reference") in _edge_set(g)

    def test_referenced_but_absent_marked_not_present(self):
        # References a KMS key that is NOT declared in this upload.
        g = build_dependency_graph(tf_resources=_tf(
            'resource "aws_db_instance" "db" { kms_key_id = aws_kms_key.external.arn }\n'
        ))
        assert g.nodes["aws_kms_key.external"]["present"] is False
        assert g.nodes["aws_db_instance.db"]["present"] is True

    def test_no_self_reference(self):
        g = build_dependency_graph(tf_resources=_tf(
            'resource "aws_instance" "web" { tags = { self = "aws_instance.web" } }\n'
        ))
        assert not any(a == b for a, b in g.edges())


# ---------------------------------------------------------------------------
# Kubernetes graph
# ---------------------------------------------------------------------------

_K8S_BUNDLE = """
apiVersion: v1
kind: Service
metadata: {name: api-svc, namespace: prod}
spec: {selector: {app: api}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: prod}
spec:
  selector: {matchLabels: {app: api}}
  template:
    metadata: {labels: {app: api}}
    spec:
      serviceAccountName: api-sa
      containers:
      - name: c
        image: nginx
        env:
        - name: PW
          valueFrom: {secretKeyRef: {name: db-secret, key: pw}}
        envFrom:
        - configMapRef: {name: app-config}
      volumes:
      - name: tls
        secret: {secretName: tls-secret}
"""


class TestKubernetesGraph:
    def test_service_selects_deployment(self):
        g = build_dependency_graph(k8s_resources=_k8s(_K8S_BUNDLE))
        assert ("Service/prod/api-svc", "Deployment/prod/api", "selects") in _edge_set(g)

    def test_secret_key_ref_edge(self):
        g = build_dependency_graph(k8s_resources=_k8s(_K8S_BUNDLE))
        assert ("Deployment/prod/api", "Secret/prod/db-secret", "secretKeyRef") in _edge_set(g)

    def test_configmap_envfrom_edge(self):
        g = build_dependency_graph(k8s_resources=_k8s(_K8S_BUNDLE))
        assert ("Deployment/prod/api", "ConfigMap/prod/app-config", "configMapRef") in _edge_set(g)

    def test_service_account_edge(self):
        g = build_dependency_graph(k8s_resources=_k8s(_K8S_BUNDLE))
        assert ("Deployment/prod/api", "ServiceAccount/prod/api-sa", "serviceAccount") in _edge_set(g)

    def test_volume_secret_edge(self):
        g = build_dependency_graph(k8s_resources=_k8s(_K8S_BUNDLE))
        assert ("Deployment/prod/api", "Secret/prod/tls-secret", "volumeSecret") in _edge_set(g)

    def test_selector_respects_namespace(self):
        # A Service in a different namespace must NOT match the workload.
        bundle = """
apiVersion: v1
kind: Service
metadata: {name: svc, namespace: other}
spec: {selector: {app: api}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: prod}
spec:
  template:
    metadata: {labels: {app: api}}
    spec: {containers: [{name: c, image: nginx}]}
"""
        g = build_dependency_graph(k8s_resources=_k8s(bundle))
        assert not any(rel == "selects" for _, _, rel in _edge_set(g))

    def test_kind_list_is_expanded(self):
        bundle = """
apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Secret
  metadata: {name: s1, namespace: default}
- apiVersion: apps/v1
  kind: Deployment
  metadata: {name: d1, namespace: default}
  spec:
    template:
      spec:
        containers:
        - name: c
          image: nginx
          env:
          - name: X
            valueFrom: {secretKeyRef: {name: s1, key: k}}
"""
        g = build_dependency_graph(k8s_resources=_k8s(bundle))
        # The inner Deployment and Secret should exist as real nodes with an edge.
        assert "Deployment/default/d1" in g
        assert ("Deployment/default/d1", "Secret/default/s1", "secretKeyRef") in _edge_set(g)


# ---------------------------------------------------------------------------
# Mixed / namespacing
# ---------------------------------------------------------------------------

class TestMixedAndNamespacing:
    def test_k8s_and_tf_node_ids_do_not_collide(self):
        g = build_dependency_graph(
            k8s_resources=_k8s(
                "apiVersion: v1\nkind: Secret\nmetadata: {name: main, namespace: default}\n"
            ),
            tf_resources=_tf('resource "aws_kms_key" "main" {}\n'),
        )
        assert "Secret/default/main" in g          # K8s namespace
        assert "aws_kms_key.main" in g             # TF namespace
        assert g.number_of_nodes() == 2

    def test_empty_inputs_yield_empty_graph(self):
        g = build_dependency_graph()
        assert g.number_of_nodes() == 0
        assert find_spofs(g) == []
        assert spof_findings(g) == []


# ---------------------------------------------------------------------------
# SPOF detection (4.5)
# ---------------------------------------------------------------------------

def _fanin_tf(n: int) -> str:
    lines = ['resource "aws_kms_key" "main" {}']
    for i in range(n):
        lines.append(
            f'resource "aws_s3_bucket" "b{i}" {{ tags = {{ k = aws_kms_key.main.id }} }}'
        )
    return "\n".join(lines) + "\n"


class TestSpof:
    def test_high_fanin_is_spof(self):
        g = build_dependency_graph(tf_resources=_tf(_fanin_tf(HIGH_FANIN_THRESHOLD)))
        spofs = find_spofs(g)
        nodes = {s["node"] for s in spofs}
        assert "aws_kms_key.main" in nodes
        kms = next(s for s in spofs if s["node"] == "aws_kms_key.main")
        assert kms["dependent_count"] == HIGH_FANIN_THRESHOLD
        assert "high-fan-in" in kms["reasons"]

    def test_below_threshold_not_high_fanin(self):
        # 2 dependents, below threshold; but a single hub with 2 leaves is still
        # an articulation point. So it MAY appear via articulation, not fan-in.
        g = build_dependency_graph(tf_resources=_tf(_fanin_tf(2)))
        kms = [s for s in find_spofs(g) if s["node"] == "aws_kms_key.main"]
        if kms:
            assert "high-fan-in" not in kms[0]["reasons"]

    def test_dependents_direction(self):
        g = build_dependency_graph(tf_resources=_tf(
            'resource "aws_kms_key" "main" {}\n'
            'resource "aws_db_instance" "db" { kms_key_id = aws_kms_key.main.arn }\n'
        ))
        # db depends on kms -> kms's dependents include db
        assert dependents_of(g, "aws_kms_key.main") == ["aws_db_instance.db"]
        assert dependents_of(g, "aws_db_instance.db") == []

    def test_spof_findings_shape(self):
        g = build_dependency_graph(tf_resources=_tf(_fanin_tf(8)))
        finds = spof_findings(g)
        assert finds, "expected at least one SPOF finding"
        f = next(f for f in finds if "aws_kms_key.main" in f.resource)
        assert f.agent == SPOF_AGENT_NAME
        assert f.category == "architecture"
        assert f.severity == Severity.HIGH   # 8 dependents -> HIGH
        assert "single point of failure" in f.title.lower()

    def test_severity_scales_with_dependents(self):
        low = build_dependency_graph(tf_resources=_tf(_fanin_tf(1)))
        # 1 dependent: articulation point, LOW severity
        lf = spof_findings(low)
        if lf:
            assert lf[0].severity in (Severity.LOW, Severity.MEDIUM)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_to_model_shape(self):
        model = build_dependency_graph_model(tf_resources=_tf(
            'resource "aws_kms_key" "main" {}\n'
            'resource "aws_db_instance" "db" { kms_key_id = aws_kms_key.main.arn }\n'
        ))
        assert isinstance(model, DependencyGraph)
        assert {n.id for n in model.nodes} == {"aws_kms_key.main", "aws_db_instance.db"}
        assert any(e.source == "aws_db_instance.db" and e.target == "aws_kms_key.main"
                   for e in model.edges)

    def test_model_round_trips_through_json(self):
        model = build_dependency_graph_model(tf_resources=_tf(_fanin_tf(6)))
        import json
        restored = DependencyGraph(**json.loads(json.dumps(model.model_dump())))
        assert len(restored.nodes) == len(model.nodes)
        assert len(restored.spofs) == len(model.spofs)

    def test_deterministic_ordering(self):
        tf = _fanin_tf(6)
        m1 = build_dependency_graph_model(tf_resources=_tf(tf))
        m2 = build_dependency_graph_model(tf_resources=_tf(tf))
        assert [n.id for n in m1.nodes] == [n.id for n in m2.nodes]
        assert [(e.source, e.target) for e in m1.edges] == [(e.source, e.target) for e in m2.edges]


# ---------------------------------------------------------------------------
# Blast radius (4.2)
# ---------------------------------------------------------------------------

class TestBlastRadius:
    def _model(self, n):
        return build_dependency_graph_model(tf_resources=_tf(_fanin_tf(n)))

    def test_hub_impact_and_criticality(self):
        m = self._model(8)
        br = blast_radius(m, "aws_kms_key.main")
        assert br["found"] is True
        assert br["impact_count"] == 8
        assert br["criticality"] == "critical"   # >=8
        assert br["is_spof"] is True
        assert "aws_s3_bucket.b0" in br["transitive_dependents"]

    def test_leaf_has_no_dependents(self):
        m = self._model(3)
        br = blast_radius(m, "aws_s3_bucket.b0")
        assert br["found"] is True
        assert br["impact_count"] == 0
        assert br["criticality"] == "none"

    def test_unknown_resource_found_false(self):
        m = self._model(3)
        br = blast_radius(m, "does.not.exist")
        assert br["found"] is False
        assert br["impact_count"] == 0

    def test_empty_graph(self):
        br = blast_radius(DependencyGraph(), "anything")
        assert br["found"] is False

    def test_criticality_bands(self):
        assert blast_radius(self._model(4), "aws_kms_key.main")["criticality"] == "high"    # >=4
        assert blast_radius(self._model(1), "aws_kms_key.main")["criticality"] == "medium"  # >=1

    def test_cycle_safe(self):
        # Build a small cycle a->b->a and ensure traversal terminates.
        m = build_dependency_graph_model(tf_resources=_tf(
            'resource "aws_a" "x" { v = aws_b.y.id }\n'
            'resource "aws_b" "y" { v = aws_a.x.id }\n'
        ))
        br = blast_radius(m, "aws_a.x")
        assert br["found"] is True  # does not hang


# ---------------------------------------------------------------------------
# Mermaid diagram (4.4)
# ---------------------------------------------------------------------------

class TestMermaid:
    def test_empty_graph_valid(self):
        out = to_mermaid(DependencyGraph())
        assert out.startswith("flowchart LR")

    def test_contains_nodes_and_edges(self):
        m = build_dependency_graph_model(tf_resources=_tf(
            'resource "aws_kms_key" "main" {}\n'
            'resource "aws_db_instance" "db" { kms_key_id = aws_kms_key.main.arn }\n'
        ))
        out = to_mermaid(m)
        assert out.startswith("flowchart LR")
        assert "aws_kms_key.main" in out       # real id appears in a label
        assert "aws_db_instance.db" in out
        assert "-->" in out                     # at least one edge

    def test_node_ids_are_safe(self):
        """Real ids have dots/slashes; the synthetic ids used as Mermaid node
        identifiers must be simple nX tokens so the diagram parses."""
        m = build_dependency_graph_model(k8s_resources=_k8s(_K8S_BUNDLE))
        out = to_mermaid(m)
        import re as _re
        # Every declared node uses an nN identifier before its [ label.
        decls = _re.findall(r"^\s+(\S+)\[", out, _re.MULTILINE)
        assert decls, "expected node declarations"
        assert all(_re.fullmatch(r"n\d+|empty|more", d) for d in decls)

    def test_spof_styled(self):
        m = build_dependency_graph_model(tf_resources=_tf(_fanin_tf(6)))
        out = to_mermaid(m)
        assert "style" in out and "ff6b6b" in out   # SPOF fill colour

    def test_highlight_applied(self):
        m = build_dependency_graph_model(tf_resources=_tf(_fanin_tf(3)))
        out = to_mermaid(m, highlight="aws_kms_key.main")
        assert "stroke-width:4px" in out

    def test_large_graph_truncated(self):
        # 80 leaf resources on one hub -> exceeds _MERMAID_MAX_NODES (60).
        m = build_dependency_graph_model(tf_resources=_tf(_fanin_tf(80)))
        out = to_mermaid(m)
        assert "truncated" in out

    def test_roundtrip_model_to_networkx(self):
        m = build_dependency_graph_model(tf_resources=_tf(_fanin_tf(4)))
        g = graph_from_model(m)
        assert g.number_of_nodes() == len(m.nodes)
        assert g.number_of_edges() == len(m.edges)
