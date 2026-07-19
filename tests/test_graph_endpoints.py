"""Tests for the Phase 4.2 blast-radius and 4.4 diagram API endpoints.

Served from the dependency graph persisted on the report — no re-parse of the
original files (which are not persisted).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.graph import build_dependency_graph_model
from app.core.store import delete_report, save_report
from app.main import app
from app.models import AnalysisReport
from app.parsers.terraform import extract_tf_resources, parse_terraform

client = TestClient(app)


def _fanin_tf(n: int) -> str:
    lines = ['resource "aws_kms_key" "main" {}']
    for i in range(n):
        lines.append(f'resource "aws_s3_bucket" "b{i}" {{ tags = {{ k = aws_kms_key.main.id }} }}')
    return "\n".join(lines) + "\n"


@pytest.fixture
def report_with_graph():
    tf = _fanin_tf(6)
    model = build_dependency_graph_model(
        tf_resources=extract_tf_resources(parse_terraform(tf))
    )
    report = AnalysisReport(
        files_analyzed=["main.tf"],
        overall_score=80.0,
        executive_summary="",
        risk_summary="",
        dependency_graph=model,
    )
    save_report(report)
    yield report
    delete_report(report.report_id)


@pytest.fixture
def report_without_graph():
    report = AnalysisReport(
        files_analyzed=["notes.txt"],
        overall_score=0.0,
        executive_summary="",
        risk_summary="",
        dependency_graph=None,
    )
    save_report(report)
    yield report
    delete_report(report.report_id)


class TestBlastRadiusEndpoint:
    def test_known_resource(self, report_with_graph):
        rid = report_with_graph.report_id
        r = client.get(f"/api/v1/reports/{rid}/blast-radius", params={"resource": "aws_kms_key.main"})
        assert r.status_code == 200
        data = r.json()
        assert data["found"] is True
        assert data["impact_count"] == 6
        assert data["is_spof"] is True

    def test_unknown_resource_404(self, report_with_graph):
        rid = report_with_graph.report_id
        r = client.get(f"/api/v1/reports/{rid}/blast-radius", params={"resource": "nope.nope"})
        assert r.status_code == 404

    def test_report_not_found_404(self):
        r = client.get("/api/v1/reports/deadbeef/blast-radius", params={"resource": "x.y"})
        assert r.status_code == 404

    def test_report_without_graph_404(self, report_without_graph):
        rid = report_without_graph.report_id
        r = client.get(f"/api/v1/reports/{rid}/blast-radius", params={"resource": "x.y"})
        assert r.status_code == 404
        assert "no dependency graph" in r.json()["detail"].lower()

    def test_missing_resource_param_422(self, report_with_graph):
        rid = report_with_graph.report_id
        r = client.get(f"/api/v1/reports/{rid}/blast-radius")
        assert r.status_code == 422  # FastAPI validation: required query param


class TestDiagramEndpoint:
    def test_returns_mermaid(self, report_with_graph):
        rid = report_with_graph.report_id
        r = client.get(f"/api/v1/reports/{rid}/diagram")
        assert r.status_code == 200
        assert r.text.startswith("flowchart LR")
        assert "aws_kms_key.main" in r.text

    def test_highlight_param(self, report_with_graph):
        rid = report_with_graph.report_id
        r = client.get(f"/api/v1/reports/{rid}/diagram", params={"highlight": "aws_kms_key.main"})
        assert r.status_code == 200
        assert "stroke-width:4px" in r.text

    def test_unsupported_format_400(self, report_with_graph):
        rid = report_with_graph.report_id
        r = client.get(f"/api/v1/reports/{rid}/diagram", params={"format": "svg"})
        assert r.status_code == 400

    def test_report_not_found_404(self):
        r = client.get("/api/v1/reports/deadbeef/diagram")
        assert r.status_code == 404

    def test_report_without_graph_404(self, report_without_graph):
        rid = report_without_graph.report_id
        r = client.get(f"/api/v1/reports/{rid}/diagram")
        assert r.status_code == 404
