"""Tests for Phase 3.4 file_contents echo + cache plumbing.

When a user uploads files (including .tgz Helm charts), the live /analyze
response echoes file_contents so the frontend can cache the post-render
YAML. The same field is NEVER persisted to ChromaDB — reports loaded from
history have file_contents={}, prompting the frontend to ask the user to
re-upload before remediation.

This decouples the stateless-by-design persistence from the practical need
to remediate against the *actual* file the analysis ran on.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.core.store import delete_report, get_report, save_report
from app.main import app
from app.models import (
    AgentReport,
    AnalysisReport,
    Finding,
    Severity,
)


# ---------------------------------------------------------------------------
# save_report strips file_contents
# ---------------------------------------------------------------------------


class TestPersistenceExclusion:
    def test_save_report_drops_file_contents(self):
        """Even if a report carries file_contents in memory, it must NOT
        land in ChromaDB. This guards the stateless-files invariant."""
        report = AnalysisReport(
            files_analyzed=["main.tf"],
            agent_reports=[AgentReport(
                agent_name="Security Agent", findings=[], summary="x", score=80.0,
            )],
            overall_score=80.0,
            executive_summary="x",
            risk_summary="y",
            file_contents={"main.tf": 'resource "aws_s3_bucket" "x" { bucket = "y" }\n'},
        )
        save_report(report)
        try:
            loaded = get_report(report.report_id)
            assert loaded is not None
            assert loaded.file_contents == {}, (
                "file_contents must NOT be persisted in ChromaDB"
            )
        finally:
            delete_report(report.report_id)

    def test_get_report_returns_empty_file_contents_for_legacy_data(self):
        """A report saved before this feature existed (or any report
        cleanly persisted) deserializes with file_contents={}, not None
        and not missing the field."""
        report = AnalysisReport(
            files_analyzed=["main.tf"],
            agent_reports=[],
            overall_score=80.0,
            executive_summary="x",
            risk_summary="y",
        )
        save_report(report)
        try:
            loaded = get_report(report.report_id)
            assert loaded is not None
            assert loaded.file_contents == {}
        finally:
            delete_report(report.report_id)


# ---------------------------------------------------------------------------
# /analyze/text echoes file_contents in the response
# ---------------------------------------------------------------------------


class TestAnalyzeTextEcho:
    def test_analyze_text_returns_file_contents(self, mock_llm):
        client = TestClient(app)
        tf_src = (
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "company-data"\n'
            '}\n'
        )
        resp = client.post(
            "/api/v1/analyze/text",
            json={"file_contents": {"main.tf": tf_src}},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Echo present and matches input
        assert data.get("file_contents") == {"main.tf": tf_src}
        # And the report itself was saved
        rid = data["report_id"]
        try:
            saved = get_report(rid)
            assert saved is not None
            # Saved record has empty file_contents — not the echoed payload
            assert saved.file_contents == {}
        finally:
            delete_report(rid)

    def test_get_report_after_analyze_does_not_leak_file_contents(self, mock_llm):
        """End-to-end: live response has file_contents, but a subsequent
        GET on the same report_id returns it empty. This is the cache
        invalidation contract for history-loaded views."""
        client = TestClient(app)
        tf_src = 'resource "aws_kms_key" "main" { description = "main" }\n'
        live = client.post(
            "/api/v1/analyze/text",
            json={"file_contents": {"main.tf": tf_src}},
        ).json()
        rid = live["report_id"]
        try:
            assert live["file_contents"] != {}
            history = client.get(f"/api/v1/reports/{rid}").json()
            assert history["file_contents"] == {}
        finally:
            delete_report(rid)


# ---------------------------------------------------------------------------
# Remediation works against echoed file_contents (post-render YAML)
# ---------------------------------------------------------------------------


class TestRemediationUsesEchoedContents:
    def test_remediate_endpoint_works_with_echoed_yaml(self, mock_llm):
        """End-to-end: a YAML upload analyses, the response echoes the
        file_contents, and the remediator uses those exact contents to
        produce a patch. This is the path that was broken for .tgz before
        the fix — same code path now exercised."""
        client = TestClient(app)
        yaml_src = (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: api\n"
            "  namespace: default\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: app\n"
            "          image: app:1.0\n"
            "          securityContext:\n"
            "            privileged: true\n"
        )
        resp = client.post(
            "/api/v1/analyze/text",
            json={"file_contents": {"deploy.yaml": yaml_src}},
        ).json()
        rid = resp["report_id"]
        try:
            echoed = resp["file_contents"]
            assert "deploy.yaml" in echoed

            # Find the privileged-container finding
            findings = []
            for ar in resp["agent_reports"]:
                findings.extend(ar["findings"])
            priv_idx = next(
                (i for i, f in enumerate(findings)
                 if f["category"] == "privileged"),
                None,
            )
            assert priv_idx is not None, "expected a privileged finding"

            fix = client.post(
                f"/api/v1/reports/{rid}/remediate/{priv_idx}",
                json={"file_contents": echoed},
            )
            assert fix.status_code == 200, fix.text
            patch = fix.json()
            assert patch["strategy"] == "deterministic"
            assert "privileged: false" in patch["patched_content"]
        finally:
            delete_report(rid)


# ---------------------------------------------------------------------------
# Helm chart (.tgz) end-to-end — the original bug from the screenshot
# ---------------------------------------------------------------------------


class TestHelmChartCachePath:
    """The exact bug the user hit: uploading my-chart-1.0.0.tgz, then
    clicking Generate fix on a finding, used to fail with 'No cached file
    contents'. The fix: the analyze response now includes the rendered
    YAML in file_contents, which the frontend caches and uses for
    remediation."""

    def test_helm_chart_response_includes_rendered_yaml(self, mock_llm):
        """Skips automatically if `helm` CLI isn't installed — the chart
        renderer needs it. Otherwise: upload a .tgz, confirm the response
        contains the rendered .yaml in file_contents (not the raw .tgz)."""
        from pathlib import Path
        import shutil

        if not shutil.which("helm"):
            pytest.skip("helm CLI not installed — skipping Helm chart e2e")

        chart_path = Path(__file__).parent.parent / "samples" / "my-chart-1.0.0.tgz"
        if not chart_path.exists():
            pytest.skip(f"sample chart not found at {chart_path}")

        client = TestClient(app)
        with open(chart_path, "rb") as fh:
            raw = fh.read()
        resp = client.post(
            "/api/v1/analyze",
            files=[("files", ("my-chart-1.0.0.tgz", raw, "application/gzip"))],
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        rid = data["report_id"]
        try:
            files_analyzed = data["files_analyzed"]
            file_contents = data.get("file_contents", {})
            # Rendered filename has -rendered.yaml suffix
            rendered_files = [f for f in files_analyzed if f.endswith("-rendered.yaml")]
            assert rendered_files, (
                f"expected a -rendered.yaml entry in files_analyzed, got {files_analyzed}"
            )
            for rf in rendered_files:
                assert rf in file_contents, (
                    f"rendered file {rf} missing from echoed file_contents"
                )
                # Sanity: rendered YAML should contain K8s markers
                content = file_contents[rf]
                assert "apiVersion:" in content
                assert "kind:" in content
        finally:
            delete_report(rid)
