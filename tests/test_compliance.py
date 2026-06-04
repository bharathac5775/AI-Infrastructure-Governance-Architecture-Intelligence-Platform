"""Tests for compliance framework mapping (Phase 3.3, cloud-aware).

Reference: app/core/compliance.py, app/core/pdf_export.py, app/data/compliance_mappings.json
"""
from __future__ import annotations

from app.core.compliance import (
    _classify_control,
    _detect_clouds,
    _entry_controls,
    _entry_domain,
    compute_compliance_scorecard,
    enrich_findings_with_compliance,
    get_controls_for_finding,
    load_mappings,
)
from app.core.pdf_export import generate_pdf_report
from app.models import (
    AgentReport,
    AnalysisReport,
    ArchitectureReview,
    ComplianceFrameworkScore,
    ComplianceScorecard,
    Finding,
)

from tests.fixtures.findings import make_finding


# ---------------------------------------------------------------------------
# Helper: build a full AnalysisReport in memory
# ---------------------------------------------------------------------------


def _full_report(
    findings_by_agent: dict[str, list[Finding]] | None = None,
    overall: float = 80.0,
    arch_score: float | None = None,
    report_id: str = "test-id",
    files_analyzed: list[str] | None = None,
) -> AnalysisReport:
    findings_by_agent = findings_by_agent or {}
    agent_reports = [
        AgentReport(agent_name=name, findings=fs, summary="ok", score=80.0)
        for name, fs in findings_by_agent.items()
    ]
    arch = (
        ArchitectureReview(architecture_score=arch_score, summary="ok")
        if arch_score is not None
        else None
    )
    return AnalysisReport(
        report_id=report_id,
        files_analyzed=files_analyzed if files_analyzed is not None else ["main.tf"],
        agent_reports=agent_reports,
        architecture_review=arch,
        overall_score=overall,
        executive_summary="",
        risk_summary="",
    )


# ---------------------------------------------------------------------------
# Mappings JSON sanity checks (updated for new schema)
# ---------------------------------------------------------------------------


class TestComplianceMappings:
    def test_mappings_load_successfully(self):
        m = load_mappings()
        assert "frameworks" in m
        assert "rule_mappings" in m
        assert "title_overrides" in m
        assert "framework_prefix_map" in m
        assert "control_descriptions" in m

    def test_five_frameworks_defined(self):
        m = load_mappings()
        assert "cis_kubernetes" in m["frameworks"]
        assert "cis_aws" in m["frameworks"]
        assert "cis_azure" in m["frameworks"]
        assert "cis_gcp" in m["frameworks"]
        assert "nist_800_53" in m["frameworks"]

    def test_every_mapped_control_has_a_description(self):
        """Every control ID referenced in rule_mappings must have a description."""
        m = load_mappings()
        descriptions = m["control_descriptions"]
        for agent, cat_map in m["rule_mappings"].items():
            for category, entry in cat_map.items():
                for c in _entry_controls(entry):
                    assert c in descriptions, (
                        f"{agent}.{category} maps to '{c}' but no description exists"
                    )

    def test_every_title_override_control_has_a_description(self):
        m = load_mappings()
        descriptions = m["control_descriptions"]
        for title, entry in m["title_overrides"].items():
            for c in _entry_controls(entry):
                assert c in descriptions, (
                    f"title_override '{title}' maps to '{c}' but no description exists"
                )

    def test_every_mapped_control_resolves_to_a_framework(self):
        """Every control prefix used in mappings must be in framework_prefix_map."""
        m = load_mappings()
        for cat_map in m["rule_mappings"].values():
            for entry in cat_map.values():
                for c in _entry_controls(entry):
                    assert _classify_control(c, m) is not None, (
                        f"Control '{c}' has no framework prefix match"
                    )

    def test_every_rule_mapping_has_a_domain(self):
        """Every (agent, category) entry must have a 'domain' field."""
        m = load_mappings()
        valid_domains = {"kubernetes", "aws", "azure", "gcp", "cross-cloud"}
        for agent, cat_map in m["rule_mappings"].items():
            for category, entry in cat_map.items():
                domain = _entry_domain(entry)
                assert domain in valid_domains, (
                    f"{agent}.{category} has invalid domain '{domain}'"
                )

    def test_every_title_override_has_a_domain(self):
        m = load_mappings()
        valid_domains = {"kubernetes", "aws", "azure", "gcp", "cross-cloud"}
        for title, entry in m["title_overrides"].items():
            domain = _entry_domain(entry)
            assert domain in valid_domains, (
                f"title_override '{title}' has invalid domain '{domain}'"
            )

    def test_frameworks_have_requires_any_of(self):
        """Phase 3.3 fix: each framework must declare which clouds make it relevant."""
        m = load_mappings()
        for fw_id, fw_meta in m["frameworks"].items():
            assert "requires_any_of" in fw_meta, (
                f"Framework '{fw_id}' missing 'requires_any_of'"
            )
            assert isinstance(fw_meta["requires_any_of"], list)
            assert fw_meta["requires_any_of"], f"Framework '{fw_id}' has empty requires_any_of"


# ---------------------------------------------------------------------------
# Cloud attribution per finding (still relevant under new schema)
# ---------------------------------------------------------------------------


class TestCloudAttributionCorrectness:
    @staticmethod
    def _ctrls(title, category, agent="Security Agent"):
        f = make_finding(agent=agent, category=category, title=title, resource="r1")
        return get_controls_for_finding(f)

    def test_azure_nsg_finding_does_not_get_cis_aws_or_cis_k8s(self):
        ctrls = self._ctrls("Azure NSG rule open to internet", "network")
        assert not any(c.startswith("CIS-AWS") for c in ctrls)
        assert not any(c.startswith("CIS-K8s") for c in ctrls)

    def test_gcp_firewall_finding_does_not_get_cis_aws_or_cis_k8s(self):
        ctrls = self._ctrls("GCP firewall open to 0.0.0.0/0", "network")
        assert not any(c.startswith("CIS-AWS") for c in ctrls)
        assert not any(c.startswith("CIS-K8s") for c in ctrls)

    def test_aws_security_group_finding_keeps_cis_aws(self):
        ctrls = self._ctrls("Security group open to 0.0.0.0/0", "network")
        assert "CIS-AWS-5.2" in ctrls

    def test_kubernetes_privileged_container_keeps_cis_k8s(self):
        ctrls = self._ctrls("Privileged container", "privileged")
        assert "CIS-K8s-5.2.1" in ctrls

    def test_default_network_category_has_no_cloud_specific_controls(self):
        """A bare K8s NetworkPolicy finding (no title override) only gets NIST."""
        ctrls = self._ctrls("NetworkPolicy missing", "network")
        assert not any(c.startswith("CIS-AWS") for c in ctrls)


# ---------------------------------------------------------------------------
# get_controls_for_finding + enrich_findings_with_compliance
# ---------------------------------------------------------------------------


class TestEnrichFindings:
    def test_enrich_by_category(self):
        f = make_finding(agent="Security Agent", category="privileged",
                         title="Privileged container", resource="r1")
        ctrls = get_controls_for_finding(f)
        assert "CIS-K8s-5.2.1" in ctrls
        assert "NIST-AC-3" in ctrls

    def test_title_override_takes_precedence(self):
        f = make_finding(agent="Security Agent", category="public-exposure",
                         title="Public S3 bucket", resource="r1")
        ctrls = get_controls_for_finding(f)
        assert "CIS-AWS-2.1.5" in ctrls

    def test_unknown_category_yields_empty_controls(self):
        f = make_finding(agent="Security Agent", category="bogus-category",
                         title="Unknown", resource="r1")
        assert get_controls_for_finding(f) == []

    def test_unknown_agent_yields_empty_controls(self):
        f = make_finding(agent="Mystery Agent", category="iam",
                         title="X", resource="r1")
        assert get_controls_for_finding(f) == []

    def test_enrich_mutates_report_in_place(self):
        f = make_finding(agent="Security Agent", category="privileged",
                         title="Privileged container", resource="r1")
        report = _full_report({"Security Agent": [f]})
        enrich_findings_with_compliance(report)
        assert report.agent_reports[0].findings[0].compliance_controls
        assert "CIS-K8s-5.2.1" in report.agent_reports[0].findings[0].compliance_controls


# ---------------------------------------------------------------------------
# _detect_clouds — cloud detection from report data
# ---------------------------------------------------------------------------


class TestDetectClouds:
    def test_aws_resource_detected(self):
        f = make_finding(resource="aws_s3_bucket.data")
        report = _full_report({"Security Agent": [f]})
        assert _detect_clouds(report)["aws"] is True
        assert _detect_clouds(report)["azure"] is False

    def test_azure_resource_detected(self):
        f = make_finding(resource="azurerm_storage_account.data")
        report = _full_report({"Security Agent": [f]})
        clouds = _detect_clouds(report)
        assert clouds["azure"] is True
        assert clouds["aws"] is False
        assert clouds["gcp"] is False

    def test_gcp_resource_detected(self):
        f = make_finding(resource="google_compute_firewall.allow_ssh")
        report = _full_report({"Security Agent": [f]})
        clouds = _detect_clouds(report)
        assert clouds["gcp"] is True
        assert clouds["aws"] is False
        assert clouds["azure"] is False

    def test_kubernetes_resource_detected(self):
        f = make_finding(resource="Deployment/production/api")
        report = _full_report({"Security Agent": [f]})
        assert _detect_clouds(report)["kubernetes"] is True

    def test_yaml_extension_fallback_for_kubernetes(self):
        """Clean K8s upload (no findings) still detects kubernetes via extension."""
        report = _full_report({"Security Agent": []}, files_analyzed=["good-deployment.yaml"])
        assert _detect_clouds(report)["kubernetes"] is True

    def test_tf_extension_does_NOT_imply_any_cloud(self):
        """Phase 3.3 fix: a clean .tf file (no findings) must not falsely
        imply AWS/Azure/GCP. If we can't detect cloud from content, all
        detected booleans stay False."""
        report = _full_report({"Security Agent": []}, files_analyzed=["empty.tf"])
        clouds = _detect_clouds(report)
        assert clouds["aws"] is False
        assert clouds["azure"] is False
        assert clouds["gcp"] is False

    def test_mixed_clouds_detected(self):
        f1 = make_finding(resource="aws_s3_bucket.x")
        f2 = make_finding(resource="azurerm_storage_account.y")
        report = _full_report({"Security Agent": [f1, f2]})
        clouds = _detect_clouds(report)
        assert clouds["aws"] is True
        assert clouds["azure"] is True

    def test_na_resource_does_not_falsely_classify_as_kubernetes(self):
        """Phase 3.3 regression: LLM-emitted findings sometimes use
        ``resource="N/A"`` for non-resource-bound advisories. The previous
        heuristic accepted any ``X/...`` string starting with a capital
        letter as Kubernetes — which leaked CIS Kubernetes framework into
        AWS-only scorecards. This test pins the fix.
        """
        f_aws = make_finding(resource="aws_s3_bucket.data")
        f_na = make_finding(resource="N/A", category="ai-analysis")
        report = _full_report({"Security Agent": [f_aws, f_na]})
        clouds = _detect_clouds(report)
        assert clouds["aws"] is True
        assert clouds["kubernetes"] is False, (
            "N/A must not be classified as a Kubernetes resource"
        )

    def test_aws_shorthand_does_not_falsely_classify_as_kubernetes(self):
        """All-uppercase abbreviations like RDS, KMS, IAM, EC2, S3 are AWS
        shorthand the LLM sometimes emits — must not be treated as K8s Kinds.
        """
        for shorthand in ("S3/bucket/data", "RDS/main", "KMS/key/x",
                          "EC2/i-abc/foo", "IAM/role/admin"):
            f = make_finding(resource=shorthand, category="ai-analysis")
            report = _full_report({"Security Agent": [f]})
            assert _detect_clouds(report)["kubernetes"] is False, (
                f"{shorthand!r} must not be classified as Kubernetes"
            )

    def test_capitalcase_stopwords_do_not_falsely_classify_as_kubernetes(self):
        """Generic CapitalCase words like Infrastructure, Database, Storage
        are not K8s Kinds — must not flip the kubernetes detection."""
        for word in ("Infrastructure/global/all", "Database/main",
                     "Storage/bucket/x", "Network/vpc/foo"):
            f = make_finding(resource=word, category="ai-analysis")
            report = _full_report({"Security Agent": [f]})
            assert _detect_clouds(report)["kubernetes"] is False, (
                f"{word!r} must not be classified as Kubernetes"
            )

    def test_aws_only_upload_with_llm_na_finding_excludes_cis_kubernetes(self):
        """End-to-end pin: a real-world AWS-only upload that includes an
        LLM advisory with ``resource='N/A'`` must NOT show the CIS
        Kubernetes framework in the scorecard.
        """
        f_aws = make_finding(
            agent="Security Agent", category="encryption",
            title="S3 bucket without encryption", resource="aws_s3_bucket.data",
            compliance_controls=["CIS-AWS-2.1.1", "NIST-SC-28"],
        )
        f_advisory = make_finding(
            agent="Cost Agent", category="ai-analysis",
            title="Missing Commitment Discounts", resource="N/A",
        )
        report = _full_report({
            "Security Agent": [f_aws],
            "Cost Agent": [f_advisory],
        })
        sc = compute_compliance_scorecard(report)
        framework_ids = [fw.framework_id for fw in sc.frameworks]
        assert "cis_aws" in framework_ids
        assert "cis_kubernetes" not in framework_ids, (
            f"CIS Kubernetes leaked into AWS-only upload via N/A finding. "
            f"Got: {framework_ids}"
        )


# ---------------------------------------------------------------------------
# compute_compliance_scorecard — cloud-aware behavior (the bug fix)
# ---------------------------------------------------------------------------


class TestCloudAwareScorecard:
    def test_azure_only_upload_excludes_cis_aws_framework(self):
        """The bug regression test: an Azure-only upload must NOT show
        CIS AWS Foundations Benchmark in the compliance scorecard."""
        f = make_finding(
            agent="Security Agent", category="network",
            title="Azure NSG rule open to internet",
            resource="azurerm_network_security_rule.allow_ssh",
            compliance_controls=["CIS-Azure-6.2", "CIS-Azure-6.3", "NIST-SC-7"],
        )
        report = _full_report({"Security Agent": [f]})
        sc = compute_compliance_scorecard(report)
        framework_ids = [fw.framework_id for fw in sc.frameworks]
        assert "cis_aws" not in framework_ids, (
            f"CIS AWS must NOT appear on Azure-only upload, got: {framework_ids}"
        )
        assert "cis_kubernetes" not in framework_ids
        assert "cis_gcp" not in framework_ids
        assert "cis_azure" in framework_ids
        assert "nist_800_53" in framework_ids

    def test_aws_only_upload_excludes_cis_kubernetes_framework(self):
        f = make_finding(
            agent="Security Agent", category="public-exposure",
            title="Public S3 bucket", resource="aws_s3_bucket.data",
            compliance_controls=["CIS-AWS-2.1.5", "NIST-AC-3", "NIST-SC-7"],
        )
        report = _full_report({"Security Agent": [f]})
        sc = compute_compliance_scorecard(report)
        framework_ids = [fw.framework_id for fw in sc.frameworks]
        assert "cis_aws" in framework_ids
        assert "nist_800_53" in framework_ids
        assert "cis_kubernetes" not in framework_ids
        assert "cis_azure" not in framework_ids
        assert "cis_gcp" not in framework_ids

    def test_gcp_only_upload_excludes_aws_and_k8s_cis_frameworks(self):
        """GCP-only upload must NOT show CIS AWS or CIS K8s. (CIS GCP IS shown
        — see test_gcp_only_upload_includes_cis_gcp.)"""
        f = make_finding(
            agent="Security Agent", category="network",
            title="GCP firewall open to 0.0.0.0/0",
            resource="google_compute_firewall.allow_ssh",
            compliance_controls=["CIS-GCP-3.6", "CIS-GCP-3.7", "NIST-SC-7"],
        )
        report = _full_report({"Security Agent": [f]})
        sc = compute_compliance_scorecard(report)
        framework_ids = [fw.framework_id for fw in sc.frameworks]
        assert "cis_aws" not in framework_ids
        assert "cis_kubernetes" not in framework_ids
        assert "cis_azure" not in framework_ids
        assert "cis_gcp" in framework_ids
        assert "nist_800_53" in framework_ids

    def test_kubernetes_only_upload_excludes_cis_aws(self):
        f = make_finding(
            agent="Security Agent", category="privileged",
            title="Privileged container", resource="Deployment/production/app",
            compliance_controls=["CIS-K8s-5.2.1", "NIST-AC-3", "NIST-AC-6"],
        )
        report = _full_report({"Security Agent": [f]})
        sc = compute_compliance_scorecard(report)
        framework_ids = [fw.framework_id for fw in sc.frameworks]
        assert "cis_kubernetes" in framework_ids
        assert "nist_800_53" in framework_ids
        assert "cis_aws" not in framework_ids
        assert "cis_azure" not in framework_ids
        assert "cis_gcp" not in framework_ids

    # ---- New regression tests for CIS Azure / CIS GCP inclusion ----

    def test_azure_only_upload_includes_cis_azure(self):
        """Azure-only upload MUST show CIS Azure Foundations Benchmark."""
        f = make_finding(
            agent="Security Agent", category="network",
            title="Azure NSG rule open to internet",
            resource="azurerm_network_security_rule.allow_ssh",
            compliance_controls=["CIS-Azure-6.2", "CIS-Azure-6.3", "NIST-SC-7"],
        )
        report = _full_report({"Security Agent": [f]})
        sc = compute_compliance_scorecard(report)
        framework_ids = {fw.framework_id for fw in sc.frameworks}
        assert "cis_azure" in framework_ids

    def test_gcp_only_upload_includes_cis_gcp(self):
        """GCP-only upload MUST show CIS GCP Foundations Benchmark."""
        f = make_finding(
            agent="Security Agent", category="public-exposure",
            title="GCS bucket without uniform access",
            resource="google_storage_bucket.data",
            compliance_controls=["CIS-GCP-5.2", "NIST-AC-3"],
        )
        report = _full_report({"Security Agent": [f]})
        sc = compute_compliance_scorecard(report)
        framework_ids = {fw.framework_id for fw in sc.frameworks}
        assert "cis_gcp" in framework_ids

    def test_azure_finding_gets_cis_azure_control(self):
        """Phase 3.3 extension: Azure NSG-open finding must carry CIS-Azure-6.2."""
        f = make_finding(
            agent="Security Agent", category="network",
            title="Azure NSG rule open to internet", resource="azurerm_network_security_rule.x",
        )
        from app.core.compliance import get_controls_for_finding
        ctrls = get_controls_for_finding(f)
        assert "CIS-Azure-6.2" in ctrls
        # And NEVER cross-cloud:
        assert not any(c.startswith("CIS-AWS-") for c in ctrls)
        assert not any(c.startswith("CIS-K8s-") for c in ctrls)
        assert not any(c.startswith("CIS-GCP-") for c in ctrls)

    def test_gcp_finding_gets_cis_gcp_control(self):
        """Phase 3.3 extension: GCS uniform-access finding must carry CIS-GCP-5.2."""
        f = make_finding(
            agent="Security Agent", category="public-exposure",
            title="GCS bucket without uniform access", resource="google_storage_bucket.x",
        )
        from app.core.compliance import get_controls_for_finding
        ctrls = get_controls_for_finding(f)
        assert "CIS-GCP-5.2" in ctrls
        assert not any(c.startswith("CIS-AWS-") for c in ctrls)
        assert not any(c.startswith("CIS-K8s-") for c in ctrls)
        assert not any(c.startswith("CIS-Azure-") for c in ctrls)

    def test_aws_finding_does_not_inherit_cis_azure_or_cis_gcp(self):
        """Locking in: AWS findings must NEVER carry CIS-Azure or CIS-GCP."""
        f = make_finding(
            agent="Security Agent", category="public-exposure",
            title="Public S3 bucket", resource="aws_s3_bucket.x",
        )
        from app.core.compliance import get_controls_for_finding
        ctrls = get_controls_for_finding(f)
        assert not any(c.startswith("CIS-Azure-") for c in ctrls)
        assert not any(c.startswith("CIS-GCP-") for c in ctrls)

    def test_k8s_finding_does_not_inherit_cis_azure_or_cis_gcp(self):
        """Locking in: K8s findings must NEVER carry CIS-Azure or CIS-GCP."""
        f = make_finding(
            agent="Security Agent", category="privileged",
            title="Privileged container", resource="Deployment/prod/api",
        )
        from app.core.compliance import get_controls_for_finding
        ctrls = get_controls_for_finding(f)
        assert not any(c.startswith("CIS-Azure-") for c in ctrls)
        assert not any(c.startswith("CIS-GCP-") for c in ctrls)

    def test_mixed_azure_gcp_upload_includes_both_cis_frameworks(self):
        """Bundle with both Azure and GCP findings: both CIS-Azure and CIS-GCP appear."""
        f_az = make_finding(
            agent="Security Agent", category="network",
            title="Azure NSG rule open to internet",
            resource="azurerm_network_security_rule.x",
            compliance_controls=["CIS-Azure-6.2", "CIS-Azure-6.3", "NIST-SC-7"],
        )
        f_gcp = make_finding(
            agent="Security Agent", category="network",
            title="GCP firewall open to 0.0.0.0/0",
            resource="google_compute_firewall.x",
            compliance_controls=["CIS-GCP-3.6", "CIS-GCP-3.7", "NIST-SC-7"],
        )
        report = _full_report({"Security Agent": [f_az, f_gcp]})
        sc = compute_compliance_scorecard(report)
        framework_ids = {fw.framework_id for fw in sc.frameworks}
        assert {"cis_azure", "cis_gcp", "nist_800_53"}.issubset(framework_ids)
        assert "cis_aws" not in framework_ids
        assert "cis_kubernetes" not in framework_ids

    def test_mixed_k8s_aws_upload_includes_both_cis_frameworks(self):
        f_k8s = make_finding(
            agent="Security Agent", category="privileged",
            title="Privileged container", resource="Deployment/x/y",
            compliance_controls=["CIS-K8s-5.2.1", "NIST-AC-3", "NIST-AC-6"],
        )
        f_aws = make_finding(
            agent="Security Agent", category="public-exposure",
            title="Public S3 bucket", resource="aws_s3_bucket.data",
            compliance_controls=["CIS-AWS-2.1.5", "NIST-AC-3", "NIST-SC-7"],
        )
        report = _full_report({"Security Agent": [f_k8s, f_aws]})
        sc = compute_compliance_scorecard(report)
        framework_ids = {fw.framework_id for fw in sc.frameworks}
        assert framework_ids == {"cis_kubernetes", "cis_aws", "nist_800_53"}

    def test_unassessable_controls_not_inflated_into_passed(self):
        """The deeper bug: even when CIS AWS framework gets included, controls
        that have no AWS-domain rule mapping to them in this upload must NOT
        show up as "passed" in CIS AWS."""
        # Force CIS AWS to be relevant by including an AWS finding (NSG-style)
        f = make_finding(
            agent="Security Agent", category="network",
            title="Security group open to 0.0.0.0/0",
            resource="aws_security_group.web",
            compliance_controls=["CIS-AWS-5.2", "CIS-AWS-5.3", "NIST-SC-7"],
        )
        report = _full_report({"Security Agent": [f]})
        sc = compute_compliance_scorecard(report)
        cis_aws = next(fw for fw in sc.frameworks if fw.framework_id == "cis_aws")
        # Failed controls must be the actual ones we tagged
        assert "CIS-AWS-5.2" in cis_aws.controls_failed
        assert "CIS-AWS-5.3" in cis_aws.controls_failed
        # Score should NOT be 100% (we have failing controls)
        assert cis_aws.score_pct < 100.0
        # No control appears in both lists at once
        assert not (set(cis_aws.controls_passed) & set(cis_aws.controls_failed))

    def test_clean_aws_report_yields_genuine_100_pct(self):
        """Distinct from the bug case: AWS rules ran AND found nothing →
        legitimate 100%. The cloud was detected via files_analyzed AWS-flavored
        evidence, but we need at least one finding to imply a cloud.
        Fallback: extension-based AWS detection isn't supported (intentional),
        so we synthesize an info-severity finding to simulate "AWS rules ran"."""
        # Use a finding with empty compliance_controls — counts as "ran, no failures"
        f = make_finding(resource="aws_s3_bucket.data", compliance_controls=[])
        report = _full_report({"Security Agent": [f]})
        sc = compute_compliance_scorecard(report)
        framework_ids = {fw.framework_id for fw in sc.frameworks}
        assert "cis_aws" in framework_ids  # AWS detected
        cis_aws = next(fw for fw in sc.frameworks if fw.framework_id == "cis_aws")
        assert cis_aws.score_pct == 100.0  # nothing failed

    def test_no_clouds_detected_yields_no_frameworks(self):
        """Edge case: an empty report with no findings and no recognizable
        files. No clouds detected → no frameworks emitted."""
        report = _full_report({}, files_analyzed=[])
        sc = compute_compliance_scorecard(report)
        assert sc.frameworks == []


# ---------------------------------------------------------------------------
# Existing scorecard semantics still hold under cloud-aware mode
# ---------------------------------------------------------------------------


class TestComputeScorecardSemantics:
    def test_clean_k8s_report_yields_100_pct_for_applicable_frameworks(self):
        """K8s upload, no findings → all assessable controls pass → 100%."""
        report = _full_report({"Security Agent": []}, files_analyzed=["good.yaml"])
        sc = compute_compliance_scorecard(report)
        assert sc.frameworks
        for fw in sc.frameworks:
            assert fw.score_pct == 100.0
            assert fw.controls_failed == []

    def test_failed_finding_drops_score(self):
        f = make_finding(
            agent="Security Agent", category="privileged",
            title="Privileged container",
            resource="Deployment/production/app",
            compliance_controls=["CIS-K8s-5.2.1", "NIST-AC-3", "NIST-AC-6"],
        )
        report = _full_report({"Security Agent": [f]})
        sc = compute_compliance_scorecard(report)
        cis_k8s = next(fw for fw in sc.frameworks if fw.framework_id == "cis_kubernetes")
        assert "CIS-K8s-5.2.1" in cis_k8s.controls_failed
        assert cis_k8s.score_pct < 100.0

    def test_score_formula_passed_over_total(self):
        f = make_finding(
            agent="Security Agent", category="privileged",
            title="Privileged container",
            resource="Deployment/x/y",
            compliance_controls=["CIS-K8s-5.2.1"],
        )
        report = _full_report({"Security Agent": [f]})
        sc = compute_compliance_scorecard(report)
        cis = next(fw for fw in sc.frameworks if fw.framework_id == "cis_kubernetes")
        total = len(cis.controls_passed) + len(cis.controls_failed)
        expected = round(len(cis.controls_passed) / total * 100, 1)
        assert cis.score_pct == expected

    def test_unmapped_finding_does_not_affect_score(self):
        """A finding with empty compliance_controls is neutral."""
        f = make_finding(resource="Deployment/x/y", compliance_controls=[])
        report = _full_report({"Security Agent": [f]})
        sc = compute_compliance_scorecard(report)
        for fw in sc.frameworks:
            assert fw.score_pct == 100.0


# ---------------------------------------------------------------------------
# PDF export (unaffected by this fix; the data shape didn't change)
# ---------------------------------------------------------------------------


class TestPDFExport:
    def test_pdf_returns_non_empty_bytes(self):
        report = _full_report({"Security Agent": []})
        pdf_bytes = generate_pdf_report(report)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0

    def test_pdf_starts_with_pdf_magic_bytes(self):
        report = _full_report({"Security Agent": []})
        pdf_bytes = generate_pdf_report(report)
        assert pdf_bytes.startswith(b"%PDF-")

    def test_pdf_contains_report_id_in_string_content(self):
        rid = "abc12345"
        report = _full_report({"Security Agent": []}, report_id=rid)
        pdf_bytes = generate_pdf_report(report)
        assert rid.encode() in pdf_bytes

    def test_pdf_handles_compliance_scorecard(self):
        fw = ComplianceFrameworkScore(
            framework_id="cis_aws",
            framework_name="CIS AWS Foundations Benchmark",
            version="3.0",
            score_pct=85.0,
            controls_passed=["CIS-AWS-2.1.1"],
            controls_failed=["CIS-AWS-1.16"],
        )
        report = _full_report({"Security Agent": []})
        report.compliance = ComplianceScorecard(frameworks=[fw])
        pdf_bytes = generate_pdf_report(report)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 1000

    def test_pdf_handles_empty_report(self):
        report = _full_report({})
        pdf_bytes = generate_pdf_report(report)
        assert pdf_bytes.startswith(b"%PDF-")

    def test_pdf_handles_findings_with_compliance_controls(self):
        f = make_finding(agent="Security Agent", category="iam",
                         title="Wildcard policy", resource="aws_iam_policy.x",
                         compliance_controls=["NIST-AC-6", "CIS-AWS-1.16"])
        report = _full_report({"Security Agent": [f]})
        pdf_bytes = generate_pdf_report(report)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 1000
