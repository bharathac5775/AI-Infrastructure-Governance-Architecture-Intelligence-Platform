# Graph Report - .  (2026-06-21)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 1403 nodes · 3451 edges · 92 communities (83 shown, 9 thin omitted)
- Extraction: 86% EXTRACTED · 14% INFERRED · 0% AMBIGUOUS · INFERRED: 482 edges (avg confidence: 0.56)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `05073323`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Cost Rules Engine|Cost Rules Engine]]
- [[_COMMUNITY_Auto-Remediation Pipeline|Auto-Remediation Pipeline]]
- [[_COMMUNITY_Multi-Provider LLM Factory|Multi-Provider LLM Factory]]
- [[_COMMUNITY_Drift Detection (Rule-Only)|Drift Detection (Rule-Only)]]
- [[_COMMUNITY_K8s YAML Strategy Fixers|K8s YAML Strategy Fixers]]
- [[_COMMUNITY_Reliability Rule Engine|Reliability Rule Engine]]
- [[_COMMUNITY_FastAPI Routes & Pipeline|FastAPI Routes & Pipeline]]
- [[_COMMUNITY_Drift Computation Helpers|Drift Computation Helpers]]
- [[_COMMUNITY_Report Persistence & PDF API|Report Persistence & PDF API]]
- [[_COMMUNITY_Terraform Patch & SG Rules|Terraform Patch & SG Rules]]
- [[_COMMUNITY_Cloud-Aware Compliance Scoring|Cloud-Aware Compliance Scoring]]
- [[_COMMUNITY_K8s Remediator Internals|K8s Remediator Internals]]
- [[_COMMUNITY_Compliance Framework Mappings|Compliance Framework Mappings]]
- [[_COMMUNITY_Security & Cost Agents|Security & Cost Agents]]
- [[_COMMUNITY_Test Conftest Fakes|Test Conftest Fakes]]
- [[_COMMUNITY_Architecture Gap Filters|Architecture Gap Filters]]
- [[_COMMUNITY_Terraform JSONHCL Fixers|Terraform JSON/HCL Fixers]]
- [[_COMMUNITY_Bundle Fingerprinting|Bundle Fingerprinting]]
- [[_COMMUNITY_Sample AWS Production HCL|Sample: AWS Production HCL]]
- [[_COMMUNITY_Rules-Only Regression Suite|Rules-Only Regression Suite]]
- [[_COMMUNITY_Cloud Detection Heuristics|Cloud Detection Heuristics]]
- [[_COMMUNITY_K8s Resource Parser|K8s Resource Parser]]
- [[_COMMUNITY_Compliance Test Fixtures|Compliance Test Fixtures]]
- [[_COMMUNITY_Development Phases Doc|Development Phases Doc]]
- [[_COMMUNITY_Terraform JSON Fixer Tests|Terraform JSON Fixer Tests]]
- [[_COMMUNITY_Terraform File Locator|Terraform File Locator]]
- [[_COMMUNITY_Cosmetic Drift Filter|Cosmetic Drift Filter]]
- [[_COMMUNITY_File-Contents Echo Plumbing|File-Contents Echo Plumbing]]
- [[_COMMUNITY_Remediation Errors & Bugs|Remediation Errors & Bugs]]
- [[_COMMUNITY_Structural Patch Validation|Structural Patch Validation]]
- [[_COMMUNITY_Architecture Reviewer Agent|Architecture Reviewer Agent]]
- [[_COMMUNITY_Cross-Cutting Gap Dedup|Cross-Cutting Gap Dedup]]
- [[_COMMUNITY_K8s Resource Locator (Layered)|K8s Resource Locator (Layered)]]
- [[_COMMUNITY_Agent Skill Conventions|Agent Skill Conventions]]
- [[_COMMUNITY_Score Weighting Math|Score Weighting Math]]
- [[_COMMUNITY_Keyword Extraction & Synonyms|Keyword Extraction & Synonyms]]
- [[_COMMUNITY_Sample Good Helm Chart|Sample: Good Helm Chart]]
- [[_COMMUNITY_Architecture Score Calculation|Architecture Score Calculation]]
- [[_COMMUNITY_LLM JSON Parsing Recovery|LLM JSON Parsing Recovery]]
- [[_COMMUNITY_Non-Patchable Findings|Non-Patchable Findings]]
- [[_COMMUNITY_PDF Export Module|PDF Export Module]]
- [[_COMMUNITY_Cloud-Specific CIS Mapping|Cloud-Specific CIS Mapping]]
- [[_COMMUNITY_Mocked LLM Response Builders|Mocked LLM Response Builders]]
- [[_COMMUNITY_Companion Resource Parsing|Companion Resource Parsing]]
- [[_COMMUNITY_Sample K8s Production Manifest|Sample: K8s Production Manifest]]
- [[_COMMUNITY_Terraform Secrets Gap Filter|Terraform Secrets Gap Filter]]
- [[_COMMUNITY_Advisory-Language Detection|Advisory-Language Detection]]
- [[_COMMUNITY_Cross-Cutting Gap Echo Filter|Cross-Cutting Gap Echo Filter]]
- [[_COMMUNITY_Advisory & File Locators|Advisory & File Locators]]
- [[_COMMUNITY_Patch Validation Rationale|Patch Validation Rationale]]
- [[_COMMUNITY_Terraform Block Span Surgery|Terraform Block Span Surgery]]
- [[_COMMUNITY_Full-Pipeline Integration Tests|Full-Pipeline Integration Tests]]
- [[_COMMUNITY_Cloud Attribution Correctness|Cloud Attribution Correctness]]
- [[_COMMUNITY_K8s JSON Round-Trip|K8s JSON Round-Trip]]
- [[_COMMUNITY_Praise-Finding Filter|Praise-Finding Filter]]
- [[_COMMUNITY_Helm Template Path Detection|Helm Template Path Detection]]
- [[_COMMUNITY_Skill File Loader|Skill File Loader]]
- [[_COMMUNITY_Report Text Formatter|Report Text Formatter]]
- [[_COMMUNITY_AI-Analysis Inference Helper|AI-Analysis Inference Helper]]
- [[_COMMUNITY_Sample Terraform Serverless JSON|Sample: Terraform Serverless JSON]]
- [[_COMMUNITY_Control Assessability|Control Assessability]]
- [[_COMMUNITY_Severity Deductions Sync|Severity Deductions Sync]]
- [[_COMMUNITY_Sample K8s CriticalHardened|Sample: K8s Critical/Hardened]]
- [[_COMMUNITY_Docker Compose Services|Docker Compose Services]]
- [[_COMMUNITY_Streamlit Frontend|Streamlit Frontend]]
- [[_COMMUNITY_Architecture Reviewer Skill|Architecture Reviewer Skill]]
- [[_COMMUNITY_LLM Provider Settings|LLM Provider Settings]]
- [[_COMMUNITY_Sample AWS AverageGood HCL|Sample: AWS Average/Good HCL]]
- [[_COMMUNITY_Sample AzureGCP Average HCL|Sample: Azure/GCP Average HCL]]
- [[_COMMUNITY_Sample AzureGCP Production HCL|Sample: Azure/GCP Production HCL]]
- [[_COMMUNITY_Misc Singleton 77|Misc Singleton 77]]
- [[_COMMUNITY_Community 79|Community 79]]
- [[_COMMUNITY_Community 80|Community 80]]
- [[_COMMUNITY_Community 81|Community 81]]
- [[_COMMUNITY_Community 82|Community 82]]
- [[_COMMUNITY_Community 83|Community 83]]
- [[_COMMUNITY_Community 84|Community 84]]
- [[_COMMUNITY_Community 85|Community 85]]
- [[_COMMUNITY_Community 86|Community 86]]
- [[_COMMUNITY_Community 87|Community 87]]
- [[_COMMUNITY_Community 88|Community 88]]
- [[_COMMUNITY_Community 89|Community 89]]
- [[_COMMUNITY_Community 90|Community 90]]
- [[_COMMUNITY_Community 91|Community 91]]

## God Nodes (most connected - your core abstractions)
1. `_f()` - 121 edges
2. `remediate_sync()` - 111 edges
3. `Severity` - 101 edges
4. `Finding` - 93 edges
5. `make_finding()` - 74 edges
6. `AgentReport` - 64 edges
7. `AnalysisReport` - 61 edges
8. `make_gap()` - 47 edges
9. `RemediationError` - 46 edges
10. `ArchitectureReview` - 44 edges

## Surprising Connections (you probably didn't know these)
- `Deterministic Architecture Score` --rationale_for--> `_calculate_architecture_score()`  [INFERRED]
  DEVELOPMENT_PHASES.md → app/agents/architecture_reviewer.py
- `Cross-Cutting Gap Dedup` --rationale_for--> `_dedup_cross_cutting_gaps()`  [INFERRED]
  DEVELOPMENT_PHASES.md → app/agents/architecture_reviewer.py
- `Deterministic Fixers Before LLM Fallback` --rationale_for--> `remediate()`  [INFERRED]
  DEVELOPMENT_PHASES.md → app/agents/remediator.py
- `Non-Infra File Hallucination Guard (3-layer)` --rationale_for--> `_detect_infra_type()`  [INFERRED]
  DEVELOPMENT_PHASES.md → app/agents/security.py
- `LangGraph Sequential Pipeline Architecture` --conceptually_related_to--> `build_analysis_graph()`  [INFERRED]
  README.md → app/agents/supervisor.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **LangGraph Sequential Pipeline Nodes** — agents_supervisor_parse_files_node, agents_supervisor_security_node, agents_supervisor_reliability_node, agents_supervisor_cost_node, agents_supervisor_architecture_reviewer_node, agents_supervisor_supervisor_node [EXTRACTED 1.00]
- **Hybrid Rules + LLM Agents** — agents_security_analyze_security, agents_reliability_analyze_reliability, agents_cost_analyze_cost, agents_architecture_reviewer_analyze_architecture [EXTRACTED 1.00]
- **Phase 3.3 Compliance Scoring Pipeline** — api_routes_parse_tf_resources, core_compliance_enrich_findings_with_compliance, core_compliance_compute_compliance_scorecard, core_compliance_detect_clouds, core_compliance_is_control_assessable [EXTRACTED 1.00]
- **Drift detection pipeline (fingerprint -> baseline lookup -> compare)** — core_fingerprint_compute, core_store_find_by_bundle_fingerprint, core_drift_find_baseline, core_drift_compute_drift [EXTRACTED 0.95]
- **Provider factory pattern across Ollama/Anthropic/OpenAI/Google** — core_llm_get_llm, core_llm_build_ollama, core_llm_build_anthropic, core_llm_build_openai, core_llm_build_google [EXTRACTED 0.95]
- **Report lifecycle: score -> persist -> render (text/PDF)** — core_report_calculate_overall_score, core_store_save_report, core_pdf_export_generate, core_report_format_report_text [INFERRED 0.85]
- **good-chart Helm template bundle (production-grade)** — good_chart_chart, good_chart_values, good_chart_templates_deployment, good_chart_templates_hpa, good_chart_templates_networkpolicy, good_chart_templates_pdb, good_chart_templates_service, good_chart_templates_serviceaccount, good_chart_templates_servicemonitor [EXTRACTED 1.00]
- **Order-service production K8s workload set** — samples_k8s_production_grade_serviceaccount, samples_k8s_production_grade_deployment, samples_k8s_production_grade_service, samples_k8s_production_grade_networkpolicy, samples_k8s_production_grade_hpa, samples_k8s_production_grade_pdb [EXTRACTED 1.00]
- **Vulnerable AWS Terraform anti-pattern set** — samples_vulnerable_infra_db_sg, samples_vulnerable_infra_main_db, samples_vulnerable_infra_data_bucket, samples_vulnerable_infra_admin_policy, samples_vulnerable_infra_main_trail [EXTRACTED 1.00]
- **Per-Infra-Type Agent Skill Family** — skills_security_kubernetes, skills_security_terraform, skills_reliability_kubernetes, skills_reliability_terraform, skills_cost_kubernetes, skills_cost_terraform [INFERRED 0.95]
- **Supervisor synthesizes per-domain agent reports** — skills_supervisor, skills_security_kubernetes, skills_reliability_kubernetes, skills_cost_kubernetes [EXTRACTED 1.00]
- **mock_llm fixture powers full-pipeline tests** — tests_conftest_mock_llm_fixture, tests_test_mock_llm, tests_test_file_contents_echo, tests_test_compliance [EXTRACTED 1.00]
- **Rule-test files share has_finding_with helper pattern** — tests_test_security_rules, tests_test_reliability_rules, tests_test_samples_rules_only [INFERRED 0.85]
- **Test-fixture builders consumed by rule and remediator tests** — fixtures_findings_minimal_deployment, fixtures_findings_minimal_container, fixtures_findings_tf_resource [EXTRACTED 1.00]
- **Remediator test classes covering Phase 3.4 sub-features** — tests_test_remediator_testegressfixer, tests_test_remediator_testfuzzykubernetesmatching, tests_test_remediator_testcompanionresourcerequired, tests_test_remediator_testk8sjsonroundtrip, tests_test_remediator_testterraformjsonfixers [EXTRACTED 1.00]

## Communities (92 total, 9 thin omitted)

### Community 0 - "Cost Rules Engine"
Cohesion: 0.05
Nodes (46): Run deterministic cost checks on parsed Terraform resources., Run deterministic cost checks., run_cost_rules(), run_terraform_cost_rules(), Run deterministic reliability checks., Run deterministic reliability checks on parsed Terraform resources., run_reliability_rules(), run_terraform_reliability_rules() (+38 more)

### Community 1 - "Auto-Remediation Pipeline"
Cohesion: 0.09
Nodes (40): Phase 3.4 Auto-Remediation, _f(), Tests for Phase 3.4 Auto-Remediation.  Covers: - File discovery: finding -> file, The Reliability/Cost agents emit findings with category="ai-analysis"     that f, Real failure mode from samples/vulnerable-infra.tf: Reliability         Agent em, The inference helper must be a no-op for findings with a real         rule-engin, When the inference table doesn't match (novel title, unknown         resource ty, Title keywords match but resource prefix doesn't — must NOT         route to the (+32 more)

### Community 2 - "Multi-Provider LLM Factory"
Cohesion: 0.07
Nodes (27): Configuration: env-driven settings for the platform.  LLM provider is selected v, Settings, Any, Multi-provider LLM Factory Routing, _build_anthropic(), _build_google(), _build_ollama(), _build_openai() (+19 more)

### Community 3 - "Drift Detection (Rule-Only)"
Cohesion: 0.13
Nodes (15): compute_drift(), Drift excludes LLM-augmented findings, Compute finding-level and score-level drift between two reports.      All compar, make_finding(), Drift panel: introduced/resolved/persisting findings UI, _full_report(), _llm_finding(), The whole point of the fix: LLM findings don't affect drift score. (+7 more)

### Community 4 - "K8s YAML Strategy Fixers"
Cohesion: 0.08
Nodes (27): Any, parse_kubernetes_yaml(), Parse Kubernetes YAML (supports multi-document YAML)., _k8s_bundle(), Bug from samples/good-chart-1.1.0.tgz: the Reliability Agent's     rule-engine ', If the deployment already has a strategy block, the fixer         refuses to ove, Pods don't have an update strategy. If the LLM somehow emits         a strategy, The fixer adds default 25%/0 values — must surface a warning         so the user (+19 more)

### Community 5 - "Reliability Rule Engine"
Cohesion: 0.12
Nodes (31): analyze_cost(), parse_resource_value(), Parse K8s resource value to a numeric value., Run cost analysis using rules + LLM reasoning., analyze_reliability(), Run reliability analysis using rules + LLM reasoning., analyze_security(), _detect_infra_type() (+23 more)

### Community 6 - "FastAPI Routes & Pipeline"
Cohesion: 0.10
Nodes (40): CompanionResourceRequired, NonPatchableFinding, PatchValidationError, Raised when remediation cannot proceed (no file match, no fixer, etc.)., The finding is advisory — it has no associated resource in any file     and is n, The finding requires creating a NEW Kubernetes resource alongside     the existi, Raised when a generated patch produces unparseable output., RemediationError (+32 more)

### Community 7 - "Drift Computation Helpers"
Cohesion: 0.10
Nodes (23): AnalysisReport, Finding, Severity deductions table (CRITICAL=20 HIGH=10 MEDIUM=5 LOW=2 INFO=0), _agent_findings_by_prefix(), _agent_has_data(), _all_deterministic_findings(), _finding_signature(), _is_deterministic() (+15 more)

### Community 8 - "Report Persistence & PDF API"
Cohesion: 0.06
Nodes (38): drift_endpoint(), Find past reports with similar risk profiles., Compare a report against the most recent prior scan of the same bundle.      Pha, similar_reports_endpoint(), AnalysisReport, Collection, file_contents echo (live but never persisted), find_baseline() (+30 more)

### Community 9 - "Terraform Patch & SG Rules"
Cohesion: 0.06
Nodes (19): Synchronous wrapper around :func:`remediate` for tests / scripts.      Spawns a, remediate_sync(), End-to-end: LLM emits a patch with dash-line drift; the cleaned         diff has, The 'Overly Permissive Egress on Security Group' finding (LLM-emitted     title), The rule-based 'Security group open to 0.0.0.0/0' finding (which         is ingr, If the SG has no literal 0.0.0.0/0 (e.g. it uses var.allowed_cidrs),         the, Single-quoted, double-quoted, and bare strings must keep their         quoting s, A 4-space-indented input should round-trip with 4 spaces. (+11 more)

### Community 10 - "Cloud-Aware Compliance Scoring"
Cohesion: 0.09
Nodes (15): compute_compliance_scorecard(), Compute per-framework compliance scores for a report.      Phase 3.3 fix: cloud-, ComplianceFrameworkScore model, ComplianceScorecard model, The bug regression test: an Azure-only upload must NOT show         CIS AWS Foun, GCP-only upload must NOT show CIS AWS or CIS K8s. (CIS GCP IS shown         — se, Azure-only upload MUST show CIS Azure Foundations Benchmark., GCP-only upload MUST show CIS GCP Foundations Benchmark. (+7 more)

### Community 11 - "K8s Remediator Internals"
Cohesion: 0.09
Nodes (30): _detect_json_indent(), _dump_docs_for_kind(), _ensure_pod_spec(), _filename_kind(), _find_workload_doc(), _fix_k8s(), _iter_containers(), _k8s_container_match() (+22 more)

### Community 12 - "Compliance Framework Mappings"
Cohesion: 0.10
Nodes (22): _build_control_assessability(), _classify_control(), _detect_clouds_from_resource(), _empty_mappings(), _entry_controls(), _entry_domain(), _is_control_assessable(), load_mappings() (+14 more)

### Community 13 - "Security & Cost Agents"
Cohesion: 0.25
Nodes (13): AnalysisState, architecture_reviewer_node(), build_analysis_graph(), cost_node(), Synthesize all agent reports into final report., Build the LangGraph multi-agent analysis workflow (sequential for local LLM)., Run security analysis., Run reliability analysis. (+5 more)

### Community 14 - "Test Conftest Fakes"
Cohesion: 0.22
Nodes (6): Phase 2 Regression Sentinels, expected_scores(), _FakeMessage, Shared pytest fixtures for the AI Infrastructure Governance Platform test suite., Return the parsed expected_scores.yaml manifest, or an empty dict if absent., expected_scores.yaml manifest

### Community 15 - "Architecture Gap Filters"
Cohesion: 0.26
Nodes (4): _filter_k8s_platform_gaps(), Drop gaps that are platform/cluster-level concerns for K8s/Helm infrastructure., Non-'terraform' infra_type follows the K8s filtering path., TestK8sPlatformGapFilter

### Community 16 - "Terraform JSON/HCL Fixers"
Cohesion: 0.09
Nodes (26): _companion_template(), _fix_tf(), _fix_tf_json(), _fix_with_llm(), _infer_rule_category(), _is_advisory_language(), _locate_file_for_finding(), _make_unified_diff() (+18 more)

### Community 17 - "Bundle Fingerprinting"
Cohesion: 0.12
Nodes (13): Bundle fingerprint identifies same deployment across re-uploads, compute_fingerprints(), Bundle hash is over filenames only, not content, SHA256 fingerprinting for uploaded infrastructure file bundles.  Used by drift d, Compute per-file content hashes and a bundle hash over filenames.      Args:, Tests for SHA256 fingerprinting of uploaded file bundles.  Reference: app/core/f, Editing file content does NOT change the bundle hash. This is the         proper, Renaming a file DOES change the bundle hash — it's a different         bundle (d (+5 more)

### Community 18 - "Sample: AWS Production HCL"
Cohesion: 0.11
Nodes (25): Encryption at Rest (KMS), High Availability / Multi-AZ, IAM Least Privilege, Zero Trust Security, Enterprise Production-Grade Terraform (HCL), aws_autoscaling_group.app_asg, aws_cloudtrail.main, aws_flow_log.vpc (+17 more)

### Community 19 - "Rules-Only Regression Suite"
Cohesion: 0.13
Nodes (18): Rules-only deterministic regression suite, Return a callable that reads a sample file from the repo's samples/ dir., sample_loader(), _parse_sample(), pytest_generate_tests(), Strict regression tests: run rule-based checks on each sample file and assert de, Parametrize the regression tests across every sample in the manifest., For each manifest entry, assert overall_score within tolerance. (+10 more)

### Community 20 - "Cloud Detection Heuristics"
Cohesion: 0.16
Nodes (11): _detect_clouds(), Detect which clouds are present in the report.      Detection signals, in priori, _full_report(), Clean K8s upload (no findings) still detects kubernetes via extension., Phase 3.3 fix: a clean .tf file (no findings) must not falsely         imply AWS, Phase 3.3 regression: LLM-emitted findings sometimes use         ``resource="N/A, All-uppercase abbreviations like RDS, KMS, IAM, EC2, S3 are AWS         shorthan, Generic CapitalCase words like Infrastructure, Database, Storage         are not (+3 more)

### Community 21 - "K8s Resource Parser"
Cohesion: 0.18
Nodes (3): get_pod_spec(), Get pod spec from various resource types., TestKubernetesParser

### Community 22 - "Compliance Test Fixtures"
Cohesion: 0.19
Nodes (23): AnalysisReport, AgentReport, AnalysisReport, ArchitectureReview, AgentReport, AnalysisReport, ArchitectureReview, Rule-only Drift Score (excludes ai-analysis) (+15 more)

### Community 23 - "Development Phases Doc"
Cohesion: 0.20
Nodes (9): Bundle Fingerprint over Filenames, Development Phases, Drift Compares Rule Findings Only, Mock LLM by Replacing Chain Primitive, Phase 3.1 Pytest Regression Harness, Phase 3.2 Drift Detection, Phase 3.3 Compliance Framework Mapping, LangGraph Sequential Pipeline Architecture (+1 more)

### Community 24 - "Terraform JSON Fixer Tests"
Cohesion: 0.21
Nodes (5): Bug from terraform-serverless.json: clicking Generate fix on     'S3 bucket with, If a companion resource of the same name already exists, we         refuse to si, Categories without a deterministic JSON fixer flow to LLM         cleanly (no cr, End-to-end on the actual samples/terraform-serverless.json., TestTerraformJsonFixers

### Community 25 - "Terraform File Locator"
Cohesion: 0.18
Nodes (12): _parse_tf_resources(), Parse all Terraform-flavored files in the bundle into a flat resource     list., Any, extract_tf_resources(), extract_tf_variables(), parse_terraform(), Extract resources from parsed Terraform.      Handles two formats:     - HCL2 pa, Extract variables from parsed Terraform. (+4 more)

### Community 26 - "Cosmetic Drift Filter"
Cohesion: 0.16
Nodes (8): _is_cosmetic_drift(), Return True iff the difference between the two lines is cosmetic only:      - Pu, Walk original/patched in lockstep and revert lines that differ only     cosmetic, _strip_cosmetic_drift(), Different decoration character means it's an intentional change., Inserted lines (no original counterpart) flow through unchanged., The filter strips dash-rule comment drift and trailing-whitespace     drift from, TestCosmeticDriftFilter

### Community 27 - "File-Contents Echo Plumbing"
Cohesion: 0.12
Nodes (16): AI Infrastructure Governance & Architecture Intelligence Platform, API Endpoints, Architecture, Development, Docker, Environment Variables, License, Local Development (+8 more)

### Community 28 - "Remediation Errors & Bugs"
Cohesion: 0.25
Nodes (4): Bug 3: LLM emits Helm template paths in resource field. The     locator now trea, Sanity: don't false-positive on legitimate Kind/ns/name., Sanity: aws_*.foo doesn't match the file-path heuristic., TestTemplatePathDetection

### Community 29 - "Structural Patch Validation"
Cohesion: 0.17
Nodes (9): _count_resources(), Count the number of top-level resources in a patched file.      Used by :func:`_, Raise :class:`PatchValidationError` if the patch removed top-level     resources, _verify_no_resources_dropped(), Higher-leverage protection: ANY LLM patch that drops resources     from a multi-, The exact attack vector: LLM kept doc 1, dropped docs 2 and 3., Adding resources (e.g., an HPA companion) is fine., When either side is unparseable (-1), skip the check rather         than false-f (+1 more)

### Community 30 - "Architecture Reviewer Agent"
Cohesion: 0.17
Nodes (18): analyze_architecture(), _build_infrastructure_summary(), _extract_k8s_resources(), _extract_tf_resources(), _format_findings(), Architecture Reviewer agent — cross-cutting tradeoff analysis across all agent f, Extract Kubernetes resource kinds and names from YAML content., Extract Terraform resource types and names from HCL content. (+10 more)

### Community 31 - "Cross-Cutting Gap Dedup"
Cohesion: 0.20
Nodes (8): Finding, Cross-cutting Gap Dedup Rules, is_duplicate(), Check if an LLM finding duplicates any rule finding using keyword overlap., AgentReport model, Finding model, Tests for keyword extraction, finding-level dedup, and cross-cutting gap dedup., TestIsDuplicate

### Community 32 - "K8s Resource Locator (Layered)"
Cohesion: 0.12
Nodes (9): The Cost-Agent LLM occasionally emits 2-segment Kind/name resources     (no name, Kind/name (no namespace) — match via exact name + Kind., Bug from the screenshot: the Cost LLM emitted         ``Deployment/my-chart`` ag, If the bundle has exactly ONE Deployment, even a name that         doesn't match, Two Deployments both contain 'app' in their name — the locator         must NOT, When two Deployments exist but one matches Kind/ns/name exactly,         layer 1, Kind/name resolves UNAMBIGUOUSLY when only one workload has         that exact n, Sanity: don't break the original happy path. (+1 more)

### Community 33 - "Agent Skill Conventions"
Cohesion: 0.20
Nodes (6): Architecture Gaps, CHANGE_ME_ Placeholder Convention, Executive Summary Output, Kubernetes Infra Type, Terraform Infra Type, TODO(governance) Comment Convention

### Community 34 - "Score Weighting Math"
Cohesion: 0.27
Nodes (7): Score weighting (Sec 0.34, Rel 0.30, Cost 0.21, Arch 0.15), calculate_overall_score(), Dimension weights: security 0.34 / reliability 0.30 / cost 0.21 / arch 0.15, Calculate weighted overall score from agent reports + architecture review., make_report(), Tests for scoring math.  Reference code: - app/core/report.py::calculate_overall, TestCalculateOverallScore

### Community 35 - "Keyword Extraction & Synonyms"
Cohesion: 0.22
Nodes (5): extract_keywords(), Insert spaces at camelCase and PascalCase boundaries.      'HorizontalPodAutosca, Extract significant keywords from text, with synonym expansion., _split_camelcase(), TestExtractKeywords

### Community 36 - "Sample: Good Helm Chart"
Cohesion: 0.16
Nodes (17): good-chart Chart.yaml, good-chart Deployment template, good-chart HPA template, good-chart NetworkPolicy template, good-chart PDB template, good-chart Service template, good-chart ServiceAccount template, good-chart ServiceMonitor template (+9 more)

### Community 37 - "Architecture Score Calculation"
Cohesion: 0.30
Nodes (4): _calculate_architecture_score(), Calculate architecture score from gaps, capped by agent average.      The archit, make_gap(), TestArchitectureScore

### Community 38 - "LLM JSON Parsing Recovery"
Cohesion: 0.20
Nodes (8): _coerce_llm_payload(), _parse_llm_json_response(), Best-effort extraction of (patched_content, explanation) from a     local-LLM re, Normalize a parsed LLM payload to (patched_content, explanation)., Bug 2: the local LLM emits JSON with literal newlines inside string     values., The exact failure mode you saw: 'Invalid control character at: line 1 column 25', The LLM rambles before the JSON. Regex extraction rescues., TestLLMJsonParsing

### Community 39 - "Non-Patchable Findings"
Cohesion: 0.19
Nodes (6): is_non_patchable(), Return True for findings that don't map to any file-level edit.      These are t, Findings whose resource is N/A, empty, or a whole-infrastructure     sentinel ca, The bug from the screenshot: 'Lack of Commitment Discounts' with         resourc, Existing API code that catches RemediationError still catches         the new No, TestNonPatchableFindings

### Community 40 - "PDF Export Module"
Cohesion: 0.18
Nodes (7): AnalysisReport, _agent_score(), generate_pdf_report(), PDF export for governance reports (Phase 3.3).  Renders an AnalysisReport to a P, Render an AnalysisReport to a PDF byte stream.      Returns the raw bytes of the, _severity_color_hex(), TestPDFExport

### Community 41 - "Cloud-Specific CIS Mapping"
Cohesion: 0.13
Nodes (16): AnalysisReport, Finding, ComplianceFrameworkScore, ComplianceScorecard, ComplianceScorecard, Cloud-aware Compliance Scorecard, enrich_findings_with_compliance(), get_controls_for_finding() (+8 more)

### Community 42 - "Mocked LLM Response Builders"
Cohesion: 0.21
Nodes (12): Run the complete multi-agent analysis pipeline., run_analysis(), make_arch_response(), Build an architecture-reviewer response. Useful for testing dedup filters     by, mock_llm fixture, Sanity tests for the mock_llm fixture.  The mock must intercept all 5 agent get_, The full pipeline runs end-to-end with no Ollama process available., Default mock returns empty findings — score equals rule-only baseline. (+4 more)

### Community 43 - "Companion Resource Parsing"
Cohesion: 0.25
Nodes (6): AWS provider v4+ splits S3 bucket config across companion resources, Return parent resource names that have a companion resource of the given type., resources_with_companion(), When the bucket field isn't standard, scan all string values., HCL2 sometimes wraps single string values in lists., TestResourcesWithCompanion

### Community 44 - "Sample: K8s Production Manifest"
Cohesion: 0.23
Nodes (13): K8s Production-Grade Manifest (order-service), Deployment order-service, HorizontalPodAutoscaler order-service, NetworkPolicy order-service, PodDisruptionBudget order-service, Service order-service, ServiceAccount order-service, Vulnerable K8s Deployment Sample (+5 more)

### Community 45 - "Terraform Secrets Gap Filter"
Cohesion: 0.27
Nodes (4): _filter_terraform_secrets_gap(), Drop secrets management gap if Terraform uses variable refs or manage_master_use, A gap with 'secret' alone but neither 'management' nor 'credential' is kept., TestTerraformSecretsGapFilter

### Community 46 - "Advisory-Language Detection"
Cohesion: 0.20
Nodes (5): Bug from terraform-serverless.json's "DynamoDB Billing Mode" finding:     Cost A, A real fixable finding whose recommendation starts with an         imperative ve, Critical: only LLM-produced (category='ai-analysis') findings         are eligib, Critical efficiency check: advisory-language findings must NEVER         reach t, TestAdvisoryLanguageDetection

### Community 47 - "Cross-Cutting Gap Echo Filter"
Cohesion: 0.31
Nodes (3): _dedup_cross_cutting_gaps(), Remove cross-cutting gaps that merely echo what individual agents already found., TestDedupCrossCuttingGaps

### Community 48 - "Advisory & File Locators"
Cohesion: 0.17
Nodes (12): API Changes, Architecture Decisions, Challenges Addressed, Components Delivered, Phase 2 Late Additions: Anti-Hallucination & Quality Hardening, Phase 2 — Skill Files, Architecture Reviewer, Report Memory & Multi-Cloud Expansion, Pipeline Change, Rule Coverage After Phase 2 (+4 more)

### Community 49 - "Patch Validation Rationale"
Cohesion: 0.20
Nodes (10): Re-parse the patched output. Raise PatchValidationError if it fails., _validate_patch(), Deterministic Fixers Before LLM Fallback, Stateless File Contents at Remediation, Validate Patches by Re-Parse, Phase 3.4 Auto-Remediation, test_validate_passes_for_well_formed_terraform(), test_validate_rejects_empty_patched_content() (+2 more)

### Community 50 - "Terraform Block Span Surgery"
Cohesion: 0.15
Nodes (13): _find_tf_block_span(), Locate the byte span ``[start, end)`` of a Terraform resource block in     HCL s, Insert ``argument_lines`` (one or more lines, no trailing newline) just     befo, Remove all lines in the block that match ``key_regex`` at the start     (whitesp, If ``key`` exists in the block, replace its value with ``new_value_literal``., _tf_inject_argument_in_block(), _tf_remove_argument_in_block(), _tf_replace_block() (+5 more)

### Community 51 - "Full-Pipeline Integration Tests"
Cohesion: 0.22
Nodes (7): Full-pipeline integration test (mocked LLM), EMPTY_RESPONSES, End-to-end integration tests: run the full pipeline (security/reliability/cost a, Full pipeline overall_score should be close to rules-only score.      The archit, Phase 2 sentinels must remain absent in the full pipeline too., test_sample_full_pipeline_must_not_have_findings(), test_sample_full_pipeline_overall_score()

### Community 53 - "K8s JSON Round-Trip"
Cohesion: 0.29
Nodes (4): _filter_terraform_speculative_gaps(), Drop Terraform gaps that flag absence of strategies rather than misconfiguration, Tests for the three architecture-reviewer gap filters.  Reference: app/agents/ar, TestTerraformSpeculativeGapFilter

### Community 54 - "Praise-Finding Filter"
Cohesion: 0.25
Nodes (4): Bug from good-chart-1.1.0.tgz: the LLM emitted INFO findings     congratulating, Keep/Maintain only fire when they're the FIRST word of the         recommendatio, Critical efficiency check — praise findings must never reach         the LLM. Se, TestPraiseFindings

### Community 55 - "Helm Template Path Detection"
Cohesion: 0.38
Nodes (4): _looks_like_file_path(), True if the resource string looks like a Helm template path or a     file path r, Bug from samples/good-chart-1.1.0.tgz: the Security Agent's LLM     emitted reso, TestHelmAnnotatedPathDetection

### Community 56 - "Skill File Loader"
Cohesion: 0.38
Nodes (6): Any, list_skills(), load_skill(), Skill file loader — reads agent behavior from markdown skill files., Load a skill file and return its metadata + prompt content.      Skill files use, List all available skill files with their metadata.

### Community 57 - "Report Text Formatter"
Cohesion: 0.18
Nodes (11): API Added, Architecture Decisions, Challenges Addressed, Components Delivered, Framework Matrix (Verified Against All 6 Samples), Models Added, Phase 3.3 — Compliance Framework Mapping, Production-Grade Samples Added (+3 more)

### Community 58 - "AI-Analysis Inference Helper"
Cohesion: 0.20
Nodes (10): API & Frontend, Challenges Addressed, Components Delivered, Critical Design Decisions (Locked in by Tests), K8s Categories with Deterministic Fixers, Phase 3.4 — Auto-Remediation (Scaffolding) — SHIPPED 2026-05-31, Terraform Categories with Deterministic Fixers, Test Sentinels (+2 more)

### Community 59 - "Sample: Terraform Serverless JSON"
Cohesion: 0.60
Nodes (5): Terraform Serverless JSON sample, aws_api_gateway_rest_api.main, aws_dynamodb_table.sessions, aws_lambda_function.api_handler (serverless), aws_s3_bucket.uploads

### Community 60 - "Control Assessability"
Cohesion: 0.22
Nodes (9): API Added, Architecture Decisions, Challenges Addressed, Components Delivered, Models Added, Phase 3.2 — Drift Detection, Tests Added, Verification (+1 more)

### Community 61 - "Severity Deductions Sync"
Cohesion: 0.20
Nodes (8): compute_agent_score(), Per-agent score deductions table.  This duplicates the table from app/agents/{se, Apply the standard deduction table to a list of Finding objects., SEVERITY_DEDUCTIONS, _build_reports(), AgentReport, Guard against drift between the test-side deductions table and prod., TestSeverityDeductionsInSync

### Community 62 - "Sample: K8s Critical/Hardened"
Cohesion: 0.50
Nodes (4): Sample: K8s critical-security-failure (privileged hostPID node debugger), Sample: K8s good-deployment manifest, Sample: K8s hardened-production manifest, Sample: K8s payments-api Deployment (JSON)

### Community 64 - "Streamlit Frontend"
Cohesion: 0.22
Nodes (9): Architecture Decisions, Build Order, Challenges Addressed, Components Delivered, Coverage, Phase 2 Regression Sentinels (Non-Negotiable), Phase 3.1 — Pytest Regression Test Harness, Verification (+1 more)

### Community 79 - "Community 79"
Cohesion: 0.22
Nodes (9): Challenges Addressed, Components Delivered, Core Architecture Decisions, External Review Feedback, Known Limitations (Phase 1), Phase 1 — MVP: Intelligent Infrastructure Analysis, Rule Coverage, Sample Files Created (+1 more)

### Community 80 - "Community 80"
Cohesion: 0.22
Nodes (5): mock_llm(), MockLLMHandle, Returned by the mock_llm fixture. Tests can override per-agent responses., Override the canned JSON for a specific agent route., Replace get_llm() in every agent module with a fake that returns canned JSON.

### Community 81 - "Community 81"
Cohesion: 0.22
Nodes (9): Adding a new rule, Cheat sheet, Conventions, How the LLM mock works, Setup, Tests, Try breaking a fix on purpose (the satisfying experiment), Updating `expected_scores.yaml` (+1 more)

### Community 82 - "Community 82"
Cohesion: 0.25
Nodes (8): Non-Infra File Hallucination Guard (3-layer), ChromaDB Report Persistence, AWS Provider v4+ Companion Resource Lookup, Cross-Cutting Gap Dedup, Deterministic Architecture Score, Native Helm Chart Support via helm template, Skill File System (Externalized Prompts), Phase 2 Skill Files & Architecture Reviewer

### Community 83 - "Community 83"
Cohesion: 0.36
Nodes (5): Runnable, _FakeRunnable, Identify which agent is invoking based on system-prompt content.      Order matt, Drop-in replacement for ChatOllama. Implements ainvoke()/invoke().      Plugs in, _route_by_prompt()

### Community 84 - "Community 84"
Cohesion: 0.29
Nodes (5): parse_files_node(), Parse uploaded files and extract K8s + Terraform resources., extract_k8s_resources(), Group parsed K8s documents by resource kind., Documents the CURRENT behavior — kind:List is NOT expanded into items.

### Community 85 - "Community 85"
Cohesion: 0.43
Nodes (3): _delta(), Compute current minus baseline. Returns None if either side is missing., TestDeltaHelper

### Community 86 - "Community 86"
Cohesion: 0.29
Nodes (7): Discover without running, Filter what runs, Optional: coverage report, Running tests, See test names as they run, The daily-driver command, When something fails

### Community 87 - "Community 87"
Cohesion: 0.33
Nodes (5): analyze_infrastructure(), Upload infrastructure files and run multi-agent analysis., FastAPI app (main.py), Run helm template on a packaged .tgz chart and return rendered Kubernetes YAML., render_helm_chart()

### Community 88 - "Community 88"
Cohesion: 0.33
Nodes (6): K8s/Terraform Concept Leakage Fix, Content-First File Type Detection, Deduplication Engine, Hybrid Rules + LLM Analysis, Sequential Agent Execution, Phase 1 MVP

### Community 89 - "Community 89"
Cohesion: 0.50
Nodes (4): compare_reports_endpoint(), Compare two reports and return score deltas., compare_reports(), Compare two reports and return score deltas.

### Community 90 - "Community 90"
Cohesion: 0.50
Nodes (3): make_agent_finding(), Canned LLM responses keyed by agent type.  Each agent's `chain.ainvoke(...)` is, Build an agent finding for use inside an LLM-mocked response.

## Knowledge Gaps
- **136 isolated node(s):** `Settings`, `Any`, `Any`, `graphify`, `What Was Built` (+131 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **9 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Severity` connect `Reliability Rule Engine` to `Cost Rules Engine`, `Auto-Remediation Pipeline`, `Drift Detection (Rule-Only)`, `K8s YAML Strategy Fixers`, `FastAPI Routes & Pipeline`, `Drift Computation Helpers`, `Report Persistence & PDF API`, `Terraform Patch & SG Rules`, `K8s Remediator Internals`, `Architecture Gap Filters`, `Terraform JSON/HCL Fixers`, `Rules-Only Regression Suite`, `Compliance Test Fixtures`, `Terraform JSON Fixer Tests`, `Cosmetic Drift Filter`, `Remediation Errors & Bugs`, `Structural Patch Validation`, `Architecture Reviewer Agent`, `Cross-Cutting Gap Dedup`, `K8s Resource Locator (Layered)`, `Score Weighting Math`, `Keyword Extraction & Synonyms`, `Architecture Score Calculation`, `LLM JSON Parsing Recovery`, `Non-Patchable Findings`, `Terraform Secrets Gap Filter`, `Advisory-Language Detection`, `Cross-Cutting Gap Echo Filter`, `K8s JSON Round-Trip`, `Praise-Finding Filter`, `Helm Template Path Detection`, `Severity Deductions Sync`, `Community 85`?**
  _High betweenness centrality (0.157) - this node is a cross-community bridge._
- **Why does `Finding` connect `Reliability Rule Engine` to `Cost Rules Engine`, `Auto-Remediation Pipeline`, `Drift Detection (Rule-Only)`, `K8s YAML Strategy Fixers`, `FastAPI Routes & Pipeline`, `Drift Computation Helpers`, `Report Persistence & PDF API`, `Terraform Patch & SG Rules`, `Cloud-Aware Compliance Scoring`, `K8s Remediator Internals`, `Compliance Framework Mappings`, `Terraform JSON/HCL Fixers`, `Cloud Detection Heuristics`, `Compliance Test Fixtures`, `Terraform JSON Fixer Tests`, `Cosmetic Drift Filter`, `Remediation Errors & Bugs`, `Structural Patch Validation`, `Architecture Reviewer Agent`, `Cross-Cutting Gap Dedup`, `K8s Resource Locator (Layered)`, `LLM JSON Parsing Recovery`, `Non-Patchable Findings`, `PDF Export Module`, `Cloud-Specific CIS Mapping`, `Advisory-Language Detection`, `Cloud Attribution Correctness`, `Praise-Finding Filter`, `Helm Template Path Detection`, `Community 85`?**
  _High betweenness centrality (0.153) - this node is a cross-community bridge._
- **Why does `Development Phases` connect `Development Phases Doc` to `Streamlit Frontend`, `Community 79`, `Advisory & File Locators`, `Report Text Formatter`, `AI-Analysis Inference Helper`, `Control Assessability`?**
  _High betweenness centrality (0.074) - this node is a cross-community bridge._
- **Are the 75 inferred relationships involving `Severity` (e.g. with `CompanionResourceRequired` and `NonPatchableFinding`) actually correct?**
  _`Severity` has 75 INFERRED edges - model-reasoned connections that need verification._
- **Are the 67 inferred relationships involving `Finding` (e.g. with `CompanionResourceRequired` and `NonPatchableFinding`) actually correct?**
  _`Finding` has 67 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Architecture Reviewer agent — cross-cutting tradeoff analysis across all agent f`, `Drop gaps that are platform/cluster-level concerns for K8s/Helm infrastructure.`, `Drop Terraform gaps that flag absence of strategies rather than misconfiguration` to the rest of the system?**
  _490 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Cost Rules Engine` be split into smaller, more focused modules?**
  _Cohesion score 0.05229610314356077 - nodes in this community are weakly interconnected._