# Graph Report - AI-Infrastructure-Governance-Architecture-Intelligence-Platform  (2026-07-19)

## Corpus Check
- 86 files · ~91,836 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1453 nodes · 3724 edges · 89 communities (87 shown, 2 thin omitted)
- Extraction: 87% EXTRACTED · 13% INFERRED · 0% AMBIGUOUS · INFERRED: 487 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `6ffd9e83`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]
- [[_COMMUNITY_Community 50|Community 50]]
- [[_COMMUNITY_Community 51|Community 51]]
- [[_COMMUNITY_Community 52|Community 52]]
- [[_COMMUNITY_Community 53|Community 53]]
- [[_COMMUNITY_Community 54|Community 54]]
- [[_COMMUNITY_Community 55|Community 55]]
- [[_COMMUNITY_Community 56|Community 56]]
- [[_COMMUNITY_Community 57|Community 57]]
- [[_COMMUNITY_Community 58|Community 58]]
- [[_COMMUNITY_Community 59|Community 59]]
- [[_COMMUNITY_Community 60|Community 60]]
- [[_COMMUNITY_Community 61|Community 61]]
- [[_COMMUNITY_Community 62|Community 62]]
- [[_COMMUNITY_Community 63|Community 63]]
- [[_COMMUNITY_Community 65|Community 65]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 84|Community 84]]
- [[_COMMUNITY_Community 85|Community 85]]
- [[_COMMUNITY_Community 86|Community 86]]
- [[_COMMUNITY_Community 87|Community 87]]
- [[_COMMUNITY_Community 88|Community 88]]

## God Nodes (most connected - your core abstractions)
1. `Severity` - 127 edges
2. `_f()` - 122 edges
3. `Finding` - 115 edges
4. `remediate_sync()` - 112 edges
5. `AgentReport` - 80 edges
6. `make_finding()` - 74 edges
7. `AnalysisReport` - 65 edges
8. `make_gap()` - 46 edges
9. `RemediationError` - 45 edges
10. `ArchitectureReview` - 44 edges

## Surprising Connections (you probably didn't know these)
- `Severity` --uses--> `Severity`  [INFERRED]
  tests/test_security_rules.py → app/models.py
- `TestAdvisoryLanguageDetection` --uses--> `RemediationError`  [INFERRED]
  tests/test_remediator.py → app/agents/remediator.py
- `TestAiAnalysisCategoryInference` --uses--> `RemediationError`  [INFERRED]
  tests/test_remediator.py → app/agents/remediator.py
- `TestCompanionResourceRequired` --uses--> `RemediationError`  [INFERRED]
  tests/test_remediator.py → app/agents/remediator.py
- `TestCosmeticDriftFilter` --uses--> `RemediationError`  [INFERRED]
  tests/test_remediator.py → app/agents/remediator.py

## Import Cycles
- None detected.

## Communities (89 total, 2 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.10
Nodes (19): compute_drift(), Compute finding-level and score-level drift between two reports.      All compar, _full_report(), _llm_finding(), AnalysisReport, Finding, Tests for drift detection (Phase 3.2).  Reference: app/core/drift.py  These test, The whole point of the fix: LLM findings don't affect drift score. (+11 more)

### Community 1 - "Community 1"
Cohesion: 0.10
Nodes (28): _detect_json_indent(), _dump_docs_for_kind(), _ensure_pod_spec(), _filename_kind(), _find_workload_doc(), _fix_k8s(), _iter_containers(), _k8s_container_match() (+20 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (50): drift_endpoint(), Find past reports with similar risk profiles., Compare a report against the most recent prior scan of the same bundle.      Pha, similar_reports_endpoint(), AnalysisReport, Finding, AnalysisReport, Collection (+42 more)

### Community 3 - "Community 3"
Cohesion: 0.12
Nodes (11): extract_k8s_resources(), get_containers(), get_pod_spec(), get_resource_name(), Group parsed K8s documents by resource kind., Extract containers from a pod spec., Get pod spec from various resource types., Get the name of a K8s resource. (+3 more)

### Community 4 - "Community 4"
Cohesion: 0.10
Nodes (44): analyze_cost(), Run cost analysis using rules + LLM reasoning., analyze_reliability(), Run reliability analysis using rules + LLM reasoning., analyze_security(), _detect_infra_type(), Detect whether files are kubernetes, terraform, mixed, or none (non-infra)., Run security analysis using rules + LLM reasoning. (+36 more)

### Community 5 - "Community 5"
Cohesion: 0.09
Nodes (42): _locate_file_for_finding(), Find which uploaded file holds the resource the finding is about.      Returns `, _f(), Tests for Phase 3.4 Auto-Remediation.  Covers: - File discovery: finding -> file, The Reliability/Cost agents emit findings with category="ai-analysis"     that f, Real failure mode from samples/vulnerable-infra.tf: Reliability         Agent em, The inference helper must be a no-op for findings with a real         rule-engin, When the inference table doesn't match (novel title, unknown         resource ty (+34 more)

### Community 6 - "Community 6"
Cohesion: 0.08
Nodes (24): Configuration: env-driven settings for the platform.  LLM provider is selected v, Settings, Any, _build_anthropic(), _build_google(), _build_ollama(), _build_openai(), get_llm() (+16 more)

### Community 7 - "Community 7"
Cohesion: 0.08
Nodes (27): Any, parse_kubernetes_yaml(), Parse Kubernetes YAML (supports multi-document YAML)., _k8s_bundle(), Bug from samples/good-chart-1.1.0.tgz: the Reliability Agent's     rule-engine ', If the deployment already has a strategy block, the fixer         refuses to ove, Pods don't have an update strategy. If the LLM somehow emits         a strategy, The fixer adds default 25%/0 values — must surface a warning         so the user (+19 more)

### Community 8 - "Community 8"
Cohesion: 0.09
Nodes (18): enrich_findings_with_compliance(), get_controls_for_finding(), Mutates report in-place: sets `finding.compliance_controls` on every finding., Return the compliance controls that this finding implicates.      Lookup priorit, make_finding(), The bug regression test: an Azure-only upload must NOT show         CIS AWS Foun, GCP-only upload must NOT show CIS AWS or CIS K8s. (CIS GCP IS shown         — se, Azure-only upload MUST show CIS Azure Foundations Benchmark. (+10 more)

### Community 9 - "Community 9"
Cohesion: 0.15
Nodes (19): CompanionResourceRequired, _looks_like_file_path(), NonPatchableFinding, PatchValidationError, True if the resource string looks like a Helm template path or a     file path r, Raised when remediation cannot proceed (no file match, no fixer, etc.)., The finding is advisory — it has no associated resource in any file     and is n, The finding requires creating a NEW Kubernetes resource alongside     the existi (+11 more)

### Community 10 - "Community 10"
Cohesion: 0.16
Nodes (7): is_non_patchable(), Return True for findings that don't map to any file-level edit.      These are t, Findings whose resource is N/A, empty, or a whole-infrastructure     sentinel ca, The bug from the screenshot: 'Lack of Commitment Discounts' with         resourc, Existing API code that catches RemediationError still catches         the new No, Phase 3.5 bug: the Compliance Agent emits roll-up findings whose         resourc, TestNonPatchableFindings

### Community 11 - "Community 11"
Cohesion: 0.18
Nodes (7): Run deterministic security checks on parsed K8s resources., run_security_rules(), has_finding_with(), Severity, Tests for security rule-based checks (run_security_rules + run_terraform_securit, Phase 1 regression: pod-level runAsNonRoot should suppress per-container finding, TestKubernetesSecurityRules

### Community 12 - "Community 12"
Cohesion: 0.24
Nodes (8): Run deterministic cost checks on parsed Terraform resources., run_terraform_cost_rules(), has_finding_with(), Tests for cost rule-based checks (run_cost_rules + run_terraform_cost_rules).  R, retention_in_days=0 means never expire — should still flag., Pre-v4 inline lifecycle_rule also suppresses., PROVISIONED with high capacity should flag., TestTerraformCostRules

### Community 13 - "Community 13"
Cohesion: 0.13
Nodes (10): Finding, extract_keywords(), is_duplicate(), Insert spaces at camelCase and PascalCase boundaries.      'HorizontalPodAutosca, Extract significant keywords from text, with synonym expansion., Check if an LLM finding duplicates any rule finding using keyword overlap., _split_camelcase(), Tests for keyword extraction, finding-level dedup, and cross-cutting gap dedup. (+2 more)

### Community 14 - "Community 14"
Cohesion: 0.11
Nodes (27): AnalysisReport, Finding, ComplianceFrameworkScore, ComplianceScorecard, ComplianceScorecard, _build_control_assessability(), _classify_control(), compute_compliance_scorecard() (+19 more)

### Community 15 - "Community 15"
Cohesion: 0.20
Nodes (8): calculate_overall_score(), Calculate weighted overall score from agent reports + architecture review., make_report(), TestScoringWithPlugins, Tests for scoring math.  Reference code: - app/core/report.py::calculate_overall, Guard against drift between the test-side deductions table and prod., TestCalculateOverallScore, TestSeverityDeductionsInSync

### Community 16 - "Community 16"
Cohesion: 0.13
Nodes (10): Run deterministic security checks on parsed Terraform resources., run_terraform_security_rules(), Phase 2 regression: AWS-required wildcard actions must be exempt., Phase 2 regression: EC2 ENI actions also exempt (Lambda VPC requirement)., Counterpart: arbitrary action with Resource:'*' must still flag., Terraform interpolations make JSON unparseable; fall back to substring match., Mixed statement: xray exempt + s3:* on Resource:* → still flag because of s3:*., Phase 2: AWS provider v4+ encryption companion suppresses the finding. (+2 more)

### Community 17 - "Community 17"
Cohesion: 0.09
Nodes (25): AgentReport, Path, Run a single plugin agent and return its report (or None if skipped)., Discover (or accept) plugins and run them sequentially.      Returns the list of, run_all_plugins(), run_plugin(), discover_plugins(), PluginAgent (+17 more)

### Community 18 - "Community 18"
Cohesion: 0.13
Nodes (11): _detect_clouds(), _detect_clouds_from_resource(), Identify the cloud from a single Finding.resource string, or None.      K8s reso, Detect which clouds are present in the report.      Detection signals, in priori, Clean K8s upload (no findings) still detects kubernetes via extension., Phase 3.3 fix: a clean .tf file (no findings) must not falsely         imply AWS, Phase 3.3 regression: LLM-emitted findings sometimes use         ``resource="N/A, All-uppercase abbreviations like RDS, KMS, IAM, EC2, S3 are AWS         shorthan (+3 more)

### Community 19 - "Community 19"
Cohesion: 0.14
Nodes (22): compute_agent_score(), Apply the standard deduction table to a list of Finding objects., Return a callable that reads a sample file from the repo's samples/ dir., sample_loader(), _build_reports(), _parse_sample(), pytest_generate_tests(), Strict regression tests: run rule-based checks on each sample file and assert de (+14 more)

### Community 20 - "Community 20"
Cohesion: 0.13
Nodes (11): compute_fingerprints(), SHA256 fingerprinting for uploaded infrastructure file bundles.  Used by drift d, Compute per-file content hashes and a bundle hash over filenames.      Args:, Tests for SHA256 fingerprinting of uploaded file bundles.  Reference: app/core/f, Editing file content does NOT change the bundle hash. This is the         proper, Renaming a file DOES change the bundle hash — it's a different         bundle (d, Adding a new file to the upload set changes the bundle hash., Dict insertion order must not affect the bundle hash. (+3 more)

### Community 21 - "Community 21"
Cohesion: 0.11
Nodes (14): Runnable, expected_scores(), _FakeMessage, _FakeRunnable, mock_llm(), MockLLMHandle, Shared pytest fixtures for the AI Infrastructure Governance Platform test suite., Identify which agent is invoking based on system-prompt content.      Order matt (+6 more)

### Community 22 - "Community 22"
Cohesion: 0.25
Nodes (9): Run deterministic reliability checks on parsed Terraform resources., run_terraform_reliability_rules(), Build a parsed-Terraform resource dict shaped like extract_tf_resources output., tf_resource(), has_finding_with(), Tests for reliability rule-based checks (run_reliability_rules + run_terraform_r, HCL2 sometimes wraps single-instance config in a list., Phase 2 regression: queue named *_dlq must NOT flag for missing DLQ. (+1 more)

### Community 23 - "Community 23"
Cohesion: 0.29
Nodes (3): K8s upload, no findings → all assessable controls pass → 100%., A finding with empty compliance_controls is neutral., TestComputeScorecardSemantics

### Community 24 - "Community 24"
Cohesion: 0.21
Nodes (5): Bug from terraform-serverless.json: clicking Generate fix on     'S3 bucket with, If a companion resource of the same name already exists, we         refuse to si, Categories without a deterministic JSON fixer flow to LLM         cleanly (no cr, End-to-end on the actual samples/terraform-serverless.json., TestTerraformJsonFixers

### Community 25 - "Community 25"
Cohesion: 0.22
Nodes (16): analyze_architecture(), _build_infrastructure_summary(), _extract_k8s_resources(), _extract_tf_resources(), _format_findings(), Architecture Reviewer agent — cross-cutting tradeoff analysis across all agent f, Extract Kubernetes resource kinds and names from YAML content., Extract Terraform resource types and names from HCL content. (+8 more)

### Community 26 - "Community 26"
Cohesion: 0.16
Nodes (8): _is_cosmetic_drift(), Return True iff the difference between the two lines is cosmetic only:      - Pu, Walk original/patched in lockstep and revert lines that differ only     cosmetic, _strip_cosmetic_drift(), Different decoration character means it's an intentional change., Inserted lines (no original counterpart) flow through unchanged., The filter strips dash-rule comment drift and trailing-whitespace     drift from, TestCosmeticDriftFilter

### Community 27 - "Community 27"
Cohesion: 0.07
Nodes (53): Any, Finding, Severity, DependencyGraph, GraphEdge, GraphNode, Spof, BaseModel (+45 more)

### Community 28 - "Community 28"
Cohesion: 0.08
Nodes (33): Run the complete multi-agent analysis pipeline., run_analysis(), AnalysisRequest, analyze_infrastructure(), analyze_text(), delete_report_endpoint(), _flat_findings(), get_report_endpoint() (+25 more)

### Community 29 - "Community 29"
Cohesion: 0.17
Nodes (9): _count_resources(), Count the number of top-level resources in a patched file.      Used by :func:`_, Raise :class:`PatchValidationError` if the patch removed top-level     resources, _verify_no_resources_dropped(), Higher-leverage protection: ANY LLM patch that drops resources     from a multi-, The exact attack vector: LLM kept doc 1, dropped docs 2 and 3., Adding resources (e.g., an HPA companion) is fine., When either side is unparseable (-1), skip the check rather         than false-f (+1 more)

### Community 30 - "Community 30"
Cohesion: 0.17
Nodes (13): _locate_terraform_file(), Locate the .tf/.hcl/.json file containing ``aws_foo.bar``., parse_files_node(), Parse uploaded files and extract K8s + Terraform resources., Any, extract_tf_resources(), extract_tf_variables(), parse_terraform() (+5 more)

### Community 31 - "Community 31"
Cohesion: 0.12
Nodes (16): AI Infrastructure Governance & Architecture Intelligence Platform, API Endpoints, Architecture, Development, Docker, Environment Variables, License, Local Development (+8 more)

### Community 32 - "Community 32"
Cohesion: 0.12
Nodes (16): Adding a new rule, Cheat sheet, Conventions, Discover without running, Filter what runs, How the LLM mock works, Optional: coverage report, Running tests (+8 more)

### Community 33 - "Community 33"
Cohesion: 0.12
Nodes (15): Architecture, Data flow, Error handling, Existing skill migration (discoverability, not behavior), First plugin: compliance, Goal, Hard constraints (non-negotiable acceptance gates), New module: `app/core/plugin_loader.py` (execution layer) (+7 more)

### Community 34 - "Community 34"
Cohesion: 0.12
Nodes (9): The Cost-Agent LLM occasionally emits 2-segment Kind/name resources     (no name, Kind/name (no namespace) — match via exact name + Kind., Bug from the screenshot: the Cost LLM emitted         ``Deployment/my-chart`` ag, If the bundle has exactly ONE Deployment, even a name that         doesn't match, Two Deployments both contain 'app' in their name — the locator         must NOT, When two Deployments exist but one matches Kind/ns/name exactly,         layer 1, Kind/name resolves UNAMBIGUOUSLY when only one workload has         that exact n, Sanity: don't break the original happy path. (+1 more)

### Community 35 - "Community 35"
Cohesion: 0.25
Nodes (3): _calculate_architecture_score(), Calculate architecture score from gaps, capped by agent average.      The archit, TestArchitectureScore

### Community 36 - "Community 36"
Cohesion: 0.20
Nodes (8): _coerce_llm_payload(), _parse_llm_json_response(), Best-effort extraction of (patched_content, explanation) from a     local-LLM re, Normalize a parsed LLM payload to (patched_content, explanation)., Bug 2: the local LLM emits JSON with literal newlines inside string     values., The exact failure mode you saw: 'Invalid control character at: line 1 column 25', The LLM rambles before the JSON. Regex extraction rescues., TestLLMJsonParsing

### Community 37 - "Community 37"
Cohesion: 0.18
Nodes (11): export_report_pdf(), Phase 3.3 — render the report as an auditor-ready PDF.      Returns the PDF inli, AnalysisReport, _agent_score(), generate_pdf_report(), PDF export for governance reports (Phase 3.3).  Renders an AnalysisReport to a P, Render an AnalysisReport to a PDF byte stream.      Returns the raw bytes of the, _severity_color_hex() (+3 more)

### Community 38 - "Community 38"
Cohesion: 0.15
Nodes (12): make_agent_finding(), make_arch_response(), Canned LLM responses keyed by agent type.  Each agent's `chain.ainvoke(...)` is, Build an architecture-reviewer response. Useful for testing dedup filters     by, Build an agent finding for use inside an LLM-mocked response., Sanity tests for the mock_llm fixture.  The mock must intercept all 5 agent get_, The full pipeline runs end-to-end with no Ollama process available., Default mock returns empty findings — score equals rule-only baseline. (+4 more)

### Community 39 - "Community 39"
Cohesion: 0.28
Nodes (6): _filter_k8s_platform_gaps(), Drop gaps that are platform/cluster-level concerns for K8s/Helm infrastructure., make_gap(), Tests for the three architecture-reviewer gap filters.  Reference: app/agents/ar, Non-'terraform' infra_type follows the K8s filtering path., TestK8sPlatformGapFilter

### Community 40 - "Community 40"
Cohesion: 0.17
Nodes (12): parse_resource_value(), Parse K8s resource value to a numeric value., Run deterministic cost checks., run_cost_rules(), Run deterministic reliability checks., run_reliability_rules(), minimal_container(), minimal_deployment() (+4 more)

### Community 41 - "Community 41"
Cohesion: 0.15
Nodes (13): _find_tf_block_span(), Locate the byte span ``[start, end)`` of a Terraform resource block in     HCL s, Insert ``argument_lines`` (one or more lines, no trailing newline) just     befo, Remove all lines in the block that match ``key_regex`` at the start     (whitesp, If ``key`` exists in the block, replace its value with ``new_value_literal``., _tf_inject_argument_in_block(), _tf_remove_argument_in_block(), _tf_replace_block() (+5 more)

### Community 42 - "Community 42"
Cohesion: 0.07
Nodes (18): Synchronous wrapper around :func:`remediate` for tests / scripts.      Spawns a, remediate_sync(), End-to-end: LLM emits a patch with dash-line drift; the cleaned         diff has, The rule-based 'Security group open to 0.0.0.0/0' finding (which         is ingr, If the SG has no literal 0.0.0.0/0 (e.g. it uses var.allowed_cidrs),         the, Single-quoted, double-quoted, and bare strings must keep their         quoting s, Bug 3: LLM emits Helm template paths in resource field. The     locator now trea, Sanity: don't false-positive on legitimate Kind/ns/name. (+10 more)

### Community 43 - "Community 43"
Cohesion: 0.12
Nodes (22): _companion_template(), _fix_tf(), _fix_tf_json(), _fix_with_llm(), _infer_rule_category(), _make_unified_diff(), Return (yaml_template, suggested_filename) for the companion     resource implie, Apply a deterministic Terraform fix. Returns (patched, explanation, warnings). (+14 more)

### Community 44 - "Community 44"
Cohesion: 0.31
Nodes (3): _dedup_cross_cutting_gaps(), Remove cross-cutting gaps that merely echo what individual agents already found., TestDedupCrossCuttingGaps

### Community 45 - "Community 45"
Cohesion: 0.27
Nodes (4): _filter_terraform_secrets_gap(), Drop secrets management gap if Terraform uses variable refs or manage_master_use, A gap with 'secret' alone but neither 'management' nor 'credential' is kept., TestTerraformSecretsGapFilter

### Community 46 - "Community 46"
Cohesion: 0.24
Nodes (11): AgentReport, Finding, _format_infra_content(), parse_llm_findings(), Shared LLM-agent execution helper.  Phase 3.5 extracts the LLM invoke -> parse -, Compute a 0-100 agent score from findings via severity deductions.      Identica, Concatenate uploaded files into a single prompt-ready block.      Matches the ``, Parse an LLM JSON response into findings + summary.      Tolerates a leading/tra (+3 more)

### Community 47 - "Community 47"
Cohesion: 0.17
Nodes (12): API Changes, Architecture Decisions, Challenges Addressed, Components Delivered, Phase 2 Late Additions: Anti-Hallucination & Quality Hardening, Phase 2 — Skill Files, Architecture Reviewer, Report Memory & Multi-Cloud Expansion, Pipeline Change, Rule Coverage After Phase 2 (+4 more)

### Community 48 - "Community 48"
Cohesion: 0.14
Nodes (8): _is_advisory_language(), True when the finding's recommendation reads like a decision/research     task,, Bug from terraform-serverless.json's "DynamoDB Billing Mode" finding:     Cost A, A real fixable finding whose recommendation starts with an         imperative ve, Critical: only LLM-produced (category='ai-analysis') findings         are eligib, Unit test for _is_advisory_language., Critical efficiency check: advisory-language findings must NEVER         reach t, TestAdvisoryLanguageDetection

### Community 49 - "Community 49"
Cohesion: 0.36
Nodes (3): _filter_terraform_speculative_gaps(), Drop Terraform gaps that flag absence of strategies rather than misconfiguration, TestTerraformSpeculativeGapFilter

### Community 50 - "Community 50"
Cohesion: 0.18
Nodes (11): API Added, Architecture Decisions, Challenges Addressed, Components Delivered, Framework Matrix (Verified Against All 6 Samples), Models Added, Phase 3.3 — Compliance Framework Mapping, Production-Grade Samples Added (+3 more)

### Community 51 - "Community 51"
Cohesion: 0.16
Nodes (13): Any, Any, Path, _derive_agent_name(), _plugin_from_meta(), Plugin registry — discovers agent plugins from ``skills/*.md`` frontmatter.  Pha, Choose a display name for the agent.      Prefers an explicit ``agent_name`` in, Build a ``PluginAgent`` from one skill's frontmatter, or None if not eligible. (+5 more)

### Community 52 - "Community 52"
Cohesion: 0.20
Nodes (10): API & Frontend, Challenges Addressed, Components Delivered, Critical Design Decisions (Locked in by Tests), K8s Categories with Deterministic Fixers, Phase 3.4 — Auto-Remediation (Scaffolding), Terraform Categories with Deterministic Fixers, Test Sentinels (+2 more)

### Community 53 - "Community 53"
Cohesion: 0.22
Nodes (9): API Added, Architecture Decisions, Challenges Addressed, Components Delivered, Models Added, Phase 3.2 — Drift Detection, Tests Added, Verification (+1 more)

### Community 54 - "Community 54"
Cohesion: 0.22
Nodes (9): Architecture Decisions, Build Order, Challenges Addressed, Components Delivered, Coverage, Phase 2 Regression Sentinels (Non-Negotiable), Phase 3.1 — Pytest Regression Test Harness, Verification (+1 more)

### Community 55 - "Community 55"
Cohesion: 0.22
Nodes (9): Challenges Addressed, Components Delivered, Core Architecture Decisions, External Review Feedback, Known Limitations (Phase 1), Phase 1 — MVP: Intelligent Infrastructure Analysis, Rule Coverage, Sample Files Created (+1 more)

### Community 56 - "Community 56"
Cohesion: 0.29
Nodes (5): Return parent resource names that have a companion resource of the given type., resources_with_companion(), When the bucket field isn't standard, scan all string values., HCL2 sometimes wraps single string values in lists., TestResourcesWithCompanion

### Community 57 - "Community 57"
Cohesion: 0.33
Nodes (6): Architecture Decisions, Challenges Addressed, Components Delivered, Phase 3.5 — Plugin Harness (Dynamic Agent Registration), Verification, What Was Built

### Community 59 - "Community 59"
Cohesion: 0.25
Nodes (7): Architecture Decisions, Challenges Addressed, Components Delivered, Development Phases, Phase 4.1 + 4.5 — Resource Dependency Graph & SPOF Detector, Verification, What Was Built

### Community 60 - "Community 60"
Cohesion: 0.25
Nodes (4): Bug from k8s-api-deployment.json: a Kubernetes manifest uploaded as     .json wa, A 4-space-indented input should round-trip with 4 spaces., Hardcoded-secret fix on a JSON manifest: the env section is         rewritten an, TestK8sJsonRoundTrip

### Community 61 - "Community 61"
Cohesion: 0.25
Nodes (4): Bug from good-chart-1.1.0.tgz: the LLM emitted INFO findings     congratulating, Keep/Maintain only fire when they're the FIRST word of the         recommendatio, Critical efficiency check — praise findings must never reach         the LLM. Se, TestPraiseFindings

### Community 62 - "Community 62"
Cohesion: 0.13
Nodes (18): build_analysis_graph(), Build the LangGraph multi-agent analysis workflow (sequential for local LLM)., AgentReport, AnalysisReport, ArchitectureReview, AnalysisReport, ArchitectureReview, _compliance_adapter() (+10 more)

### Community 63 - "Community 63"
Cohesion: 0.40
Nodes (4): Compliance Agent (Phase 3.5 plugin), Scoring, What it does, Why a plugin

### Community 65 - "Community 65"
Cohesion: 0.50
Nodes (3): Intentional issues (for analysis testing), my-chart, Package and test

### Community 84 - "Community 84"
Cohesion: 0.43
Nodes (3): _delta(), Compute current minus baseline. Returns None if either side is missing., TestDeltaHelper

### Community 85 - "Community 85"
Cohesion: 0.33
Nodes (6): Re-parse the patched output. Raise PatchValidationError if it fails., _validate_patch(), test_validate_passes_for_well_formed_terraform(), test_validate_rejects_empty_patched_content(), test_validate_rejects_unparseable_terraform(), test_validate_rejects_unparseable_yaml()

### Community 86 - "Community 86"
Cohesion: 0.47
Nodes (3): _finding_signature(), Stable identity for a finding across runs.      Tuple of (agent, category, title, TestFindingSignature

### Community 87 - "Community 87"
Cohesion: 0.50
Nodes (4): compare_reports_endpoint(), Compare two reports and return score deltas., compare_reports(), Compare two reports and return score deltas.

### Community 88 - "Community 88"
Cohesion: 0.50
Nodes (3): The exact bug the user hit: uploading my-chart-1.0.0.tgz, then     clicking Gene, Skips automatically if `helm` CLI isn't installed — the chart         renderer n, TestHelmChartCachePath

## Knowledge Gaps
- **116 isolated node(s):** `Settings`, `Any`, `Path`, `Path`, `Any` (+111 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Finding` connect `Community 4` to `Community 0`, `Community 1`, `Community 2`, `Community 5`, `Community 7`, `Community 8`, `Community 9`, `Community 10`, `Community 11`, `Community 12`, `Community 13`, `Community 14`, `Community 15`, `Community 16`, `Community 17`, `Community 18`, `Community 22`, `Community 23`, `Community 24`, `Community 26`, `Community 27`, `Community 29`, `Community 34`, `Community 36`, `Community 37`, `Community 40`, `Community 42`, `Community 43`, `Community 46`, `Community 48`, `Community 58`, `Community 60`, `Community 61`, `Community 62`, `Community 84`, `Community 86`, `Community 88`?**
  _High betweenness centrality (0.164) - this node is a cross-community bridge._
- **Why does `Severity` connect `Community 4` to `Community 0`, `Community 1`, `Community 2`, `Community 5`, `Community 7`, `Community 9`, `Community 10`, `Community 11`, `Community 12`, `Community 13`, `Community 15`, `Community 16`, `Community 17`, `Community 19`, `Community 22`, `Community 24`, `Community 25`, `Community 26`, `Community 27`, `Community 29`, `Community 34`, `Community 35`, `Community 36`, `Community 39`, `Community 40`, `Community 42`, `Community 43`, `Community 44`, `Community 45`, `Community 46`, `Community 48`, `Community 49`, `Community 60`, `Community 61`, `Community 62`, `Community 84`, `Community 86`, `Community 88`?**
  _High betweenness centrality (0.162) - this node is a cross-community bridge._
- **Why does `get_llm()` connect `Community 6` to `Community 1`, `Community 4`, `Community 43`, `Community 46`, `Community 25`?**
  _High betweenness centrality (0.051) - this node is a cross-community bridge._
- **Are the 95 inferred relationships involving `Severity` (e.g. with `CompanionResourceRequired` and `NonPatchableFinding`) actually correct?**
  _`Severity` has 95 INFERRED edges - model-reasoned connections that need verification._
- **Are the 81 inferred relationships involving `Finding` (e.g. with `CompanionResourceRequired` and `NonPatchableFinding`) actually correct?**
  _`Finding` has 81 INFERRED edges - model-reasoned connections that need verification._
- **Are the 52 inferred relationships involving `AgentReport` (e.g. with `AnalysisState` and `AgentReport`) actually correct?**
  _`AgentReport` has 52 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Architecture Reviewer agent — cross-cutting tradeoff analysis across all agent f`, `Drop gaps that are platform/cluster-level concerns for K8s/Helm infrastructure.`, `Drop Terraform gaps that flag absence of strategies rather than misconfiguration` to the rest of the system?**
  _497 weakly-connected nodes found - possible documentation gaps or missing edges._