# Graph Report - AI-Infrastructure-Governance-Architecture-Intelligence-Platform  (2026-07-19)

## Corpus Check
- 87 files · ~98,056 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1556 nodes · 3966 edges · 93 communities (91 shown, 2 thin omitted)
- Extraction: 87% EXTRACTED · 13% INFERRED · 0% AMBIGUOUS · INFERRED: 499 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `7480ff9a`
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
- [[_COMMUNITY_Community 64|Community 64]]
- [[_COMMUNITY_Community 65|Community 65]]
- [[_COMMUNITY_Community 66|Community 66]]
- [[_COMMUNITY_Community 84|Community 84]]
- [[_COMMUNITY_Community 85|Community 85]]
- [[_COMMUNITY_Community 88|Community 88]]
- [[_COMMUNITY_Community 89|Community 89]]
- [[_COMMUNITY_Community 90|Community 90]]
- [[_COMMUNITY_Community 91|Community 91]]
- [[_COMMUNITY_Community 92|Community 92]]
- [[_COMMUNITY_Community 93|Community 93]]
- [[_COMMUNITY_Community 94|Community 94]]

## God Nodes (most connected - your core abstractions)
1. `Severity` - 130 edges
2. `_f()` - 127 edges
3. `remediate_sync()` - 117 edges
4. `Finding` - 116 edges
5. `AgentReport` - 80 edges
6. `make_finding()` - 74 edges
7. `AnalysisReport` - 70 edges
8. `RemediationError` - 47 edges
9. `make_gap()` - 46 edges
10. `ArchitectureReview` - 44 edges

## Surprising Connections (you probably didn't know these)
- `Severity` --uses--> `Severity`  [INFERRED]
  tests/test_security_rules.py → app/models.py
- `Finding` --uses--> `RemediationError`  [INFERRED]
  tests/test_remediator.py → app/agents/remediator.py
- `Severity` --uses--> `RemediationError`  [INFERRED]
  tests/test_remediator.py → app/agents/remediator.py
- `TestAdvisoryLanguageDetection` --uses--> `RemediationError`  [INFERRED]
  tests/test_remediator.py → app/agents/remediator.py
- `TestAiAnalysisCategoryInference` --uses--> `RemediationError`  [INFERRED]
  tests/test_remediator.py → app/agents/remediator.py

## Import Cycles
- None detected.

## Communities (93 total, 2 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.10
Nodes (20): compute_drift(), Return rule-only score for an agent, or None if the agent isn't in the report., Recompute the overall score from rule-only per-agent scores.      Architecture i, Compute finding-level and score-level drift between two reports.      All compar, _rule_only_overall_score(), _rule_only_score(), _full_report(), _llm_finding() (+12 more)

### Community 1 - "Community 1"
Cohesion: 0.17
Nodes (9): apply_structured_edit(), _parse_structured_edit(), Return the per-resource config dict from parsed Terraform JSON.      Shape: ``pa, Extract a structured-edit JSON object from an LLM response.      Returns the dic, Apply a structured edit to file content using the deterministic editors.      Su, _tfjson_get_resource_block(), Phase 4 follow-up: the LLM fallback for Terraform asks the model for a     SMALL, The whole point: applying an edit must NOT drop other resources. (+1 more)

### Community 2 - "Community 2"
Cohesion: 0.08
Nodes (30): drift_endpoint(), _flat_findings(), Compare a report against the most recent prior scan of the same bundle.      Pha, Return findings in a stable order matching how the frontend indexes them., Phase 3.4 — generate a code patch that fixes a single finding.      The finding, remediate_finding(), AnalysisReport, Finding (+22 more)

### Community 3 - "Community 3"
Cohesion: 0.13
Nodes (9): extract_k8s_resources(), get_pod_spec(), get_resource_name(), Group parsed K8s documents by resource kind., Get pod spec from various resource types., Get the name of a K8s resource., Tests for parsers — K8s YAML/JSON and Terraform HCL/JSON.  Reference: - app/pars, Documents the CURRENT behavior — kind:List is NOT expanded into items. (+1 more)

### Community 4 - "Community 4"
Cohesion: 0.09
Nodes (54): analyze_cost(), Run cost analysis using rules + LLM reasoning., Synthesize all agent reports into final report., supervisor_node(), Caller re-supplies the original file bundle at remediation time.      Reports ar, RemediationRequest, AgentReport, Finding (+46 more)

### Community 5 - "Community 5"
Cohesion: 0.08
Nodes (45): _f(), Tests for Phase 3.4 Auto-Remediation.  Covers: - File discovery: finding -> file, Setting an existing key should overwrite, not duplicate., The Reliability/Cost agents emit findings with category="ai-analysis"     that f, Real failure mode from samples/vulnerable-infra.tf: Reliability         Agent em, The inference helper must be a no-op for findings with a real         rule-engin, When the inference table doesn't match (novel title, unknown         resource ty, Title keywords match but resource prefix doesn't — must NOT         route to the (+37 more)

### Community 6 - "Community 6"
Cohesion: 0.08
Nodes (24): Configuration: env-driven settings for the platform.  LLM provider is selected v, Settings, Any, _build_anthropic(), _build_google(), _build_ollama(), _build_openai(), get_llm() (+16 more)

### Community 7 - "Community 7"
Cohesion: 0.07
Nodes (29): Any, parse_kubernetes_yaml(), Parse Kubernetes YAML (supports multi-document YAML)., _k8s_bundle(), Critical efficiency check — praise findings must never reach         the LLM. Se, Bug from samples/good-chart-1.1.0.tgz: the Reliability Agent's     rule-engine ', If the deployment already has a strategy block, the fixer         refuses to ove, Pods don't have an update strategy. If the LLM somehow emits         a strategy (+21 more)

### Community 8 - "Community 8"
Cohesion: 0.08
Nodes (24): _detect_clouds(), Detect which clouds are present in the report.      Detection signals, in priori, make_finding(), _full_report(), Clean K8s upload (no findings) still detects kubernetes via extension., Phase 3.3 fix: a clean .tf file (no findings) must not falsely         imply AWS, Phase 3.3 regression: LLM-emitted findings sometimes use         ``resource="N/A, All-uppercase abbreviations like RDS, KMS, IAM, EC2, S3 are AWS         shorthan (+16 more)

### Community 9 - "Community 9"
Cohesion: 0.05
Nodes (66): Any, Finding, Severity, DependencyGraph, GraphEdge, GraphNode, Spof, _add_k8s_ingress_refs() (+58 more)

### Community 10 - "Community 10"
Cohesion: 0.14
Nodes (8): is_non_patchable(), Return True for findings that don't map to any file-level edit.      These are t, Findings whose resource is N/A, empty, or a whole-infrastructure     sentinel ca, The bug from the screenshot: 'Lack of Commitment Discounts' with         resourc, Existing API code that catches RemediationError still catches         the new No, Phase 3.5 bug: the Compliance Agent emits roll-up findings whose         resourc, Phase 4.5 bug: the Resilience Agent emits SPOF findings (category         'resil, TestNonPatchableFindings

### Community 11 - "Community 11"
Cohesion: 0.21
Nodes (10): Run deterministic security checks on parsed K8s resources., run_security_rules(), minimal_container(), minimal_deployment(), Return a Deployment dict shaped like extract_k8s_resources output., has_finding_with(), Severity, Tests for security rule-based checks (run_security_rules + run_terraform_securit (+2 more)

### Community 12 - "Community 12"
Cohesion: 0.15
Nodes (13): parse_resource_value(), Parse K8s resource value to a numeric value., Run deterministic cost checks on parsed Terraform resources., Run deterministic cost checks., run_cost_rules(), run_terraform_cost_rules(), has_finding_with(), Tests for cost rule-based checks (run_cost_rules + run_terraform_cost_rules).  R (+5 more)

### Community 13 - "Community 13"
Cohesion: 0.43
Nodes (3): get_controls_for_finding(), Return the compliance controls that this finding implicates.      Lookup priorit, TestEnrichFindings

### Community 14 - "Community 14"
Cohesion: 0.12
Nodes (17): _build_control_assessability(), _detect_clouds_from_resource(), _empty_mappings(), _entry_controls(), _entry_domain(), load_mappings(), Compliance framework mapping (Phase 3.3 — cloud-aware).  Tags every rule-based f, Identify the cloud from a single Finding.resource string, or None.      K8s reso (+9 more)

### Community 15 - "Community 15"
Cohesion: 0.12
Nodes (21): AgentReport, Finding, AgentReport, _format_infra_content(), parse_llm_findings(), Shared LLM-agent execution helper.  Phase 3.5 extracts the LLM invoke -> parse -, Compute a 0-100 agent score from findings via severity deductions.      Identica, Concatenate uploaded files into a single prompt-ready block.      Matches the `` (+13 more)

### Community 16 - "Community 16"
Cohesion: 0.13
Nodes (10): Run deterministic security checks on parsed Terraform resources., run_terraform_security_rules(), Phase 2 regression: AWS-required wildcard actions must be exempt., Phase 2 regression: EC2 ENI actions also exempt (Lambda VPC requirement)., Counterpart: arbitrary action with Resource:'*' must still flag., Terraform interpolations make JSON unparseable; fall back to substring match., Mixed statement: xray exempt + s3:* on Resource:* → still flag because of s3:*., Phase 2: AWS provider v4+ encryption companion suppresses the finding. (+2 more)

### Community 17 - "Community 17"
Cohesion: 0.07
Nodes (31): Any, Path, Any, Path, _derive_agent_name(), discover_plugins(), _plugin_from_meta(), PluginAgent (+23 more)

### Community 18 - "Community 18"
Cohesion: 0.17
Nodes (15): AnalysisReport, Finding, ComplianceFrameworkScore, ComplianceScorecard, ComplianceScorecard, _classify_control(), compute_compliance_scorecard(), _is_control_assessable() (+7 more)

### Community 19 - "Community 19"
Cohesion: 0.15
Nodes (19): Return a callable that reads a sample file from the repo's samples/ dir., sample_loader(), _parse_sample(), pytest_generate_tests(), Strict regression tests: run rule-based checks on each sample file and assert de, Parametrize the regression tests across every sample in the manifest., For each manifest entry, assert overall_score within tolerance., Per-agent scores must match the manifest exactly (deterministic). (+11 more)

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
Cohesion: 0.12
Nodes (22): _find_tf_block_span(), _fix_tf(), Locate the byte span ``[start, end)`` of a Terraform resource block in     HCL s, Insert ``argument_lines`` (one or more lines, no trailing newline) just     befo, Remove all lines in the block that match ``key_regex`` at the start     (whitesp, If ``key`` exists in the block, replace its value with ``new_value_literal``., Apply a deterministic Terraform fix. Returns (patched, explanation, warnings)., Add a new entry under parsed["resource"][rtype][rname] = config.      Creates th (+14 more)

### Community 24 - "Community 24"
Cohesion: 0.16
Nodes (10): Synchronous wrapper around :func:`remediate` for tests / scripts.      Spawns a, remediate_sync(), End-to-end: LLM emits a patch with dash-line drift; the cleaned         diff has, A finding with NO deterministic rule goes to the LLM, which returns a         ti, Bug from terraform-serverless.json: clicking Generate fix on     'S3 bucket with, If a companion resource of the same name already exists, we         refuse to si, Categories without a deterministic JSON fixer flow to LLM         cleanly (no cr, End-to-end on the actual samples/terraform-serverless.json. (+2 more)

### Community 25 - "Community 25"
Cohesion: 0.22
Nodes (15): analyze_architecture(), _build_infrastructure_summary(), _extract_k8s_resources(), _extract_tf_resources(), _format_findings(), Architecture Reviewer agent — cross-cutting tradeoff analysis across all agent f, Extract Kubernetes resource kinds and names from YAML content., Extract Terraform resource types and names from HCL content. (+7 more)

### Community 26 - "Community 26"
Cohesion: 0.16
Nodes (8): _is_cosmetic_drift(), Return True iff the difference between the two lines is cosmetic only:      - Pu, Walk original/patched in lockstep and revert lines that differ only     cosmetic, _strip_cosmetic_drift(), The filter strips dash-rule comment drift and trailing-whitespace     drift from, Different decoration character means it's an intentional change., Inserted lines (no original counterpart) flow through unchanged., TestCosmeticDriftFilter

### Community 27 - "Community 27"
Cohesion: 0.25
Nodes (3): _calculate_architecture_score(), Calculate architecture score from gaps, capped by agent average.      The archit, TestArchitectureScore

### Community 28 - "Community 28"
Cohesion: 0.07
Nodes (24): CompanionResourceRequired, NonPatchableFinding, PatchValidationError, The finding is advisory — it has no associated resource in any file     and is n, The finding requires creating a NEW Kubernetes resource alongside     the existi, Raised when a generated patch produces unparseable output., Finding, Severity (+16 more)

### Community 29 - "Community 29"
Cohesion: 0.17
Nodes (9): _count_resources(), Count the number of top-level resources in a patched file.      Used by :func:`_, Raise :class:`PatchValidationError` if the patch removed top-level     resources, _verify_no_resources_dropped(), Higher-leverage protection: ANY LLM patch that drops resources     from a multi-, The exact attack vector: LLM kept doc 1, dropped docs 2 and 3., Adding resources (e.g., an HPA companion) is fine., When either side is unparseable (-1), skip the check rather         than false-f (+1 more)

### Community 30 - "Community 30"
Cohesion: 0.16
Nodes (18): _companion_template(), _fix_tf_json(), _fix_with_llm(), _infer_rule_category(), _is_advisory_language(), _locate_file_for_finding(), Return (yaml_template, suggested_filename) for the companion     resource implie, Apply a deterministic fix to a Terraform JSON file.      Same category coverage (+10 more)

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
Cohesion: 0.17
Nodes (15): AnalysisState, architecture_reviewer_node(), build_analysis_graph(), cost_node(), parse_files_node(), plugin_agents_node(), Run dynamically-registered plugin agents (Phase 3.5).      Discovers plugins fro, Build the LangGraph multi-agent analysis workflow (sequential for local LLM). (+7 more)

### Community 36 - "Community 36"
Cohesion: 0.10
Nodes (15): _parse_llm_json_response(), _parse_sentinel_response(), Extract (patched_content, explanation) from the sentinel format.      Bulletproo, Best-effort extraction of (patched_content, explanation) from a     local-LLM re, Bug 2: the local LLM emits JSON with literal newlines inside string     values., The exact failure mode you saw: 'Invalid control character at: line 1 column 25', The LLM rambles before the JSON. Regex extraction rescues., The azure-average.tf failure: the model emitted patched_content with         a r (+7 more)

### Community 37 - "Community 37"
Cohesion: 0.23
Nodes (7): AnalysisReport, _agent_score(), generate_pdf_report(), PDF export for governance reports (Phase 3.3).  Renders an AnalysisReport to a P, Render an AnalysisReport to a PDF byte stream.      Returns the raw bytes of the, _severity_color_hex(), TestPDFExport

### Community 38 - "Community 38"
Cohesion: 0.11
Nodes (19): Run the complete multi-agent analysis pipeline., run_analysis(), make_agent_finding(), make_arch_response(), Canned LLM responses keyed by agent type.  Each agent's `chain.ainvoke(...)` is, Build an architecture-reviewer response. Useful for testing dedup filters     by, Build an agent finding for use inside an LLM-mocked response., Sanity tests for the mock_llm fixture.  The mock must intercept all 5 agent get_ (+11 more)

### Community 39 - "Community 39"
Cohesion: 0.23
Nodes (10): analyze_reliability(), Run reliability analysis using rules + LLM reasoning., analyze_security(), _detect_infra_type(), Detect whether files are kubernetes, terraform, mixed, or none (non-infra)., Run security analysis using rules + LLM reasoning., get_agent_prompt(), Get the prompt for a specific agent and infrastructure type.      Args: (+2 more)

### Community 40 - "Community 40"
Cohesion: 0.26
Nodes (4): Run deterministic reliability checks., run_reliability_rules(), Phase 2 regression: HPA targeting a Deployment suppresses SPOF finding., TestKubernetesReliabilityRules

### Community 41 - "Community 41"
Cohesion: 0.11
Nodes (26): _detect_json_indent(), _dump_docs_for_kind(), _ensure_pod_spec(), _find_workload_doc(), _fix_k8s(), _iter_containers(), _k8s_container_match(), _make_unified_diff() (+18 more)

### Community 42 - "Community 42"
Cohesion: 0.15
Nodes (6): Bug from k8s-api-deployment.json: clicking Generate fix on     'No HorizontalPod, The API endpoint catches NonPatchableFinding for 409.         CompanionResourceR, An empty bundle with an HPA finding still raises         CompanionResourceRequir, Probes findings ARE in-place patches (add to container spec) —         they shou, Resource with only Kind/name (no namespace) still produces a         valid HPA t, TestCompanionResourceRequired

### Community 43 - "Community 43"
Cohesion: 0.22
Nodes (9): Any, extract_tf_resources(), extract_tf_variables(), parse_terraform(), Extract resources from parsed Terraform.      Handles two formats:     - HCL2 pa, Extract variables from parsed Terraform., Parse Terraform HCL content., Phase 2 regression: extract_tf_resources must handle JSON dict format. (+1 more)

### Community 44 - "Community 44"
Cohesion: 0.19
Nodes (6): extract_keywords(), Insert spaces at camelCase and PascalCase boundaries.      'HorizontalPodAutosca, Extract significant keywords from text, with synonym expansion., _split_camelcase(), Tests for keyword extraction, finding-level dedup, and cross-cutting gap dedup., TestExtractKeywords

### Community 45 - "Community 45"
Cohesion: 0.29
Nodes (6): Architecture Decisions, Challenges Addressed, Development Phases, Phase 4.2 + 4.4 — Blast Radius, Architecture Diagram & UI Panel, Verification, What Was Built

### Community 46 - "Community 46"
Cohesion: 0.36
Nodes (4): _dedup_cross_cutting_gaps(), Remove cross-cutting gaps that merely echo what individual agents already found., make_report(), TestDedupCrossCuttingGaps

### Community 47 - "Community 47"
Cohesion: 0.17
Nodes (12): API Changes, Architecture Decisions, Challenges Addressed, Components Delivered, Phase 2 Late Additions: Anti-Hallucination & Quality Hardening, Phase 2 — Skill Files, Architecture Reviewer, Report Memory & Multi-Cloud Expansion, Pipeline Change, Rule Coverage After Phase 2 (+4 more)

### Community 48 - "Community 48"
Cohesion: 0.27
Nodes (4): _filter_terraform_secrets_gap(), Drop secrets management gap if Terraform uses variable refs or manage_master_use, A gap with 'secret' alone but neither 'management' nor 'credential' is kept., TestTerraformSecretsGapFilter

### Community 49 - "Community 49"
Cohesion: 0.18
Nodes (9): _filter_k8s_platform_gaps(), _filter_terraform_speculative_gaps(), Drop gaps that are platform/cluster-level concerns for K8s/Helm infrastructure., Drop Terraform gaps that flag absence of strategies rather than misconfiguration, make_gap(), Tests for the three architecture-reviewer gap filters.  Reference: app/agents/ar, Non-'terraform' infra_type follows the K8s filtering path., TestK8sPlatformGapFilter (+1 more)

### Community 50 - "Community 50"
Cohesion: 0.18
Nodes (11): API Added, Architecture Decisions, Challenges Addressed, Components Delivered, Framework Matrix (Verified Against All 6 Samples), Models Added, Phase 3.3 — Compliance Framework Mapping, Production-Grade Samples Added (+3 more)

### Community 51 - "Community 51"
Cohesion: 0.33
Nodes (4): Finding, is_duplicate(), Check if an LLM finding duplicates any rule finding using keyword overlap., TestIsDuplicate

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
Cohesion: 0.08
Nodes (31): analyze_infrastructure(), analyze_text(), blast_radius_endpoint(), compare_reports_endpoint(), diagram_endpoint(), export_report_pdf(), get_report_endpoint(), health_check() (+23 more)

### Community 57 - "Community 57"
Cohesion: 0.33
Nodes (6): Architecture Decisions, Challenges Addressed, Components Delivered, Phase 3.5 — Plugin Harness (Dynamic Agent Registration), Verification, What Was Built

### Community 59 - "Community 59"
Cohesion: 0.33
Nodes (6): Architecture Decisions, Challenges Addressed, Components Delivered, Phase 4.1 + 4.5 — Resource Dependency Graph & SPOF Detector, Verification, What Was Built

### Community 60 - "Community 60"
Cohesion: 0.29
Nodes (4): The 'Overly Permissive Egress on Security Group' finding (LLM-emitted     title), The rule-based 'Security group open to 0.0.0.0/0' finding (which         is ingr, If the SG has no literal 0.0.0.0/0 (e.g. it uses var.allowed_cidrs),         the, TestEgressFixer

### Community 61 - "Community 61"
Cohesion: 0.47
Nodes (3): _finding_signature(), Stable identity for a finding across runs.      Tuple of (agent, category, title, TestFindingSignature

### Community 62 - "Community 62"
Cohesion: 0.50
Nodes (3): compute_agent_score(), Per-agent score deductions table.  This duplicates the table from app/agents/{se, Apply the standard deduction table to a list of Finding objects.

### Community 63 - "Community 63"
Cohesion: 0.40
Nodes (4): Compliance Agent (Phase 3.5 plugin), Scoring, What it does, Why a plugin

### Community 64 - "Community 64"
Cohesion: 0.29
Nodes (4): _mermaid_html(), Wrap a Mermaid diagram string in a self-contained HTML doc that renders     it c, Phase 4 Architecture panel: SPOFs, dependency diagram, blast radius., _render_architecture_panel()

### Community 65 - "Community 65"
Cohesion: 0.50
Nodes (3): Intentional issues (for analysis testing), my-chart, Package and test

### Community 84 - "Community 84"
Cohesion: 0.43
Nodes (3): _delta(), Compute current minus baseline. Returns None if either side is missing., TestDeltaHelper

### Community 85 - "Community 85"
Cohesion: 0.38
Nodes (4): _looks_like_file_path(), True if the resource string looks like a Helm template path or a     file path r, Bug from samples/good-chart-1.1.0.tgz: the Security Agent's LLM     emitted reso, TestHelmAnnotatedPathDetection

### Community 88 - "Community 88"
Cohesion: 0.07
Nodes (18): delete_report_endpoint(), Delete a specific report., Collection, delete_report(), _get_collection(), Delete a specific report from ChromaDB and the in-memory cache., Get or create the ChromaDB collection (lazy singleton)., Persist a report to ChromaDB. Returns report_id. (+10 more)

### Community 89 - "Community 89"
Cohesion: 0.29
Nodes (5): Return parent resource names that have a companion resource of the given type., resources_with_companion(), When the bucket field isn't standard, scan all string values., HCL2 sometimes wraps single string values in lists., TestResourcesWithCompanion

### Community 90 - "Community 90"
Cohesion: 0.29
Nodes (7): _coerce_llm_payload(), _json_value_from_edit(), Normalize a parsed LLM payload to (patched_content, explanation)., Convert a JSON edit value to an HCL literal.      - Python bool -> true/false, Coerce an edit value into a native JSON value for Terraform-JSON., _value_to_hcl_literal(), Any

### Community 91 - "Community 91"
Cohesion: 0.29
Nodes (4): Bug 3: LLM emits Helm template paths in resource field. The     locator now trea, Sanity: don't false-positive on legitimate Kind/ns/name., Sanity: aws_*.foo doesn't match the file-path heuristic., TestTemplatePathDetection

### Community 92 - "Community 92"
Cohesion: 0.33
Nodes (6): _filename_kind(), _locate_kubernetes_file(), _locate_terraform_file(), Return one of: 'kubernetes_yaml', 'terraform_hcl', 'terraform_json',     or 'unk, Locate the .tf/.hcl/.json file containing ``aws_foo.bar``., Locate the .yaml/.yml file containing the named K8s resource.      The canonical

### Community 93 - "Community 93"
Cohesion: 0.33
Nodes (6): Re-parse the patched output. Raise PatchValidationError if it fails., _validate_patch(), test_validate_passes_for_well_formed_terraform(), test_validate_rejects_empty_patched_content(), test_validate_rejects_unparseable_terraform(), test_validate_rejects_unparseable_yaml()

### Community 94 - "Community 94"
Cohesion: 0.16
Nodes (7): calculate_overall_score(), Calculate weighted overall score from agent reports + architecture review., TestScoringWithPlugins, Tests for scoring math.  Reference code: - app/core/report.py::calculate_overall, Guard against drift between the test-side deductions table and prod., TestCalculateOverallScore, TestSeverityDeductionsInSync

## Knowledge Gaps
- **120 isolated node(s):** `Settings`, `Any`, `Path`, `Path`, `Any` (+115 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Severity` connect `Community 4` to `Community 0`, `Community 1`, `Community 2`, `Community 5`, `Community 7`, `Community 9`, `Community 10`, `Community 11`, `Community 12`, `Community 15`, `Community 16`, `Community 17`, `Community 19`, `Community 22`, `Community 23`, `Community 24`, `Community 25`, `Community 26`, `Community 27`, `Community 28`, `Community 29`, `Community 30`, `Community 34`, `Community 36`, `Community 39`, `Community 40`, `Community 41`, `Community 42`, `Community 44`, `Community 46`, `Community 48`, `Community 49`, `Community 51`, `Community 60`, `Community 61`, `Community 62`, `Community 84`, `Community 85`, `Community 90`, `Community 91`, `Community 94`?**
  _High betweenness centrality (0.219) - this node is a cross-community bridge._
- **Why does `Finding` connect `Community 4` to `Community 0`, `Community 1`, `Community 2`, `Community 5`, `Community 7`, `Community 8`, `Community 9`, `Community 10`, `Community 11`, `Community 12`, `Community 13`, `Community 14`, `Community 15`, `Community 16`, `Community 17`, `Community 18`, `Community 22`, `Community 23`, `Community 24`, `Community 26`, `Community 28`, `Community 29`, `Community 30`, `Community 34`, `Community 36`, `Community 37`, `Community 39`, `Community 40`, `Community 41`, `Community 42`, `Community 51`, `Community 58`, `Community 60`, `Community 61`, `Community 84`, `Community 85`, `Community 90`, `Community 91`, `Community 94`?**
  _High betweenness centrality (0.155) - this node is a cross-community bridge._
- **Why does `_f()` connect `Community 5` to `Community 34`, `Community 4`, `Community 7`, `Community 42`, `Community 10`, `Community 60`, `Community 24`, `Community 91`, `Community 28`?**
  _High betweenness centrality (0.042) - this node is a cross-community bridge._
- **Are the 98 inferred relationships involving `Severity` (e.g. with `CompanionResourceRequired` and `NonPatchableFinding`) actually correct?**
  _`Severity` has 98 INFERRED edges - model-reasoned connections that need verification._
- **Are the 82 inferred relationships involving `Finding` (e.g. with `CompanionResourceRequired` and `NonPatchableFinding`) actually correct?**
  _`Finding` has 82 INFERRED edges - model-reasoned connections that need verification._
- **Are the 52 inferred relationships involving `AgentReport` (e.g. with `AnalysisState` and `AgentReport`) actually correct?**
  _`AgentReport` has 52 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Architecture Reviewer agent — cross-cutting tradeoff analysis across all agent f`, `Drop gaps that are platform/cluster-level concerns for K8s/Helm infrastructure.`, `Drop Terraform gaps that flag absence of strategies rather than misconfiguration` to the rest of the system?**
  _527 weakly-connected nodes found - possible documentation gaps or missing edges._