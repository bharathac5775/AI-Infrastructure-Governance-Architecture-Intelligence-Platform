# Graph Report - AI-Infrastructure-Governance-Architecture-Intelligence-Platform  (2026-07-20)

## Corpus Check
- 131 files · ~465,310 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1806 nodes · 4473 edges · 109 communities (105 shown, 4 thin omitted)
- Extraction: 89% EXTRACTED · 11% INFERRED · 0% AMBIGUOUS · INFERRED: 499 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `4ccebce1`
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
- [[_COMMUNITY_Community 67|Community 67]]
- [[_COMMUNITY_Community 68|Community 68]]
- [[_COMMUNITY_Community 69|Community 69]]
- [[_COMMUNITY_Community 70|Community 70]]
- [[_COMMUNITY_Community 71|Community 71]]
- [[_COMMUNITY_Community 72|Community 72]]
- [[_COMMUNITY_Community 73|Community 73]]
- [[_COMMUNITY_Community 74|Community 74]]
- [[_COMMUNITY_Community 75|Community 75]]
- [[_COMMUNITY_Community 76|Community 76]]
- [[_COMMUNITY_Community 77|Community 77]]
- [[_COMMUNITY_Community 78|Community 78]]
- [[_COMMUNITY_Community 80|Community 80]]
- [[_COMMUNITY_Community 81|Community 81]]
- [[_COMMUNITY_Community 84|Community 84]]
- [[_COMMUNITY_Community 85|Community 85]]
- [[_COMMUNITY_Community 87|Community 87]]
- [[_COMMUNITY_Community 88|Community 88]]
- [[_COMMUNITY_Community 89|Community 89]]
- [[_COMMUNITY_Community 90|Community 90]]
- [[_COMMUNITY_Community 92|Community 92]]
- [[_COMMUNITY_Community 93|Community 93]]

## God Nodes (most connected - your core abstractions)
1. `_f()` - 133 edges
2. `Severity` - 130 edges
3. `remediate_sync()` - 121 edges
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

## Communities (109 total, 4 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.08
Nodes (25): Any, Path, Any, Path, _derive_agent_name(), discover_plugins(), _plugin_from_meta(), PluginAgent (+17 more)

### Community 1 - "Community 1"
Cohesion: 0.05
Nodes (53): AnalysisReport, Finding, ComplianceFrameworkScore, ComplianceScorecard, ComplianceScorecard, _build_control_assessability(), _classify_control(), compute_compliance_scorecard() (+45 more)

### Community 2 - "Community 2"
Cohesion: 0.10
Nodes (23): ArchitectureReview, compute_drift(), Return rule-only score for an agent, or None if the agent isn't in the report., Recompute the overall score from rule-only per-agent scores.      Architecture i, Compute finding-level and score-level drift between two reports.      All compar, _rule_only_overall_score(), _rule_only_score(), _full_report() (+15 more)

### Community 3 - "Community 3"
Cohesion: 0.13
Nodes (8): extract_k8s_resources(), get_pod_spec(), get_resource_name(), Group parsed K8s documents by resource kind., Get pod spec from various resource types., Get the name of a K8s resource., Documents the CURRENT behavior — kind:List is NOT expanded into items., TestKubernetesParser

### Community 4 - "Community 4"
Cohesion: 0.08
Nodes (24): Configuration: env-driven settings for the platform.  LLM provider is selected v, Settings, Any, _build_anthropic(), _build_google(), _build_ollama(), _build_openai(), get_llm() (+16 more)

### Community 5 - "Community 5"
Cohesion: 0.10
Nodes (45): Synchronous wrapper around :func:`remediate` for tests / scripts.      Spawns a, Re-parse the patched output. Raise PatchValidationError if it fails., remediate_sync(), _validate_patch(), parse_terraform(), Parse Terraform HCL content., Tests for Phase 3.4 Auto-Remediation.  Covers: - File discovery: finding -> file, Setting an existing key should overwrite, not duplicate. (+37 more)

### Community 6 - "Community 6"
Cohesion: 0.26
Nodes (18): Any, Finding, Severity, DependencyGraph, GraphEdge, GraphNode, Spof, BaseModel (+10 more)

### Community 7 - "Community 7"
Cohesion: 0.08
Nodes (28): Any, parse_kubernetes_yaml(), Parse Kubernetes YAML (supports multi-document YAML)., _k8s_bundle(), Bug from samples/good-chart-1.1.0.tgz: the Reliability Agent's     rule-engine ', If the deployment already has a strategy block, the fixer         refuses to ove, Pods don't have an update strategy. If the LLM somehow emits         a strategy, The fixer adds default 25%/0 values — must surface a warning         so the user (+20 more)

### Community 8 - "Community 8"
Cohesion: 0.11
Nodes (9): Bug from k8s-api-deployment.json: clicking Generate fix on     'No HorizontalPod, Bug from hardened-production.yaml: 'Stateful workload using         ephemeral st, Even with an empty bundle, the data-persistence finding raises         Companion, If the description doesn't contain a quoted volume name, the         template st, The API endpoint catches NonPatchableFinding for 409.         CompanionResourceR, An empty bundle with an HPA finding still raises         CompanionResourceRequir, Probes findings ARE in-place patches (add to container spec) —         they shou, Resource with only Kind/name (no namespace) still produces a         valid HPA t (+1 more)

### Community 9 - "Community 9"
Cohesion: 0.10
Nodes (15): _f(), End-to-end: LLM emits a patch with dash-line drift; the cleaned         diff has, A finding with NO deterministic rule goes to the LLM, which returns a         ti, End-to-end: the exact bug from the screenshot., The Reliability/Cost agents emit findings with category="ai-analysis"     that f, Real failure mode from samples/vulnerable-infra.tf: Reliability         Agent em, The inference helper must be a no-op for findings with a real         rule-engin, When the inference table doesn't match (novel title, unknown         resource ty (+7 more)

### Community 10 - "Community 10"
Cohesion: 0.47
Nodes (5): AnalysisReport, format_report_text(), Count findings by severity across all agents., Format report as readable text., severity_counts()

### Community 11 - "Community 11"
Cohesion: 0.06
Nodes (35): dependencies, class-variance-authority, clsx, lucide-react, mermaid, @radix-ui/react-dialog, @radix-ui/react-dropdown-menu, @radix-ui/react-slot (+27 more)

### Community 12 - "Community 12"
Cohesion: 0.20
Nodes (14): ArchitectureReviewPanel(), scoreTextClass(), SectionHeading(), ScoreHeader(), TONE_TEXT, isAdvisoryAgent(), scoreLabel(), scoreTone() (+6 more)

### Community 13 - "Community 13"
Cohesion: 0.10
Nodes (37): CompanionResourceRequired, NonPatchableFinding, Raised when remediation cannot proceed (no file match, no fixer, etc.)., The finding is advisory — it has no associated resource in any file     and is n, The finding requires creating a NEW Kubernetes resource alongside     the existi, RemediationError, AnalysisRequest, analyze_infrastructure() (+29 more)

### Community 14 - "Community 14"
Cohesion: 0.09
Nodes (28): drift_endpoint(), Compare a report against the most recent prior scan of the same bundle.      Pha, AnalysisReport, AnalysisReport, Finding, AnalysisReport, AnalysisReport, _agent_findings_by_prefix() (+20 more)

### Community 15 - "Community 15"
Cohesion: 0.21
Nodes (10): Run deterministic security checks on parsed K8s resources., run_security_rules(), minimal_container(), minimal_deployment(), Return a Deployment dict shaped like extract_k8s_resources output., has_finding_with(), Severity, Tests for security rule-based checks (run_security_rules + run_terraform_securit (+2 more)

### Community 16 - "Community 16"
Cohesion: 0.17
Nodes (10): _empty_mappings(), _entry_controls(), load_mappings(), Load and cache the compliance mappings JSON file., Extract the controls list from a mapping entry. Tolerates both the     new {doma, Every control prefix used in mappings must be in framework_prefix_map., Every (agent, category) entry must have a 'domain' field., Phase 3.3 fix: each framework must declare which clouds make it relevant. (+2 more)

### Community 17 - "Community 17"
Cohesion: 0.16
Nodes (11): Run deterministic cost checks on parsed Terraform resources., Run deterministic cost checks., run_cost_rules(), run_terraform_cost_rules(), has_finding_with(), Tests for cost rule-based checks (run_cost_rules + run_terraform_cost_rules).  R, retention_in_days=0 means never expire — should still flag., Pre-v4 inline lifecycle_rule also suppresses. (+3 more)

### Community 18 - "Community 18"
Cohesion: 0.10
Nodes (15): _parse_llm_json_response(), _parse_sentinel_response(), Extract (patched_content, explanation) from the sentinel format.      Bulletproo, Best-effort extraction of (patched_content, explanation) from a     local-LLM re, Bug 2: the local LLM emits JSON with literal newlines inside string     values., The exact failure mode you saw: 'Invalid control character at: line 1 column 25', The LLM rambles before the JSON. Regex extraction rescues., The azure-average.tf failure: the model emitted patched_content with         a r (+7 more)

### Community 19 - "Community 19"
Cohesion: 0.33
Nodes (6): AnalyzeWorkspace(), ApiError, useRunAnalysis(), TabsContent, TabsList, TabsTrigger

### Community 20 - "Community 20"
Cohesion: 0.14
Nodes (14): build_dependency_graph_model(), graph_from_model(), Convenience: build the graph and return the serialized model in one call., Rebuild a NetworkX DiGraph from the persisted DependencyGraph model., Render the dependency graph as a Mermaid ``flowchart LR`` string.      - Synthet, to_mermaid(), _fanin_tf(), Tests for the Phase 4.1 dependency graph + 4.5 SPOF detector.  Reference code: - (+6 more)

### Community 21 - "Community 21"
Cohesion: 0.21
Nodes (10): parse_resource_value(), Parse K8s resource value to a numeric value., analyze_reliability(), Run reliability analysis using rules + LLM reasoning., _detect_infra_type(), Detect whether files are kubernetes, terraform, mixed, or none (non-infra)., get_agent_prompt(), Get the prompt for a specific agent and infrastructure type.      Args: (+2 more)

### Community 22 - "Community 22"
Cohesion: 0.18
Nodes (16): FindingDetail(), AgentChip(), FilterSelect(), FindingsTable(), IndexedFinding, SEVERITIES, severityTone(), cn() (+8 more)

### Community 23 - "Community 23"
Cohesion: 0.09
Nodes (30): _detect_json_indent(), _dump_docs_for_kind(), _ensure_pod_spec(), _filename_kind(), _find_workload_doc(), _fix_k8s(), _iter_containers(), _k8s_container_match() (+22 more)

### Community 24 - "Community 24"
Cohesion: 0.13
Nodes (10): Run deterministic security checks on parsed Terraform resources., run_terraform_security_rules(), Phase 2 regression: AWS-required wildcard actions must be exempt., Phase 2 regression: EC2 ENI actions also exempt (Lambda VPC requirement)., Counterpart: arbitrary action with Resource:'*' must still flag., Terraform interpolations make JSON unparseable; fall back to substring match., Mixed statement: xray exempt + s3:* on Resource:* → still flag because of s3:*., Phase 2: AWS provider v4+ encryption companion suppresses the finding. (+2 more)

### Community 25 - "Community 25"
Cohesion: 0.06
Nodes (27): _calculate_architecture_score(), _dedup_cross_cutting_gaps(), _filter_k8s_platform_gaps(), _filter_terraform_secrets_gap(), _filter_terraform_speculative_gaps(), Drop secrets management gap if Terraform uses variable refs or manage_master_use, Calculate architecture score from gaps, capped by agent average.      The archit, Remove cross-cutting gaps that merely echo what individual agents already found. (+19 more)

### Community 26 - "Community 26"
Cohesion: 0.15
Nodes (16): ArchitecturePanel(), Mermaid, CompliancePanel(), TONE_TEXT, DeltaValue(), DriftPanel(), Crumb, PageHeader() (+8 more)

### Community 27 - "Community 27"
Cohesion: 0.20
Nodes (17): analyze_architecture(), _build_infrastructure_summary(), _extract_k8s_resources(), _extract_tf_resources(), _format_findings(), Architecture Reviewer agent — cross-cutting tradeoff analysis across all agent f, Extract Kubernetes resource kinds and names from YAML content., Extract Terraform resource types and names from HCL content. (+9 more)

### Community 28 - "Community 28"
Cohesion: 0.13
Nodes (11): compute_fingerprints(), SHA256 fingerprinting for uploaded infrastructure file bundles.  Used by drift d, Compute per-file content hashes and a bundle hash over filenames.      Args:, Tests for SHA256 fingerprinting of uploaded file bundles.  Reference: app/core/f, Editing file content does NOT change the bundle hash. This is the         proper, Renaming a file DOES change the bundle hash — it's a different         bundle (d, Adding a new file to the upload set changes the bundle hash., Dict insertion order must not affect the bundle hash. (+3 more)

### Community 29 - "Community 29"
Cohesion: 0.11
Nodes (14): Runnable, expected_scores(), _FakeMessage, _FakeRunnable, mock_llm(), MockLLMHandle, Shared pytest fixtures for the AI Infrastructure Governance Platform test suite., Identify which agent is invoking based on system-prompt content.      Order matt (+6 more)

### Community 30 - "Community 30"
Cohesion: 0.09
Nodes (22): compilerOptions, allowImportingTsExtensions, baseUrl, isolatedModules, jsx, lib, module, moduleDetection (+14 more)

### Community 31 - "Community 31"
Cohesion: 0.25
Nodes (9): Run deterministic reliability checks on parsed Terraform resources., run_terraform_reliability_rules(), Build a parsed-Terraform resource dict shaped like extract_tf_resources output., tf_resource(), has_finding_with(), Tests for reliability rule-based checks (run_reliability_rules + run_terraform_r, HCL2 sometimes wraps single-instance config in a list., Phase 2 regression: queue named *_dlq must NOT flag for missing DLQ. (+1 more)

### Community 32 - "Community 32"
Cohesion: 0.21
Nodes (7): Any, extract_tf_resources(), extract_tf_variables(), Extract resources from parsed Terraform.      Handles two formats:     - HCL2 pa, Extract variables from parsed Terraform., Phase 2 regression: extract_tf_resources must handle JSON dict format., TestTerraformParser

### Community 33 - "Community 33"
Cohesion: 0.12
Nodes (23): compute_agent_score(), Per-agent score deductions table.  This duplicates the table from app/agents/{se, Apply the standard deduction table to a list of Finding objects., Return a callable that reads a sample file from the repo's samples/ dir., sample_loader(), _build_reports(), _parse_sample(), pytest_generate_tests() (+15 more)

### Community 34 - "Community 34"
Cohesion: 0.13
Nodes (16): AgentReport, ArchitectureReview, BlastRadius, CompareResult, ComplianceFrameworkScore, ComplianceScorecard, CrossCuttingGap, DependencyGraph (+8 more)

### Community 35 - "Community 35"
Cohesion: 0.21
Nodes (5): Bug from terraform-serverless.json: clicking Generate fix on     'S3 bucket with, If a companion resource of the same name already exists, we         refuse to si, Categories without a deterministic JSON fixer flow to LLM         cleanly (no cr, End-to-end on the actual samples/terraform-serverless.json., TestTerraformJsonFixers

### Community 36 - "Community 36"
Cohesion: 0.12
Nodes (22): _companion_template(), _fix_tf(), _fix_tf_json(), _fix_with_llm(), _infer_rule_category(), _is_advisory_language(), _locate_file_for_finding(), _make_unified_diff() (+14 more)

### Community 37 - "Community 37"
Cohesion: 0.16
Nodes (8): _is_cosmetic_drift(), Return True iff the difference between the two lines is cosmetic only:      - Pu, Walk original/patched in lockstep and revert lines that differ only     cosmetic, _strip_cosmetic_drift(), The filter strips dash-rule comment drift and trailing-whitespace     drift from, Different decoration character means it's an intentional change., Inserted lines (no original counterpart) flow through unchanged., TestCosmeticDriftFilter

### Community 38 - "Community 38"
Cohesion: 0.11
Nodes (16): apply_structured_edit(), _coerce_llm_payload(), _json_value_from_edit(), _parse_structured_edit(), Return the per-resource config dict from parsed Terraform JSON.      Shape: ``pa, Normalize a parsed LLM payload to (patched_content, explanation)., Extract a structured-edit JSON object from an LLM response.      Returns the dic, Convert a JSON edit value to an HCL literal.      - Python bool -> true/false (+8 more)

### Community 39 - "Community 39"
Cohesion: 0.11
Nodes (11): is_non_patchable(), Return True for findings that don't map to any file-level edit.      These are t, Findings whose resource is N/A, empty, or a whole-infrastructure     sentinel ca, The LLM decorates sentinels — 'N/A (Global Opportunity)',         'Global (all r, A real resource that happens to carry a parenthetical note must stay         pat, The exact screenshot bug: 'Missing Commitment Discounts' with         resource=', The bug from the screenshot: 'Lack of Commitment Discounts' with         resourc, Existing API code that catches RemediationError still catches         the new No (+3 more)

### Community 40 - "Community 40"
Cohesion: 0.27
Nodes (3): extract_keywords(), Extract significant keywords from text, with synonym expansion., TestExtractKeywords

### Community 41 - "Community 41"
Cohesion: 0.15
Nodes (13): DiffView(), CompanionDetail, RemediationPanel(), ADVISORY_VERBS, AdvisoryKind, FILE_EXTS, getPatchability(), isScopeSentinel() (+5 more)

### Community 42 - "Community 42"
Cohesion: 0.24
Nodes (6): Return parent resource names that have a companion resource of the given type., resources_with_companion(), Tests for parsers — K8s YAML/JSON and Terraform HCL/JSON.  Reference: - app/pars, When the bucket field isn't standard, scan all string values., HCL2 sometimes wraps single string values in lists., TestResourcesWithCompanion

### Community 43 - "Community 43"
Cohesion: 0.17
Nodes (9): _count_resources(), Count the number of top-level resources in a patched file.      Used by :func:`_, Raise :class:`PatchValidationError` if the patch removed top-level     resources, _verify_no_resources_dropped(), Higher-leverage protection: ANY LLM patch that drops resources     from a multi-, The exact attack vector: LLM kept doc 1, dropped docs 2 and 3., Adding resources (e.g., an HPA companion) is fine., When either side is unparseable (-1), skip the check rather         than false-f (+1 more)

### Community 44 - "Community 44"
Cohesion: 0.14
Nodes (19): analyze_cost(), Run cost analysis using rules + LLM reasoning., AnalysisState, architecture_reviewer_node(), build_analysis_graph(), cost_node(), parse_files_node(), plugin_agents_node() (+11 more)

### Community 45 - "Community 45"
Cohesion: 0.18
Nodes (8): Finding, is_duplicate(), Shared utility functions for agent deduplication., Insert spaces at camelCase and PascalCase boundaries.      'HorizontalPodAutosca, Check if an LLM finding duplicates any rule finding using keyword overlap., _split_camelcase(), Tests for keyword extraction, finding-level dedup, and cross-cutting gap dedup., TestIsDuplicate

### Community 46 - "Community 46"
Cohesion: 0.47
Nodes (3): _finding_signature(), Stable identity for a finding across runs.      Tuple of (agent, category, title, TestFindingSignature

### Community 47 - "Community 47"
Cohesion: 0.10
Nodes (20): API, API request flow, Architecture, Configuration, Documentation, Highlights, Infrastructure Governance & Architecture Intelligence, License (+12 more)

### Community 48 - "Community 48"
Cohesion: 0.12
Nodes (16): Adding a new rule, Cheat sheet, Conventions, Discover without running, Filter what runs, How the LLM mock works, Optional: coverage report, Running tests (+8 more)

### Community 49 - "Community 49"
Cohesion: 0.14
Nodes (15): AppShell(), AGENT_VISUALS, AgentCopy, AGENTS, agentVisual, CAPABILITIES, FALLBACK_VISUAL, StepCopy (+7 more)

### Community 50 - "Community 50"
Cohesion: 0.33
Nodes (6): build_dependency_graph(), Build a directed dependency graph from parsed resources.      Every node carries, _edge_set(), _k8s(), Ingress backend.service.name (networking.k8s.io/v1) must create an         Ingre, TestKubernetesGraph

### Community 51 - "Community 51"
Cohesion: 0.12
Nodes (9): The Cost-Agent LLM occasionally emits 2-segment Kind/name resources     (no name, Kind/name (no namespace) — match via exact name + Kind., Bug from the screenshot: the Cost LLM emitted         ``Deployment/my-chart`` ag, If the bundle has exactly ONE Deployment, even a name that         doesn't match, Two Deployments both contain 'app' in their name — the locator         must NOT, When two Deployments exist but one matches Kind/ns/name exactly,         layer 1, Kind/name resolves UNAMBIGUOUSLY when only one workload has         that exact n, Sanity: don't break the original happy path. (+1 more)

### Community 52 - "Community 52"
Cohesion: 0.20
Nodes (9): export_report_pdf(), Phase 3.3 — render the report as an auditor-ready PDF.      Returns the PDF inli, AnalysisReport, _agent_score(), generate_pdf_report(), PDF export for governance reports (Phase 3.3).  Renders an AnalysisReport to a P, Render an AnalysisReport to a PDF byte stream.      Returns the raw bytes of the, _severity_color_hex() (+1 more)

### Community 53 - "Community 53"
Cohesion: 0.11
Nodes (19): Run the complete multi-agent analysis pipeline., run_analysis(), make_agent_finding(), make_arch_response(), Canned LLM responses keyed by agent type.  Each agent's `chain.ainvoke(...)` is, Build an architecture-reviewer response. Useful for testing dedup filters     by, Build an agent finding for use inside an LLM-mocked response., Sanity tests for the mock_llm fixture.  The mock must intercept all 5 agent get_ (+11 more)

### Community 54 - "Community 54"
Cohesion: 0.50
Nodes (4): compare_reports_endpoint(), Compare two reports and return score deltas., compare_reports(), Compare two reports and return score deltas.

### Community 55 - "Community 55"
Cohesion: 0.26
Nodes (4): Run deterministic reliability checks., run_reliability_rules(), Phase 2 regression: HPA targeting a Deployment suppresses SPOF finding., TestKubernetesReliabilityRules

### Community 56 - "Community 56"
Cohesion: 0.43
Nodes (3): _delta(), Compute current minus baseline. Returns None if either side is missing., TestDeltaHelper

### Community 57 - "Community 57"
Cohesion: 0.15
Nodes (12): Mermaid(), ReuploadPanel(), ResolvedTheme, Theme, ThemeContext, ThemeContextValue, ThemeProvider(), useTheme() (+4 more)

### Community 58 - "Community 58"
Cohesion: 0.17
Nodes (12): API Changes, Architecture Decisions, Challenges Addressed, Components Delivered, Phase 2 Late Additions: Anti-Hallucination & Quality Hardening, Phase 2 — Skill Files, Architecture Reviewer, Report Memory & Multi-Cloud Expansion, Pipeline Change, Rule Coverage After Phase 2 (+4 more)

### Community 59 - "Community 59"
Cohesion: 0.17
Nodes (6): Bug from terraform-serverless.json's "DynamoDB Billing Mode" finding:     Cost A, A real fixable finding whose recommendation starts with an         imperative ve, Critical: only LLM-produced (category='ai-analysis') findings         are eligib, Unit test for _is_advisory_language., Critical efficiency check: advisory-language findings must NEVER         reach t, TestAdvisoryLanguageDetection

### Community 61 - "Community 61"
Cohesion: 0.18
Nodes (11): _find_tf_block_span(), Locate the byte span ``[start, end)`` of a Terraform resource block in     HCL s, Insert ``argument_lines`` (one or more lines, no trailing newline) just     befo, Remove all lines in the block that match ``key_regex`` at the start     (whitesp, If ``key`` exists in the block, replace its value with ``new_value_literal``., _tf_inject_argument_in_block(), _tf_remove_argument_in_block(), _tf_replace_block() (+3 more)

### Community 62 - "Community 62"
Cohesion: 0.08
Nodes (54): analyze_security(), Run security analysis using rules + LLM reasoning., AgentReport, Finding, AgentReport, Finding, AgentReport, Finding (+46 more)

### Community 63 - "Community 63"
Cohesion: 0.05
Nodes (31): delete_report_endpoint(), list_reports_endpoint(), List recent reports with metadata., Delete a specific report., Find past reports with similar risk profiles., similar_reports_endpoint(), Serve a real dist file if one exists; otherwise return index.html so         Rea, spa_fallback() (+23 more)

### Community 64 - "Community 64"
Cohesion: 0.18
Nodes (11): API Added, Architecture Decisions, Challenges Addressed, Components Delivered, Framework Matrix (Verified Against All 6 Samples), Models Added, Phase 3.3 — Compliance Framework Mapping, Production-Grade Samples Added (+3 more)

### Community 65 - "Community 65"
Cohesion: 0.18
Nodes (10): compilerOptions, allowSyntheticDefaultImports, composite, emitDeclarationOnly, module, moduleResolution, outDir, skipLibCheck (+2 more)

### Community 66 - "Community 66"
Cohesion: 0.40
Nodes (3): blast_radius(), Compute the blast radius of ``resource``: everything that (transitively)     dep, TestBlastRadius

### Community 67 - "Community 67"
Cohesion: 0.20
Nodes (10): API & Frontend, Challenges Addressed, Components Delivered, Critical Design Decisions (Locked in by Tests), K8s Categories with Deterministic Fixers, Phase 3.4 — Auto-Remediation (Scaffolding), Terraform Categories with Deterministic Fixers, Test Sentinels (+2 more)

### Community 68 - "Community 68"
Cohesion: 0.24
Nodes (6): _add_tf_nodes_and_edges(), extract_tf_references(), _iter_strings(), Yield every string found anywhere inside a nested dict/list structure., Return the set of Terraform resource addresses (``type.name``) this     config r, TestTfReferences

### Community 69 - "Community 69"
Cohesion: 0.22
Nodes (9): API Added, Architecture Decisions, Challenges Addressed, Components Delivered, Models Added, Phase 3.2 — Drift Detection, Tests Added, Verification (+1 more)

### Community 70 - "Community 70"
Cohesion: 0.22
Nodes (9): Architecture Decisions, Build Order, Challenges Addressed, Components Delivered, Coverage, Phase 2 Regression Sentinels (Non-Negotiable), Phase 3.1 — Pytest Regression Test Harness, Verification (+1 more)

### Community 71 - "Community 71"
Cohesion: 0.22
Nodes (9): Challenges Addressed, Components Delivered, Core Architecture Decisions, External Review Feedback, Known Limitations (Phase 1), Phase 1 — MVP: Intelligent Infrastructure Analysis, Rule Coverage, Sample Files Created (+1 more)

### Community 72 - "Community 72"
Cohesion: 0.25
Nodes (7): Architecture Decisions, Challenges Addressed, Development Phases, Phase 4.2 + 4.4 — Blast Radius, Architecture Diagram & UI Panel, Phase 4 — Infrastructure Simulation — COMPLETE, Verification, What Was Built

### Community 73 - "Community 73"
Cohesion: 0.29
Nodes (4): _mermaid_html(), Wrap a Mermaid diagram string in a self-contained HTML doc that renders     it c, Phase 4 Architecture panel: SPOFs, dependency diagram, blast radius., _render_architecture_panel()

### Community 75 - "Community 75"
Cohesion: 0.15
Nodes (18): _add_k8s_ingress_refs(), _add_k8s_nodes_and_edges(), _add_k8s_workload_refs(), _ensure_ref_node(), _expand_k8s_lists(), _k8s_namespace(), _k8s_ref_node_id(), _mermaid_escape_label() (+10 more)

### Community 76 - "Community 76"
Cohesion: 0.14
Nodes (9): PatchValidationError, Raised when a generated patch produces unparseable output., The 'Overly Permissive Egress on Security Group' finding (LLM-emitted     title), The rule-based 'Security group open to 0.0.0.0/0' finding (which         is ingr, If the SG has no literal 0.0.0.0/0 (e.g. it uses var.allowed_cidrs),         the, Bug 1: deterministic K8s fixers must produce minimal diffs.      Before the ruam, Single-quoted, double-quoted, and bare strings must keep their         quoting s, TestEgressFixer (+1 more)

### Community 77 - "Community 77"
Cohesion: 0.29
Nodes (6): Build, Develop, Notes, Stack, Structure, Web Frontend

### Community 78 - "Community 78"
Cohesion: 0.26
Nodes (9): RunWatcher(), NAV, Sidebar(), ANALYSIS_MUTATION_KEY, AnalysisRunState, AnalyzePayload, useAnalysisRunState(), useClearAnalysisRuns() (+1 more)

### Community 80 - "Community 80"
Cohesion: 0.33
Nodes (6): Architecture Decisions, Challenges Addressed, Components Delivered, Phase 3.5 — Plugin Harness (Dynamic Agent Registration), Verification, What Was Built

### Community 81 - "Community 81"
Cohesion: 0.33
Nodes (6): Architecture Decisions, Challenges Addressed, Components Delivered, Phase 4.1 + 4.5 — Resource Dependency Graph & SPOF Detector, Verification, What Was Built

### Community 84 - "Community 84"
Cohesion: 0.25
Nodes (4): Bug 3: LLM emits Helm template paths in resource field. The     locator now trea, Sanity: don't false-positive on legitimate Kind/ns/name., Sanity: aws_*.foo doesn't match the file-path heuristic., TestTemplatePathDetection

### Community 85 - "Community 85"
Cohesion: 0.38
Nodes (4): _looks_like_file_path(), True if the resource string looks like a Helm template path or a     file path r, Bug from samples/good-chart-1.1.0.tgz: the Security Agent's LLM     emitted reso, TestHelmAnnotatedPathDetection

### Community 87 - "Community 87"
Cohesion: 0.40
Nodes (4): Compliance Agent (Phase 3.5 plugin), Scoring, What it does, Why a plugin

### Community 88 - "Community 88"
Cohesion: 0.50
Nodes (3): Intentional issues (for analysis testing), my-chart, Package and test

### Community 89 - "Community 89"
Cohesion: 0.25
Nodes (4): Bug from k8s-api-deployment.json: a Kubernetes manifest uploaded as     .json wa, A 4-space-indented input should round-trip with 4 spaces., Hardcoded-secret fix on a JSON manifest: the env section is         rewritten an, TestK8sJsonRoundTrip

### Community 90 - "Community 90"
Cohesion: 0.25
Nodes (4): Bug from good-chart-1.1.0.tgz: the LLM emitted INFO findings     congratulating, Keep/Maintain only fire when they're the FIRST word of the         recommendatio, Critical efficiency check — praise findings must never reach         the LLM. Se, TestPraiseFindings

## Knowledge Gaps
- **218 isolated node(s):** `Settings`, `Any`, `Path`, `Path`, `Any` (+213 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Severity` connect `Community 62` to `Community 0`, `Community 2`, `Community 5`, `Community 6`, `Community 7`, `Community 8`, `Community 9`, `Community 10`, `Community 13`, `Community 14`, `Community 15`, `Community 17`, `Community 18`, `Community 20`, `Community 21`, `Community 23`, `Community 24`, `Community 25`, `Community 27`, `Community 31`, `Community 33`, `Community 35`, `Community 36`, `Community 37`, `Community 38`, `Community 39`, `Community 40`, `Community 43`, `Community 44`, `Community 45`, `Community 46`, `Community 50`, `Community 51`, `Community 55`, `Community 56`, `Community 59`, `Community 66`, `Community 68`, `Community 75`, `Community 76`, `Community 84`, `Community 85`, `Community 89`, `Community 90`?**
  _High betweenness centrality (0.163) - this node is a cross-community bridge._
- **Why does `Finding` connect `Community 62` to `Community 0`, `Community 1`, `Community 2`, `Community 5`, `Community 6`, `Community 7`, `Community 8`, `Community 9`, `Community 13`, `Community 14`, `Community 15`, `Community 16`, `Community 17`, `Community 18`, `Community 21`, `Community 23`, `Community 24`, `Community 25`, `Community 27`, `Community 31`, `Community 35`, `Community 36`, `Community 37`, `Community 38`, `Community 39`, `Community 43`, `Community 44`, `Community 45`, `Community 46`, `Community 51`, `Community 52`, `Community 55`, `Community 56`, `Community 59`, `Community 74`, `Community 75`, `Community 76`, `Community 84`, `Community 85`, `Community 89`, `Community 90`?**
  _High betweenness centrality (0.118) - this node is a cross-community bridge._
- **Why does `_f()` connect `Community 9` to `Community 35`, `Community 5`, `Community 7`, `Community 8`, `Community 39`, `Community 76`, `Community 13`, `Community 51`, `Community 84`, `Community 89`, `Community 90`, `Community 59`, `Community 62`?**
  _High betweenness centrality (0.032) - this node is a cross-community bridge._
- **Are the 98 inferred relationships involving `Severity` (e.g. with `CompanionResourceRequired` and `NonPatchableFinding`) actually correct?**
  _`Severity` has 98 INFERRED edges - model-reasoned connections that need verification._
- **Are the 82 inferred relationships involving `Finding` (e.g. with `CompanionResourceRequired` and `NonPatchableFinding`) actually correct?**
  _`Finding` has 82 INFERRED edges - model-reasoned connections that need verification._
- **Are the 52 inferred relationships involving `AgentReport` (e.g. with `AnalysisState` and `AgentReport`) actually correct?**
  _`AgentReport` has 52 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Architecture Reviewer agent — cross-cutting tradeoff analysis across all agent f`, `Drop gaps that are platform/cluster-level concerns for K8s/Helm infrastructure.`, `Drop Terraform gaps that flag absence of strategies rather than misconfiguration` to the rest of the system?**
  _636 weakly-connected nodes found - possible documentation gaps or missing edges._