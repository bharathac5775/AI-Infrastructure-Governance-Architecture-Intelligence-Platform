# Graph Report - graphify-data-wt  (2026-07-20)

## Corpus Check
- 129 files · ~115,116 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1804 nodes · 4169 edges · 124 communities (118 shown, 6 thin omitted)
- Extraction: 88% EXTRACTED · 12% INFERRED · 0% AMBIGUOUS · INFERRED: 499 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `9cfe86fd`
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
- [[_COMMUNITY_Community 92|Community 92]]
- [[_COMMUNITY_Community 93|Community 93]]
- [[_COMMUNITY_Community 94|Community 94]]
- [[_COMMUNITY_Community 95|Community 95]]
- [[_COMMUNITY_Community 96|Community 96]]
- [[_COMMUNITY_Community 116|Community 116]]
- [[_COMMUNITY_Community 117|Community 117]]
- [[_COMMUNITY_Community 118|Community 118]]
- [[_COMMUNITY_Community 119|Community 119]]
- [[_COMMUNITY_Community 120|Community 120]]
- [[_COMMUNITY_Community 121|Community 121]]
- [[_COMMUNITY_Community 123|Community 123]]
- [[_COMMUNITY_Community 124|Community 124]]

## God Nodes (most connected - your core abstractions)
1. `_f()` - 133 edges
2. `remediate_sync()` - 121 edges
3. `Severity` - 108 edges
4. `Finding` - 101 edges
5. `make_finding()` - 71 edges
6. `AgentReport` - 66 edges
7. `AnalysisReport` - 58 edges
8. `RemediationError` - 46 edges
9. `make_gap()` - 43 edges
10. `_full_report()` - 39 edges

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

## Communities (124 total, 6 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.08
Nodes (27): Any, Path, Any, Path, _derive_agent_name(), discover_plugins(), _plugin_from_meta(), PluginAgent (+19 more)

### Community 1 - "Community 1"
Cohesion: 0.12
Nodes (16): compute_compliance_scorecard(), Compute per-framework compliance scores for a report.      Phase 3.3 fix: cloud-, _full_report(), End-to-end pin: a real-world AWS-only upload that includes an         LLM adviso, The bug regression test: an Azure-only upload must NOT show         CIS AWS Foun, GCP-only upload must NOT show CIS AWS or CIS K8s. (CIS GCP IS shown         — se, Azure-only upload MUST show CIS Azure Foundations Benchmark., GCP-only upload MUST show CIS GCP Foundations Benchmark. (+8 more)

### Community 2 - "Community 2"
Cohesion: 0.16
Nodes (14): compute_drift(), Compute finding-level and score-level drift between two reports.      All compar, make_finding(), _full_report(), _llm_finding(), Tests for drift detection (Phase 3.2).  Reference: app/core/drift.py  These test, Critical regression test: LLM findings must not appear in any bucket.          T, Phase 3.2 fix: identical rule findings produce zero deltas, even if         LLM (+6 more)

### Community 3 - "Community 3"
Cohesion: 0.17
Nodes (9): _count_resources(), Count the number of top-level resources in a patched file.      Used by :func:`_, Raise :class:`PatchValidationError` if the patch removed top-level     resources, _verify_no_resources_dropped(), Higher-leverage protection: ANY LLM patch that drops resources     from a multi-, The exact attack vector: LLM kept doc 1, dropped docs 2 and 3., Adding resources (e.g., an HPA companion) is fine., When either side is unparseable (-1), skip the check rather         than false-f (+1 more)

### Community 4 - "Community 4"
Cohesion: 0.09
Nodes (22): Any, _build_anthropic(), _build_google(), _build_ollama(), _build_openai(), get_llm(), LLMConfigError, Provider-agnostic LLM factory.  Every agent in the platform calls :func:`get_llm (+14 more)

### Community 5 - "Community 5"
Cohesion: 0.08
Nodes (44): Synchronous wrapper around :func:`remediate` for tests / scripts.      Spawns a, Re-parse the patched output. Raise PatchValidationError if it fails., remediate_sync(), _validate_patch(), Tests for Phase 3.4 Auto-Remediation.  Covers: - File discovery: finding -> file, Setting an existing key should overwrite, not duplicate., Real failure mode from samples/vulnerable-infra.tf: Reliability         Agent em, The inference helper must be a no-op for findings with a real         rule-engin (+36 more)

### Community 6 - "Community 6"
Cohesion: 0.28
Nodes (5): _looks_like_file_path(), True if the resource string looks like a Helm template path or a     file path r, Bug from samples/good-chart-1.1.0.tgz: the Security Agent's LLM     emitted reso, End-to-end: the exact bug from the screenshot., TestHelmAnnotatedPathDetection

### Community 7 - "Community 7"
Cohesion: 0.07
Nodes (25): Any, parse_kubernetes_yaml(), Parse Kubernetes YAML (supports multi-document YAML)., _k8s_bundle(), When two Deployments exist but one matches Kind/ns/name exactly,         layer 1, If the deployment already has a strategy block, the fixer         refuses to ove, Pods don't have an update strategy. If the LLM somehow emits         a strategy, The fixer adds default 25%/0 values — must surface a warning         so the user (+17 more)

### Community 8 - "Community 8"
Cohesion: 0.11
Nodes (9): Bug from k8s-api-deployment.json: clicking Generate fix on     'No HorizontalPod, Bug from hardened-production.yaml: 'Stateful workload using         ephemeral st, Even with an empty bundle, the data-persistence finding raises         Companion, If the description doesn't contain a quoted volume name, the         template st, The API endpoint catches NonPatchableFinding for 409.         CompanionResourceR, An empty bundle with an HPA finding still raises         CompanionResourceRequir, Probes findings ARE in-place patches (add to container spec) —         they shou, Resource with only Kind/name (no namespace) still produces a         valid HPA t (+1 more)

### Community 9 - "Community 9"
Cohesion: 0.19
Nodes (11): _parse_tf_resources(), Parse all Terraform-flavored files in the bundle into a flat resource     list., Any, extract_tf_resources(), extract_tf_variables(), parse_terraform(), Extract resources from parsed Terraform.      Handles two formats:     - HCL2 pa, Extract variables from parsed Terraform. (+3 more)

### Community 10 - "Community 10"
Cohesion: 0.12
Nodes (43): analyze_cost(), Run cost analysis using rules + LLM reasoning., analyze_reliability(), Run reliability analysis using rules + LLM reasoning., AgentReport, Finding, AgentReport, Finding (+35 more)

### Community 11 - "Community 11"
Cohesion: 0.06
Nodes (35): dependencies, class-variance-authority, clsx, lucide-react, mermaid, @radix-ui/react-dialog, @radix-ui/react-dropdown-menu, @radix-ui/react-slot (+27 more)

### Community 12 - "Community 12"
Cohesion: 0.11
Nodes (29): _add_k8s_ingress_refs(), _add_k8s_nodes_and_edges(), _add_k8s_workload_refs(), _add_tf_nodes_and_edges(), dependents_of(), _ensure_ref_node(), _expand_k8s_lists(), find_spofs() (+21 more)

### Community 13 - "Community 13"
Cohesion: 0.13
Nodes (15): blast_radius_endpoint(), compare_reports_endpoint(), diagram_endpoint(), export_report_pdf(), _flat_findings(), get_report_endpoint(), health_check(), Retrieve a previously generated report. (+7 more)

### Community 14 - "Community 14"
Cohesion: 0.14
Nodes (9): enrich_findings_with_compliance(), get_controls_for_finding(), Mutates report in-place: sets `finding.compliance_controls` on every finding., Return the compliance controls that this finding implicates.      Lookup priorit, Phase 3.3 extension: Azure NSG-open finding must carry CIS-Azure-6.2., Phase 3.3 extension: GCS uniform-access finding must carry CIS-GCP-5.2., Locking in: AWS findings must NEVER carry CIS-Azure or CIS-GCP., Locking in: K8s findings must NEVER carry CIS-Azure or CIS-GCP. (+1 more)

### Community 15 - "Community 15"
Cohesion: 0.23
Nodes (9): Run deterministic security checks on parsed K8s resources., run_security_rules(), minimal_container(), minimal_deployment(), Return a Deployment dict shaped like extract_k8s_resources output., has_finding_with(), Severity, Phase 1 regression: pod-level runAsNonRoot should suppress per-container finding (+1 more)

### Community 16 - "Community 16"
Cohesion: 0.11
Nodes (19): _build_control_assessability(), _classify_control(), _empty_mappings(), _entry_controls(), _entry_domain(), _is_control_assessable(), load_mappings(), Compliance framework mapping (Phase 3.3 — cloud-aware).  Tags every rule-based f (+11 more)

### Community 17 - "Community 17"
Cohesion: 0.14
Nodes (13): parse_resource_value(), Parse K8s resource value to a numeric value., Run deterministic cost checks on parsed Terraform resources., Run deterministic cost checks., run_cost_rules(), run_terraform_cost_rules(), has_finding_with(), Tests for cost rule-based checks (run_cost_rules + run_terraform_cost_rules).  R (+5 more)

### Community 18 - "Community 18"
Cohesion: 0.10
Nodes (15): _parse_llm_json_response(), _parse_sentinel_response(), Extract (patched_content, explanation) from the sentinel format.      Bulletproo, Best-effort extraction of (patched_content, explanation) from a     local-LLM re, Bug 2: the local LLM emits JSON with literal newlines inside string     values., The exact failure mode you saw: 'Invalid control character at: line 1 column 25', The LLM rambles before the JSON. Regex extraction rescues., The azure-average.tf failure: the model emitted patched_content with         a r (+7 more)

### Community 19 - "Community 19"
Cohesion: 0.33
Nodes (6): AnalyzeWorkspace(), ApiError, useRunAnalysis(), TabsContent, TabsList, TabsTrigger

### Community 20 - "Community 20"
Cohesion: 0.18
Nodes (11): build_dependency_graph_model(), Convenience: build the graph and return the serialized model in one call., Render the dependency graph as a Mermaid ``flowchart LR`` string.      - Synthet, to_mermaid(), _fanin_tf(), Tests for the Phase 4.1 dependency graph + 4.5 SPOF detector.  Reference code: -, Real ids have dots/slashes; the synthetic ids used as Mermaid node         ident, TestMermaid (+3 more)

### Community 21 - "Community 21"
Cohesion: 0.16
Nodes (14): list_reports_endpoint(), List recent reports with metadata., Find past reports with similar risk profiles., similar_reports_endpoint(), Collection, find_by_bundle_fingerprint(), find_similar_reports(), _get_collection() (+6 more)

### Community 22 - "Community 22"
Cohesion: 0.18
Nodes (16): FindingDetail(), AgentChip(), FilterSelect(), FindingsTable(), IndexedFinding, SEVERITIES, severityTone(), cn() (+8 more)

### Community 23 - "Community 23"
Cohesion: 0.13
Nodes (22): _detect_json_indent(), _dump_docs_for_kind(), _ensure_pod_spec(), _find_workload_doc(), _fix_k8s(), _iter_containers(), _k8s_container_match(), _new_ruamel_yaml() (+14 more)

### Community 24 - "Community 24"
Cohesion: 0.14
Nodes (13): Run deterministic security checks on parsed Terraform resources., run_terraform_security_rules(), Build a parsed-Terraform resource dict shaped like extract_tf_resources output., tf_resource(), Tests for security rule-based checks (run_security_rules + run_terraform_securit, Phase 2 regression: AWS-required wildcard actions must be exempt., Phase 2 regression: EC2 ENI actions also exempt (Lambda VPC requirement)., Counterpart: arbitrary action with Resource:'*' must still flag. (+5 more)

### Community 25 - "Community 25"
Cohesion: 0.27
Nodes (4): _filter_terraform_secrets_gap(), Drop secrets management gap if Terraform uses variable refs or manage_master_use, A gap with 'secret' alone but neither 'management' nor 'credential' is kept., TestTerraformSecretsGapFilter

### Community 26 - "Community 26"
Cohesion: 0.15
Nodes (16): ArchitecturePanel(), Mermaid, CompliancePanel(), TONE_TEXT, DeltaValue(), DriftPanel(), Crumb, PageHeader() (+8 more)

### Community 27 - "Community 27"
Cohesion: 0.20
Nodes (16): analyze_architecture(), _build_infrastructure_summary(), _extract_k8s_resources(), _extract_tf_resources(), _format_findings(), Architecture Reviewer agent — cross-cutting tradeoff analysis across all agent f, Extract Kubernetes resource kinds and names from YAML content., Extract Terraform resource types and names from HCL content. (+8 more)

### Community 28 - "Community 28"
Cohesion: 0.12
Nodes (11): compute_fingerprints(), SHA256 fingerprinting for uploaded infrastructure file bundles.  Used by drift d, Compute per-file content hashes and a bundle hash over filenames.      Args:, Tests for SHA256 fingerprinting of uploaded file bundles.  Reference: app/core/f, Editing file content does NOT change the bundle hash. This is the         proper, Renaming a file DOES change the bundle hash — it's a different         bundle (d, Adding a new file to the upload set changes the bundle hash., Dict insertion order must not affect the bundle hash. (+3 more)

### Community 29 - "Community 29"
Cohesion: 0.11
Nodes (14): Runnable, expected_scores(), _FakeMessage, _FakeRunnable, mock_llm(), MockLLMHandle, Shared pytest fixtures for the AI Infrastructure Governance Platform test suite., Identify which agent is invoking based on system-prompt content.      Order matt (+6 more)

### Community 30 - "Community 30"
Cohesion: 0.09
Nodes (22): compilerOptions, allowImportingTsExtensions, baseUrl, isolatedModules, jsx, lib, module, moduleDetection (+14 more)

### Community 31 - "Community 31"
Cohesion: 0.13
Nodes (11): Run deterministic reliability checks., Run deterministic reliability checks on parsed Terraform resources., run_reliability_rules(), run_terraform_reliability_rules(), has_finding_with(), Tests for reliability rule-based checks (run_reliability_rules + run_terraform_r, HCL2 sometimes wraps single-instance config in a list., Phase 2 regression: queue named *_dlq must NOT flag for missing DLQ. (+3 more)

### Community 32 - "Community 32"
Cohesion: 0.15
Nodes (10): _detect_clouds(), _detect_clouds_from_resource(), Identify the cloud from a single Finding.resource string, or None.      K8s reso, Detect which clouds are present in the report.      Detection signals, in priori, Clean K8s upload (no findings) still detects kubernetes via extension., Phase 3.3 fix: a clean .tf file (no findings) must not falsely         imply AWS, Phase 3.3 regression: LLM-emitted findings sometimes use         ``resource="N/A, All-uppercase abbreviations like RDS, KMS, IAM, EC2, S3 are AWS         shorthan (+2 more)

### Community 33 - "Community 33"
Cohesion: 0.15
Nodes (19): Return a callable that reads a sample file from the repo's samples/ dir., sample_loader(), _parse_sample(), pytest_generate_tests(), Strict regression tests: run rule-based checks on each sample file and assert de, Parametrize the regression tests across every sample in the manifest., For each manifest entry, assert overall_score within tolerance., Per-agent scores must match the manifest exactly (deterministic). (+11 more)

### Community 34 - "Community 34"
Cohesion: 0.13
Nodes (16): AgentReport, ArchitectureReview, BlastRadius, CompareResult, ComplianceFrameworkScore, ComplianceScorecard, CrossCuttingGap, DependencyGraph (+8 more)

### Community 35 - "Community 35"
Cohesion: 0.21
Nodes (5): Bug from terraform-serverless.json: clicking Generate fix on     'S3 bucket with, If a companion resource of the same name already exists, we         refuse to si, Categories without a deterministic JSON fixer flow to LLM         cleanly (no cr, End-to-end on the actual samples/terraform-serverless.json., TestTerraformJsonFixers

### Community 36 - "Community 36"
Cohesion: 0.16
Nodes (17): _companion_template(), _fix_tf(), _fix_with_llm(), _infer_rule_category(), _is_advisory_language(), _locate_file_for_finding(), _make_unified_diff(), Return (yaml_template, suggested_filename) for the companion     resource implie (+9 more)

### Community 37 - "Community 37"
Cohesion: 0.16
Nodes (8): _is_cosmetic_drift(), Return True iff the difference between the two lines is cosmetic only:      - Pu, Walk original/patched in lockstep and revert lines that differ only     cosmetic, _strip_cosmetic_drift(), The filter strips dash-rule comment drift and trailing-whitespace     drift from, Different decoration character means it's an intentional change., Inserted lines (no original counterpart) flow through unchanged., TestCosmeticDriftFilter

### Community 38 - "Community 38"
Cohesion: 0.20
Nodes (7): apply_structured_edit(), _parse_structured_edit(), Extract a structured-edit JSON object from an LLM response.      Returns the dic, Apply a structured edit to file content using the deterministic editors.      Su, Phase 4 follow-up: the LLM fallback for Terraform asks the model for a     SMALL, The whole point: applying an edit must NOT drop other resources., TestStructuredEditFallback

### Community 39 - "Community 39"
Cohesion: 0.09
Nodes (18): is_non_patchable(), Return True for findings that don't map to any file-level edit.      These are t, _f(), End-to-end: LLM emits a patch with dash-line drift; the cleaned         diff has, Findings whose resource is N/A, empty, or a whole-infrastructure     sentinel ca, The LLM decorates sentinels — 'N/A (Global Opportunity)',         'Global (all r, A real resource that happens to carry a parenthetical note must stay         pat, The exact screenshot bug: 'Missing Commitment Discounts' with         resource=' (+10 more)

### Community 40 - "Community 40"
Cohesion: 0.20
Nodes (14): ArchitectureReviewPanel(), scoreTextClass(), SectionHeading(), ScoreHeader(), TONE_TEXT, isAdvisoryAgent(), scoreLabel(), scoreTone() (+6 more)

### Community 41 - "Community 41"
Cohesion: 0.15
Nodes (13): DiffView(), CompanionDetail, RemediationPanel(), ADVISORY_VERBS, AdvisoryKind, FILE_EXTS, getPatchability(), isScopeSentinel() (+5 more)

### Community 42 - "Community 42"
Cohesion: 0.24
Nodes (4): calculate_overall_score(), Calculate weighted overall score from agent reports + architecture review., TestScoringWithPlugins, TestCalculateOverallScore

### Community 43 - "Community 43"
Cohesion: 0.11
Nodes (10): extract_k8s_resources(), get_containers(), get_pod_spec(), get_resource_name(), Group parsed K8s documents by resource kind., Extract containers from a pod spec., Get pod spec from various resource types., Get the name of a K8s resource. (+2 more)

### Community 44 - "Community 44"
Cohesion: 0.12
Nodes (21): analyze_security(), _detect_infra_type(), Detect whether files are kubernetes, terraform, mixed, or none (non-infra)., Run security analysis using rules + LLM reasoning., AnalysisState, architecture_reviewer_node(), build_analysis_graph(), cost_node() (+13 more)

### Community 45 - "Community 45"
Cohesion: 0.16
Nodes (7): extract_keywords(), Shared utility functions for agent deduplication., Insert spaces at camelCase and PascalCase boundaries.      'HorizontalPodAutosca, Extract significant keywords from text, with synonym expansion., _split_camelcase(), Tests for keyword extraction, finding-level dedup, and cross-cutting gap dedup., TestExtractKeywords

### Community 46 - "Community 46"
Cohesion: 0.18
Nodes (26): AnalysisRequest, Caller re-supplies the original file bundle at remediation time.      Reports ar, RemediationRequest, AnalysisReport, AnalysisReport, Finding, Any, Finding (+18 more)

### Community 47 - "Community 47"
Cohesion: 0.10
Nodes (19): API, API request flow, Architecture, Configuration, Documentation, Highlights, Infrastructure Governance & Architecture Intelligence, License (+11 more)

### Community 48 - "Community 48"
Cohesion: 0.12
Nodes (16): Adding a new rule, Cheat sheet, Conventions, Discover without running, Filter what runs, How the LLM mock works, Optional: coverage report, Running tests (+8 more)

### Community 49 - "Community 49"
Cohesion: 0.14
Nodes (15): AppShell(), AGENT_VISUALS, AgentCopy, AGENTS, agentVisual, CAPABILITIES, FALLBACK_VISUAL, StepCopy (+7 more)

### Community 50 - "Community 50"
Cohesion: 0.21
Nodes (8): build_dependency_graph(), Build a directed dependency graph from parsed resources.      Every node carries, _edge_set(), _k8s(), Ingress backend.service.name (networking.k8s.io/v1) must create an         Ingre, TestKubernetesGraph, TestMixedAndNamespacing, TestTerraformGraph

### Community 51 - "Community 51"
Cohesion: 0.07
Nodes (27): CompanionResourceRequired, NonPatchableFinding, PatchValidationError, The finding is advisory — it has no associated resource in any file     and is n, The finding requires creating a NEW Kubernetes resource alongside     the existi, Raised when a generated patch produces unparseable output., Finding, Severity (+19 more)

### Community 52 - "Community 52"
Cohesion: 0.21
Nodes (4): _calculate_architecture_score(), Calculate architecture score from gaps, capped by agent average.      The archit, Tests for scoring math.  Reference code: - app/core/report.py::calculate_overall, TestArchitectureScore

### Community 53 - "Community 53"
Cohesion: 0.13
Nodes (14): Run the complete multi-agent analysis pipeline., run_analysis(), analyze_text(), Analyze infrastructure from text content (for programmatic access)., Sanity tests for the mock_llm fixture.  The mock must intercept all 5 agent get_, The full pipeline runs end-to-end with no Ollama process available., Default mock returns empty findings — score equals rule-only baseline., test_mock_llm_default_finds_nothing_extra() (+6 more)

### Community 54 - "Community 54"
Cohesion: 0.32
Nodes (5): _filter_k8s_platform_gaps(), Drop gaps that are platform/cluster-level concerns for K8s/Helm infrastructure., make_gap(), Non-'terraform' infra_type follows the K8s filtering path., TestK8sPlatformGapFilter

### Community 55 - "Community 55"
Cohesion: 0.27
Nodes (10): Finding, _format_infra_content(), parse_llm_findings(), Shared LLM-agent execution helper.  Phase 3.5 extracts the LLM invoke -> parse -, Compute a 0-100 agent score from findings via severity deductions.      Identica, Concatenate uploaded files into a single prompt-ready block.      Matches the ``, Parse an LLM JSON response into findings + summary.      Tolerates a leading/tra, Run a single LLM-backed agent and return its ``AgentReport``.      This is the d (+2 more)

### Community 56 - "Community 56"
Cohesion: 0.43
Nodes (3): _delta(), Compute current minus baseline. Returns None if either side is missing., TestDeltaHelper

### Community 57 - "Community 57"
Cohesion: 0.15
Nodes (12): Mermaid(), ReuploadPanel(), ResolvedTheme, Theme, ThemeContext, ThemeContextValue, ThemeProvider(), useTheme() (+4 more)

### Community 58 - "Community 58"
Cohesion: 0.14
Nodes (16): AgentReport, _compliance_adapter(), Plugin loader — runs discovered plugin agents and returns their reports.  Phase, Run a single plugin agent and return its report (or None if skipped)., Discover (or accept) plugins and run them sequentially.      Returns the list of, Wrap the existing compliance scorecard into an ``AgentReport``.      Reuses ``ap, run_all_plugins(), run_plugin() (+8 more)

### Community 59 - "Community 59"
Cohesion: 0.17
Nodes (6): Bug from terraform-serverless.json's "DynamoDB Billing Mode" finding:     Cost A, A real fixable finding whose recommendation starts with an         imperative ve, Critical: only LLM-produced (category='ai-analysis') findings         are eligib, Unit test for _is_advisory_language., Critical efficiency check: advisory-language findings must NEVER         reach t, TestAdvisoryLanguageDetection

### Community 60 - "Community 60"
Cohesion: 0.29
Nodes (5): _dedup_cross_cutting_gaps(), Remove cross-cutting gaps that merely echo what individual agents already found., make_report(), Test fixture builders for Findings, CrossCuttingGaps, and AgentReports.  Default, TestDedupCrossCuttingGaps

### Community 61 - "Community 61"
Cohesion: 0.15
Nodes (16): _find_tf_block_span(), Locate the byte span ``[start, end)`` of a Terraform resource block in     HCL s, Insert ``argument_lines`` (one or more lines, no trailing newline) just     befo, Remove all lines in the block that match ``key_regex`` at the start     (whitesp, If ``key`` exists in the block, replace its value with ``new_value_literal``., Raised when remediation cannot proceed (no file match, no fixer, etc.)., RemediationError, _tf_inject_argument_in_block() (+8 more)

### Community 62 - "Community 62"
Cohesion: 0.25
Nodes (4): Bug from k8s-api-deployment.json: a Kubernetes manifest uploaded as     .json wa, A 4-space-indented input should round-trip with 4 spaces., Hardcoded-secret fix on a JSON manifest: the env section is         rewritten an, TestK8sJsonRoundTrip

### Community 63 - "Community 63"
Cohesion: 0.20
Nodes (8): _agent_score(), generate_pdf_report(), PDF export for governance reports (Phase 3.3).  Renders an AnalysisReport to a P, Render an AnalysisReport to a PDF byte stream.      Returns the raw bytes of the, _severity_color_hex(), compare_reports(), Compare two reports and return score deltas., TestPDFExport

### Community 64 - "Community 64"
Cohesion: 0.26
Nodes (9): RunWatcher(), NAV, Sidebar(), ANALYSIS_MUTATION_KEY, AnalysisRunState, AnalyzePayload, useAnalysisRunState(), useClearAnalysisRuns() (+1 more)

### Community 65 - "Community 65"
Cohesion: 0.18
Nodes (10): compilerOptions, allowSyntheticDefaultImports, composite, emitDeclarationOnly, module, moduleResolution, outDir, skipLibCheck (+2 more)

### Community 66 - "Community 66"
Cohesion: 0.40
Nodes (3): blast_radius(), Compute the blast radius of ``resource``: everything that (transitively)     dep, TestBlastRadius

### Community 67 - "Community 67"
Cohesion: 0.17
Nodes (12): API Changes, Architecture Decisions, Challenges Addressed, Components Delivered, Phase 2 Late Additions: Anti-Hallucination & Quality Hardening, Phase 2 — Skill Files, Architecture Reviewer, Report Memory & Multi-Cloud Expansion, Pipeline Change, Rule Coverage After Phase 2 (+4 more)

### Community 68 - "Community 68"
Cohesion: 0.27
Nodes (5): extract_tf_references(), _iter_strings(), Yield every string found anywhere inside a nested dict/list structure., Return the set of Terraform resource addresses (``type.name``) this     config r, TestTfReferences

### Community 69 - "Community 69"
Cohesion: 0.27
Nodes (4): _filter_terraform_speculative_gaps(), Drop Terraform gaps that flag absence of strategies rather than misconfiguration, Tests for the three architecture-reviewer gap filters.  Reference: app/agents/ar, TestTerraformSpeculativeGapFilter

### Community 70 - "Community 70"
Cohesion: 0.18
Nodes (11): API Added, Architecture Decisions, Challenges Addressed, Components Delivered, Framework Matrix (Verified Against All 6 Samples), Models Added, Phase 3.3 — Compliance Framework Mapping, Production-Grade Samples Added (+3 more)

### Community 71 - "Community 71"
Cohesion: 0.20
Nodes (10): API & Frontend, Challenges Addressed, Components Delivered, Critical Design Decisions (Locked in by Tests), K8s Categories with Deterministic Fixers, Phase 3.4 — Auto-Remediation (Scaffolding), Terraform Categories with Deterministic Fixers, Test Sentinels (+2 more)

### Community 72 - "Community 72"
Cohesion: 0.22
Nodes (9): API Added, Architecture Decisions, Challenges Addressed, Components Delivered, Models Added, Phase 3.2 — Drift Detection, Tests Added, Verification (+1 more)

### Community 73 - "Community 73"
Cohesion: 0.29
Nodes (4): _mermaid_html(), Wrap a Mermaid diagram string in a self-contained HTML doc that renders     it c, Phase 4 Architecture panel: SPOFs, dependency diagram, blast radius., _render_architecture_panel()

### Community 74 - "Community 74"
Cohesion: 0.31
Nodes (3): Tests for compliance framework mapping (Phase 3.3, cloud-aware).  Reference: app, A bare K8s NetworkPolicy finding (no title override) only gets NIST., TestCloudAttributionCorrectness

### Community 75 - "Community 75"
Cohesion: 0.22
Nodes (9): Architecture Decisions, Build Order, Challenges Addressed, Components Delivered, Coverage, Phase 2 Regression Sentinels (Non-Negotiable), Phase 3.1 — Pytest Regression Test Harness, Verification (+1 more)

### Community 76 - "Community 76"
Cohesion: 0.09
Nodes (25): AnalysisReport, Finding, _agent_findings_by_prefix(), _agent_has_data(), _all_deterministic_findings(), _finding_signature(), _is_deterministic(), Drift detection between successive analyses of the same infrastructure bundle. (+17 more)

### Community 77 - "Community 77"
Cohesion: 0.29
Nodes (6): Build, Develop, Notes, Stack, Structure, Web Frontend

### Community 78 - "Community 78"
Cohesion: 0.23
Nodes (6): Return parent resource names that have a companion resource of the given type., resources_with_companion(), Tests for parsers — K8s YAML/JSON and Terraform HCL/JSON.  Reference: - app/pars, When the bucket field isn't standard, scan all string values., HCL2 sometimes wraps single string values in lists., TestResourcesWithCompanion

### Community 79 - "Community 79"
Cohesion: 0.50
Nodes (4): format_report_text(), Count findings by severity across all agents., Format report as readable text., severity_counts()

### Community 80 - "Community 80"
Cohesion: 0.22
Nodes (9): Challenges Addressed, Components Delivered, Core Architecture Decisions, External Review Feedback, Known Limitations (Phase 1), Phase 1 — MVP: Intelligent Infrastructure Analysis, Rule Coverage, Sample Files Created (+1 more)

### Community 81 - "Community 81"
Cohesion: 0.25
Nodes (7): Architecture Decisions, Challenges Addressed, Development Phases, Phase 4.2 + 4.4 — Blast Radius, Architecture Diagram & UI Panel, Phase 4 — Infrastructure Simulation — COMPLETE, Verification, What Was Built

### Community 82 - "Community 82"
Cohesion: 0.50
Nodes (3): compute_agent_score(), Per-agent score deductions table.  This duplicates the table from app/agents/{se, Apply the standard deduction table to a list of Finding objects.

### Community 84 - "Community 84"
Cohesion: 0.25
Nodes (4): Bug 3: LLM emits Helm template paths in resource field. The     locator now trea, Sanity: don't false-positive on legitimate Kind/ns/name., Sanity: aws_*.foo doesn't match the file-path heuristic., TestTemplatePathDetection

### Community 85 - "Community 85"
Cohesion: 0.25
Nodes (4): Bug from good-chart-1.1.0.tgz: the LLM emitted INFO findings     congratulating, Keep/Maintain only fire when they're the FIRST word of the         recommendatio, Critical efficiency check — praise findings must never reach         the LLM. Se, TestPraiseFindings

### Community 87 - "Community 87"
Cohesion: 0.40
Nodes (4): Compliance Agent (Phase 3.5 plugin), Scoring, What it does, Why a plugin

### Community 88 - "Community 88"
Cohesion: 0.50
Nodes (3): Intentional issues (for analysis testing), my-chart, Package and test

### Community 89 - "Community 89"
Cohesion: 0.20
Nodes (7): delete_report_endpoint(), Delete a specific report., delete_report(), Delete a specific report from ChromaDB and the in-memory cache., End-to-end: live response has file_contents, but a subsequent         GET on the, End-to-end: a YAML upload analyses, the response echoes the         file_content, Skips automatically if `helm` CLI isn't installed — the chart         renderer n

### Community 90 - "Community 90"
Cohesion: 0.33
Nodes (6): Architecture Decisions, Challenges Addressed, Components Delivered, Phase 3.5 — Plugin Harness (Dynamic Agent Registration), Verification, What Was Built

### Community 92 - "Community 92"
Cohesion: 0.33
Nodes (6): Architecture Decisions, Challenges Addressed, Components Delivered, Phase 4.1 + 4.5 — Resource Dependency Graph & SPOF Detector, Verification, What Was Built

### Community 94 - "Community 94"
Cohesion: 0.33
Nodes (4): Finding, is_duplicate(), Check if an LLM finding duplicates any rule finding using keyword overlap., TestIsDuplicate

### Community 116 - "Community 116"
Cohesion: 0.22
Nodes (8): drift_endpoint(), Compare a report against the most recent prior scan of the same bundle.      Pha, AnalysisReport, find_baseline(), Return the most recent prior report with the same bundle_fingerprint.      Retur, get_report(), Retrieve a report by ID., A report saved before this feature existed (or any report         cleanly persis

### Community 117 - "Community 117"
Cohesion: 0.33
Nodes (6): _filename_kind(), _locate_kubernetes_file(), _locate_terraform_file(), Return one of: 'kubernetes_yaml', 'terraform_hcl', 'terraform_json',     or 'unk, Locate the .tf/.hcl/.json file containing ``aws_foo.bar``., Locate the .yaml/.yml file containing the named K8s resource.      The canonical

### Community 118 - "Community 118"
Cohesion: 0.29
Nodes (7): _coerce_llm_payload(), _json_value_from_edit(), Normalize a parsed LLM payload to (patched_content, explanation)., Convert a JSON edit value to an HCL literal.      - Python bool -> true/false, Coerce an edit value into a native JSON value for Terraform-JSON., _value_to_hcl_literal(), Any

### Community 119 - "Community 119"
Cohesion: 0.18
Nodes (7): Persist a report to ChromaDB. Returns report_id., save_report(), _fanin_tf(), Tests for the Phase 4.2 blast-radius and 4.4 diagram API endpoints.  Served from, report_with_graph(), report_without_graph(), TestDiagramEndpoint

### Community 120 - "Community 120"
Cohesion: 0.29
Nodes (4): The 'Overly Permissive Egress on Security Group' finding (LLM-emitted     title), The rule-based 'Security group open to 0.0.0.0/0' finding (which         is ingr, If the SG has no literal 0.0.0.0/0 (e.g. it uses var.allowed_cidrs),         the, TestEgressFixer

### Community 121 - "Community 121"
Cohesion: 0.25
Nodes (7): make_agent_finding(), make_arch_response(), Canned LLM responses keyed by agent type.  Each agent's `chain.ainvoke(...)` is, Build an architecture-reviewer response. Useful for testing dedup filters     by, Build an agent finding for use inside an LLM-mocked response., Verify mock_llm.set() actually changes architecture review output., test_mock_llm_can_override_architecture_response()

### Community 123 - "Community 123"
Cohesion: 0.40
Nodes (4): analyze_infrastructure(), Upload infrastructure files and run multi-agent analysis., Run helm template on a packaged .tgz chart and return rendered Kubernetes YAML., render_helm_chart()

### Community 124 - "Community 124"
Cohesion: 0.25
Nodes (8): _fix_tf_json(), Return the per-resource config dict from parsed Terraform JSON.      Shape: ``pa, Add a new entry under parsed["resource"][rtype][rname] = config.      Creates th, Re-emit parsed Terraform JSON, preserving the original indent and     trailing-n, Apply a deterministic fix to a Terraform JSON file.      Same category coverage, _tfjson_add_companion_resource(), _tfjson_dump(), _tfjson_get_resource_block()

## Knowledge Gaps
- **217 isolated node(s):** `Settings`, `Any`, `Path`, `Path`, `Any` (+212 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **6 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Severity` connect `Community 10` to `Community 0`, `Community 2`, `Community 3`, `Community 5`, `Community 6`, `Community 8`, `Community 12`, `Community 15`, `Community 17`, `Community 18`, `Community 20`, `Community 23`, `Community 24`, `Community 25`, `Community 27`, `Community 31`, `Community 35`, `Community 36`, `Community 37`, `Community 38`, `Community 39`, `Community 42`, `Community 44`, `Community 45`, `Community 46`, `Community 50`, `Community 51`, `Community 52`, `Community 54`, `Community 55`, `Community 56`, `Community 58`, `Community 59`, `Community 60`, `Community 61`, `Community 62`, `Community 66`, `Community 68`, `Community 69`, `Community 76`, `Community 84`, `Community 85`, `Community 91`, `Community 94`, `Community 118`, `Community 120`?**
  _High betweenness centrality (0.163) - this node is a cross-community bridge._
- **Why does `Finding` connect `Community 10` to `Community 0`, `Community 1`, `Community 2`, `Community 3`, `Community 5`, `Community 6`, `Community 8`, `Community 12`, `Community 14`, `Community 15`, `Community 16`, `Community 17`, `Community 18`, `Community 23`, `Community 24`, `Community 31`, `Community 32`, `Community 35`, `Community 36`, `Community 37`, `Community 38`, `Community 39`, `Community 42`, `Community 44`, `Community 46`, `Community 51`, `Community 55`, `Community 56`, `Community 58`, `Community 59`, `Community 61`, `Community 62`, `Community 63`, `Community 74`, `Community 76`, `Community 84`, `Community 85`, `Community 94`, `Community 118`, `Community 120`?**
  _High betweenness centrality (0.143) - this node is a cross-community bridge._
- **Why does `_f()` connect `Community 39` to `Community 35`, `Community 5`, `Community 6`, `Community 7`, `Community 8`, `Community 10`, `Community 51`, `Community 84`, `Community 85`, `Community 120`, `Community 59`, `Community 62`?**
  _High betweenness centrality (0.035) - this node is a cross-community bridge._
- **Are the 98 inferred relationships involving `Severity` (e.g. with `CompanionResourceRequired` and `NonPatchableFinding`) actually correct?**
  _`Severity` has 98 INFERRED edges - model-reasoned connections that need verification._
- **Are the 82 inferred relationships involving `Finding` (e.g. with `CompanionResourceRequired` and `NonPatchableFinding`) actually correct?**
  _`Finding` has 82 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Architecture Reviewer agent — cross-cutting tradeoff analysis across all agent f`, `Drop gaps that are platform/cluster-level concerns for K8s/Helm infrastructure.`, `Drop Terraform gaps that flag absence of strategies rather than misconfiguration` to the rest of the system?**
  _635 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.07665505226480836 - nodes in this community are weakly interconnected._