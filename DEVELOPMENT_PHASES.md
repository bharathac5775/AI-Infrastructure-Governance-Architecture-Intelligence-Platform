# Development Phases

This document tracks the development history, technical decisions, and progress of the AI Infrastructure Governance Platform.

---

## Phase 1 — MVP: Intelligent Infrastructure Analysis

**Status:** Complete  
**Duration:** Initial build + iterative improvements

### What Was Built

A multi-agent AI platform that analyzes Kubernetes YAML and Terraform HCL files across three dimensions — security, reliability, and cost — using a hybrid approach of deterministic rules and LLM-powered reasoning.

### Core Architecture Decisions

**1. Sequential Agent Execution**  
LangGraph pipeline runs agents one at a time (`parse → security → reliability → cost → supervisor`). Parallel execution was considered but rejected — a local Ollama instance handles one request efficiently and would starve under parallel load.

**2. Hybrid Rules + LLM Analysis**  
Each agent runs two passes:
- **Rule-based checks** — Deterministic `if/else` checks against parsed data structures. Fast, reliable, always consistent.
- **LLM analysis** — Sends raw file content to Gemma4 for contextual reasoning that rules can't express.

Rules carry 60% weight in the final score; LLM carries 40%.

**3. Deduplication**  
Both rules and the LLM often find the same issue worded differently. A keyword + synonym overlap algorithm (`dedup.py`) filters LLM findings that duplicate rule findings. The threshold has evolved over phases — see Phase 2 for the final fixed-integer implementation.

**4. Separate K8s/Terraform Prompts**  
Initially a single prompt was used per agent. This caused **concept leakage** — the LLM applied Kubernetes concepts (resource requests/limits, probes) to Terraform resources (EC2 instances). Fixed by creating 6 separate prompts (2 per agent) with explicit guardrails like "EC2 instances do NOT have resource requests."

**5. Content-First File Type Detection**  
`_detect_infra_type()` checks file content for K8s/Terraform markers before falling back to file extension. This handles the case where users paste Terraform content with a `.yaml` filename in the Streamlit UI.

### Components Delivered

| Component | Details |
|-----------|---------|
| **FastAPI Backend** | REST API with file upload + text analysis endpoints |
| **Streamlit Frontend** | Upload files or paste content, view scored reports |
| **Security Agent** | ~10 K8s rules + ~21 Terraform rules + LLM analysis |
| **Reliability Agent** | ~7 K8s rules + ~13 Terraform rules + LLM analysis |
| **Cost Agent** | ~6 K8s rules + ~12 Terraform rules + LLM analysis |
| **Supervisor Agent** | LLM-powered synthesis of all 3 agent reports into executive summary |
| **K8s Parser** | Multi-document YAML parsing, resource grouping by kind |
| **Terraform Parser** | HCL parsing via `hcl2` library, resource extraction |
| **Dedup Engine** | Shared stop words, domain synonyms, keyword overlap matching |
| **Report System** | Weighted scoring (Security 40%, Reliability 35%, Cost 25%) — rebalanced in Phase 2 to 34/30/21/15 with Architecture |
| **Docker Setup** | `docker-compose.yml` with api + frontend services |
| **Sample Files** | 7 test files: good/average/vulnerable/critical for K8s and TF |

### Rule Coverage

**Kubernetes Rules:**
- Security: host namespaces, privileged containers, runAsRoot, readOnlyRootFilesystem, resource limits, image tags, LoadBalancer exposure, RBAC cluster-admin, hardcoded secrets in env vars
- Reliability: single replicas (workload-aware for caches), missing liveness/readiness probes, no HPA, no PDB, no anti-affinity, missing resource requests, no rolling update strategy
- Cost: unbounded resources, overprovisioning, excessive replicas, LoadBalancer services, large PVCs

**Terraform Rules:**
- Security: open security groups (0.0.0.0/0), public S3 buckets, S3 encryption, RDS public access/encryption, Azure storage, hardcoded DB passwords, IAM wildcard policies, EC2 IMDSv2, EBS encryption, CloudTrail (logging/multi-region/validation), VPC flow logs, ALB HTTP listeners, RDS SSL, ECS privileged containers, KMS key rotation, Lambda VPC, GCP firewall
- Reliability: RDS Multi-AZ/backups/deletion protection, ASG health checks, standalone EC2, S3 versioning, DynamoDB PITR, ElastiCache failover, Lambda/SQS DLQ, ELB cross-zone, CloudWatch alarms
- Cost: expensive EC2/RDS/Azure instance types (prefix matching), large RDS storage/EBS, NAT Gateways, unattached EIPs, S3 lifecycle, CloudWatch log retention, EBS io1/io2, DynamoDB provisioned mode, ElastiCache expensive node types

### Challenges Addressed

- Severity calibration — tuned findings like HPA, anti-affinity, and cache replicas to appropriate severity levels
- Scoring accuracy — fixed LLM fallback scoring and score blending logic
- Deduplication — evolved from exact title matching to keyword + synonym overlap to prevent duplicate findings
- K8s/Terraform concept leakage — separated LLM prompts per infrastructure type to prevent cross-domain confusion
- Content-aware detection — prioritized file content analysis over extension-based routing
- Terraform integration — extended the full pipeline (parser, supervisor, all 3 agents) to support HCL
- Docker networking — resolved inter-container communication for frontend-to-API connectivity
- CORS configuration — fixed browser-rejected wildcard origin + credentials combination
- Code maintainability — consolidated duplicated logic into shared modules, pinned dependency versions

### Sample Files Created

| File | Purpose | Expected Score |
|------|---------|---------------|
| `good-infra.tf` | Well-configured AWS (KMS, restricted SG, encrypted Multi-AZ RDS, private S3 with lifecycle) | 85–95 |
| `average-infra.tf` | Mid-level AWS (private SG, encrypted RDS but no Multi-AZ, versioned S3 but no encryption) | 75–85 |
| `vulnerable-infra.tf` | 16+ insecure AWS resources (open SG, public RDS, hardcoded password, public S3, GPU instance) | 20–40 |
| `good-deployment.yaml` | Hardened K8s deployment | 85–95 |
| `hardened-production.yaml` | PSS restricted, 3 deployments, NetworkPolicies, PDBs, HPAs, ResourceQuota, least-privilege RBAC | 90–100 |
| `vulnerable-deployment.yaml` | Insecure K8s deployment | 30–50 |
| `critical-security-failure.yaml` | Privileged + hostPID + hostNetwork + hostPath / + cluster-admin + public SSH LB | 20–40 |

### External Review Feedback

Reports were validated by external AI review (ChatGPT). Key outcomes:
- Average-infra.tf report scored 80.5/100 — rated as "very good", "realistic", "balanced", "VERY believable"
- Platform now behaves like "cloud posture governance tooling" rather than "rule-based IaC linting"
- Severity calibration rated as excellent (proper INFO/MEDIUM/HIGH/CRITICAL distinction)
- Minor LLM nuances identified (EC2 "deletion protection" phrasing, cross-finding consistency) — deferred to Phase 2

### Known Limitations (Phase 1)

- In-memory report store (`_reports` dict) — grows unbounded, no persistence
- No hostPath volume mount dedicated rule (caught by LLM only)
- No dangerous-port detection rule for SSH/DB ports on LoadBalancers
- LLM may occasionally produce cross-finding contradictions (e.g., "oversized EC2" + "undersized RDS")
- No positive validation in reports (e.g., "Good: encryption is enabled")
- Analysis takes ~3 minutes per run (4 sequential LLM calls)

---

## Phase 2 — Skill Files, Architecture Reviewer, Report Memory & Multi-Cloud Expansion

**Status:** Complete

### What Was Built

Five major capability areas were delivered in Phase 2:
1. Externalized agent prompts via skill files
2. Architecture Reviewer agent for cross-cutting analysis
3. ChromaDB-backed persistent report storage with history, comparison, and similarity search
4. Native Helm chart support (`.tgz` upload → `helm template` → full analysis pipeline)
5. Multi-cloud rule expansion: Azure and GCP rules across all three agents

---

### Architecture Decisions

**1. Skill File System**  
All agent prompts were extracted from hardcoded Python strings into `.md` skill files with YAML frontmatter under `skills/`. Prompt tuning no longer requires code changes — agents call `get_agent_prompt("security", "kubernetes")` at runtime via `app/core/skills.py`.

**2. Architecture Reviewer Agent**  
A new 4th analysis agent that receives all Security/Reliability/Cost findings and the raw infrastructure content. Performs cross-cutting analysis: tradeoff conflicts (where fixing one area hurts another), architectural pattern detection, cross-cutting gaps no single agent would catch, and scope-aware severity calibration.

Scope rules added to prevent hallucinations:
- For Kubernetes/Helm: DR plan is **not flagged** as a cross-cutting gap (it is a platform concern, not a chart concern)
- For Terraform: DR plan IS in scope — the infra author controls replication and backup directly
- Observability severity for a single K8s service is capped at MEDIUM

**3. ChromaDB Report Persistence**  
Replaced the in-memory `_reports` dict with ChromaDB persistent storage. Reports survive server restarts. Vector-indexed for semantic similarity search across historical reports.

**4. Native Helm Chart Support**  
`.tgz` files are handled server-side: the binary is written to a temp file, `helm template` is called as a subprocess to render it to Kubernetes YAML, and the rendered YAML enters the standard analysis pipeline under the name `{chart}-rendered.yaml`. The frontend sends `.tgz` as multipart binary (not JSON text). Helm CLI is included in the Docker image.

**5. Companion Resource Support (AWS Provider v4+)**  
AWS Terraform provider v4 split `aws_s3_bucket` config into separate companion resources (`aws_s3_bucket_versioning`, `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_lifecycle_configuration`, `aws_s3_bucket_public_access_block`). A generic `resources_with_companion(tf_resources, companion_type)` function in `app/parsers/terraform.py` resolves which parent resources have companions, eliminating false-positive findings on modern provider configurations.

**6. Dedup Engine Improvements**  
Three root causes of duplicate findings were fixed in `dedup.py`:
- **CamelCase tokenization**: `_split_camelcase()` added so `HorizontalPodAutoscaler` splits into individual tokens (`Horizontal`, `Pod`, `Autoscaler`) and matches LLM findings
- **Stop word injection via synonyms**: Generic qualifiers (`missing`, `lacks`, `absent`, `without`) added to stop words and filtered during synonym expansion to prevent them polluting keyword sets
- **Threshold finalized as fixed integer**: After a percentage-based threshold (`max(3, len * 0.20)`) caused float-comparison misses (e.g., `3 >= 3.2` is False, letting duplicates through when LLM produced ≥16 keywords), the threshold was simplified to a fixed `>= 3` keyword overlap. Predictable, no float pitfalls.

**7. Scoring Rebalanced**  
With the Architecture Reviewer added as a 4th scoring dimension, overall score weights were rebalanced (actual values in `app/core/report.py`):
- Security: 40% → **34%**
- Reliability: 35% → **30%**
- Cost: 25% → **21%**
- Architecture: **15%** (new)

**8. Supervisor Architecture Awareness**  
The supervisor node now receives architecture review data (score, gap count, gap titles) alongside the three agent summaries. The skill prompt was updated with an explicit rule: even if Security/Reliability/Cost all score 100/100, the supervisor **must** include HIGH/CRITICAL architecture gaps in the risk summary.

**9. HPA-Aware Reliability Rules**  
The "Single replica (SPOF)" rule now checks whether an HPA targets the workload before firing. When a Deployment intentionally omits `replicas:` because HPA manages scaling, the rule no longer generates a false positive.

---

### Components Delivered

| Component | Details |
|-----------|---------|
| **Skill Loader** | `app/core/skills.py` — YAML frontmatter parser + prompt loader |
| **8 Skill Files** | `skills/` — security-k8s, security-tf, reliability-k8s, reliability-tf, cost-k8s, cost-tf, supervisor, architecture-reviewer |
| **Architecture Reviewer** | `app/agents/architecture_reviewer.py` — tradeoffs, patterns, gaps, prioritized actions, scope-aware severity |
| **New Models** | `ArchitectureReview`, `Tradeoff`, `PatternDetected`, `CrossCuttingGap` |
| **Report Store** | `app/core/store.py` — ChromaDB-backed with save/get/list/compare/delete/similar |
| **Helm Parser** | `app/parsers/helm.py` — `render_helm_chart()` subprocess wrapper |
| **Companion Resource Lookup** | `app/parsers/terraform.py` — `resources_with_companion()` for AWS provider v4+ |
| **Dedup Engine v2** | `app/core/dedup.py` — CamelCase splitting, expanded stop words, tuned threshold |
| **Azure Security Rules** | NSG open to internet, Storage HTTPS/TLS, Key Vault purge/soft-delete, SQL firewall, App Service HTTPS, Managed Disk CMK, AKS RBAC/AD/NetworkPolicy |
| **Azure Reliability Rules** | SQL zone-redundant/LTR, App Service backup, AKS zones/auto-upgrade, Cosmos DB multi-region, VM availability zone |
| **Azure Cost Rules** | Expensive VM SKUs, App Service premium plans, SQL Business Critical tier, Managed Disk Premium, Cosmos DB expensive consistency, AKS expensive node size |
| **GCP Security Rules** | Firewall 0.0.0.0/0, Cloud SQL public IP/SSL (`require_ssl` + `ssl_mode`), GCS uniform access, GKE private nodes/NetworkPolicy/master auth, Compute shielded VM, IAM allUsers |
| **GCP Reliability Rules** | Cloud SQL HA/backups/deletion protection, GKE node auto-repair/auto-upgrade, cluster maintenance window, Compute preemptible flag |
| **GCP Cost Rules** | Expensive machine types, premium/large persistent disks, Cloud SQL expensive tiers, GKE expensive node pools, GCS lifecycle rules |
| **New API Endpoints** | `DELETE /reports/{id}`, `GET /reports/{id}/similar` |
| **Frontend Updates** | Architecture Review section, Report History, `.tgz` upload support (multipart) |
| **Docker Update** | Helm CLI installed in image |
| **Sample Helm Charts** | `samples/my-chart/` (intentional issues), `samples/good-chart/` (best practices, v1.2.0) |

---

### Rule Coverage After Phase 2

**Kubernetes Rules:**
- Security: host namespaces, privileged containers, runAsRoot, readOnlyRootFilesystem, resource limits, image tags, LoadBalancer exposure, RBAC cluster-admin, hardcoded secrets in env vars
- Reliability: single replicas (HPA-aware, workload-aware for caches), missing liveness/readiness probes, no HPA, no PDB, no anti-affinity, missing resource requests, no rolling update strategy
- Cost: unbounded resources, overprovisioning, excessive replicas, LoadBalancer services, large PVCs

**Terraform Rules — AWS:**
- Security: open security groups, public S3 buckets, S3 encryption + public access block (v4+ companion-aware), RDS public access/encryption, hardcoded DB passwords, IAM wildcard policies, EC2/Launch Template IMDSv2, EBS encryption, CloudTrail (logging/multi-region/validation), VPC flow logs, ALB HTTP listeners, RDS SSL, ECS privileged containers, KMS key rotation, Lambda VPC
- Reliability: RDS Multi-AZ/backups/deletion protection, ASG health checks, standalone EC2, S3 versioning (v4+ companion-aware), DynamoDB PITR, ElastiCache failover, Lambda/SQS DLQ, ELB cross-zone, CloudWatch alarms
- Cost: expensive EC2/RDS instance types, large storage, NAT Gateways, unattached EIPs, S3 lifecycle (v4+ companion-aware), CloudWatch log retention, EBS io1/io2, DynamoDB provisioned mode, ElastiCache expensive nodes

**Terraform Rules — Azure:**
- Security: NSG open to internet, Storage public access/HTTPS/TLS version, Key Vault purge protection/soft delete, SQL firewall permissiveness, App Service HTTPS enforcement, Managed Disk customer-managed key, AKS RBAC/AAD integration/NetworkPolicy
- Reliability: SQL zone redundancy/LTR, App Service backup, AKS availability zones/auto-upgrade, Cosmos DB multi-region, VM availability set/zone
- Cost: expensive VM SKUs (E/M/L/N series), App Service premium plans, SQL Business Critical/Hyperscale, large SQL storage, Managed Disk Premium/UltraSSD, Cosmos DB Strong/BoundedStaleness consistency, AKS expensive node VM sizes

**Terraform Rules — GCP:**
- Security: Compute Firewall 0.0.0.0/0, Cloud SQL public IP + SSL (`require_ssl` and modern `ssl_mode`), GCS uniform bucket access, GKE private nodes/NetworkPolicy/master authorized networks, Compute shielded VM, IAM allUsers/allAuthenticatedUsers
- Reliability: Cloud SQL HA (REGIONAL)/backups/deletion protection, GKE node pool auto-repair/auto-upgrade, cluster maintenance window, Compute preemptible instances
- Cost: expensive machine types (n2-highmem, c2, m1-m3, a2-a3, g2), premium/large persistent disks, Cloud SQL expensive tiers, GKE expensive node pool machine types, GCS lifecycle rules

---

### Pipeline Change

Pipeline expanded from 4 to 6 nodes (5 LLM calls):
```
parse_files → security → reliability → cost → architecture_review → supervisor
```

---

### API Changes

| Endpoint | Method | Added |
|----------|--------|-------|
| `/api/v1/reports` | GET | Phase 2.1 — list recent reports |
| `/api/v1/reports/compare/{a}/{b}` | GET | Phase 2.1 — score deltas between two reports |
| `/api/v1/reports/{id}` | DELETE | Phase 2.2 — delete a report |
| `/api/v1/reports/{id}/similar` | GET | Phase 2.2 — semantic similarity search |

---

### Challenges Addressed

- **Helm binary upload**: Frontend switched from JSON text API to multipart to handle binary `.tgz` files; routes.py branches on extension before UTF-8 decode
- **Duplicate findings across rule/LLM**: Three-root-cause dedup fix (CamelCase tokenization, stop word injection via synonyms, threshold calibration)
- **Architecture reviewer hallucinations**: Scope rules added to skill prompt preventing out-of-scope DR plan findings for single-service Helm charts
- **HPA + replica interaction**: Reliability agent now cross-checks HPA targets before firing single-replica SPOF finding
- **AWS provider v4+ false positives**: Generic companion resource lookup eliminates false encryption/versioning/lifecycle findings on modern Terraform configs
- **Supervisor blindspot**: Supervisor now receives architecture review data; will include HIGH/CRITICAL architecture gaps in risk summary even when all agent scores are 100/100
- **GCP SSL deprecation**: Cloud SQL SSL check handles both deprecated `require_ssl` and modern `ssl_mode` attribute
- **Azure disk encryption false positive**: Managed disk check changed from `encryption_type` (always missing — PMK is default) to `disk_encryption_set_id` (CMK-specific), severity lowered to LOW

### Sample Terraform Files (Phase 2)

| File | Cloud | Purpose | Expected Score |
|------|-------|---------|---------------|
| `azure-average.tf` | Azure | Mixed gaps (open NSG, no KV purge protection, SQL not zone-redundant, VM no availability zone) | 55–70 |
| `gcp-average.tf` | GCP | Mixed gaps (open firewall, Cloud SQL public IP/no HA/no SSL, GCS no lifecycle, no shielded VM) | 50–65 |
| `production-good.tf` | AWS | Enterprise production-grade (Zero Trust, Multi-AZ, encryption everywhere, IAM least privilege) | 90–100 |

### Sample Helm Charts

| Chart | Version | Purpose | Expected Score |
|-------|---------|---------|---------------|
| `my-chart-1.0.0.tgz` | 1.0.0 | Intentionally flawed (hardcoded password, no probes, no HPA, no security context) | 30–50 |
| `good-chart-1.0.0.tgz` | 1.0.0 | Initial best-practices chart | 85–95 |
| `good-chart-1.1.0.tgz` | 1.1.0 | Iterative improvements over 1.0.0 | 90–96 |
| `good-chart-1.2.0.tgz` | 1.2.0 | Full best practices (NetworkPolicy, HPA, PDB, ServiceMonitor, security context, rolling update, graceful shutdown) | 95–98 |

---

### Phase 2 Late Additions: Anti-Hallucination & Quality Hardening

A second round of fixes addressed report quality issues surfaced during sample-driven testing — particularly false positives, score inflation, and the LLM contradicting its own structured output.

**1. Non-Infra File Hallucination Guard (3-layer defense)**

Uploading a `package-lock.json` or unrelated YAML previously produced a fake report with hallucinated findings. Three layers now reject non-infra content before any LLM call:

- **`app/api/routes.py`** — at upload, validates YAML files contain `apiVersion:` + `kind:`; rejects known non-infra JSON filenames (`package-lock.json`, `tsconfig.json`, etc.); requires Terraform or K8s markers in JSON content
- **`_detect_infra_type` (`app/agents/security.py`)** — content-first detection. Removed the `.yaml`/`.yml` extension fallback (was forcing "kubernetes" classification on any YAML). Added JSON-format markers (`"apiVersion":`, `"resource":`, `"terraform":`). Returns `"none"` when no infra markers found in any file.
- **`analyze_architecture` (`app/agents/architecture_reviewer.py`)** — short-circuits with `return None` when `infra_type == "none"`, preventing fake 100/100 architecture scores. `calculate_overall_score` already handles `None` by skipping the 15% architecture weight.

**2. Deterministic Architecture Score (LLM no longer guesses)**

The architecture score was previously LLM-generated and frequently capped near 85 regardless of actual gap severity. Replaced with a deterministic Python calculation:

- `architecture_score` field removed from the JSON schema returned by the LLM
- `_calculate_architecture_score(gaps, agent_scores)` computes: `100 - sum(deductions per gap severity)`, then **caps at the average of agent scores** so architecture cannot claim perfection when individual agents found real issues
- Deduction table: critical=25, high=15, medium=8, low=3
- Verified: terraform-serverless (1 HIGH + 1 MEDIUM gap) → 100−15−8 = 77; k8s-api-deployment (1 MEDIUM gap, agent avg 85.33) → min(92, 85.33) = 85.3

**3. Cross-Cutting Gap Dedup (multi-domain aware)**

The LLM frequently echoed individual agent findings as cross-cutting gaps with inflated severity (e.g., security flagged INFO → architecture flagged CRITICAL). New `_dedup_cross_cutting_gaps` filter applies three rules using `_SEVERITY_RANK = {info:0, low:1, medium:2, high:3, critical:4}`:

- **No agent match** (≥3 keyword overlap with any agent finding) → keep — genuinely new cross-cutting concern
- **Matches 2+ agent domains** → valid synthesis — keep if `gap_rank ≤ best_match_rank + 1`
- **Matches 1 agent only** → keep only if escalation is *exactly* +1 level (anything else is either echo or severity inflation)

Backed by skill-prompt rules: CROSS-CUTTING GAP RULE (don't echo single-agent findings) and SEVERITY CALIBRATION RULE (max +1 raise from agent severity floor).

**4. K8s Platform-Level Gap Filter**

`_filter_k8s_platform_gaps` strips gaps that are out-of-scope for individual Helm charts: external secrets management (Vault/ESO/KMS), full observability stack (Loki/Jaeger/centralized logging), and DR/multi-region/multi-cluster concerns. These are platform/cluster operator decisions, not chart-author decisions.

**5. Terraform JSON Parser Fix**

`extract_tf_resources` previously assumed HCL2 list-of-dicts format and silently failed on JSON-format Terraform (where `"resource"` is a nested dict). All rule-based checks were skipping JSON files. Fix normalizes both formats:
```python
blocks = [raw] if isinstance(raw, dict) else raw
```

**6. Rule-Based Check Refinements**

- **IAM overly-permissive policy** — was triggering on any `"*"` substring. Now parses JSON policy and exempts AWS service actions that *require* `Resource: "*"` (no resource-level support): `xray:PutTraceSegments`, `xray:PutTelemetryRecords`, `ec2:CreateNetworkInterface`, `ec2:DescribeNetworkInterfaces`, `ec2:DeleteNetworkInterface`. True wildcard `Action: "*"` still flags.
- **SQS DLQ** — was flagging the DLQ itself for not having a DLQ. Now skips queues whose name contains `dlq`, `dead-letter`, `deadletter`, or `dead_letter`.
- **Lambda DLQ + VPC, DynamoDB PITR, CloudWatch retention** — added during sample-driven testing for completeness.

**7. Supervisor Anti-Hallucination Rule**

When all agent scores are high and gap count is zero, the supervisor was still generating risk-laden summaries. Skill prompt now requires the executive summary to base assessments on structured findings only — not narrative restatement.

---

### Sample Files Added Late in Phase 2

| File | Purpose | Expected Score |
|------|---------|---------------|
| `k8s-api-deployment.json` | Average-quality K8s Deployment in JSON form (no securityContext, only liveness probe, 20× resource ratio, default ServiceAccount) | 80–88 |
| `terraform-serverless.json` | Average-quality Terraform JSON (S3 versioning suspended, no DLQ, no PITR, no lifecycle, no alarms, no encryption) | 75–85 |
| `k8s-production-grade.json` | Production-grade K8s `List` (ServiceAccount + hardened Deployment + Service + NetworkPolicy + HPA + PDB) | 95–100 |
| `terraform-production-grade.json` | Production-grade Terraform JSON (KMS+rotation, Secrets Manager, VPC+flow logs, RDS Multi-AZ encrypted, S3 versioned+SSE-KMS, Lambda VPC+DLQ+X-Ray, CloudWatch alarms, CloudTrail multi-region) | 98–100 |

---

## Phase 3.1 — Pytest Regression Test Harness

**Status:** Complete
**Theme:** Lock in every Phase 1/2 behavior with automated tests so future refactors fail loudly when they break a regression. The platform shipped with **zero** automated tests; every Phase 2 fix was hand-validated by re-uploading samples. That doesn't scale and doesn't prevent regressions.

### What Was Built

A pytest suite of **206 tests** that runs in **~1 second** without Ollama. The harness mocks the LLM via a fixture so tests are CI-safe and fully deterministic.

### Architecture Decisions

**1. Mock the LLM by replacing the chain primitive, not by patching call sites**
Rather than patching each `chain.ainvoke(...)` call (5 sites), the `mock_llm` fixture (`tests/conftest.py`) monkeypatches `get_llm` in **every importer's namespace** (the gotcha: each agent module does `from app.core.llm import get_llm`, which binds the name at import time). The replacement is a `_FakeRunnable(Runnable)` that inspects the rendered prompt and returns canned JSON keyed by agent type via substring matching.

**2. Two-track sample regression: rules-only AND full-pipeline**
- `test_samples_rules_only.py` — runs rule functions directly, fully synchronous, fully deterministic, tolerance 0.1
- `test_samples_full_pipeline.py` — runs `run_analysis()` end-to-end with mocked LLM, marker `slow`+`integration`
This catches both rule-level regressions AND wiring/orchestration regressions.

**3. Pinned scores in YAML manifest, not hardcoded in tests**
`tests/expected_scores.yaml` is the single contract that defines expected per-sample behavior. When a rule changes intentionally, one number in the manifest moves; failures point at exactly which sample drifted.

**4. Phase 2 regression sentinels are non-negotiable**
Every Phase 2 fix has at least one positive + one negative test. Names like `test_iam_xray_wildcard_not_flagged`, `test_sqs_named_lambda_dlq_not_flagged`, `test_parse_terraform_json_format` tell the story of what went wrong before and now can't go wrong again.

### Components Delivered

| Component | Details |
|-----------|---------|
| **Dev dependency** | `requirements-dev.txt` — pytest 8.3.4, pytest-asyncio 0.25.0 |
| **Pytest config** | `pytest.ini` with `asyncio_mode = auto`, markers: `slow`, `integration` |
| **Fixtures** | `tests/fixtures/findings.py` (builders), `tests/fixtures/scoring.py` (deduction table mirror), `tests/fixtures/llm_responses.py` (canned JSON) |
| **Conftest** | `mock_llm` fixture, `sample_loader`, `expected_scores` (session-scoped) |
| **Manifest** | `tests/expected_scores.yaml` — 14 samples pinned with overall + per-agent scores + finding sentinels |
| **Test files** | 8 regression files: `test_dedup.py` (23), `test_scoring.py` (19), `test_security_rules.py` (34), `test_reliability_rules.py` (21), `test_cost_rules.py` (14), `test_arch_filters.py` (23), `test_parsers.py` (22), `test_mock_llm.py` (3) |
| **Sample regression** | `test_samples_rules_only.py` (32) + `test_samples_full_pipeline.py` (15) |
| **Documentation** | `tests/README.md` with run commands, conventions, LLM-mock gotcha, "break a fix on purpose" experiment |

### Coverage

| Layer | What's verified |
|-------|----------------|
| Pure logic | `extract_keywords`, `is_duplicate`, multi-domain dedup with severity rules + bundle-echo coverage |
| Math | `calculate_overall_score` weighted average; `_calculate_architecture_score` deductions + agent-avg cap |
| Security rules | Privileged container, runAsRoot (pod-level fallback), RBAC wildcards, IAM xray exemption (Phase 2), S3 companion-resource awareness (Phase 2), unparseable IAM policy fallback |
| Reliability rules | Probes, PDB, HPA suppresses single-replica SPOF, DynamoDB PITR, Lambda DLQ, **SQS DLQ name skip (Phase 2)** |
| Cost rules | Overprovisioning ratios, CloudWatch retention, S3 lifecycle (companion-aware), DynamoDB billing mode |
| Architecture filters | `_filter_k8s_platform_gaps`, `_filter_terraform_speculative_gaps`, `_filter_terraform_secrets_gap` |
| Parsers | K8s YAML/JSON multi-doc, Terraform HCL+JSON dict format (Phase 2), `kind: List` documented behavior, AWS provider v4+ companion lookup |

### Phase 2 Regression Sentinels (Non-Negotiable)

| Test name | What it locks in |
|---|---|
| `test_iam_xray_wildcard_not_flagged` | AWS-required wildcard actions (xray:PutTraceSegments, ec2:CreateNetworkInterface) MUST NOT flag the IAM rule |
| `test_iam_s3_wildcard_resource_flagged` | Counterpart: arbitrary action with `Resource:"*"` MUST still flag |
| `test_sqs_named_lambda_dlq_not_flagged` | Queue named `*_dlq`, `dead-letter`, etc. MUST NOT flag missing-DLQ |
| `test_lambda_without_dlq_flagged_medium` | Lambda DLQ rule MUST flag when missing |
| `test_dynamodb_with_pitr_enabled_no_flag` | PITR-enabled DynamoDB MUST NOT flag |
| `test_parse_terraform_json_format` | JSON-format Terraform MUST extract resources (Phase 2 parser fix) |
| `test_s3_with_companion_encryption_no_flag` | AWS provider v4+ companion encryption resource MUST suppress finding |
| `test_no_gaps_capped_by_agent_average` | Architecture score MUST be capped at agent-score average |

### Challenges Addressed

- **LangChain Runnable coercion** — `_FakeRunnable` had to inherit from `langchain_core.runnables.Runnable`, otherwise `prompt | llm` fails with `TypeError: Expected a Runnable, callable or dict`
- **Prompt routing collision** — supervisor and architecture-reviewer prompts both contain "Architecture Review", so route-by-substring had to check supervisor signals (`executive_summary`, `review supervisor`) first
- **HCL2 parser hangs on malformed input** — initial test used `'resource "missing_quote { broken'` which hung the parser; replaced with `'@@@@ NOT VALID HCL @@@@'` which fails fast
- **`tf_resource(name=...)` keyword collision** — fixture builder used `name` as the Terraform local name AND the AWS-side `name` attribute; renamed builder param to `resource_name`
- **Float-comparison bug in dedup threshold** (Phase 2 carryover) — fixed-integer `>= 3` overlap, never percentage-based
- **PyYAML deprecation warning** — added `asyncio_default_fixture_loop_scope = function` to silence pytest-asyncio future-default warning

### Build Order

```
1. requirements-dev.txt
2. pytest.ini + tests/__init__.py + tests/conftest.py + tests/fixtures/__init__.py
3. tests/fixtures/findings.py (builders)
4. test_dedup.py    → 23 tests
5. test_scoring.py  → 19 tests
6. test_security_rules.py + test_reliability_rules.py + test_cost_rules.py → 69 tests
7. test_arch_filters.py → 23 tests
8. test_parsers.py → 22 tests
9. tests/conftest.py mock_llm fixture + tests/fixtures/llm_responses.py
10. tests/expected_scores.yaml
11. test_samples_rules_only.py → 32 tests
12. test_samples_full_pipeline.py → 15 tests
13. tests/README.md + root README.md update
```

### Verification

| Command | Result |
|---|---|
| `pytest` | 206 passed, 38 skipped, ~1.0s |
| `pytest -m "not slow"` | 188 passed, 25 skipped (~0.5s) — fast subset for inner-loop dev |
| `pytest -m integration` | 18 passed, 13 skipped — full-pipeline tests |
| `pytest -k iam` | All IAM-related regression sentinels |

---

## Phase 3.2 — Drift Detection

**Status:** Complete
**Theme:** When the same infrastructure is re-uploaded, automatically compare against the most recent prior scan and show what changed — score deltas per dimension, findings introduced (regressions), findings resolved (improvements), findings persisting.

### What Was Built

End-to-end drift detection from API to UI:
1. **SHA256 fingerprinting** of every uploaded bundle (filename-set hash + per-file content hashes)
2. **`GET /api/v1/reports/{id}/drift` endpoint** that finds the prior scan with the same bundle fingerprint and returns a structured drift summary
3. **Streamlit drift panel** that auto-appears when a re-upload is detected
4. **Deterministic-only comparison** — drift sees through LLM noise to the rule-based substrate

### Architecture Decisions

**1. Bundle fingerprint over filename SET, not content**
The first cut hashed filename+content pairs, which meant editing the file changed the bundle hash and broke baseline matching — exactly the wrong UX. The fix: hash the **sorted list of filenames only**. Per-file content hashes are still computed and stored as metadata (useful to show *which file* in the bundle changed), but the bundle hash itself is content-blind. Renaming, adding, or removing a file changes the bundle. Editing content does not — and that's precisely what makes drift detection work across edits.

**2. Drift compares ONLY rule-based findings**
LLM-augmented findings (`category="ai-analysis"`) have inherent run-to-run noise. The local Gemma model produces slightly different titles, resources, and wording on every invocation, even at low temperature. Including them in drift surfaced phantom "introduced" and "resolved" findings on identical re-uploads (3 new + 7 resolved when nothing actually changed). The fix: filter out `ai-analysis` findings before bucketing into introduced/resolved/persisting. LLM findings still appear in the report itself; they just don't pollute the diff.

**3. Score deltas use rule-only recomputation, not report.score directly**
The score deductions table in each agent sums over rule findings + dedup-survived LLM findings. That means even per-agent score is non-deterministic across runs of identical inputs. The fix: `compute_drift` recomputes per-agent scores from rule findings only, applying the same deduction values (CRITICAL=20, HIGH=10, MEDIUM=5, LOW=2, INFO=0). Drift's per-agent delta then equals zero on identical inputs — guaranteed.

**4. Architecture excluded from overall drift**
Even with deterministic `_calculate_architecture_score(gaps, agent_scores)`, the *gap list* is LLM-emitted and varies across runs. Including the architecture term in the overall delta leaked that noise — users saw `overall: -0.9` even when all three agent deltas were `+0.0`. The fix: `_rule_only_overall_score` is a weighted average of the three rule-only agent scores (weights renormalized to 0.85). The architecture delta is still surfaced separately in `score_deltas["architecture"]` for users who want to see it; it just doesn't pollute the overall.

**5. Finding signature is `(agent, category, title, resource)`**
Severity and description are deliberately excluded. Severity changes across LLM runs even for the same finding — re-classification shouldn't make a finding "vanish + reappear." Description is LLM-generated wording and drifts every run. The four-tuple is stable across re-runs of the rule pipeline.

**6. Backwards compatible — no schema migration**
New fields on `AnalysisReport` (`file_fingerprints`, `bundle_fingerprint`) have safe defaults (empty dict, empty string). Old reports without fingerprints deserialize cleanly. The drift `where=` query simply doesn't match them, and `find_baseline` returns `None` — frontend silently hides the panel.

### Components Delivered

| Component | Details |
|-----------|---------|
| **Fingerprint module** | `app/core/fingerprint.py::compute_fingerprints()` — SHA256 over sorted filenames; per-file content SHA256 stored as metadata |
| **Drift module** | `app/core/drift.py` — `find_baseline`, `compute_drift`, `_finding_signature`, `_rule_only_score`, `_rule_only_overall_score` |
| **Model extension** | `AnalysisReport.file_fingerprints: dict[str, str]` and `bundle_fingerprint: str` with defaults |
| **Store extension** | `app/core/store.py::find_by_bundle_fingerprint()` — queries ChromaDB by `bundle_fingerprint` metadata; `save_report` adds fingerprint to metadata when present |
| **API endpoint** | `GET /api/v1/reports/{report_id}/drift` — returns `{baseline, drift}` or `{null, null}` |
| **Routes wiring** | `analyze_infrastructure` and `analyze_text` compute fingerprints before save |
| **Frontend panel** | Drift expander after score overview — 4 metric cards (Overall/Security/Reliability/Cost with delta arrows), 3 sub-expanders (introduced/resolved/persisting), explanatory caption about LLM exclusion |

### Models Added

```python
class AnalysisReport(BaseModel):
    # ... existing fields ...
    file_fingerprints: dict[str, str] = {}    # filename -> sha256 hex
    bundle_fingerprint: str = ""              # sha256 over sorted filenames
```

### API Added

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/reports/{report_id}/drift` | Compare report against most recent prior scan of the same bundle. Returns `{baseline: null, drift: null}` if no prior version exists. |

### Tests Added

| File | Count | What's locked in |
|------|-------|------------------|
| `test_fingerprint.py` | 10 | Filename-set hash, content edits don't change bundle, file order independent, rename/add/remove DO change bundle |
| `test_drift.py` | 31 | Finding signature ignores severity/description, AI-analysis findings excluded from all buckets and severity counts, zero deltas for identical rule findings, score deltas use rule-only recomputation, **arch noise does not pollute overall delta** (the regression test for the residual bug found in smoke testing) |

### Challenges Addressed

- **First implementation hashed content** — drift panel hidden after editing file. Caught by manual smoke test before declaring done. Fix: bundle hash over filenames only.
- **LLM noise leaked into finding diff** — re-uploading identical file produced phantom "3 new, 7 resolved." Fix: exclude `ai-analysis` findings from all drift comparisons.
- **LLM noise leaked into score deltas** — per-agent score deltas were non-zero on identical inputs. Fix: rule-only score recomputation in drift module.
- **Architecture noise leaked into overall delta** — observed `overall: -0.9` on identical re-upload despite all per-agent deltas being `+0.0`. Fix: drop architecture term from `_rule_only_overall_score`, keep it as a separate field.
- **Pydantic field ordering** — adding fields to `AnalysisReport` after the custom `__init__` required keeping defaults so Pydantic field-validation order stays stable; verified against all 213 prior tests.

### Verification

| Step | Action | Expected | Verified |
|---|---|---|---|
| 1 | First upload of `k8s-api-deployment.json` | Drift panel hidden (no prior scan) | ✓ |
| 2 | Re-upload identical file | Drift panel shows all-zero deltas, "0 new, 0 resolved, 8 persisting" | ✓ |
| 3 | Add `securityContext: {runAsNonRoot: true}` and re-upload | Security: +10.0, Overall: +4.0, "0 new, 1 resolved, 7 persisting", resolved finding shows "Container may run as root" | ✓ exact match |

| Suite metric | Value |
|---|---|
| Tests passing | 248 (was 206 before Phase 3) |
| New tests | +42 (10 fingerprint + 31 drift + 1 arch-noise regression) |
| Runtime | ~1.2s |
| Manual smoke test | All three steps verified end-to-end against the live system |
