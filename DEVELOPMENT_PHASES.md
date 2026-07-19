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
`_detect_infra_type()` checks file content for K8s/Terraform markers before falling back to file extension. This handles the case where users paste Terraform content with a `.yaml` filename in the UI.

### Components Delivered

| Component | Details |
|-----------|---------|
| **FastAPI Backend** | REST API with file upload + text analysis endpoints |
| **Web Frontend** | Upload files or paste content, view scored reports |
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
3. **Drift panel** that auto-appears when a re-upload is detected
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

---

## Phase 3.3 — Compliance Framework Mapping

**Status:** Complete
**Theme:** Auditors and security-team consumers think in **compliance controls** (CIS Benchmarks, NIST 800-53), not technical findings ("Privileged container", "S3 without encryption"). Phase 3.3 bridges that gap by tagging every rule with the controls it satisfies, computing per-framework compliance scores, and shipping a one-click PDF export.

### What Was Built

End-to-end compliance scoring pipeline:
1. **Compliance mappings** — JSON file (`app/data/compliance_mappings.json`) defining 5 frameworks, 70 control descriptions, ~67 title overrides
2. **Per-finding control attribution** — every finding gets `compliance_controls: list[str]` populated post-analysis
3. **Per-framework scorecard** — passed/failed/score% for each framework, embedded in `AnalysisReport.compliance`
4. **Cloud-aware filtering** — Azure uploads only see CIS Azure (not CIS AWS); GCP uploads only see CIS GCP; etc.
5. **PDF report export** — auditor-ready document with score summary, compliance posture, per-framework control breakdown, findings appendix
6. **Frontend Compliance Posture panel** — metric cards per framework + control detail expander + PDF download button
7. **ChromaDB queryability** — per-framework score persisted as metadata for future "find reports below 70% CIS" queries

### Architecture Decisions

**1. Five Frameworks, Cloud-Scoped via `requires_any_of`**
Each framework declares which clouds make it relevant. The cloud-aware filter excludes a framework entirely when none of its required clouds is detected — no more "CIS AWS at 100%" on Azure uploads.

| Framework | Version | Required clouds |
|---|---|---|
| CIS Kubernetes Benchmark | 1.10 | `kubernetes` |
| CIS AWS Foundations Benchmark | 3.0 | `aws` |
| CIS Azure Foundations Benchmark | 3.0 | `azure` |
| CIS GCP Foundations Benchmark | 3.0 | `gcp` |
| NIST 800-53 Rev 5 | 5 | all four (cross-cloud) |

**2. Domain-Tagged Rule Mappings**
Each `(agent, category)` mapping carries a `domain` tag (`kubernetes`/`aws`/`azure`/`gcp`/`cross-cloud`) plus its `controls` list. A control is "assessable" on an upload only when at least one of its mapping domains matches a detected cloud, OR is `cross-cloud`. This prevents inflating the "passed" count with controls whose underlying rules never ran.

**3. Title Overrides for Cloud-Specific Findings**
Per-category defaults stay NIST-only and cloud-neutral (no CIS-AWS in the default `network` mapping). Cloud-specific CIS controls attach via `title_overrides` keyed by exact finding title — `Azure NSG rule open to internet` → `CIS-Azure-6.2/6.3`, `GCP firewall open to 0.0.0.0/0` → `CIS-GCP-3.6/3.7`. This was the key insight after fixing the original cloud-leakage bug.

**4. Cloud Detection from Finding Resources + tf_resources Fallback**
`_detect_clouds(report, tf_resources=None)` walks `Finding.resource` strings for `aws_*`/`azurerm_*`/`google_*` prefixes plus K8s `Kind/...` shape. For zero-finding clean uploads (production-grade samples), it falls back to the parsed `tf_resources` list passed from the route layer. Filename-based inference for `.tf`/`.hcl` extensions alone is **deliberately not used** — that's what caused the original bug.

**5. Two-Bug Fix Round (Discovered via Manual Smoke Test)**
The first cut had two layered bugs that surfaced when the user uploaded `azure-average.tf` and saw "CIS AWS 100%":
- **Bug 1:** `applies_to: ["terraform"]` matched any TF upload regardless of cloud — Azure uploads got AWS framework
- **Bug 2:** Controls with no fired rule were classified `passed` instead of `not assessed` — score inflated to 100%

Both fixed: framework-level filter via `requires_any_of`, control-level filter via `_is_control_assessable`. Documented in the JSON header and locked in by `test_unassessable_controls_not_inflated_into_passed`.

**6. PDF via reportlab.platypus**
`generate_pdf_report(report) -> bytes` builds a clean multi-page PDF: title page, score table, compliance scorecard table, per-framework PASS/FAIL control breakdown, findings appendix grouped by agent and severity. The frontend fetches via the new `GET /reports/{id}/export/pdf` endpoint and offers it as a download.

**7. Pure-JSON Extensibility**
Adding a new framework or new control attributions requires zero Python changes. The Python is data-driven via `framework_prefix_map`, `requires_any_of`, and `domain` tags. CIS Azure and CIS GCP were added in Phase 3.3's extension via JSON edits only.

### Components Delivered

| Component | Details |
|---|---|
| **Mappings file** | `app/data/compliance_mappings.json` — 5 frameworks, 70 control descriptions, ~67 title overrides, ~32 category mappings |
| **Compliance module** | `app/core/compliance.py` — `load_mappings`, `get_controls_for_finding`, `enrich_findings_with_compliance`, `compute_compliance_scorecard`, `_detect_clouds`, `_is_control_assessable`, `_classify_control` |
| **PDF export** | `app/core/pdf_export.py` — `generate_pdf_report` using `reportlab.platypus` |
| **Models added** | `Finding.compliance_controls`, `ComplianceFrameworkScore`, `ComplianceScorecard`, `AnalysisReport.compliance` |
| **API endpoint** | `GET /api/v1/reports/{report_id}/export/pdf` — returns inline PDF with `Content-Disposition: attachment` |
| **Routes wiring** | `enrich_findings_with_compliance` + `compute_compliance_scorecard` called between `run_analysis` and `save_report` in both `/analyze` endpoints; `_parse_tf_resources` helper threads `tf_resources` for clean-upload cloud detection |
| **Store extension** | `compliance_<framework_id>_pct` added to ChromaDB metadata in `save_report` |
| **Frontend** | "📋 Compliance Posture" panel after score overview; metric cards per framework; "Compliance details" expander with passed/failed control IDs; per-finding `📋 Controls:` line; "📄 Download PDF Report" button next to JSON download |
| **Dependency** | `reportlab==4.2.5` (BSD-3-Clause) added to `requirements.txt` |

### Models Added

```python
class Finding(BaseModel):
    # ... existing fields ...
    compliance_controls: list[str] = []   # safe default

class ComplianceFrameworkScore(BaseModel):
    framework_id: str            # e.g. "cis_azure"
    framework_name: str          # e.g. "CIS Azure Foundations Benchmark"
    version: str
    score_pct: float             # 0-100
    controls_passed: list[str] = []
    controls_failed: list[str] = []

class ComplianceScorecard(BaseModel):
    frameworks: list[ComplianceFrameworkScore] = []

class AnalysisReport(BaseModel):
    # ... existing fields ...
    compliance: Optional[ComplianceScorecard] = None
```

### API Added

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/reports/{report_id}/export/pdf` | Render the full report as an auditor-ready PDF |

### Tests Added

`tests/test_compliance.py` — 50 tests covering:
- Mappings sanity (every control has a description, every prefix resolves to a framework, every mapping has a domain, all 5 frameworks defined, all `requires_any_of` declared)
- Cloud attribution per finding (Azure NSG → CIS-Azure not CIS-AWS; GCP IAM → CIS-GCP not CIS-AWS; etc.)
- Cloud detection from `Finding.resource` strings
- Cloud-aware framework filtering (Azure-only upload excludes CIS AWS / CIS K8s / CIS GCP; GCP-only excludes the others; mixed includes both relevant)
- Score formula (`passed / max(1, passed+failed) * 100`)
- Unassessable controls excluded from "passed" — the regression test for the original bug
- PDF generation (magic bytes, report ID present, handles empty reports + reports with compliance + findings with controls)

### Framework Matrix (Verified Against All 6 Samples)

| Sample | Frameworks shown | Top-level scores |
|---|---|---|
| `vulnerable-deployment.yaml` | CIS Kubernetes (0%) + NIST (42.9%) | Sec 0, Rel 23, Cost 65 |
| `vulnerable-infra.tf` | CIS AWS (9.1%) + NIST (23.5%) | Sec 0, Rel 40, Cost 59 |
| `azure-average.tf` | **CIS Azure (66.7%)** + NIST (77.8%) | Sec 70, Rel 88, Cost 100 |
| `azure-production-grade.tf` | **CIS Azure (100%)** + NIST (100%) | Sec 100, Rel 100, Cost 100 |
| `gcp-average.tf` | **CIS GCP (57.1%)** + NIST (64.7%) | Sec 53, Rel 85, Cost 90 |
| `gcp-production-grade.tf` | **CIS GCP (100%)** + NIST (100%) | Sec 100, Rel 100, Cost 100 |

**No cross-cloud leakage anywhere.** Every cloud-only upload sees exactly its own clouds' frameworks plus NIST. Mixed uploads see all relevant frameworks.

### Production-Grade Samples Added

| File | Purpose | Predicted scores |
|---|---|---|
| `samples/gcp-production-grade.tf` | Hardened GCP: private GKE + network policy + master authorized networks, REGIONAL Cloud SQL with SSL + private IP + deletion protection, GCS uniform access + lifecycle + KMS, shielded VM, restricted firewall (IAP only) | 100/100/100 + CIS GCP 100% + NIST 100% |
| `samples/azure-production-grade.tf` | Hardened Azure: hardened NSG (no 0.0.0.0/0), Storage with HTTPS+TLS1.2+private+lifecycle+CMK, Key Vault purge+soft-delete, zone-redundant SQL with LTR, App Service https_only+backup, AKS multi-zone+RBAC+AAD+network_policy+auto-upgrade, Cosmos multi-region | 100/100/100 + CIS Azure 100% + NIST 100% |

### Challenges Addressed

- **Original cloud-leakage bug** (Azure upload showed CIS AWS at 100%): root cause was `applies_to: ["terraform"]` being too coarse + "passed" default for unfired rules. Fixed via two-layer cloud-aware filter; locked in by `test_azure_only_upload_excludes_cis_aws_framework` and `test_unassessable_controls_not_inflated_into_passed`.
- **Clean-upload cloud detection**: a 100%-perfect Azure file has zero findings, so `_detect_clouds` would return `{}` and emit no frameworks. Fixed by threading parsed `tf_resources` into the cloud-detection helper as a fallback signal — the route layer parses Terraform inline via `_parse_tf_resources` and passes it through.
- **`reportlab.colors.Color.int_value` doesn't exist** in 4.2.x: replaced with a hardcoded hex-string lookup `_severity_color_hex(sev)`.
- **PDF text content stream is compressed**: tests assert magic bytes (`%PDF-`) and presence of report ID in the title metadata (uncompressed), not raw-byte greps for content strings.
- **CIS GCP / CIS Azure missing in v1**: user surfaced the asymmetry. Fixed via JSON-only extension (no Python changes) — added 2 frameworks, 2 prefixes, ~32 control attributions across `title_overrides`, ~26 new control descriptions.
- **Reverse cross-cloud leakage** (Azure findings inheriting CIS-GCP, K8s findings inheriting CIS-Azure, etc.): preempted by 4 new regression tests added during the CIS GCP/Azure extension. Locked in.

### Verification

| Check | Result |
|---|---|
| `pytest` | 298 passed, 38 skipped, 0 failed (~3.7s) |
| `pytest tests/test_compliance.py` | 50 tests pass |
| Cloud attribution invariants | All cross-cloud "must NOT inherit" assertions hold |
| End-to-end framework matrix | All 6 samples produce the correct framework set |
| Manual smoke test | Verified live for `azure-average.tf` (CIS Azure 66.7%, NIST 77.8%, no CIS AWS), `gcp-average.tf` (CIS GCP 57.1%, NIST 64.7%, no CIS AWS), `vulnerable-deployment.yaml` (CIS K8s, NIST), `vulnerable-infra.tf` (CIS AWS, NIST) |
| PDF export | Renders cleanly across all sample types, opens in standard viewers, contains scores + controls + findings |

---

## Phase 3.4 — Auto-Remediation (Scaffolding)

**Headline feature.** Transforms the platform from "tells you what's wrong" to "gives you the patch that fixes it." For every finding the platform produces, the user can click "Generate fix" and receive a unified diff + the full patched file, validated by re-parsing.

### What Was Built

For each finding, the new remediator agent:

1. **Locates the source file** in the upload bundle by re-parsing every uploaded file and matching the finding's `resource` string (e.g. `aws_kms_key.main`, `Deployment/default/api`) against the parsed resources.
2. **Applies a deterministic fixer** — for every category the rule engine raises, the agent hand-builds the exact edit (PyYAML round-trip for K8s manifests; surgical regex-anchored block edits for HCL).
3. **Falls back to the local LLM** for `category="ai-analysis"` findings and any category without a deterministic fixer. The LLM returns the full patched file via the `remediator-k8s` / `remediator-tf` skill files; output is validated by re-parse and retried once on validation failure.
4. **Validates every patch by re-parsing the output.** Patches that produce unparseable YAML or HCL are rejected — the platform never returns broken IaC.
5. **Returns a `Patch`** containing the original content, patched content, unified diff (`difflib.unified_diff`, stdlib only — no `unidiff` dependency added), strategy, validation status, explanation, and warnings. The frontend renders the diff and offers a "Download patched file" button.

### Critical Design Decisions (Locked in by Tests)

| Decision | Choice | Rationale |
|---|---|---|
| **File contents persistence** | NOT stored server-side. Caller re-supplies them in the remediation request body. | Matches Phase 3.2's stateless ethos (we persist fingerprints, not file contents). Avoids storing potentially sensitive IaC indefinitely. |
| **Diff library** | `difflib` (stdlib) | `unidiff` parses diffs; we *generate* them. `difflib.unified_diff` is sufficient — no extra dependency. |
| **Deterministic fixers first** | Try rule-aware hand-built fixers before invoking the LLM | Reliable, fast, no Ollama needed for the 80% case. LLM only gets the long tail (ai-analysis findings, weird shapes). |
| **Validation by re-parse** | Both deterministic and LLM patches go through `_validate_patch` (PyYAML / hcl2 / json). | "Never generate broken IaC" guarantee. Locked in by `test_validate_rejects_unparseable_yaml`, `test_validate_rejects_unparseable_terraform`. |
| **LLM retry-on-invalid** | One retry with the previous error appended to the prompt | Local Ollama models occasionally emit malformed JSON or unparseable HCL; one retry lifts the success rate substantially. Locked in by `test_llm_fallback_retries_on_invalid_output`. |
| **No automatic file writes** | The platform returns `Patch.patched_content`; the user copies it manually. | Authorization scope is minimal — we never modify the user's working tree. |
| **Placeholders use `CHANGE_ME_*` prefix** | When a fix needs a value the user must choose (CIDRs, KMS key ids, SA emails) | Consistent, greppable, makes follow-up edits explicit. Surfaced via `Patch.warnings`. |
| **Inline-block aware HCL editing** | Multi-line blocks for nested HCL (`metadata_options { ... }`); avoid trailing `#` comments inside inline blocks | `python-hcl2` doesn't accept semicolons as separators; trailing `#` consumes the closing brace of inline blocks. Both pitfalls discovered during test, locked in by `test_tf_imdsv2_required` and `test_tf_security_group_open_ingress_fixer`. |
| **Brace-aware HCL block locator** | Custom string-and-comment-aware brace counter (`_find_tf_block_span`) | Strings with `{` or `}`, single-line and multi-line comments, and nested blocks all work. Locked in by `test_tf_block_span_with_braces_in_strings` and `test_tf_block_span_with_nested_blocks`. |

### Components Delivered

| File | Purpose |
|---|---|
| `app/agents/remediator.py` | Core remediator agent: file discovery, K8s & TF deterministic fixers, LLM fallback, validation, diff generation. ~1100 lines. |
| `skills/remediator-k8s.md` | LLM skill for Kubernetes patches — strict JSON schema, smallest-diff rule, CHANGE_ME placeholder convention. |
| `skills/remediator-tf.md` | LLM skill for Terraform patches — same conventions, allows companion-resource additions. |
| `app/models.py` | New `Patch` Pydantic model carrying full patch payload + diagnostics. |
| `app/api/routes.py` | New `POST /api/v1/reports/{id}/remediate/{finding_index}` endpoint. Re-supplies file_contents in body. |
| `frontend/app.py` | "🛠️ Generate fix" button per finding; renders diff inline; offers "Download patched file"; handles deterministic vs LLM strategy badge. |
| `tests/test_remediator.py` | 43 tests covering K8s + TF fixers, validation, LLM fallback (with retry), edge cases, file discovery errors. |
| `tests/conftest.py` | Mock LLM router updated to recognize remediator prompts; remediator monkeypatch added. |
| `tests/fixtures/llm_responses.py` | Default canned remediator response (no-op) so unrelated tests don't accidentally invoke remediation. |

### K8s Categories with Deterministic Fixers

`privileged`, `run-as-root`, `filesystem` (readOnlyRootFilesystem), `resource-limits` (CPU/memory requests + limits), `image-tag` (replace `:latest`), `host-namespace` (hostPID/hostNetwork/hostIPC), `public-exposure` (LoadBalancer→ClusterIP), `rbac` (cluster-admin downgrade, wildcard narrowing), `hardcoded-secret` (env value→secretKeyRef).

### Terraform Categories with Deterministic Fixers

| Category | Coverage |
|---|---|
| `network` | aws_security_group ingress, google_compute_firewall source_ranges, azurerm_network_security_rule source prefix, AKS network_policy, GKE network_policy + private cluster + master authorized networks, Lambda VPC config |
| `encryption` | aws_s3_bucket SSE companion resource, aws_db_instance storage_encrypted, aws_ebs_volume encrypted, aws_kms_key rotation, azurerm_key_vault purge_protection + soft_delete, azurerm_managed_disk CMK |
| `encryption-in-transit` | aws_lb_listener HTTPS:443, azurerm_storage_account HTTPS-only + min_tls_version |
| `public-exposure` | aws_s3_bucket ACL=private + public_access_block companion, aws_db_instance publicly_accessible=false, google_sql_database_instance ipv4_enabled=false, google_storage_bucket uniform_bucket_level_access=true |
| `instance-metadata` | aws_instance / aws_launch_template IMDSv2, google_compute_instance shielded VM |
| `logging` | aws_cloudtrail enable_logging + multi-region + log validation, aws_vpc flow_log companion |
| `hardcoded-secret` | password / administrator_login_password / master_password → var.db_password |
| `iam` | aws_iam_policy / aws_iam_role_policy TODO annotation; google_project_iam_binding allUsers/allAuthenticatedUsers replacement |
| `rbac` | azurerm_kubernetes_cluster role_based_access_control_enabled + Azure AD integration |
| `privileged` | aws_ecs_task_definition `"privileged":true → false` |

Anything outside this matrix flows to the LLM fallback.

### Test Sentinels

- `test_k8s_privileged_fixer` — round-trip patches privileged container, re-parses, verifies field set
- `test_k8s_multi_doc_yaml_preserves_other_documents` — patching one workload doesn't drop adjacent ConfigMaps
- `test_k8s_finding_against_init_container_falls_back_to_first` — container-name parsing from finding description
- `test_tf_block_span_balanced_braces`, `_with_braces_in_strings`, `_with_nested_blocks` — locator robustness
- `test_tf_set_argument_replaces_existing` — no duplicate keys when toggling a flag
- `test_validate_rejects_unparseable_yaml`, `_unparseable_terraform` — broken IaC never escapes
- `test_llm_fallback_retries_on_invalid_output` — retry path proven
- `test_llm_fallback_fails_when_both_attempts_invalid` — proper error propagation
- `test_unsupported_category_falls_back_to_llm_then_fails` — categories without deterministic fixers route to LLM as designed

### API & Frontend

**Endpoint:** `POST /api/v1/reports/{report_id}/remediate/{finding_index}`
- Body: `{"file_contents": {filename: content, ...}}` (the original uploaded files)
- Response: `Patch` model — full patched content, unified diff, strategy, validation status, warnings
- Errors: `404` (report not found), `400` (bad index, missing file_contents), `422` (RemediationError — unsupported category for which the LLM also failed), `500` (unexpected error)

**Frontend:** Per-finding "🛠️ Generate fix" button caches the response in `st.session_state` keyed by `(report_id, global_finding_index)`. Renders strategy badge (⚡ Deterministic vs 🤖 LLM), warnings, the unified diff (`st.code(language="diff")`), and a download button for the patched file.

### Verification

| Check | Result |
|---|---|
| `pytest` | **341 passed, 38 skipped, 0 failed** (~1.7s) |
| `pytest tests/test_remediator.py` | 43 tests pass |
| End-to-end via FastAPI TestClient | `aws_kms_key.main` deterministic fix returns valid patch with correct diff |
| Re-parse of every deterministic patch | All patches produce parseable YAML / HCL |
| LLM fallback with mocked toggle | Retry-on-invalid path works; both-invalid path raises RemediationError cleanly |
| Backwards compatibility | Existing 298 tests still pass; no regressions |

### Challenges Addressed

- **`python-hcl2` doesn't accept `;` as a separator** — initial inline-block injection (`metadata_options { http_tokens = "required"; ... }`) failed to re-parse. Fixed by emitting multi-line HCL blocks. Locked in by `test_tf_imdsv2_required`.
- **Trailing `#` comments inside inline single-line HCL blocks** consume the rest of the line including the closing brace. Fixed by dropping trailing-comment placeholders; warnings use `Patch.warnings` instead. Locked in by `test_tf_security_group_open_ingress_fixer`.
- **LangChain `ChatPromptTemplate` interprets `{}` in templates as variables** — passing an HCL/JSON file body through `human` template variables blew up because file content contains literal braces. Fixed by building `SystemMessage` + `HumanMessage` directly and bypassing `ChatPromptTemplate.from_messages`.
- **Mocked LLM didn't recognize raw message-list inputs** — the test fake's `_extract_prompt_text` only handled `PromptValue` shapes. Extended to handle `list[BaseMessage]` so the remediator's direct-call form is mockable.
- **Stateless file content** — chose to NOT persist file contents in ChromaDB. The frontend caches the original upload in `st.session_state["cached_file_contents"]` and re-supplies it via the remediation request body.

## Phase 3.5 — Plugin Harness (Dynamic Agent Registration)

**Theme:** Drop a new skill file into `skills/` and have it picked up automatically as a new analysis agent — no Python code change for a new LLM agent. Compliance (Phase 3.3) becomes the first registered plugin. This closes out Phase 3.

### What Was Built

A two-layer plugin harness, additive-only so the existing hardcoded pipeline and scoring are untouched when no plugin is present:

1. **`app/core/plugin_registry.py` (descriptor layer)** — `PluginAgent` pydantic model (`name`, `agent_name`, `agent_type: rule_based|llm_only|hybrid`, `weight`, `infra_type`, `skill_name`, `prompt`) and `discover_plugins()`. A skill is a registerable plugin **only if its frontmatter declares BOTH `agent_type` and `weight`**. Core agents (`security`/`reliability`/`cost`/`architecture-reviewer`/`supervisor`/`remediator`) are excluded from runtime registration even when tagged, so migration frontmatter never causes double-execution.
2. **`app/core/plugin_loader.py` (execution layer)** — `run_all_plugins()` runs discovered plugins sequentially (Ollama single-stream). `llm_only`/`hybrid` route through the shared `run_llm_agent` helper; `rule_based` plugins dispatch to a registered adapter in `RULE_BASED_ADAPTERS`. Every plugin runs isolated — a discovery error, missing adapter, or runtime exception is logged and yields no report, never breaking the pipeline.
3. **`app/core/llm_agent.py` (de-duplication)** — the LLM invoke → strip-fence → `json.loads` → build-findings → dedup → severity-deduction score pattern (previously inlined in `security.py`/`reliability.py`/`cost.py`) extracted into one reusable `run_llm_agent(...)`. New agents use it; the three core agents are intentionally left unchanged to keep their diffs and behavior minimal.

### Architecture Decisions

- **Additive, normalized scoring.** `calculate_overall_score` gains an optional `plugin_reports: list[(AgentReport, weight)]`. Plugin weights join the same normalized pool (`weighted_sum / total_weight`). When `plugin_reports` is empty/None the code path and result are **byte-identical to pre-3.5** — the exact scoring assertions (88.5 / 100.0 / 85.0, unknown-agent 0.28) are preserved verbatim.
- **Compliance as the first plugin = deterministic adapter, not a new LLM skill.** `skills/compliance.md` declares `agent_type: rule_based`, `weight: 0.10`. Its adapter (`_compliance_adapter`) reuses the Phase 3.3 engine (`enrich_findings_with_compliance` + `compute_compliance_scorecard`) verbatim — no LLM, no re-derivation. Score = mean per-framework `score_pct`; 100.0 (no penalty) when no framework applies. The authoritative `report.compliance` scorecard is still computed in `routes.py` exactly as before; the adapter's internal scorecard is ephemeral (only to derive the agent score).
- **New pipeline node, pass-through when empty.** `plugin_agents_node` runs between `architecture_review` and `supervisor`. With an empty registry it returns `{"plugin_reports": []}` and the existing 6-node behavior is unchanged.
- **Existing skills migrated for discoverability only.** `security-*`/`reliability-*`/`cost-*`/`architecture-reviewer` skills gained `agent_type: hybrid` + weights mirroring `report.py` (0.34/0.30/0.21/0.15). Their hardcoded execution path is unchanged; the core-agent exclusion set keeps them out of the runtime plugin set.

### Components Delivered

| Component | Detail |
|---|---|
| **New module** | `app/core/plugin_registry.py` — discovery + `PluginAgent` model |
| **New module** | `app/core/plugin_loader.py` — execution + compliance adapter |
| **New module** | `app/core/llm_agent.py` — shared `run_llm_agent` + `SEVERITY_DEDUCTIONS` |
| **New skill** | `skills/compliance.md` — first plugin (rule_based) |
| **Changed** | `app/core/report.py` — `plugin_reports` param (backwards-compatible) |
| **Changed** | `app/agents/supervisor.py` — `plugin_agents_node`, state key, edge rewire |
| **Changed** | `app/core/skills.py` — `load_skill(skill_name, skills_dir=None)` |
| **Changed** | 7 existing skill files — `agent_type` + `weight` frontmatter |
| **Tests** | `tests/test_plugin_harness.py` — 19 tests |

### Verification

| Check | Result |
|---|---|
| `pytest tests/test_plugin_harness.py` | **19 passed** |
| Full suite | **524 passed, 38 skipped** (was 505 passed at baseline + 19 new) |
| Regressions | **0** — the only 8 failures are pre-existing `test_llm_provider.py` cloud-SDK `ModuleNotFoundError`s, unrelated to this phase and present before any change |
| Zero-plugin invariance | `calculate_overall_score(core, plugin_reports=[])` == `calculate_overall_score(core)` == 88.5 (asserted) |
| Weight math | core + `(Compliance, 0.10)` → 84.4 (asserted) |
| End-to-end | `run_analysis` on a privileged-container Deployment yields `[Security, Reliability, Cost, Compliance]` agents; overall score folds in the plugin weight |

### Challenges Addressed

- **`discover_plugins(skills_dir=...)` scanned a custom dir but loaded from the hardcoded `SKILLS_DIR`** — caught by a test using `tmp_path`. Fixed by threading an optional `skills_dir` through `load_skill` (one parser, no duplication) rather than re-implementing frontmatter parsing in the registry.
- **Double-processing risk from the Compliance Agent's own findings** — verified that its `compliance-gap` findings (empty `compliance_controls`) contribute nothing to the routes-level `failed` control set, so the authoritative `report.compliance` scorecard is unaffected by the plugin also appearing in `agent_reports`.
- **Smuggling weight onto a pydantic `AgentReport`** — the first scoring draft attached a private `_plugin_weight` attribute; replaced with explicit `(report, weight)` tuples so scoring never depends on model-mutation behavior.

## Phase 4.1 + 4.5 — Resource Dependency Graph & SPOF Detector

**Theme:** Move from "what's wrong with each resource" to "how do these resources depend on each other, and which ones are single points of failure." Pure graph analysis over resources already extracted during analysis — no cloud, no live state, no LLM, no paid APIs.

### What Was Built

- **`app/core/graph.py`** — a dependency-graph builder over the two structures every input format normalizes into (`k8s_resources` from YAML/YML/K8s-JSON/rendered-.tgz Helm; `tf_resources` from TF/HCL/Terraform-JSON). Directed graph via **NetworkX** (BSD-3, pure-Python, no system deps). Edge `A -> B` means "A depends on B".
- **SPOF detector (4.5)** in the same module — flags resources that are high-fan-in (>= 5 transitive dependents) and/or articulation points (removal partitions the graph). Emits `architecture`-category `Finding`s under an "Architecture Agent", severity scaling with dependent count.
- **Persisted graph (Option A)** — new `DependencyGraph` / `GraphNode` / `GraphEdge` / `Spof` models on `AnalysisReport.dependency_graph` (Optional, None default so old reports and non-infra uploads deserialize cleanly). Built in `supervisor_node` from the live parsed resources and serialized onto the report, so future blast-radius / diagram endpoints can serve it without re-parsing.

### Architecture Decisions

- **Universal coverage by construction.** All six input types converge into `k8s_resources` + `tf_resources` before analysis (`.tgz` is Helm-rendered to YAML in `routes.py`; `.json` is routed to K8s or TF by content). The graph builder targets only those two structures, so it covers every format automatically. Verified against real samples (Terraform-JSON: 26 nodes/37 edges/4 SPOFs; K8s-JSON; HCL).
- **Edges preserved by the parsers.** Confirmed empirically that `hcl2` keeps `${...}` interpolations and `depends_on` as raw strings, and the K8s parser preserves selectors, `secretKeyRef`/`configMapKeyRef`/`envFrom`, `serviceAccountName`, and volume secret/configMap/PVC names. No parser changes were needed.
- **Node-id namespacing.** Kubernetes uses `Kind/namespace/name`; Terraform uses `type.name`. Separate namespaces so a mixed upload never collides.
- **SPOF findings never perturb the score.** The dependency graph and SPOF findings are computed AFTER `calculate_overall_score`, and the SPOF "Architecture Agent" report carries score 100.0 (informational). The locked scoring weights (0.34/0.30/0.21/0.15) and their exact assertions are untouched.
- **Referenced-but-absent resources** are added as nodes with `present=False` (e.g. a Secret used by a Deployment but not in the upload), so blast-radius can still reason about them.
- **`kind: List` is expanded** inside the graph builder (the base parser leaves it unexpanded), so List-wrapped manifests contribute real nodes/edges.

### Components Delivered

| Component | Detail |
|---|---|
| **New module** | `app/core/graph.py` — builder, SPOF detector, serializer |
| **New dependency** | `networkx==3.4.2` (BSD-3-Clause) in `requirements.txt` |
| **Models** | `DependencyGraph`, `GraphNode`, `GraphEdge`, `Spof` + `AnalysisReport.dependency_graph` field |
| **Changed** | `app/agents/supervisor.py` — build + persist graph, surface SPOFs (isolated in try/except; never breaks a run) |
| **Tests** | `tests/test_graph.py` — 27 tests |

### Verification

| Check | Result |
|---|---|
| `pytest tests/test_graph.py` | **27 passed** |
| Full suite | **552 passed, 38 skipped** (525 baseline + 27 new) |
| Regressions | **0** — only the pre-existing 8 `test_llm_provider.py` cloud-SDK failures remain |
| End-to-end | `run_analysis` on a 7-resource TF bundle produces the graph + a KMS SPOF (6 dependents) as an Architecture Agent finding; graph survives a JSON serialization round-trip |
| Real samples | Terraform-JSON / K8s-JSON / HCL all build sensible graphs |

### Challenges Addressed

- **Spurious edges from `data.`/`module.` paths** — the reference regex initially matched the middle of `${data.aws_ami.ubuntu.id}`, yielding a bogus `aws_ami.ubuntu` resource edge. Caught by `test_data_source_excluded`. Fixed by also inspecting the token immediately preceding a match and rejecting non-resource prefixes there.
- **HCL single-value list-wrapping** — references appear as both `"${...}"` and `["${...}"]`; the recursive `_iter_strings` walk handles both.
- **Drift determinism preserved** — SPOF findings are `architecture`-category (deterministic), so they enter drift's `persisting` bucket for identical uploads and contribute zero to introduced/resolved, keeping the "identical bundle -> all-zero deltas" invariant intact.

## Phase 4.2 + 4.4 — Blast Radius, Architecture Diagram & UI Panel

**Theme:** Make the Phase 4.1/4.5 dependency graph *usable*. The graph was computed and persisted but only visible in the raw report JSON; this increment surfaces it as an interactive Architecture view and adds the query endpoints — served entirely from the stored graph (no re-parse, since original files aren't persisted).

### What Was Built

- **`app/core/graph.py`**:
  - `graph_from_model()` — rebuild a NetworkX DiGraph from the persisted `DependencyGraph`.
  - `blast_radius(model, resource)` (4.2) — reverse-graph traversal returning direct + transitive dependents, an impact count, a criticality band (none/medium/high/critical), and whether the resource is a known SPOF. Cycle-safe (`nx.descendants` on the reversed graph). Returns `found=False` for unknown resources rather than raising.
  - `to_mermaid(model, highlight)` (4.4) — a valid Mermaid `flowchart LR`. Real ids (which contain dots/slashes/colons) map to synthetic `nN` node identifiers with the real id in a quoted label, so Mermaid never mis-parses. SPOF nodes styled red, referenced-but-absent nodes dashed, an optional highlight node emphasized. Large graphs truncate to 60 nodes (SPOF neighborhood prioritized) with a note.
- **`app/api/routes.py`**:
  - `GET /reports/{id}/blast-radius?resource=...` — `resource` is a query param so K8s `Kind/ns/name` ids (with slashes) and TF `type.name` ids work without path-encoding. 404 for missing report / missing graph / unknown resource.
  - `GET /reports/{id}/diagram?format=mermaid&highlight=...` — returns the Mermaid text (`text/plain`). 400 for unsupported format, 404 for missing report/graph.
- **`frontend/app.py`** — **🏛️ Architecture & Dependencies** panel in the report view: resource/dependency/SPOF metric row, a prominent SPOF list, the Mermaid dependency diagram (rendered client-side via mermaid.js from CDN inside `components.html` — version-agnostic, no dependency on a native `st.mermaid`), and an interactive blast-radius resource picker that highlights the selected node in the diagram and lists affected resources. Hidden when the report has no `dependency_graph` (pre-Phase-4 or history reloads).

### Architecture Decisions

- **Served from the persisted graph, never re-parsed.** Endpoints read `report.dependency_graph` (Option A from 4.1). This is why the graph had to be stored on the report — original files aren't persisted.
- **Synthetic Mermaid node ids.** Resource ids are not valid Mermaid identifiers; mapping to `nN` + quoted labels is the robust fix (locked by `test_node_ids_are_safe`).
- **Mermaid over Graphviz.** No system binary, renders client-side, zero new Python dependency.
- **4.3 (failure-mode LLM narrative) deferred** — LLM-dependent and fragile on the local model; the deterministic blast radius already answers "what breaks if X fails."

### Verification

| Check | Result |
|---|---|
| `pytest tests/test_graph.py` | 40 passed (13 new blast/mermaid) |
| `pytest tests/test_graph_endpoints.py` | 10 passed (TestClient: 404/400/422 edge cases) |
| Full suite | **601 passed, 38 skipped** (venv incl. networkx) |
| Live E2E | `terraform-production-grade.json` → report with 26 nodes/37 edges/4 SPOFs; diagram endpoint returns valid Mermaid; blast-radius on `aws_kms_key.main` returns its dependents; unknown resource + bad report both 404 |

### Challenges Addressed

- **networkx missing in the venv** — the backend server crashed silently in the graph node (`try/except` swallowed `ModuleNotFoundError`), so `dependency_graph` came back NULL in live reports even though tests passed (they ran in system Python). Fixed by installing `networkx==3.4.2` into the venv; `requirements.txt` already declared it.
- **Mermaid `\n` label break** — `_mermaid_escape_label` stripped backslashes, so `\n` became a literal `n`. Switched to Mermaid's `<br/>`.
- **Node-id path routing** — K8s ids contain `/`; used a query param for `resource` instead of a path segment.

## Phase 4 — Infrastructure Simulation — COMPLETE

Phase 4 is complete. It shifted the platform from per-resource findings to
whole-system reasoning: how resources depend on each other, which ones are
single points of failure, and what breaks if one fails. All of it is pure,
deterministic graph analysis over data already extracted during analysis — no
cloud, no live state, no paid APIs.

**Shipped sub-phases** (details in the sections above):

| Sub-phase | Delivered |
|---|---|
| 4.1 Dependency Graph | Directed graph over every resource; works for all six input formats (YAML/YML/TF/JSON/HCL/TGZ), which all normalize into `k8s_resources` + `tf_resources`. Persisted on `AnalysisReport.dependency_graph`. |
| 4.2 Blast Radius | `GET /reports/{id}/blast-radius?resource=...` — everything that transitively depends on a resource, with a criticality band. |
| 4.4 Architecture Diagram + UI | `GET /reports/{id}/diagram` (Mermaid) + the "Architecture & Dependencies" UI panel (diagram, SPOF list, interactive blast-radius picker). |
| 4.5 SPOF Detector | High-fan-in + articulation-point detection → "Resilience Agent" findings (informational; excluded from the weighted score). |

**4.3 Failure-Mode LLM narrative — DROPPED (deliberate).**
The plan was to feed the dependency graph to the local LLM for a "what if X
fails" prose narrative. It was dropped, not deferred-indefinitely, for two
reasons: (1) it relies on the local Ollama model, which is unreliable for this
kind of open-ended generation (the same fragility that made whole-file LLM
remediation fail); and (2) the deterministic **blast radius (4.2)** already
answers "what breaks if X fails" — accurately, instantly, and without an LLM.
An LLM narrative would be a lower-trust addition on top, so it was intentionally
left out to keep Phase 4 fully deterministic and trustworthy.

**Edge coverage note.** The graph detects only *explicit* dependencies —
literal `${...}` interpolations / `depends_on` in Terraform, and concrete
references in Kubernetes (Service selectors, Ingress backends, secret/configMap
refs, service accounts, volumes). It does not infer *implicit* links (e.g. a
CloudWatch log group tied to a Lambda by naming convention), because guessing
those risks drawing wrong edges — a wrong dependency is worse than a missing
one for blast-radius analysis. Resources with no explicit reference appear as
isolated nodes, which is itself a useful signal (standalone, implicitly linked,
or possibly missing a wiring resource).

