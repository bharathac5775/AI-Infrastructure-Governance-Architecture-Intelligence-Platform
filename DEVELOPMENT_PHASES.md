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
Both rules and the LLM often find the same issue worded differently. A keyword + synonym overlap algorithm (`dedup.py`) filters LLM findings that duplicate rule findings, using a 0.25 overlap threshold.

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
| **Report System** | Weighted scoring (Security 40%, Reliability 35%, Cost 25%) — rebalanced in Phase 2 |
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
- **Threshold tuning**: Minimum overlap raised from 2 to 3, percentage lowered from 25% to 20%, improving precision

**7. Scoring Rebalanced**  
With the Architecture Reviewer added as a 4th scoring dimension, overall score weights were rebalanced:
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
