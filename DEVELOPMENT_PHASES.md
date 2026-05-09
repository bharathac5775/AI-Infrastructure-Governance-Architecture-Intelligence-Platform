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
| **Report System** | Weighted scoring (Security 40%, Reliability 35%, Cost 25%) |
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

### Bugs Fixed During Phase 1

| Bug | Root Cause | Fix |
|-----|-----------|-----|
| Pod-level securityContext false positive | Only checked container-level `runAsNonRoot`, not pod-level | Check both `pod_spec.securityContext` and `container.securityContext` with proper cascading |
| LLM fallback scoring set to 80 | When LLM unavailable, score defaulted to 80 instead of using rule score | Use `rule_score` directly when LLM fails |
| HPA flagged as HIGH severity | Missing HPA was over-penalized | Changed to LOW — HPA is a nice-to-have, not critical |
| Anti-affinity flagged as HIGH | Over-severity for missing anti-affinity | Changed to LOW |
| Redis single-replica flagged as HIGH | Same severity as stateful workloads | Changed to MEDIUM — cache workloads are more resilient to restarts |
| Duplicate findings between rules and LLM | Exact title matching was too strict | Implemented keyword + synonym overlap dedup with 0.25 threshold |
| Hardcoded secrets undetected | No rule for env vars containing passwords | Added rule checking env var names for password/secret/token/key keywords |
| Terraform files ignored | Supervisor only parsed K8s YAML | Added TF parsing in supervisor, `tf_resources` passed to all agents |
| IAM wildcard policy not detected | HCL2 parses `jsonencode()` with single quotes | Adjusted string matching for HCL2 output format |
| EC2 instance type matching too broad | Substring matching caused false positives | Changed to prefix matching with tuples |
| K8s/Terraform concept leakage | Single LLM prompt per agent mixed K8s and TF concepts | Created 6 separate prompts (K8s + TF per agent) with explicit guardrails |
| Pasted TF content detected as K8s | File extension checked first (`.yaml` default in UI) | Changed `_detect_infra_type()` to check content before extension |
| Docker frontend can't reach API | `localhost` inside container resolves to frontend, not api | Made API_URL configurable via env var, set to `http://api:8000/api/v1` in docker-compose |
| CORS `*` + credentials | Browsers reject wildcard origin with `allow_credentials=True` | Set `allow_credentials=False` |
| ECS privileged check never matches | `.replace(" ", "")` strips space but check still looks for `": true"` with space | Fixed to check `":true"` (no space) |
| Dedup code duplicated across 3 agents | Same `_STOP_WORDS`, `_SYNONYMS`, `_is_duplicate` copy-pasted | Extracted to shared `app/core/dedup.py`, agents import from it |
| LangGraph rebuilt on every request | `build_analysis_graph()` called inside `run_analysis()` | Moved to module-level singleton `_compiled_graph` |
| Loose LangChain version pins | `>=` pins could break on minor version changes | Pinned to exact tested versions |
| Cost agent dedup threshold inconsistent | Cost used 0.35 while others used 0.25 | Unified to 0.25 via shared dedup module |

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

## Phase 2 — (Planned)

_To be documented when Phase 2 begins._
