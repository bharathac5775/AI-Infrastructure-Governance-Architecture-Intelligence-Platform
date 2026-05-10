# AI Infrastructure Governance & Architecture Intelligence Platform

An AI-powered multi-agent platform that analyzes Kubernetes, Terraform, and Helm infrastructure configurations for **security vulnerabilities**, **reliability risks**, and **cost optimization** opportunities — delivering actionable governance reports with scored findings and executive summaries.

## Why This Platform?

Traditional IaC linting tools (tfsec, checkov, kube-score) rely purely on static rules. This platform combines **deterministic rules with LLM-powered contextual reasoning**, enabling it to:

- Detect issues that rules alone can't express (e.g., "this architecture has no defense-in-depth")
- Provide contextual recommendations tailored to the specific infrastructure
- Generate executive summaries and prioritized action plans
- Score infrastructure posture across security, reliability, cost, and architecture dimensions
- Analyze AWS, Azure, and GCP resources from a single upload

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **LLM** | Gemma4 via Ollama (local, privacy-first) |
| **Agent Orchestration** | LangGraph + LangChain |
| **Backend** | FastAPI + Uvicorn |
| **Frontend** | Streamlit |
| **Parsers** | PyYAML (Kubernetes), python-hcl2 (Terraform), Helm CLI (Charts) |
| **Report Storage** | ChromaDB (persistent, vector search) |
| **Data Models** | Pydantic |
| **Containerization** | Docker + Docker Compose |
| **Language** | Python 3.11+ |

## Architecture

```
┌──────────────────────┐
│   Streamlit UI       │  port 8501
│   Upload / Paste     │
│   Report Dashboard   │
│   Report History     │
└──────────┬───────────┘
           │  HTTP (multipart)
           ▼
┌──────────────────────┐
│   FastAPI Backend    │  port 8000
│   /api/v1/analyze    │
│   .tgz → helm template → YAML
└──────────┬───────────┘
           │
           ▼
┌──────────────────────────────────────┐
│   LangGraph Sequential Pipeline      │
│                                      │
│   ┌─────────────┐                    │
│   │ File Parser  │  K8s / HCL / YAML │
│   └──────┬──────┘                    │
│          ▼                           │
│   ┌─────────────┐  Rules + LLM      │
│   │  Security   │──────────┐        │
│   └──────┬──────┘          │        │
│          ▼                 │        │
│   ┌─────────────┐         │ Dedup  │
│   │ Reliability │─────────│        │
│   └──────┬──────┘         │        │
│          ▼                 │        │
│   ┌─────────────┐         │         │
│   │    Cost     │──────────┘        │
│   └──────┬──────┘                    │
│          ▼                           │
│   ┌─────────────────┐                │
│   │ Arch. Reviewer  │  Cross-cutting │
│   └──────┬──────────┘                │
│          ▼                           │
│   ┌─────────────┐                    │
│   │ Supervisor  │  LLM Synthesis     │
│   └─────────────┘                    │
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│   Governance Report (JSON)           │
│   • Overall Score (0-100)            │
│   • Agent Reports + Findings         │
│   • Architecture Review              │
│   • Executive Summary                │
│   • Top Recommendations              │
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│   ChromaDB (Persistent Storage)      │
│   • Report history                   │
│   • Score comparison over time       │
│   • Similar report search            │
└──────────────────────────────────────┘
```

## Supported File Types

| Type | Extensions | Notes |
|------|-----------|-------|
| Kubernetes | `.yaml`, `.yml`, `.json` | Multi-document YAML supported |
| Terraform | `.tf`, `.hcl`, `.json` | AWS, Azure, GCP resources |
| Helm Charts | `.tgz` | Rendered server-side via `helm template` |

## Prerequisites

- **Python 3.11+**
- **Ollama** — [install here](https://ollama.com/download)
- **Helm CLI** — required for `.tgz` chart analysis ([install here](https://helm.sh/docs/intro/install/))

## Setup

### Local Development

```bash
# 1. Clone the repository
git clone <repo-url>
cd AI-Infrastructure-Governance-Architecture-Intelligence-Platform

# 2. Start Ollama and pull the model
ollama serve
ollama pull gemma4:E2B

# 3. Create virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env

# 5. Start the backend (Terminal 1)
uvicorn app.main:app --reload --port 8000 --timeout-keep-alive 600

# 6. Start the frontend (Terminal 2)
source venv/bin/activate
streamlit run frontend/app.py
```

Open **http://localhost:8501** to access the platform.

### Docker

```bash
docker-compose up --build
```

The Docker image automatically installs the Helm CLI.

| Service | URL |
|---------|-----|
| Frontend | http://localhost:8501 |
| Backend | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `gemma4:E2B` | LLM model to use |
| `API_URL` | `http://localhost:8000/api/v1` | Backend URL (used by frontend in Docker) |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/analyze` | Upload files (multipart) — supports `.yaml`, `.tf`, `.tgz` |
| `POST` | `/api/v1/analyze/text` | Analyze from JSON `{"file_contents": {"file.tf": "..."}}` |
| `GET` | `/api/v1/reports` | List recent reports with metadata |
| `GET` | `/api/v1/reports/{id}` | Retrieve a generated report |
| `DELETE` | `/api/v1/reports/{id}` | Delete a report |
| `GET` | `/api/v1/reports/compare/{a}/{b}` | Compare two reports (score deltas) |
| `GET` | `/api/v1/reports/{id}/similar` | Find past reports with similar risk profiles |
| `GET` | `/api/v1/health` | Health check |

## Project Structure

```
├── app/
│   ├── main.py                # FastAPI application
│   ├── config.py              # Environment configuration
│   ├── models.py              # Pydantic data models
│   ├── api/
│   │   └── routes.py          # REST API endpoints
│   ├── agents/
│   │   ├── security.py        # Security agent (K8s + AWS/Azure/GCP Terraform)
│   │   ├── reliability.py     # Reliability agent (K8s + AWS/Azure/GCP Terraform)
│   │   ├── cost.py            # Cost agent (K8s + AWS/Azure/GCP Terraform)
│   │   ├── architecture_reviewer.py  # Cross-cutting architecture review
│   │   └── supervisor.py      # LangGraph pipeline orchestrator
│   ├── parsers/
│   │   ├── kubernetes.py      # Kubernetes YAML parser
│   │   ├── terraform.py       # Terraform HCL parser + companion resource lookup
│   │   └── helm.py            # Helm chart renderer (helm template)
│   └── core/
│       ├── llm.py             # LLM configuration
│       ├── dedup.py           # Finding deduplication (keyword + synonym overlap)
│       ├── skills.py          # Skill file loader
│       ├── store.py           # ChromaDB report persistence
│       └── report.py          # Score calculation & formatting
├── skills/                    # Agent prompt skill files (.md)
│   ├── security-kubernetes.md
│   ├── security-terraform.md
│   ├── reliability-kubernetes.md
│   ├── reliability-terraform.md
│   ├── cost-kubernetes.md
│   ├── cost-terraform.md
│   ├── architecture-reviewer.md
│   └── supervisor.md
├── frontend/
│   └── app.py                 # Streamlit UI
├── samples/
│   ├── good-infra.tf          # Well-configured AWS Terraform
│   ├── average-infra.tf       # Mid-level AWS Terraform
│   ├── vulnerable-infra.tf    # Insecure AWS Terraform
│   ├── production-good.tf     # Production-grade AWS Terraform
│   ├── good-deployment.yaml   # Hardened Kubernetes deployment
│   ├── hardened-production.yaml
│   ├── vulnerable-deployment.yaml
│   ├── critical-security-failure.yaml
│   ├── my-chart/              # Sample Helm chart (intentional issues)
│   ├── my-chart-1.0.0.tgz
│   ├── good-chart/            # Best-practices Helm chart
│   └── good-chart-1.2.0.tgz
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

## Sample Files

Test files are provided in `samples/` covering intentionally good, average, vulnerable, and critical scenarios for Kubernetes, Terraform, and Helm.

| File | Type | Purpose |
|------|------|---------|
| `good-infra.tf` | Terraform | Well-configured AWS (KMS, restricted SG, encrypted Multi-AZ RDS) |
| `average-infra.tf` | Terraform | Mid-level AWS (some controls missing) |
| `vulnerable-infra.tf` | Terraform | 16+ intentional AWS security issues |
| `production-good.tf` | Terraform | Production-grade AWS — high score reference |
| `good-deployment.yaml` | Kubernetes | Hardened K8s deployment |
| `hardened-production.yaml` | Kubernetes | PSS restricted, NetworkPolicies, PDBs, HPAs, RBAC |
| `vulnerable-deployment.yaml` | Kubernetes | Insecure K8s deployment |
| `critical-security-failure.yaml` | Kubernetes | Privileged + hostPID + cluster-admin |
| `my-chart-1.0.0.tgz` | Helm | Intentionally flawed chart (for testing detection) |
| `good-chart-1.2.0.tgz` | Helm | Best-practices chart (NetworkPolicy, HPA, PDB, ServiceMonitor) |

### Packaging Helm Charts

```bash
# From samples/ directory
helm package my-chart/
helm package good-chart/

# Preview rendered output before uploading
helm template release good-chart-1.2.0.tgz
```

## Development

See [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md) for detailed development history, technical decisions, and phase-by-phase progress.

## License

MIT
