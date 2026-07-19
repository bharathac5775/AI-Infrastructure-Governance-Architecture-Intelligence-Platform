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
| **Frontend** | React + TypeScript + Vite + Tailwind CSS |
| **Parsers** | PyYAML (Kubernetes), python-hcl2 (Terraform), Helm CLI (Charts) |
| **Report Storage** | ChromaDB (persistent, vector search) |
| **Data Models** | Pydantic |
| **Containerization** | Docker + Docker Compose |
| **Language** | Python 3.11+ |

## Architecture

```
┌──────────────────────┐
│   React Web UI       │  served by the API (one port)
│   Analyze / Paste    │
│   Report Dashboard   │
│   Report History     │
└──────────┬───────────┘
           │  HTTP (multipart / JSON)
           ▼
┌──────────────────────┐
│   FastAPI Backend    │  port 8000
│   /api/v1/analyze    │  + serves the built web UI
│   .tgz → helm template → YAML
└──────────┬───────────┘
           │
           ▼
┌──────────────────────────────────────┐
│   LangGraph Sequential Pipeline      │
│                                      │
│   ┌─────────────┐                    │
│   │ File Parser │  K8s / HCL / YAML  │
│   └──────┬──────┘                    │
│          ▼                           │
│   ┌─────────────┐  Rules + LLM       │
│   │  Security   │──────────┐         │
│   └──────┬──────┘          │         │
│          ▼                 │         │
│   ┌─────────────┐          │ Dedup   │
│   │ Reliability │─────────-│         │
│   └──────┬──────┘          │         │
│          ▼                 │         │
│   ┌─────────────┐          │         │
│   │    Cost     │──────────┘         │
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
| Kubernetes | `.yaml`, `.yml`, `.json` | Multi-document YAML supported; `List` kind supported in JSON |
| Terraform | `.tf`, `.hcl`, `.json` | AWS, Azure, and GCP resources; HCL and JSON formats both supported |
| Helm Charts | `.tgz` | Rendered server-side via `helm template` |

> Non-infrastructure files (e.g., `package-lock.json`, `tsconfig.json`, application config YAML without `apiVersion`/`kind`) are rejected at upload to prevent hallucinated reports on unrelated content.

## Prerequisites

- **Python 3.11+**
- **Node.js 18+** — to build/run the web frontend
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
uvicorn app.main:app --reload --port 8001 --timeout-keep-alive 600

# 6. Start the web frontend (Terminal 2)
cd web
npm install
npm run dev
```

Open **http://localhost:5173** — the Vite dev server proxies `/api` to the
backend on port 8001, so the UI and API just work together. See
[web/README.md](web/README.md) for frontend details.

### Docker

```bash
docker compose up --build
```

A single image builds the React frontend and serves it from the FastAPI backend,
so the whole product runs on one port. The image also installs the Helm CLI.

| Service | URL |
|---------|-----|
| Web UI | http://localhost:8000 |
| Backend API | http://localhost:8000/api/v1 |
| API Docs | http://localhost:8000/docs |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `gemma4:E2B` | LLM model to use |

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
| `GET` | `/api/v1/reports/{id}/drift` | Drift vs. the previous scan of the same bundle |
| `GET` | `/api/v1/reports/{id}/blast-radius?resource=` | What breaks if a resource fails |
| `GET` | `/api/v1/reports/{id}/diagram?format=mermaid` | Dependency diagram (Mermaid) |
| `GET` | `/api/v1/reports/{id}/export/pdf` | Auditor-ready PDF export |
| `POST` | `/api/v1/reports/{id}/remediate/{i}` | Generate a code fix for a finding |
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
├── web/                       # React + TypeScript web frontend (Vite)
│   ├── src/                   # Components, pages, API client
│   └── README.md              # Frontend setup & architecture
├── samples/                   # Sample infrastructure files for testing
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```

## Sample Files

The `samples/` directory contains test infrastructure files covering good, average, vulnerable, and critical scenarios across Kubernetes, Terraform, and Helm.

## Development

See [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md) for detailed development history, technical decisions, and phase-by-phase progress.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Pytest-based regression suite covering rule logic, dedup, scoring, parsers, architecture filters, and per-sample sample regressions. Runs ~1 second; no Ollama required. See [tests/README.md](tests/README.md) for details on running, the LLM-mock fixture, and how to add tests for new rules.

## License

MIT
