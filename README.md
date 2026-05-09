# AI Infrastructure Governance & Architecture Intelligence Platform

An AI-powered multi-agent platform that analyzes Kubernetes and Terraform infrastructure configurations for **security vulnerabilities**, **reliability risks**, and **cost optimization** opportunities — delivering actionable governance reports with scored findings and executive summaries.

## Why This Platform?

Traditional IaC linting tools (tfsec, checkov, kube-score) rely purely on static rules. This platform combines **deterministic rules with LLM-powered contextual reasoning**, enabling it to:

- Detect issues that rules alone can't express (e.g., "this architecture has no defense-in-depth")
- Provide contextual recommendations tailored to the specific infrastructure
- Generate executive summaries and prioritized action plans
- Score infrastructure posture across security, reliability, and cost dimensions

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **LLM** | Gemma4 via Ollama (local, privacy-first) |
| **Agent Orchestration** | LangGraph + LangChain |
| **Backend** | FastAPI + Uvicorn |
| **Frontend** | Streamlit |
| **Parsers** | PyYAML (Kubernetes), python-hcl2 (Terraform) |
| **Data Models** | Pydantic |
| **Containerization** | Docker + Docker Compose |
| **Language** | Python 3.11+ |

## Architecture

```
┌──────────────────────┐
│   Streamlit UI       │  port 8501
│   Upload / Paste     │
│   Report Dashboard   │
└──────────┬───────────┘
           │  HTTP
           ▼
┌──────────────────────┐
│   FastAPI Backend    │  port 8000
│   /api/v1/analyze    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────────────────────┐
│   LangGraph Sequential Pipeline      │
│                                      │
│   ┌─────────────┐                    │
│   │ File Parser  │  K8s YAML / HCL   │
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
│   ┌─────────────┐         │        │
│   │    Cost     │──────────┘        │
│   └──────┬──────┘                    │
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
│   • Executive Summary                │
│   • Top Recommendations              │
└──────────────────────────────────────┘
```

## Supported File Types

| Type | Extensions |
|------|-----------|
| Kubernetes | `.yaml`, `.yml`, `.json` |
| Terraform | `.tf`, `.hcl`, `.json` |

## Prerequisites

- **Python 3.11+**
- **Ollama** — [install here](https://ollama.com/download)

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
| `POST` | `/api/v1/analyze` | Upload files (multipart) for analysis |
| `POST` | `/api/v1/analyze/text` | Analyze from JSON `{"file_contents": {"file.tf": "..."}}` |
| `GET` | `/api/v1/reports/{id}` | Retrieve a generated report |
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
│   │   ├── security.py        # Security analysis agent
│   │   ├── reliability.py     # Reliability analysis agent
│   │   ├── cost.py            # Cost optimization agent
│   │   └── supervisor.py      # LangGraph pipeline orchestrator
│   ├── parsers/
│   │   ├── kubernetes.py      # Kubernetes YAML parser
│   │   └── terraform.py       # Terraform HCL parser
│   └── core/
│       ├── llm.py             # LLM configuration
│       ├── dedup.py           # Finding deduplication
│       └── report.py          # Score calculation & formatting
├── frontend/
│   └── app.py                 # Streamlit UI
├── samples/                   # Sample infrastructure files
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

## Sample Files

Test files are provided in `samples/` covering good, average, vulnerable, and critical scenarios for both Kubernetes and Terraform.

## Development

See [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md) for detailed development history, technical decisions, and phase-by-phase progress.

## License

MIT
