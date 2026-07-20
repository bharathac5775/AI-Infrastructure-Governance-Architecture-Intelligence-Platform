<div align="center">

<img src="docs/assets/logo.svg" width="84" height="84" alt="Infrastructure Governance logo" />

# Infrastructure Governance & Architecture Intelligence

**A multi-agent platform that reviews your Terraform, Kubernetes, and Helm before it ships — scoring it for security, reliability, cost, architecture, compliance, and resilience, then handing you fixable findings.**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/tests-604%20passing-3FB950)](tests/)
[![License](https://img.shields.io/badge/license-MIT-blue)](#license)

</div>

---

## Overview

Traditional IaC scanners (tfsec, checkov, kube-score) apply static rules and stop there. This platform pairs **deterministic rules with LLM-powered reasoning** across six specialized agents, so it catches issues rules can't express — *"this architecture has no defense-in-depth,"* *"this KMS key is a single point of failure for four resources"* — and returns a scored, prioritized, **remediable** governance report.

Upload an infrastructure bundle → six agents review it in one pass → you get a weighted score, findings ranked by severity, a dependency graph of what could break, compliance scorecards, and code-level fixes you can apply.

## Highlights

- **Six governance agents** in a single analysis pass
- **Weighted governance score** with per-agent breakdowns
- **Dependency graph** with single-point-of-failure detection and blast-radius analysis
- **CIS compliance scorecards** (AWS · Azure · GCP · Kubernetes) with control-level mapping
- **Deterministic-first auto-remediation** — generates code patches, with an LLM fallback for the long tail
- **Drift detection** between successive scans of the same bundle
- **Auditor-ready exports** — PDF and JSON
- **Pluggable LLM** — local Ollama by default; Anthropic, OpenAI, or Google can be configured

## The six agents

| Agent | What it reviews |
|-------|-----------------|
| 🛡️ **Security** | Public exposure, IAM, encryption, exposed secrets |
| 📈 **Reliability** | Health checks, replicas, resource limits, restart policy |
| 💰 **Cost** | Right-sizing, idle capacity, storage tiers |
| 🏛️ **Architecture** | Cross-cutting patterns, trade-offs, prioritized actions |
| ✅ **Compliance** | CIS benchmark scoring, control-to-finding mapping |
| 🔗 **Resilience** | Dependency graph, single points of failure, blast radius |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18 · TypeScript · Vite · Tailwind CSS |
| **Backend** | FastAPI · Uvicorn |
| **LLM** | Ollama (local, default) · pluggable Anthropic / OpenAI / Google |
| **Orchestration** | LangGraph · LangChain |
| **Parsers** | PyYAML (Kubernetes) · python-hcl2 (Terraform) · Helm CLI (charts) |
| **Storage** | ChromaDB (persistent report history + vector search) |
| **Graph** | NetworkX (dependency analysis, SPOF detection) |
| **Packaging** | Docker · Docker Compose |

## Architecture

```
┌────────────────────────────┐
│   React Web UI             │   Analyze · Report · History
│   (served by the API)      │
└──────────────┬─────────────┘
               │  HTTP  (multipart / JSON)
               ▼
┌────────────────────────────┐
│   FastAPI Backend          │   /api/v1/…  +  serves the built web UI
│   .tgz → helm template      │
└──────────────┬─────────────┘
               ▼
┌────────────────────────────────────────────┐
│   LangGraph Analysis Pipeline              │
│   Parse → Security → Reliability → Cost →   │
│   Architecture → Compliance → Resilience → │
│   Supervisor (synthesis + scoring)         │
└──────────────┬─────────────────────────────┘
               ▼
┌────────────────────────────┐        ┌────────────────────────────┐
│   Governance Report (JSON) │───────▶│   ChromaDB (history)       │
│   score · findings · graph │        │   drift · similar reports  │
│   compliance · remediation │        └────────────────────────────┘
└────────────────────────────┘
```

## Supported File Types

| Type | Extensions | Notes |
|------|-----------|-------|
| Kubernetes | `.yaml` `.yml` `.json` | Multi-document YAML; `List` kind in JSON |
| Terraform | `.tf` `.hcl` `.json` | AWS, Azure, GCP; HCL and JSON both supported |
| Helm charts | `.tgz` | Rendered server-side via `helm template` |

> Non-infrastructure files (`package-lock.json`, application config without `apiVersion`/`kind`, etc.) are rejected at upload to prevent hallucinated reports on unrelated content.

## Quick Start

### Option 1 — Docker (whole product, one command)

```bash
# Ollama runs on the host; pull the model once
ollama serve
ollama pull gemma4:E2B

docker compose up --build
```

A single image builds the React frontend and serves it from the FastAPI backend, so everything runs on **one port**:

| Service | URL |
|---------|-----|
| Web UI | http://localhost:8000 |
| Backend API | http://localhost:8000/api/v1 |
| API Docs | http://localhost:8000/docs |

### Option 2 — Local development

**Prerequisites:** Python 3.11+ · Node.js 18+ · [Ollama](https://ollama.com/download) · [Helm CLI](https://helm.sh/docs/intro/install/) (for `.tgz`)

```bash
# 1. Model
ollama serve
ollama pull gemma4:E2B

# 2. Backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8001 --timeout-keep-alive 600

# 3. Frontend (second terminal)
cd web
npm install
npm run dev
```

Open **http://localhost:5173**. The Vite dev server proxies `/api` to the backend on port 8001. See [web/README.md](web/README.md) for frontend details.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_PROVIDER` | `ollama` | `ollama` · `anthropic` · `openai` · `google` |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `gemma4:E2B` | Model to use |

> Cloud providers (Anthropic / OpenAI / Google) require their respective API keys and are opt-in; the default configuration uses a local Ollama model.

## API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/analyze` | Upload files (multipart) |
| `POST` | `/api/v1/analyze/text` | Analyze from `{"file_contents": {...}}` |
| `GET` | `/api/v1/reports` | List recent reports |
| `GET` | `/api/v1/reports/{id}` | Retrieve a report |
| `DELETE` | `/api/v1/reports/{id}` | Delete a report |
| `GET` | `/api/v1/reports/compare/{a}/{b}` | Compare two reports |
| `GET` | `/api/v1/reports/{id}/similar` | Find similar past reports |
| `GET` | `/api/v1/reports/{id}/drift` | Drift vs. the previous scan |
| `GET` | `/api/v1/reports/{id}/blast-radius?resource=` | What breaks if a resource fails |
| `GET` | `/api/v1/reports/{id}/diagram?format=mermaid` | Dependency diagram |
| `GET` | `/api/v1/reports/{id}/export/pdf` | Auditor-ready PDF |
| `POST` | `/api/v1/reports/{id}/remediate/{i}` | Generate a code fix for a finding |
| `GET` | `/api/v1/health` | Health check |

Full interactive reference at **`/docs`** when the server is running.

## Project Structure

```
├── app/                       # FastAPI backend
│   ├── main.py                # App entry — API + serves the built web UI
│   ├── models.py              # Pydantic data models
│   ├── api/routes.py          # REST endpoints
│   ├── agents/                # security · reliability · cost · architecture
│   │                          #   · supervisor · remediator
│   ├── parsers/               # kubernetes · terraform · helm
│   └── core/                  # graph · compliance · drift · store · pdf …
├── skills/                    # Agent prompt skill files (.md)
├── web/                       # React + TypeScript web frontend (Vite)
│   ├── src/                   # components · pages · API client
│   └── README.md              # Frontend setup & architecture
├── samples/                   # Sample infrastructure files
├── docker-compose.yml
├── Dockerfile                 # Multi-stage: build web → serve from API
└── requirements.txt
```

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

A **604-test** regression suite covers rule logic, dedup, scoring, parsers, the dependency graph, remediation, and per-sample regressions. Runs in seconds; no Ollama required (LLM is mocked). See [tests/README.md](tests/README.md).

## Documentation

- [DEVELOPMENT_PHASES.md](DEVELOPMENT_PHASES.md) — development history and technical decisions
- [web/README.md](web/README.md) — frontend architecture and development
- [tests/README.md](tests/README.md) — test suite guide

## License

[MIT](#license)
