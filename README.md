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

```mermaid
flowchart TB
    subgraph client["Client"]
        UI["🖥️ React Web UI"]
    end

    subgraph api["API Layer — FastAPI"]
        RT["🔌 REST API /api/v1"]
    end

    subgraph ingest["Ingestion &amp; Parsing"]
        HELM["📦 Helm Renderer"]
        KP["☸️ Kubernetes Parser"]
        TP["🏗️ Terraform Parser"]
    end

    subgraph pipeline["Analysis Pipeline — LangGraph"]
        direction TB
        SEC["🛡️ Security Agent"]
        REL["📈 Reliability Agent"]
        COST["💰 Cost Agent"]
        ARCH["🏛️ Architecture Agent"]
        COMP["✅ Compliance Agent"]
        RES["🔗 Resilience Agent"]
        PLG["🧩 Plugin Agents"]
        SUP["🧭 Supervisor"]
        SEC --> SUP
        REL --> SUP
        COST --> SUP
        ARCH --> SUP
        COMP --> SUP
        RES --> SUP
        PLG --> SUP
    end

    subgraph core["Core Services"]
        GRAPH["🕸️ Dependency Graph"]
        CMPL["📋 Compliance Engine"]
        DRIFT["📉 Drift Engine"]
        SCORE["🎯 Scoring Engine"]
        REM["🔧 Remediator"]
        EXPORT["📄 PDF / JSON Export"]
    end

    subgraph ext["Providers &amp; Storage"]
        LLM["🤖 LLM Provider"]
        DB[("🗄️ ChromaDB")]
    end

    OUT["📊 Governance Report"]

    UI -->|upload| RT
    RT --> HELM
    RT --> KP
    RT --> TP
    HELM --> KP
    KP --> pipeline
    TP --> pipeline

    SEC <-.-> LLM
    REL <-.-> LLM
    COST <-.-> LLM
    ARCH <-.-> LLM
    COMP <-.-> LLM
    SUP <-.->|synthesis| LLM

    SUP --> GRAPH
    SUP --> CMPL
    SUP --> SCORE
    SUP --> OUT
    GRAPH --> OUT
    CMPL --> OUT
    SCORE --> OUT
    OUT --> DB

    RT --> REM
    RT --> DRIFT
    RT --> EXPORT
    REM <-.->|fallback| LLM
    OUT --> UI
    DRIFT --> DB
    RT -->|history| DB
```

**How it fits together**

| Component | Role |
|-----------|------|
| **React Web UI** | Analyze, Report, and History screens. In production it's served by the API on the same origin. |
| **REST API** | FastAPI endpoints for analysis, reports, remediation, blast-radius, diagram, drift, and export. |
| **Helm Renderer** | Renders uploaded `.tgz` charts with `helm template`, then feeds the YAML to the Kubernetes parser. |
| **Kubernetes / Terraform Parsers** | Normalize `.yaml`/`.json` and `.tf`/`.hcl`/`.json` into a common resource model. |
| **Analysis Pipeline** | Six agents (plus any runtime-discovered plugin agents) analyze the resources; the **Supervisor** deduplicates findings, synthesizes summaries, and computes scores. |
| **LLM Provider** | Finding-producing agents reason with the configured model (Ollama by default; Anthropic / OpenAI / Google supported). The Remediator uses it only as a fallback. |
| **Core Services** | Dependency graph (SPOF + blast radius), compliance scorecards, drift comparison, weighted scoring, remediation, and PDF/JSON export. |
| **ChromaDB** | Persists reports (with their dependency graph) for history, drift, and similarity search. |

<details>
<summary><b>Request flow, step by step</b></summary>

1. **Upload** — the UI sends files to `/api/v1/analyze`. Helm charts render server-side; Kubernetes and Terraform files parse into a normalized resource model.
2. **Analyze** — the LangGraph pipeline runs six agents (plus plugin agents). Finding-producing agents reason with the configured LLM; the Supervisor deduplicates, synthesizes, and scores.
3. **Enrich** — core services build the dependency graph (SPOF + blast radius), compute CIS compliance scorecards, and calculate the weighted overall score.
4. **Persist** — the report and its dependency graph are stored in ChromaDB for history, drift, and similarity search.
5. **Act** — from a report, the user generates remediation patches (deterministic first, LLM fallback), views drift vs. a prior scan, and exports PDF/JSON.

</details>

### What you get — the Governance Report

Every analysis produces one **Governance Report**, returned as JSON and rendered in the UI:

- **Overall governance score** (0–100) with a per-agent breakdown
- **Findings** ranked by severity, each with resource, description, recommendation, and mapped compliance controls
- **Dependency graph** — nodes/edges, single points of failure, and blast radius per resource
- **Compliance scorecards** — CIS AWS/Azure/GCP/Kubernetes with pass/fail control lists
- **Architecture review** — trade-offs, patterns, cross-cutting gaps, prioritized actions
- **Executive & risk summaries**
- **Remediation** — a code patch (unified diff) per fixable finding
- **Exports** — the full report as PDF or JSON

### API request flow

```mermaid
sequenceDiagram
    autonumber
    participant U as Web UI
    participant A as FastAPI
    participant P as Pipeline
    participant D as ChromaDB

    U->>A: POST /api/v1/analyze  (files)
    A->>P: run analysis (6 agents + supervisor)
    P-->>A: Governance Report
    A->>D: save report + dependency graph
    A-->>U: 200  Governance Report (JSON)

    U->>A: GET /api/v1/reports/{id}
    A->>D: fetch report
    A-->>U: 200  report

    U->>A: POST /api/v1/reports/{id}/remediate/{i}
    A-->>U: 200  patch  ·  409 not patchable  ·  422 failed

    U->>A: GET /api/v1/reports/{id}/export/pdf
    A-->>U: 200  application/pdf
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
