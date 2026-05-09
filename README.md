# AI Infrastructure Governance & Architecture Intelligence Platform

## Phase 1 — MVP: Intelligent Infrastructure Analysis

### Quick Start

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Ensure Ollama is running with Gemma4
ollama pull gemma4:E2B

# 4. Start the FastAPI backend
uvicorn app.main:app --reload --port 8000

# 5. Start the Streamlit frontend (in another terminal)
streamlit run frontend/app.py
```

### Architecture (Phase 1)

```
┌─────────────────┐
│ Streamlit UI    │
└────────┬────────┘
         ↓
┌─────────────────┐
│ FastAPI Gateway  │
└────────┬────────┘
         ↓
┌────────────────────────┐
│ LangGraph Supervisor   │
└────────┬───────────────┘
         ↓
┌────────────────────────────────────┐
│ Security Agent                     │
│ Reliability Agent                  │
│ Cost Optimization Agent            │
└────────────────────────────────────┘
```

### Features

- **Upload** Kubernetes YAML, Helm charts, Terraform files
- **Security Agent**: Finds privileged containers, missing limits, dangerous RBAC, public exposure
- **Reliability Agent**: Checks probes, autoscaling, anti-affinity, SPOFs, missing replicas
- **Cost Agent**: Detects overprovisioned CPU/memory, idle workloads, storage inefficiencies
- **AI-Powered**: Uses local Gemma4 model (via Ollama) for intelligent reasoning and recommendations
- **Multi-Agent**: LangGraph orchestrates agent collaboration and produces unified reports

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/analyze` | Upload and analyze infrastructure files |
| GET | `/api/v1/reports/{report_id}` | Get analysis report |
| GET | `/api/v1/health` | Health check |

### Project Structure

```
├── app/
│   ├── main.py              # FastAPI application
│   ├── config.py             # Configuration
│   ├── models.py             # Pydantic models
│   ├── api/
│   │   └── routes.py         # API endpoints
│   ├── agents/
│   │   ├── security.py       # Security analysis agent
│   │   ├── reliability.py    # Reliability analysis agent
│   │   ├── cost.py           # Cost optimization agent
│   │   └── supervisor.py     # LangGraph supervisor
│   ├── parsers/
│   │   ├── kubernetes.py     # K8s YAML parser
│   │   └── terraform.py      # Terraform HCL parser
│   └── core/
│       ├── llm.py            # Ollama/Gemma4 LLM setup
│       └── report.py         # Report generation
├── frontend/
│   └── app.py                # Streamlit UI
├── samples/                  # Sample infrastructure files
├── requirements.txt
└── README.md
```
