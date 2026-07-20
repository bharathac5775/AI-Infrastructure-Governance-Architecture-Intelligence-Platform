# ---------------------------------------------------------------------------
# Stage 1 — build the web frontend (React + Vite) into web/dist
# ---------------------------------------------------------------------------
FROM node:20-slim AS web-build

WORKDIR /web

# Install deps first (layer cached unless the manifests change).
COPY web/package.json web/package-lock.json ./
RUN npm ci

# Build the static bundle.
COPY web/ ./
RUN npm run build


# ---------------------------------------------------------------------------
# Stage 2 — Python API that also serves the built frontend
# ---------------------------------------------------------------------------
FROM python:3.12-slim

WORKDIR /app

# Helm is needed to render .tgz charts at analysis time.
RUN apt-get update && apt-get install -y curl && \
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code.
COPY app/ ./app/

# Agent prompt skill files — loaded at runtime by app/core/skills.py
# (SKILLS_DIR resolves to /app/skills). Without these the LLM agents can't
# load their prompts, so analysis and remediation would fail in the container.
COPY skills/ ./skills/

# Built frontend from stage 1. app/main.py detects web/dist and serves it from
# the same origin, so the entire product is reachable on one port.
COPY --from=web-build /web/dist ./web/dist

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
