# Web Frontend

The production web UI for the Infrastructure Governance Platform — a React
single-page app that consumes the FastAPI backend's JSON API.

## Stack

- **React 18 + TypeScript** — components and type-safe API models
- **Vite** — dev server and build
- **Tailwind CSS** + Radix primitives — design system (zinc neutrals, single
  indigo accent, 8px spacing, light/dark)
- **TanStack Query** — server-state and caching
- **React Router** — client-side routing (`/`, `/reports`, `/reports/:id`)
- **mermaid** — dependency diagrams (lazy-loaded)
- **Recharts** — score visualizations

## Develop

```bash
npm install
npm run dev
```

Opens on **http://localhost:5173**. The dev server proxies `/api` to the backend
at `http://127.0.0.1:8001` (see `vite.config.ts`). Start the backend first:

```bash
# from the repo root
uvicorn app.main:app --reload --port 8001 --timeout-keep-alive 600
```

Override the proxy target with `API_TARGET` if the backend runs elsewhere:

```bash
API_TARGET=http://127.0.0.1:9000 npm run dev
```

## Build

```bash
npm run build      # type-checks then bundles to web/dist/
npm run preview    # serve the production build locally
```

In production the backend serves `web/dist/` from the same origin (see the
static mount in `app/main.py`), so the whole product runs on one port. The
multi-stage `Dockerfile` at the repo root builds this bundle and bakes it into
the API image — `docker compose up` gives you the full app on port 8000.

## Structure

```
src/
├── App.tsx                 # Router + providers
├── components/
│   ├── layout/             # Topbar, sidebar, page header, app shell
│   ├── ui/                 # Button, badge, card, tabs, drawer, states
│   ├── analyze-workspace   # Upload + paste editor
│   ├── score-header        # Overall + per-agent scores
│   ├── findings-table      # Filterable findings + detail drawer
│   ├── remediation-panel   # Generate-fix flow (all error branches)
│   ├── architecture-panel  # Mermaid diagram, SPOFs, blast radius
│   ├── compliance-panel    # CIS scorecards
│   └── drift-panel         # Drift vs. baseline
├── pages/                  # analyze (home), reports (history), report
├── lib/                    # api client, patchability, report utils, copy
└── types/api.ts            # TypeScript mirrors of app/models.py
```

## Notes

- **Types mirror the backend.** `src/types/api.ts` matches `app/models.py`. If a
  backend model changes, update the type here.
- **Remediation gating.** `src/lib/patchability.ts` decides when the Generate-fix
  button appears — it is a faithful port of the backend's non-patchable rules so
  the two agree on what can be fixed.
- **Finding index.** The findings table flattens findings across agent reports
  in order; that index is what `POST /reports/{id}/remediate/{i}` expects.
