import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from app.api.routes import router

app = FastAPI(
    title="AI Infrastructure Governance Platform",
    description="Multi-agent AI platform for infrastructure analysis, governance, and architecture intelligence.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


# ---------------------------------------------------------------------------
# Static frontend (production). When the web app has been built into web/dist
# (Docker image, or `npm run build`), serve it from the same origin so the UI
# and `/api/...` share a host — no CORS, no proxy. Purely additive: if the build
# isn't present (local `uvicorn` dev, where Vite serves the UI on :5173 and
# proxies to the API), the API behaves exactly as before and `/` returns the
# JSON banner. Existing routes and tests are unaffected — the router is included
# first, so /api/* always wins over the SPA fallback below.
# ---------------------------------------------------------------------------
_WEB_DIST = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "dist")
_WEB_INDEX = os.path.join(_WEB_DIST, "index.html")
_HAS_WEB = os.path.isdir(_WEB_DIST) and os.path.isfile(_WEB_INDEX)


if _HAS_WEB:
    # Hashed build assets (JS/CSS) live under /assets; static files (fonts,
    # favicon) sit at the dist root and are handled by the fallback below.
    app.mount("/assets", StaticFiles(directory=os.path.join(_WEB_DIST, "assets")), name="assets")

    @app.get("/")
    async def spa_root():
        return FileResponse(_WEB_INDEX)

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        """Serve a real dist file if one exists; otherwise return index.html so
        React Router handles the client-side route. Never shadows the API or the
        docs: /api/* is registered on the router first, and /docs, /redoc,
        /openapi.json are FastAPI built-ins that also take precedence. As a
        belt-and-braces guard we 404 those prefixes here rather than serving the
        SPA shell for them."""
        if full_path.startswith(("api/", "docs", "redoc", "openapi.json")):
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        candidate = os.path.normpath(os.path.join(_WEB_DIST, full_path))
        # Prevent path traversal outside dist.
        if candidate.startswith(_WEB_DIST) and os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(_WEB_INDEX)

else:

    @app.get("/")
    async def root():
        return {
            "name": "AI Infrastructure Governance Platform",
            "version": "0.1.0",
            "docs": "/docs",
        }
