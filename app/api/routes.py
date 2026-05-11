import os
from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from app.models import AnalysisReport, AnalysisRequest, HealthResponse
from app.agents.supervisor import run_analysis
from app.config import settings
from app.core.store import save_report, get_report, list_reports, compare_reports, find_similar_reports, delete_report
from app.parsers.helm import render_helm_chart

router = APIRouter(prefix="/api/v1")


@router.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse()


@router.post("/analyze", response_model=AnalysisReport)
async def analyze_infrastructure(files: list[UploadFile] = File(...)):
    """Upload infrastructure files and run multi-agent analysis."""
    file_contents: dict[str, str] = {}

    for upload_file in files:
        # Validate extension
        _, ext = os.path.splitext(upload_file.filename or "")
        if ext.lower() not in settings.ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type: {ext}. Allowed: {settings.ALLOWED_EXTENSIONS}",
            )

        # Read content
        content = await upload_file.read()

        # Validate size
        if len(content) > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
            raise HTTPException(
                status_code=400,
                detail=f"File {upload_file.filename} exceeds {settings.MAX_FILE_SIZE_MB}MB limit.",
            )

        if ext.lower() == ".tgz":
            try:
                rendered_yaml = render_helm_chart(content)
                base = os.path.splitext(upload_file.filename)[0]
                file_contents[f"{base}-rendered.yaml"] = rendered_yaml
            except FileNotFoundError:
                raise HTTPException(
                    status_code=500,
                    detail="Helm is not installed on this server. Cannot render .tgz chart.",
                )
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
        else:
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                raise HTTPException(
                    status_code=400,
                    detail=f"File {upload_file.filename} is not valid UTF-8 text.",
                )

            # For YAML files, validate they contain K8s manifests (apiVersion + kind)
            if ext.lower() in (".yaml", ".yml"):
                has_apiversion = "apiVersion:" in text
                has_kind = "kind:" in text
                if not (has_apiversion and has_kind):
                    raise HTTPException(
                        status_code=400,
                        detail=f"'{upload_file.filename}' does not appear to be a Kubernetes manifest. "
                               f"Expected fields 'apiVersion' and 'kind'. Upload Kubernetes manifests or Helm charts (.tgz).",
                    )

            # For JSON files, validate it looks like infrastructure code
            if ext.lower() == ".json":
                _NON_INFRA_JSON = {
                    "package-lock.json", "package.json", "tsconfig.json",
                    "tsconfig.node.json", "jsconfig.json", "composer.json",
                    "composer.lock", "pipfile.lock", "poetry.lock",
                    ".eslintrc.json", ".prettierrc.json", "babel.config.json",
                    "nest-cli.json", "angular.json", "nx.json",
                    "turbo.json", "lerna.json", "rush.json",
                }
                basename = os.path.basename(upload_file.filename or "").lower()
                if basename in _NON_INFRA_JSON:
                    raise HTTPException(
                        status_code=400,
                        detail=f"'{upload_file.filename}' is not an infrastructure file. "
                               f"Upload Terraform (.tf/.json), Kubernetes (.yaml/.yml/.json), or Helm (.tgz) files.",
                    )
                # Check content for infrastructure markers
                snippet = text[:3000].lower()
                has_tf = any(k in snippet for k in ['"resource"', '"provider"', '"terraform"', '"variable"', '"module"', '"data"'])
                has_k8s = any(k in snippet for k in ['"apiversion"', '"kind"', '"metadata"'])
                if not (has_tf or has_k8s):
                    raise HTTPException(
                        status_code=400,
                        detail=f"'{upload_file.filename}' does not appear to be infrastructure code (Terraform JSON or Kubernetes JSON manifest).",
                    )

            file_contents[upload_file.filename] = text

    if not file_contents:
        raise HTTPException(status_code=400, detail="No files uploaded.")

    # Run multi-agent analysis
    report = await run_analysis(file_contents)

    # Store report
    save_report(report)

    return report


@router.post("/analyze/text", response_model=AnalysisReport)
async def analyze_text(request: AnalysisRequest):
    """Analyze infrastructure from text content (for programmatic access)."""
    if not request.file_contents:
        raise HTTPException(status_code=400, detail="No file contents provided.")

    report = await run_analysis(request.file_contents)
    save_report(report)
    return report


@router.get("/reports/{report_id}", response_model=AnalysisReport)
async def get_report_endpoint(report_id: str):
    """Retrieve a previously generated report."""
    report = get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    return report


@router.get("/reports")
async def list_reports_endpoint(limit: int = Query(default=50, le=200)):
    """List recent reports with metadata."""
    return list_reports(limit=limit)


@router.get("/reports/compare/{report_id_a}/{report_id_b}")
async def compare_reports_endpoint(report_id_a: str, report_id_b: str):
    """Compare two reports and return score deltas."""
    result = compare_reports(report_id_a, report_id_b)
    if not result:
        raise HTTPException(status_code=404, detail="One or both reports not found.")
    return result


@router.delete("/reports/{report_id}")
async def delete_report_endpoint(report_id: str):
    """Delete a specific report."""
    deleted = delete_report(report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found.")
    return {"status": "deleted", "report_id": report_id}


@router.get("/reports/{report_id}/similar")
async def similar_reports_endpoint(
    report_id: str, n: int = Query(default=3, le=10)
):
    """Find past reports with similar risk profiles."""
    report = get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    query = f"{report.executive_summary} {report.risk_summary}"
    # Detect infra type to only match same type
    has_tf = any(f.endswith((".tf", ".hcl")) for f in report.files_analyzed)
    has_k8s = any(f.endswith((".yaml", ".yml")) for f in report.files_analyzed)
    infra_type = "terraform" if has_tf and not has_k8s else "kubernetes" if has_k8s and not has_tf else "mixed"
    return find_similar_reports(query, n_results=n, exclude_id=report_id, infra_type=infra_type)
