import os
from fastapi import APIRouter, UploadFile, File, HTTPException
from app.models import AnalysisReport, AnalysisRequest, HealthResponse
from app.agents.supervisor import run_analysis
from app.config import settings

router = APIRouter(prefix="/api/v1")

# In-memory report store (for Phase 1)
_reports: dict[str, AnalysisReport] = {}


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

        try:
            file_contents[upload_file.filename] = content.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=400,
                detail=f"File {upload_file.filename} is not valid UTF-8 text.",
            )

    if not file_contents:
        raise HTTPException(status_code=400, detail="No files uploaded.")

    # Run multi-agent analysis
    report = await run_analysis(file_contents)

    # Store report
    _reports[report.report_id] = report

    return report


@router.post("/analyze/text", response_model=AnalysisReport)
async def analyze_text(request: AnalysisRequest):
    """Analyze infrastructure from text content (for programmatic access)."""
    if not request.file_contents:
        raise HTTPException(status_code=400, detail="No file contents provided.")

    report = await run_analysis(request.file_contents)
    _reports[report.report_id] = report
    return report


@router.get("/reports/{report_id}", response_model=AnalysisReport)
async def get_report(report_id: str):
    """Retrieve a previously generated report."""
    if report_id not in _reports:
        raise HTTPException(status_code=404, detail="Report not found.")
    return _reports[report_id]
