"""PDF export for governance reports (Phase 3.3).

Renders an AnalysisReport to a PDF byte stream using reportlab.platypus.
Layout:
  1. Title + report metadata
  2. Score summary table
  3. Compliance posture (per-framework table + per-framework control breakdown)
  4. Findings appendix (grouped by agent + severity, with compliance tags)
"""
from __future__ import annotations

import io
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.core.compliance import load_mappings
from app.models import AnalysisReport, Finding


def _severity_color_hex(sev: str) -> str:
    return {
        "critical": "#c00000",
        "high":     "#e65100",
        "medium":   "#f9a825",
        "low":      "#0277bd",
        "info":     "#616161",
    }.get(sev, "#616161")


def _agent_score(report: AnalysisReport, prefix: str) -> Optional[float]:
    for ar in report.agent_reports:
        if ar.agent_name.lower().startswith(prefix):
            return ar.score
    return None


def generate_pdf_report(report: AnalysisReport) -> bytes:
    """Render an AnalysisReport to a PDF byte stream.

    Returns the raw bytes of the PDF (caller wraps in a FastAPI Response).
    Defensive: never raises on missing optional fields.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        title=f"Governance Report {report.report_id}",
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
    )

    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    h3 = styles["Heading3"]
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10)

    story: list = []

    # ---- Title ----
    story.append(Paragraph("Infrastructure Governance Report", h1))
    story.append(Paragraph(
        f"<b>Report ID:</b> {report.report_id} &nbsp;&nbsp;"
        f"<b>Generated:</b> {report.timestamp}",
        body,
    ))
    files = ", ".join(report.files_analyzed) if report.files_analyzed else "(none)"
    story.append(Paragraph(f"<b>Files:</b> {files}", body))
    story.append(Spacer(1, 0.2 * inch))

    # ---- Score summary ----
    story.append(Paragraph("Score Summary", h2))
    score_rows = [["Dimension", "Score / 100"]]
    score_rows.append(["Overall", f"{report.overall_score}"])
    for prefix, label in [("security", "Security"), ("reliability", "Reliability"), ("cost", "Cost")]:
        s = _agent_score(report, prefix)
        score_rows.append([label, f"{s}" if s is not None else "—"])
    if report.architecture_review is not None:
        score_rows.append(["Architecture", f"{report.architecture_review.architecture_score}"])
    score_table = Table(score_rows, colWidths=[3 * inch, 2 * inch])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 0.3 * inch))

    # ---- Compliance posture ----
    if report.compliance and report.compliance.frameworks:
        story.append(Paragraph("Compliance Posture", h2))
        comp_rows = [["Framework", "Version", "Score", "Passed", "Failed"]]
        for fw in report.compliance.frameworks:
            comp_rows.append([
                fw.framework_name,
                fw.version,
                f"{fw.score_pct}%",
                str(len(fw.controls_passed)),
                str(len(fw.controls_failed)),
            ])
        comp_table = Table(comp_rows, colWidths=[2.5 * inch, 0.7 * inch, 0.8 * inch, 0.8 * inch, 0.8 * inch])
        comp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b5e20")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ]))
        story.append(comp_table)
        story.append(Spacer(1, 0.2 * inch))

        # Per-framework control breakdown
        descriptions = load_mappings().get("control_descriptions", {})
        for fw in report.compliance.frameworks:
            story.append(Paragraph(f"{fw.framework_name} — Control Detail", h3))
            ctrl_rows = [["Status", "Control", "Description"]]
            for c in fw.controls_failed:
                ctrl_rows.append([
                    Paragraph("<font color='#c00000'><b>FAIL</b></font>", small),
                    Paragraph(c, small),
                    Paragraph(descriptions.get(c, ""), small),
                ])
            for c in fw.controls_passed:
                ctrl_rows.append([
                    Paragraph("<font color='#1b5e20'><b>PASS</b></font>", small),
                    Paragraph(c, small),
                    Paragraph(descriptions.get(c, ""), small),
                ])
            ctrl_table = Table(ctrl_rows, colWidths=[0.7 * inch, 1.3 * inch, 4.5 * inch])
            ctrl_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474f")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]))
            story.append(ctrl_table)
            story.append(Spacer(1, 0.2 * inch))

    # ---- Findings appendix ----
    story.append(PageBreak())
    story.append(Paragraph("Findings Appendix", h2))
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    for agent_report in report.agent_reports:
        story.append(Paragraph(
            f"{agent_report.agent_name} — Score {agent_report.score}/100 — "
            f"{len(agent_report.findings)} findings",
            h3,
        ))
        if not agent_report.findings:
            story.append(Paragraph("No findings.", body))
            story.append(Spacer(1, 0.15 * inch))
            continue
        sorted_findings: list[Finding] = sorted(
            agent_report.findings,
            key=lambda f: severity_order.get(
                f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                5,
            ),
        )
        for f in sorted_findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            color_hex = _severity_color_hex(sev)
            story.append(Paragraph(
                f"<font color='{color_hex}'><b>[{sev.upper()}]</b></font> "
                f"<b>{f.title}</b>",
                body,
            ))
            story.append(Paragraph(f"<i>Resource:</i> {f.resource}", small))
            story.append(Paragraph(f.description, small))
            story.append(Paragraph(f"<i>Recommendation:</i> {f.recommendation}", small))
            if f.compliance_controls:
                ctrls = ", ".join(f.compliance_controls)
                story.append(Paragraph(f"<i>Controls:</i> {ctrls}", small))
            story.append(Spacer(1, 0.1 * inch))
        story.append(Spacer(1, 0.15 * inch))

    doc.build(story)
    return buffer.getvalue()
