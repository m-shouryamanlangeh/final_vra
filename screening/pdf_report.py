"""PDF report builder for the ERM Adverse Media & KYC/AML screening result.

Extracted from the adverse-screen FastAPI app and rebranded for the
ERM – Enterprise Risk Management team. Pure reportlab, no web framework.
"""
from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak,
    )
    from reportlab.lib.enums import TA_CENTER
    HAS_PDF = True
except ImportError:
    HAS_PDF = False

BLUE = RED = ORANGE = GREEN = LGRAY = DGRAY = None

if HAS_PDF:
    BLUE   = colors.HexColor("#002970")   # ERM navy
    CYAN   = colors.HexColor("#00BAF2")
    RED    = colors.HexColor("#dc2626")
    ORANGE = colors.HexColor("#ea580c")
    GREEN  = colors.HexColor("#16a34a")
    LGRAY  = colors.HexColor("#f1f5f9")
    DGRAY  = colors.HexColor("#475569")


def _risk_color(level: str):
    return {"HIGH": RED, "MEDIUM": ORANGE, "LOW": GREEN}.get(level.upper(), DGRAY)


def _result_color(result: str):
    return {"HIT": RED, "UNVERIFIED": ORANGE, "CLEAR": GREEN,
            "MANUAL CHECK REQUIRED": ORANGE}.get(result.upper(), DGRAY)


def _xml(t: str) -> str:
    return (t or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_pdf(data: dict, out_path: Path) -> None:
    if not HAS_PDF:
        logger.warning("reportlab not installed — PDF skipped.")
        return

    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
    )
    s = {
        "h2":    ParagraphStyle("h2",    fontSize=13, fontName="Helvetica-Bold",  textColor=BLUE,  spaceAfter=3),
        "body":  ParagraphStyle("body",  fontSize=8.5, fontName="Helvetica",      leading=12),
        "cell":  ParagraphStyle("cell",  fontSize=8,   fontName="Helvetica",      leading=11),
        "bcell": ParagraphStyle("bcell", fontSize=8,   fontName="Helvetica-Bold", leading=11),
        "small": ParagraphStyle("small", fontSize=7,   fontName="Helvetica",      textColor=DGRAY),
    }

    vendor_name = data.get("vendor_name", "")
    vendor_pan  = data.get("vendor_pan", "")
    date_str    = data.get("date_of_search", dt.date.today().isoformat())
    es          = data.get("executive_summary", {})
    risk        = str(es.get("risk_level", "UNKNOWN")).upper()
    rec         = str(es.get("recommendation", "CONDITIONAL")).upper()

    story = []

    # Cover
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("ERM · Enterprise Risk Management",
                           ParagraphStyle("brand", fontSize=11, fontName="Helvetica-Bold", textColor=BLUE)))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("Adverse Media &amp; KYC/AML Screening Report",
                           ParagraphStyle("title", fontSize=18, fontName="Helvetica-Bold",
                                          textColor=BLUE, alignment=TA_CENTER)))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(_xml(vendor_name),
                           ParagraphStyle("vname", fontSize=14, fontName="Helvetica-Bold", alignment=TA_CENTER)))
    story.append(Paragraph(f"PAN: {_xml(vendor_pan)} | Date: {_xml(date_str)}",
                           ParagraphStyle("sub", fontSize=9, textColor=DGRAY, alignment=TA_CENTER)))
    story.append(Spacer(1, 5 * mm))

    badge_bg = _risk_color(risk)
    badge = Table([[Paragraph(f"Risk: {risk}", ParagraphStyle("b", fontSize=11,
                              fontName="Helvetica-Bold", textColor=colors.white,
                              alignment=TA_CENTER))]],
                  colWidths=[60 * mm])
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), badge_bg),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(badge)
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("CONFIDENTIAL — INTERNAL USE ONLY",
                           ParagraphStyle("conf", fontSize=7, textColor=DGRAY, alignment=TA_CENTER)))
    story.append(PageBreak())

    # Executive Summary
    story.append(Paragraph("Executive Summary", s["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BLUE))
    story.append(Spacer(1, 2 * mm))
    exec_rows = [
        [Paragraph("<b>Risk Level:</b>", s["cell"]),      Paragraph(risk, s["cell"])],
        [Paragraph("<b>Recommendation:</b>", s["cell"]),  Paragraph(rec, s["cell"])],
        [Paragraph("<b>Risk Score:</b>", s["cell"]),      Paragraph(str(es.get("risk_score", 0)) + " / 100", s["cell"])],
        [Paragraph("<b>Adverse Media:</b>", s["cell"]),   Paragraph(str(es.get("adverse_media_hits", 0)), s["cell"])],
        [Paragraph("<b>Overall Finding:</b>", s["cell"]), Paragraph(_xml(str(es.get("overall_finding", ""))), s["cell"])],
    ]
    t = Table(exec_rows, colWidths=[45 * mm, None])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("BACKGROUND", (0, 0), (0, -1), LGRAY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 5 * mm))

    # Adverse Media
    media = data.get("adverse_media_findings", [])
    story.append(Paragraph("Adverse Media Findings", s["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BLUE))
    story.append(Spacer(1, 2 * mm))
    if media:
        am = [[Paragraph("<b>Entity</b>", s["bcell"]), Paragraph("<b>Severity</b>", s["bcell"]),
               Paragraph("<b>Summary</b>", s["bcell"]), Paragraph("<b>Source</b>", s["bcell"])]]
        for row in media:
            sev = str(row.get("severity", "LOW")).upper()
            sc = _risk_color(sev)
            am.append([
                Paragraph(_xml(str(row.get("entity", ""))), s["cell"]),
                Paragraph(f'<font color="#{sc.hexval()[2:]}"><b>{sev}</b></font>', s["cell"]),
                Paragraph(_xml(str(row.get("summary", ""))), s["cell"]),
                Paragraph(_xml(str(row.get("source", ""))), s["small"]),
            ])
        at = Table(am, colWidths=[38 * mm, 20 * mm, None, 35 * mm])
        at.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (-1, 0), LGRAY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(at)
        story.append(Spacer(1, 5 * mm))
    else:
        story.append(Paragraph(
            "No adverse media articles matched in open-source news search as of "
            f"{_xml(date_str)}.", s["body"]))
        story.append(Spacer(1, 5 * mm))

    # Recommendations
    recs = data.get("recommendations", [])
    if recs:
        story.append(Paragraph("Recommendations", s["h2"]))
        story.append(HRFlowable(width="100%", thickness=0.5, color=BLUE))
        story.append(Spacer(1, 2 * mm))
        for r in recs:
            story.append(Paragraph(f"• {_xml(str(r))}", s["body"]))

    story.append(Spacer(1, 4 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "Disclaimer: OSINT-based assessment only. Does not replace legal or credit bureau data. "
        "Prepared by ERM – Enterprise Risk Management. CONFIDENTIAL — internal use only.",
        ParagraphStyle("disc", fontSize=7, fontName="Helvetica-Oblique", textColor=DGRAY)
    ))
    doc.build(story)
    logger.info("PDF saved → %s", out_path)
