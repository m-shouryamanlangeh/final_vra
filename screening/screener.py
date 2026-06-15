"""
Adverse-media-only screening orchestrator.

This build focuses solely on adverse media: it crawls open-source news for the
vendor, classifies each finding by severity, scores risk from the media signal
alone, and produces a deterministic, rule-based executive summary. The
regulatory / sanctions checklist has been removed.

Risk model (media-only):
  • Per-article weights: HIGH=18, MEDIUM=8, LOW=3 (score capped at 100).
  • Classification is count-based and intuitive:
      HIGH / REJECT        → 3+ high-severity, or 1+ high with 3+ medium
      MEDIUM / CONDITIONAL → any high, or 2+ medium, or 1 medium + 2 low, or 4+ low
      LOW / PROCEED        → otherwise
  A single keyword-matched headline is treated as weak evidence (→ MEDIUM at
  most), so media alone escalates to HIGH only on a clear, repeated pattern.
"""
from __future__ import annotations

import datetime as dt
import logging

from .checkers.news import search_adverse_media

logger = logging.getLogger("erm.screen")

_SEVERITY_SCORE = {"HIGH": 18, "MEDIUM": 8, "LOW": 3}


def _counts(media: list[dict]) -> tuple[int, int, int]:
    high = sum(1 for m in media if m.get("severity") == "HIGH")
    med  = sum(1 for m in media if m.get("severity") == "MEDIUM")
    low  = sum(1 for m in media if m.get("severity") == "LOW")
    return high, med, low


def _compute_risk(media: list[dict]) -> tuple[str, str, int]:
    high, med, low = _counts(media)
    score = min(high * _SEVERITY_SCORE["HIGH"]
                + med * _SEVERITY_SCORE["MEDIUM"]
                + low * _SEVERITY_SCORE["LOW"], 100)

    if high >= 3 or (high >= 1 and med >= 3):
        return "HIGH", "REJECT", score
    if high >= 1 or med >= 2 or (med >= 1 and low >= 2) or low >= 4:
        return "MEDIUM", "CONDITIONAL", score
    return "LOW", "PROCEED", score


def _rule_based_finding(vendor_name: str, media: list[dict], risk: str) -> str:
    if not media:
        return (
            f"No adverse media found for {vendor_name} across open-source news "
            "sources. The entity appears clean based on available public data."
        )
    high, med, low = _counts(media)
    parts = [f"{len(media)} adverse media article(s) found for {vendor_name}"]
    sev_bits = []
    if high:
        sev_bits.append(f"{high} high-severity")
    if med:
        sev_bits.append(f"{med} medium-severity")
    if low:
        sev_bits.append(f"{low} low-severity")
    if sev_bits:
        parts.append(f" ({', '.join(sev_bits)})")
    parts.append(".")
    if risk == "HIGH":
        parts.append(" A repeated pattern of serious adverse coverage was detected — treat as high risk.")
    elif risk == "MEDIUM":
        parts.append(" Some adverse coverage was detected — verify before proceeding.")
    return "".join(parts)


def _make_recommendations(risk: str, media: list[dict]) -> list[str]:
    recs: list[str] = []
    high = [m for m in media if m.get("severity") == "HIGH"]

    if risk == "HIGH":
        recs.append("Do NOT onboard without escalation to the compliance officer and senior management.")
        recs.append("Obtain written sign-off from CISO/CFO before any engagement or payment release.")
    if risk in ("HIGH", "MEDIUM"):
        recs.append("Conduct enhanced due diligence (EDD) and verify the adverse media findings against primary sources.")
    if high:
        recs.append("Manually review each HIGH-severity article and confirm it refers to the same legal entity before acting.")
    if media:
        recs.append("Perform entity disambiguation — rule out similarly named but unrelated parties.")
    if risk == "LOW":
        recs.append("No significant adverse media found. Standard onboarding checks are sufficient; re-screen annually.")
    recs.append("Retain this report in the vendor file for audit trail.")
    return recs


def run_screen(payload: dict) -> dict:
    name = (payload.get("vendor_name") or "").strip()
    pan  = (payload.get("vendor_pan") or "").strip().upper()
    date = dt.date.today().isoformat()

    logger.info("Starting adverse-media screen for '%s' (PAN=%s)", name, pan or "—")

    media = search_adverse_media(name)
    risk, rec, score = _compute_risk(media)

    # Executive summary — deterministic, rule-based narrative.
    overall = _rule_based_finding(name, media, risk)

    recs = _make_recommendations(risk, media)

    result = {
        "vendor_name":    name,
        "vendor_pan":     pan,
        "date_of_search": date,
        "executive_summary": {
            "risk_level":         risk,
            "recommendation":     rec,
            "risk_score":         score,
            "adverse_media_hits": len(media),
            "overall_finding":    overall,
        },
        "adverse_media_findings": media,
        "recommendations":        recs,
    }

    logger.info(
        "Screen complete for '%s' — risk=%s rec=%s media=%d score=%d",
        name, risk, rec, len(media), score,
    )
    return result
