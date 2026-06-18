"""
Multi-source screening orchestrator.

Crawls open-source news for the vendor AND runs the regulatory / sanctions
checklist (OFAC, UN, EU, SEBI, MCA, NCLT, IBBI, ICIJ, courts, …), classifies
each media finding by severity, scores risk across both signals, and produces
a deterministic, rule-based executive summary. A confirmed watchlist HIT
overrides the media signal and forces a REJECT.

Risk model (media signal):
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
from .checklist import run_checklist, SOURCE_COUNT

logger = logging.getLogger("erm.screen")

_SEVERITY_SCORE = {"HIGH": 18, "MEDIUM": 8, "LOW": 3}


def _counts(media: list[dict]) -> tuple[int, int, int]:
    high = sum(1 for m in media if m.get("severity") == "HIGH")
    med  = sum(1 for m in media if m.get("severity") == "MEDIUM")
    low  = sum(1 for m in media if m.get("severity") == "LOW")
    return high, med, low


def _compute_risk(media: list[dict], list_hits: int = 0) -> tuple[str, str, int]:
    high, med, low = _counts(media)
    score = min(high * _SEVERITY_SCORE["HIGH"]
                + med * _SEVERITY_SCORE["MEDIUM"]
                + low * _SEVERITY_SCORE["LOW"]
                + list_hits * 30, 100)

    # A confirmed match on a sanctions / regulatory / court list is decisive —
    # it overrides the media signal and forces a reject.
    if list_hits >= 1:
        return "HIGH", "REJECT", max(score, 85)

    if high >= 3 or (high >= 1 and med >= 3):
        return "HIGH", "REJECT", score
    if high >= 1 or med >= 2 or (med >= 1 and low >= 2) or low >= 4:
        return "MEDIUM", "CONDITIONAL", score
    return "LOW", "PROCEED", score


def _rule_based_finding(vendor_name: str, media: list[dict], risk: str,
                        list_hits: list[dict] | None = None) -> str:
    list_hits = list_hits or []
    if list_hits:
        names = ", ".join(h.get("list_name", "a watchlist") for h in list_hits[:4])
        return (
            f"{vendor_name} returned a confirmed match on {len(list_hits)} "
            f"regulatory / sanctions source(s): {names}. This is a decisive "
            "adverse finding — onboarding must not proceed without escalation."
        )
    if not media:
        return (
            f"No adverse media or watchlist matches found for {vendor_name} "
            "across the sources screened. The entity appears clean based on "
            "available public data."
        )
    parts = [f"{len(media)} adverse media article(s) found for {vendor_name}."]
    if risk == "HIGH":
        parts.append(" A repeated pattern of serious adverse coverage was detected — treat as high risk.")
    elif risk == "MEDIUM":
        parts.append(" Some adverse coverage was detected — verify before proceeding.")
    return "".join(parts)


def _make_recommendations(risk: str, media: list[dict],
                          list_hits: list[dict] | None = None) -> list[str]:
    recs: list[str] = []
    high = [m for m in media if m.get("severity") == "HIGH"]
    list_hits = list_hits or []

    if list_hits:
        names = ", ".join(h.get("list_name", "watchlist") for h in list_hits[:4])
        recs.append(f"CONFIRMED watchlist match ({names}) — verify the matched "
                    "record refers to the same entity, then escalate immediately.")

    if risk == "HIGH":
        recs.append("Do NOT onboard without escalation to the compliance officer and senior management.")
        recs.append("Obtain written sign-off from CISO/CFO before any engagement or payment release.")
    if risk in ("HIGH", "MEDIUM"):
        recs.append("Conduct enhanced due diligence (EDD) and verify the adverse media findings against primary sources.")
    if high:
        recs.append("Manually review the most serious adverse media articles and confirm each refers to the same legal entity before acting.")
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

    logger.info("Starting screen for '%s' (PAN=%s) across %d sources + news",
                name, pan or "—", SOURCE_COUNT)

    # Adverse media (open-source news) + the regulatory / sanctions checklist.
    media = search_adverse_media(name)
    checklist = run_checklist(name, pan)
    list_hits = [c for c in checklist if c.get("result") == "HIT"]
    unverified = sum(1 for c in checklist if c.get("result") == "UNVERIFIED")

    risk, rec, score = _compute_risk(media, len(list_hits))

    # Executive summary — deterministic, rule-based narrative.
    overall = _rule_based_finding(name, media, risk, list_hits)
    recs = _make_recommendations(risk, media, list_hits)

    result = {
        "vendor_name":    name,
        "vendor_pan":     pan,
        "date_of_search": date,
        "executive_summary": {
            "risk_level":         risk,
            "recommendation":     rec,
            "risk_score":         score,
            "adverse_media_hits": len(media),
            "list_hits":          len(list_hits),
            "sources_screened":   SOURCE_COUNT,
            "unverified_sources": unverified,
            "overall_finding":    overall,
        },
        "adverse_media_findings": media,
        "checklist":              checklist,
        "recommendations":        recs,
    }

    logger.info(
        "Screen complete for '%s' — risk=%s rec=%s media=%d list_hits=%d score=%d",
        name, risk, rec, len(media), len(list_hits), score,
    )
    return result
