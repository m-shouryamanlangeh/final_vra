"""
Multi-source KYC / AML / regulatory checklist orchestrator.

Runs every available list-checker (sanctions + Indian regulatory + court /
insolvency records) concurrently and returns their structured results. Each
checker degrades gracefully on its own: a portal that needs a login or can't
be parsed returns an UNVERIFIED result rather than failing the whole screen.

Results carry result="HIT" | "CLEAR" | "UNVERIFIED". Only HIT is a confirmed
adverse finding; UNVERIFIED means "we could not machine-read this source —
check it manually" and is NOT treated as adverse.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from .checkers import sanctions as _s
from .checkers import india as _i

logger = logging.getLogger("erm.checklist")

# (callable, category). Order defines display order; results are reassembled in
# this order regardless of which check finishes first.
_CHECKS: list[tuple] = [
    # ── Sanctions & international ──────────────────────────────────────────
    (_s.check_ofac,            "Sanctions & International"),
    (_s.check_un,              "Sanctions & International"),
    (_s.check_eu,              "Sanctions & International"),
    (_i.check_icij,            "Sanctions & International"),
    # ── Corporate, securities & insolvency ────────────────────────────────
    (_i.check_sebi,            "Corporate, Securities & Insolvency"),
    (_i.check_mca_struck,      "Corporate, Securities & Insolvency"),
    (_i.check_mca_mlm,         "Corporate, Securities & Insolvency"),
    (_i.check_mca_shell,       "Corporate, Securities & Insolvency"),
    (_i.check_nclt,            "Corporate, Securities & Insolvency"),
    (_i.check_ibbi,            "Corporate, Securities & Insolvency"),
    # ── Credit, default & tax ─────────────────────────────────────────────
    (_i.check_rbi_defaulters,  "Credit, Default & Tax"),
    (_i.check_cibil,           "Credit, Default & Tax"),
    (_i.check_watchout,        "Credit, Default & Tax"),
    (_i.check_cbdt,            "Credit, Default & Tax"),
    (_i.check_mh_gst,          "Credit, Default & Tax"),
    # ── Law enforcement & courts ──────────────────────────────────────────
    (_i.check_cbi,             "Law Enforcement & Courts"),
    (_i.check_delhi_eow,       "Law Enforcement & Courts"),
    (_i.check_cybercrime,      "Law Enforcement & Courts"),
    (_i.check_indian_kanoon,   "Law Enforcement & Courts"),
]

# Number of registry / list sources screened (news media is reported separately).
SOURCE_COUNT = len(_CHECKS)

# Ordered, de-duplicated category labels for grouped display.
CATEGORIES = list(dict.fromkeys(cat for _, cat in _CHECKS))


def _safe_check(fn, name: str, pan: str) -> dict:
    try:
        return fn(name, pan)
    except Exception as exc:  # a checker should never take the whole screen down
        logger.warning("Checker %s failed: %s", getattr(fn, "__name__", fn), exc)
        return {
            "list_name": getattr(fn, "__name__", "unknown").replace("check_", "").upper(),
            "source_url": "",
            "entity_checked": name,
            "result": "UNVERIFIED",
            "finding": f"Check could not be completed: {exc}"[:150],
        }


def run_checklist(name: str, pan: str = "") -> list[dict]:
    """Run all list-checkers concurrently; return results in _CHECKS order."""
    out: list[dict | None] = [None] * len(_CHECKS)
    with ThreadPoolExecutor(max_workers=10) as pool:
        fut_to_idx = {
            pool.submit(_safe_check, fn, name, pan): idx
            for idx, (fn, _cat) in enumerate(_CHECKS)
        }
        for fut in as_completed(fut_to_idx):
            idx = fut_to_idx[fut]
            res = fut.result()
            res["category"] = _CHECKS[idx][1]
            out[idx] = res

    results = [r for r in out if r]
    hits = sum(1 for r in results if r.get("result") == "HIT")
    unver = sum(1 for r in results if r.get("result") == "UNVERIFIED")
    logger.info(
        "Checklist for '%s': %d source(s) — %d HIT, %d CLEAR, %d UNVERIFIED",
        name, len(results), hits,
        sum(1 for r in results if r.get("result") == "CLEAR"), unver,
    )
    return results
