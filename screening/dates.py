"""Date parsing, formatting and chronological ordering for report output.

Every date shown in a screening report — an article's publication date and
the date the system fetched it — is rendered in ONE format (``DD MMM YYYY``)
so the report is internally consistent.

Adverse-media findings are ordered newest-first by publication date. Any
article whose publication date is missing or unparseable is pushed to the
bottom (never dropped, never mis-sorted) and shown with an explicit
"date unavailable" marker so a reviewer can tell signal from absence.
"""
from __future__ import annotations

import datetime as dt
import logging
from email.utils import parsedate_to_datetime

logger = logging.getLogger(__name__)

# Single canonical display format used everywhere a date is shown in a report.
DISPLAY_FORMAT = "%d %b %Y"          # e.g. 16 Jun 2026
DATE_UNAVAILABLE = "Date unavailable"


def parse_date(raw) -> dt.datetime | None:
    """Best-effort parse of a date value into a timezone-naive ``datetime``.

    Handles the two shapes that actually occur in this app:
      • RFC-822 — Google News RSS ``pubDate`` ("Mon, 16 Jun 2026 10:30:00 GMT")
      • ISO-8601 — our own ``date_of_search`` ("2026-06-17")
    plus ``date``/``datetime`` objects and our own display format. Returns
    ``None`` for empty or unrecognised input so callers can treat it as
    "missing" rather than guessing.
    """
    if not raw:
        return None
    if isinstance(raw, dt.datetime):
        return raw.replace(tzinfo=None)
    if isinstance(raw, dt.date):
        return dt.datetime(raw.year, raw.month, raw.day)

    s = str(raw).strip()
    if not s:
        return None

    # RFC-822 (RSS pubDate)
    try:
        d = parsedate_to_datetime(s)
        if d is not None:
            return d.replace(tzinfo=None)
    except (TypeError, ValueError, IndexError):
        pass

    # ISO-8601, with or without a time component
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        pass

    # Already in a human format
    for fmt in (DISPLAY_FORMAT, "%d %B %Y", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(s, fmt)
        except ValueError:
            continue

    return None


def format_date(raw) -> str:
    """Format any supported date value as ``DD MMM YYYY``; "" if missing/invalid."""
    d = parse_date(raw)
    return d.strftime(DISPLAY_FORMAT) if d else ""


def prepare_media(findings, fetched_date="") -> list[dict]:
    """Return a display-ready, newest-first copy of ``findings``.

    Each returned item gains:
      • ``pub_date_display``     — publication date formatted, or "" if absent
      • ``fetched_date_display`` — the system fetch date (``date_of_search``)
                                   formatted, or "" if unknown

    Ordering: descending by publication date (most recent first). Items whose
    publication date is missing or unparseable sink to the bottom, keeping
    their original relative order. The input list is not mutated.
    """
    fetched_display = format_date(fetched_date)
    prepared: list[dict] = []
    for f in findings or []:
        item = dict(f)
        parsed = parse_date(f.get("pub_date"))
        item["pub_date_display"] = parsed.strftime(DISPLAY_FORMAT) if parsed else ""
        item["fetched_date_display"] = fetched_display
        item["_sort_dt"] = parsed
        prepared.append(item)

    # reverse=True → newest first; missing dates map to datetime.min so they
    # land at the bottom. Python's stable sort preserves the original order
    # among items that share a position (e.g. all the undated ones).
    prepared.sort(key=lambda it: it["_sort_dt"] or dt.datetime.min, reverse=True)

    for it in prepared:
        it.pop("_sort_dt", None)
    return prepared
