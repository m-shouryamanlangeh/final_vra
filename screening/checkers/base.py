"""Shared utilities for all checkers."""
from __future__ import annotations

import re
import time
import logging
from pathlib import Path
from typing import Any

import requests
from rapidfuzz import fuzz

logger = logging.getLogger(__name__)

# ── SSL fix: inject macOS system Keychain (truststore) + certifi fallback ────
try:
    import truststore as _truststore
    _truststore.inject_into_ssl()
except ImportError:
    pass
try:
    import certifi as _certifi
    _SSL_VERIFY: str | bool = _certifi.where()
except ImportError:
    _SSL_VERIFY = True

CACHE_DIR = Path(__file__).resolve().parent.parent.parent / "output" / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-IN,en;q=0.8",
}

# Company-type noise words stripped during normalisation
_CO_RE = re.compile(
    r"\b(private limited|pvt\.?\s*ltd\.?|public limited|limited|ltd\.?|llp|llc"
    r"|inc\.?|corp\.?|corporation|co\.?|group|holdings?|enterprises?|solutions?"
    r"|services?|technologies?|tech|global|international|india|ventures?|"
    r"|associates?|consultants?|exports?|imports?)\b",
    re.I,
)

FUZZY_THRESHOLD = 82  # rapidfuzz score 0-100


def normalize_name(name: str) -> str:
    """Lowercase, strip company-type suffixes, collapse whitespace."""
    n = _CO_RE.sub(" ", name.lower())
    return re.sub(r"[\s\-&,./]+", " ", n).strip()


def is_match(query: str, candidate: str) -> bool:
    """True if query and candidate likely refer to the same entity."""
    qn, cn = normalize_name(query), normalize_name(candidate)
    if not qn or not cn:
        return False
    if qn in cn or cn in qn:
        return True
    # token_sort_ratio handles different word orders ("Ebix Global" vs "Global Ebix")
    return fuzz.token_sort_ratio(qn, cn) >= FUZZY_THRESHOLD


def cached_get(url: str, cache_file: Path, max_age_hours: int = 12) -> bytes:
    """Download URL to cache_file; return cached bytes if still fresh."""
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    if cache_file.exists():
        age = time.time() - cache_file.stat().st_mtime
        if age < max_age_hours * 3600:
            logger.debug("Cache hit → %s", cache_file.name)
            return cache_file.read_bytes()
    logger.info("Downloading %s", url)
    resp = requests.get(url, headers=HEADERS, timeout=90, verify=_SSL_VERIFY)
    resp.raise_for_status()
    cache_file.write_bytes(resp.content)
    return resp.content


def clear_result(list_name: str, source_url: str, entity: str) -> dict:
    return {
        "list_name": list_name,
        "source_url": source_url,
        "entity_checked": entity,
        "result": "CLEAR",
        "finding": "No adverse records found.",
    }


def hit_result(list_name: str, source_url: str, entity: str, finding: str) -> dict:
    return {
        "list_name": list_name,
        "source_url": source_url,
        "entity_checked": entity,
        "result": "HIT",
        "finding": finding,
    }


def unverified_result(list_name: str, source_url: str, entity: str, reason: str = "") -> dict:
    return {
        "list_name": list_name,
        "source_url": source_url,
        "entity_checked": entity,
        "result": "UNVERIFIED",
        "finding": f"Manual check required — portal not machine-readable. {reason}".strip(),
    }
