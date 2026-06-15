"""
Sanctions checkers (pure Python, no API keys):
  • OFAC SDN — scrape sanctionssearch.ofac.treas.gov (ASP.NET form)
  • UN Consolidated Sanctions — XML download from scsanctions.un.org
  • EU Consolidated Sanctions — XML download from webgate.ec.europa.eu
"""
from __future__ import annotations

import logging

import requests
from bs4 import BeautifulSoup
from lxml import etree

from .base import (
    CACHE_DIR, HEADERS, _SSL_VERIFY,
    cached_get, is_match,
    clear_result, hit_result, unverified_result,
)

logger = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update(HEADERS)
_SESSION.verify = _SSL_VERIFY


# ── OFAC SDN (web search form) ────────────────────────────────────────────────

_OFAC_BASE = "https://sanctionssearch.ofac.treas.gov/"
_OFAC_NAME = "OFAC SDN List (US Treasury)"
_OFAC_URL  = "https://sanctionssearch.ofac.treas.gov/"


def check_ofac(name: str, pan: str = "") -> dict:
    try:
        # Step 1 — GET the form to extract ViewState / hidden fields
        r0 = _SESSION.get(_OFAC_BASE, timeout=15)
        r0.raise_for_status()
        soup0 = BeautifulSoup(r0.text, "lxml")
        form_data = {
            inp["name"]: inp.get("value", "")
            for inp in soup0.find_all("input")
            if inp.get("name")
        }

        # Inject our search term (last-name/entity field)
        form_data["ctl00$MainContent$txtLastName"] = name
        form_data["ctl00$MainContent$btnSearch"]   = "Search"

        # Step 2 — POST the form
        r1 = _SESSION.post(_OFAC_BASE, data=form_data, timeout=20)
        r1.raise_for_status()
        soup1 = BeautifulSoup(r1.text, "lxml")

        # Result table
        rows = soup1.select("#gvSearchResults tr")
        data_rows = [r for r in rows if r.find("td")]  # skip header row

        if not data_rows:
            return clear_result(_OFAC_NAME, _OFAC_URL, name)

        # Each row: Name | Address | Type | Program | List | Score
        hits = []
        for row in data_rows[:20]:
            cells = [td.get_text(" ", strip=True) for td in row.find_all("td")]
            if not cells:
                continue
            candidate = cells[0]
            score_txt = cells[-1] if len(cells) > 1 else ""
            try:
                score = float(score_txt.replace("%", "").strip())
            except ValueError:
                score = 0.0
            if is_match(name, candidate) or score >= 80:
                hits.append((candidate, score))

        if hits:
            best = max(hits, key=lambda x: x[1])
            return hit_result(
                _OFAC_NAME, _OFAC_URL, name,
                f"OFAC SDN match: '{best[0]}' (score={best[1]:.0f}%)",
            )
        return clear_result(_OFAC_NAME, _OFAC_URL, name)

    except Exception as exc:
        logger.warning("OFAC check failed: %s", exc)
        return unverified_result(_OFAC_NAME, _OFAC_URL, name, str(exc)[:100])


# ── UN Consolidated Sanctions ─────────────────────────────────────────────────

_UN_XML  = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"
_UN_URL  = "https://www.un.org/securitycouncil/content/un-sc-consolidated-list"
_UN_NAME = "UN Consolidated Sanctions List"


def check_un(name: str, pan: str = "") -> dict:
    try:
        xml_bytes = cached_get(_UN_XML, CACHE_DIR / "un_consolidated.xml", max_age_hours=24)
        root = etree.fromstring(xml_bytes)

        # Entities
        for entity in root.iter("ENTITY"):
            first = (entity.findtext("FIRST_NAME") or "").strip()
            if first and is_match(name, first):
                return hit_result(_UN_NAME, _UN_URL, name,
                                  f"Entity match in UN Sanctions: '{first}'")
            for alias in entity.iter("ALIAS"):
                aname = (alias.findtext("ALIAS_NAME") or "").strip()
                if aname and is_match(name, aname):
                    return hit_result(_UN_NAME, _UN_URL, name,
                                      f"Alias match in UN Sanctions: '{aname}'")

        # Individuals
        for indiv in root.iter("INDIVIDUAL"):
            parts = [
                (indiv.findtext("FIRST_NAME") or "").strip(),
                (indiv.findtext("SECOND_NAME") or "").strip(),
                (indiv.findtext("THIRD_NAME") or "").strip(),
            ]
            full = " ".join(p for p in parts if p)
            if full and is_match(name, full):
                return hit_result(_UN_NAME, _UN_URL, name,
                                  f"Individual match in UN Sanctions: '{full}'")

        return clear_result(_UN_NAME, _UN_URL, name)

    except Exception as exc:
        logger.warning("UN sanctions check failed: %s", exc)
        return unverified_result(_UN_NAME, _UN_URL, name, str(exc)[:100])


# ── EU Consolidated Sanctions ─────────────────────────────────────────────────

_EU_XML  = (
    "https://webgate.ec.europa.eu/fsd/fsf/public/files/"
    "xmlFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw"
)
_EU_URL  = "https://www.sanctionsmap.eu/"
_EU_NAME = "EU Consolidated Sanctions List"


def check_eu(name: str, pan: str = "") -> dict:
    try:
        xml_bytes = cached_get(_EU_XML, CACHE_DIR / "eu_sanctions.xml", max_age_hours=24)
        root = etree.fromstring(xml_bytes)

        ns = {"eu": root.nsmap.get(None, "")}
        # Try namespace-agnostic iteration
        for entry in root.iter():
            tag = entry.tag.split("}")[-1] if "}" in entry.tag else entry.tag
            if tag in ("nameAlias", "name") and entry.text:
                if is_match(name, entry.text.strip()):
                    return hit_result(_EU_NAME, _EU_URL, name,
                                      f"Match in EU Consolidated Sanctions: '{entry.text.strip()}'")
            # Also check wholeName attribute
            wn = entry.get("wholeName") or entry.get("name") or ""
            if wn and is_match(name, wn):
                return hit_result(_EU_NAME, _EU_URL, name,
                                  f"Match in EU Consolidated Sanctions: '{wn}'")

        return clear_result(_EU_NAME, _EU_URL, name)

    except Exception as exc:
        logger.warning("EU sanctions check failed: %s", exc)
        return unverified_result(_EU_NAME, _EU_URL, name, str(exc)[:100])
