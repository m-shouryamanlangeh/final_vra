"""
Indian regulatory checkers:
  • SEBI orders & debarment search
  • Indian Kanoon court-case search
  • IBBI insolvency search
  • MCA Struck-Off Companies (downloadable list)
  • Static / UNVERIFIED stubs for portals that need login
"""
from __future__ import annotations

import logging
import re
from urllib.parse import quote_plus

import requests
from bs4 import BeautifulSoup

from .base import (
    CACHE_DIR, HEADERS, _SSL_VERIFY,
    cached_get, is_match,
    clear_result, hit_result, unverified_result,
)

logger = logging.getLogger(__name__)

SESSION = requests.Session()
SESSION.headers.update(HEADERS)
SESSION.verify = _SSL_VERIFY


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_html(url: str, timeout: int = 12) -> BeautifulSoup | None:
    try:
        r = SESSION.get(url, timeout=timeout, allow_redirects=True)
        r.raise_for_status()
        return BeautifulSoup(r.text, "lxml")
    except Exception as exc:
        logger.warning("GET %s → %s", url, exc)
        return None


def _post_html(url: str, data: dict, timeout: int = 12) -> BeautifulSoup | None:
    try:
        r = SESSION.post(url, data=data, timeout=timeout, allow_redirects=True)
        r.raise_for_status()
        return BeautifulSoup(r.text, "lxml")
    except Exception as exc:
        logger.warning("POST %s → %s", url, exc)
        return None


def _contains_name(soup: BeautifulSoup, name: str) -> tuple[bool, str]:
    """Return (found, snippet) if any text node fuzzy-matches name."""
    normalized = name.lower()
    for text in soup.stripped_strings:
        if len(text) < 4:
            continue
        if is_match(name, text) or normalized in text.lower():
            snippet = text[:120].strip()
            return True, snippet
    return False, ""


# ── SEBI Orders & Debarment ───────────────────────────────────────────────────

_SEBI_NAME = "SEBI Orders & Debarment List"
_SEBI_SEARCH = "https://www.sebi.gov.in/sebiweb/other/OtherAction.do?doQuickSearch=yes&type=2&searchText={q}"
_SEBI_URL = "https://www.sebi.gov.in/enforcement/orders.html"


def check_sebi(name: str, pan: str = "") -> dict:
    url = _SEBI_SEARCH.format(q=quote_plus(name))
    soup = _get_html(url)
    if soup is None:
        return unverified_result(_SEBI_NAME, _SEBI_URL, name, "Could not reach sebi.gov.in")

    found, snippet = _contains_name(soup, name)
    # SEBI results page shows "No record found" when empty
    no_result = bool(soup.find(string=re.compile(r"No record found|no results", re.I)))

    if found and not no_result:
        return hit_result(_SEBI_NAME, _SEBI_URL, name,
                          f"Name found in SEBI search results: '{snippet[:80]}'")
    return clear_result(_SEBI_NAME, _SEBI_URL, name)


# ── Indian Kanoon (court cases) ───────────────────────────────────────────────

_IK_NAME = "eCourts / Indian Kanoon"
_IK_SEARCH = "https://indiankanoon.org/search/?formInput={q}&pagenum=0"
_IK_URL = "https://indiankanoon.org"

_CRIMINAL_KEYWORDS = re.compile(
    r"\b(fraud|cheating|criminal|offence|offender|arrested|charge.?sheet|"
    r"money laundering|ponzi|scam|default|insolvency|winding.up|ED|CBI|SFIO)\b",
    re.I,
)


def check_indian_kanoon(name: str, pan: str = "") -> dict:
    url = _IK_SEARCH.format(q=quote_plus(f'"{name}"'))
    soup = _get_html(url)
    if soup is None:
        return unverified_result(_IK_NAME, _IK_URL, name, "Could not reach indiankanoon.org")

    # Each result block has class "result"
    result_divs = soup.find_all("div", class_="result")
    if not result_divs:
        # Check for no-results message
        body_text = soup.get_text(" ", strip=True)
        if "no documents" in body_text.lower() or len(body_text) < 200:
            return clear_result(_IK_NAME, _IK_URL, name)
        return unverified_result(_IK_NAME, _IK_URL, name, "Unexpected page format")

    criminal_hits: list[str] = []
    for div in result_divs[:10]:
        text = div.get_text(" ", strip=True)
        if _CRIMINAL_KEYWORDS.search(text):
            snippet = text[:150].strip()
            criminal_hits.append(snippet)

    if criminal_hits:
        return hit_result(
            _IK_NAME, _IK_URL, name,
            f"{len(criminal_hits)} case(s) with adverse keywords found. "
            f"Sample: '{criminal_hits[0][:100]}'",
        )

    if result_divs:
        return {
            "list_name": _IK_NAME,
            "source_url": url,
            "entity_checked": name,
            "result": "UNVERIFIED",
            "finding": (
                f"{len(result_divs)} case(s) found on Indian Kanoon but no "
                "clear adverse keywords. Manual review recommended."
            ),
        }

    return clear_result(_IK_NAME, _IK_URL, name)


# ── IBBI Insolvency ───────────────────────────────────────────────────────────

_IBBI_NAME = "IBBI Insolvency Records"
_IBBI_SEARCH = "https://www.ibbi.gov.in/cirp/company-wise-detail?company_name={q}"
_IBBI_ALT = "https://ibbi.gov.in/en/search?query={q}"
_IBBI_URL = "https://www.ibbi.gov.in"


def check_ibbi(name: str, pan: str = "") -> dict:
    # Try both known IBBI search URLs
    for tpl in (_IBBI_SEARCH, _IBBI_ALT):
        url = tpl.format(q=quote_plus(name))
        soup = _get_html(url)
        if soup is None:
            continue
        found, snippet = _contains_name(soup, name)
        no_result = bool(soup.find(string=re.compile(
            r"No record|No data|No result|not found", re.I)))
        if found and not no_result:
            return hit_result(_IBBI_NAME, _IBBI_URL, name,
                              f"Found in IBBI insolvency records: '{snippet[:80]}'")

    return unverified_result(_IBBI_NAME, _IBBI_URL, name,
                             "Portal did not return parseable results.")


# ── MCA Struck-Off Companies ──────────────────────────────────────────────────

_MCA_STRUCK_NAME = "MCA Struck-Off Companies"
_MCA_STRUCK_URL = "https://www.mca.gov.in/content/mca/global/en/data-and-reports/rd-roc-info/companies-struck-roc.html"

# MCA publishes the list as a downloadable text/csv – the URL changes per year.
# We use the page itself to find a snippet mentioning the company name.
_MCA_SEARCH = "https://efiling.mca.gov.in/SearchService/rest/api/v1/company/search?companyName={q}&status=STRUCK_OFF"


def check_mca_struck(name: str, pan: str = "") -> dict:
    try:
        url = _MCA_SEARCH.format(q=quote_plus(name))
        r = SESSION.get(url, timeout=12)
        if r.status_code == 200:
            data = r.json()
            companies = data.get("companyMasterData", []) or data.get("data", [])
            hits = [
                c for c in companies
                if is_match(name, c.get("companyName", ""))
                and str(c.get("companyStatus", "")).upper() == "STRUCK_OFF"
            ]
            if hits:
                c = hits[0]
                return hit_result(
                    _MCA_STRUCK_NAME, _MCA_STRUCK_URL, name,
                    f"Company struck off on MCA: '{c.get('companyName')}' "
                    f"(CIN: {c.get('cin', '?')})",
                )
            # Any status match?
            any_hits = [c for c in companies if is_match(name, c.get("companyName", ""))]
            if any_hits:
                c = any_hits[0]
                status = c.get("companyStatus", "UNKNOWN")
                return {
                    "list_name": _MCA_STRUCK_NAME,
                    "source_url": _MCA_STRUCK_URL,
                    "entity_checked": name,
                    "result": "CLEAR",
                    "finding": f"Company found on MCA with status: {status}",
                }
        return unverified_result(_MCA_STRUCK_NAME, _MCA_STRUCK_URL, name,
                                 "MCA API did not return parseable data.")
    except Exception as exc:
        logger.warning("MCA check failed: %s", exc)
        return unverified_result(_MCA_STRUCK_NAME, _MCA_STRUCK_URL, name, str(exc)[:80])


# ── Static UNVERIFIED stubs for portals requiring login / non-scrapable ───────

def check_rbi_defaulters(name: str, pan: str = "") -> dict:
    return unverified_result(
        "RBI Wilful Defaulters",
        "https://rbi.org.in/Scripts/WilfulDefaulters.aspx",
        name,
    )


def check_cibil(name: str, pan: str = "") -> dict:
    return unverified_result(
        "CIBIL Suit Filed & Wilful Defaulters",
        "https://www.cibil.com/resources/suit-filed-and-wilful-defaulters",
        name,
    )


def check_watchout(name: str, pan: str = "") -> dict:
    url = f"https://www.watchoutinvestors.com/search?q={quote_plus(name)}"
    soup = _get_html(url)
    if soup:
        found, snippet = _contains_name(soup, name)
        if found:
            return hit_result(
                "WatchOutInvestors Wilful Default",
                url, name,
                f"Name found on WatchOutInvestors: '{snippet[:80]}'",
            )
        no_res = bool(soup.find(string=re.compile(r"No result|not found", re.I)))
        if no_res:
            return clear_result("WatchOutInvestors Wilful Default", url, name)
    return unverified_result(
        "WatchOutInvestors Wilful Default",
        f"https://www.watchoutinvestors.com/search?q={quote_plus(name)}",
        name,
    )


def check_mca_mlm(name: str, pan: str = "") -> dict:
    return unverified_result(
        "MCA Blacklisted MLM Companies",
        "https://www.mca.gov.in/content/mca/global/en/data-and-reports/company-llp-info/under-alert/mlm.html",
        name,
    )


def check_mca_shell(name: str, pan: str = "") -> dict:
    return unverified_result(
        "Shell Companies List",
        "https://www.mca.gov.in/",
        name,
    )


def check_cbi(name: str, pan: str = "") -> dict:
    return unverified_result(
        "CBI / ED / SFIO / PMLA Investigations",
        "https://cbi.gov.in/",
        name,
    )


def check_nclt(name: str, pan: str = "") -> dict:
    url = f"https://nclt.gov.in/en/search?q={quote_plus(name)}"
    soup = _get_html(url)
    if soup:
        found, snippet = _contains_name(soup, name)
        if found:
            return {
                "list_name": "NCLT / NCLAT Insolvency",
                "source_url": url,
                "entity_checked": name,
                "result": "UNVERIFIED",
                "finding": f"Name found on NCLT portal — manual review needed: '{snippet[:80]}'",
            }
    return unverified_result(
        "NCLT / NCLAT Insolvency",
        f"https://nclt.gov.in/en/search?q={quote_plus(name)}",
        name,
    )


def check_delhi_eow(name: str, pan: str = "") -> dict:
    return unverified_result(
        "Delhi Police EOW Proclaimed Offenders",
        "https://delhipolice.ncog.gov.in/Delhi_police/proclaimed.html",
        name,
    )


def check_icij(name: str, pan: str = "") -> dict:
    url = f"https://offshoreleaks.icij.org/search?q={quote_plus(name)}&c=&j=&e=0"
    soup = _get_html(url)
    if soup:
        rows = soup.select("table tbody tr")
        for row in rows[:20]:
            text = row.get_text(" ", strip=True)
            if is_match(name, text):
                return hit_result(
                    "ICIJ Offshore Leaks",
                    url, name,
                    f"Found in ICIJ Offshore Leaks database: '{text[:100]}'",
                )
        if rows:
            return clear_result("ICIJ Offshore Leaks", url, name)
    return unverified_result("ICIJ Offshore Leaks", url, name, "Could not parse page.")


def check_cybercrime(name: str, pan: str = "") -> dict:
    return unverified_result(
        "National Cybercrime Portal",
        "https://cybercrime.gov.in/",
        name,
    )


def check_cbdt(name: str, pan: str = "") -> dict:
    return unverified_result(
        "Income Tax Defaulters (CBDT)",
        "https://www.incometax.gov.in/iec/foportal/",
        name,
    )


def check_mh_gst(name: str, pan: str = "") -> dict:
    return unverified_result(
        "Maharashtra Non-Genuine GST Dealers",
        "https://mahagst.gov.in/en/list-non-genuine-dealers",
        name,
    )
