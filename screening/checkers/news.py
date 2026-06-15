"""
Adverse media checker using public news feeds.
  • Google News RSS  (no key, no auth)
  • DuckDuckGo HTML  (no key, no auth)
  • The Hindu / ET / LiveMint via Google News

v2 changes (false-positive fixes):
  1. Vendor name MUST appear in the article title or snippet — articles
     returned only via search-engine context are discarded.
  2. Exculpatory-context detection — titles like "X launches Fraud
     Detection Solution" or "X: Spam and Scam Prevention with AI" are
     skipped (vendor is the SOLVER, not the SUBJECT). Exculpatory
     language in the snippet only → severity downgraded one level.
  3. Dedup by normalised title in addition to link (same story often
     appears under different URLs across sources).
"""
from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from urllib.parse import quote_plus

import requests
from bs4 import BeautifulSoup
from rapidfuzz import fuzz

from .base import HEADERS, _SSL_VERIFY

logger = logging.getLogger(__name__)

SESSION = requests.Session()
SESSION.headers.update(HEADERS)
SESSION.verify = _SSL_VERIFY

# ---------------------------------------------------------------------------
# Keyword maps for severity classification
# ---------------------------------------------------------------------------

# Severity keyword maps — globally applicable to companies AND individuals,
# not limited to Indian regulators. Indian-specific terms are retained.
_HIGH_KEYWORDS = re.compile(
    r"\b(arrested|arrest|jailed|imprisoned|convicted|conviction|indicted|"
    r"indictment|guilty|sentenced|charged with|chargesheet|chargesheeted|"
    r"charge.?sheet|money laundering|terror financing|terrorism|trafficking|"
    r"fraud|defrauded|embezzl|bribery|bribe|corruption|kickback|extortion|"
    r"racketeering|ponzi|pyramid scheme|scam|cheating|forgery|counterfeit|"
    r"insider trading|sanction(ed|s)|blacklist(ed)?|debarred|barred|banned|"
    r"fugitive|wanted|extradition|red notice|raid(ed)?|"
    r"PMLA|ED raid|Enforcement Directorate|CBI case|SFIO|SEBI ban|"
    r"insolvency|wilful default|shell company|black money|hawala|benami|"
    r"indicted by|DOJ charges?|SEC charges?|FBI)\b",
    re.I,
)

_MEDIUM_KEYWORDS = re.compile(
    r"\b(probe|investigation|investigated|scrutiny|inquiry|notice|summons|"
    r"penalty|penalised|penalized|fine(d)?|sued|lawsuit|litigation|"
    r"settlement|class action|misconduct|wrongdoing|malpractice|"
    r"violation|breach|data breach|whistleblower|allegation|alleged|"
    r"accus(ed|ation)|tax evasion|GST fraud|loan default|NPA|non.performing|"
    r"search operation|NCLT|liquidat|winding.up|bankruptcy|arbitration|"
    r"dispute|irregularit|misappropriat|embezzl|regulator(y)? action|"
    r"recall|suspension|suspended|de.?listed)\b",
    re.I,
)

_LOW_KEYWORDS = re.compile(
    r"\b(complaint|PIL|legal battle|court case|suit filed|tribunal|lawsuit|"
    r"consumer complaint|disagreement|controversy|controversial|criticism|"
    r"criticised|criticized|backlash|scrutinis|scrutiniz|concern(s)? over|"
    r"under fire|questioned|protest)\b",
    re.I,
)

# ---------------------------------------------------------------------------
# Exculpatory / vendor-as-solver patterns
# ---------------------------------------------------------------------------
# If these appear in the TITLE alongside an adverse keyword, the entity is
# almost always FIGHTING the problem (e.g. "Airtel launches Fraud Detection
# Solution", "Bharti Airtel: Spam and Scam Prevention with AI") — skip.
# If they appear only in the SNIPPET, downgrade severity one level.

_EXCULPATORY = re.compile(
    r"\b(prevention|prevents?|preventing|detection|detects?|detecting|"
    r"solutions?|fighting|fights?|combat(s|ing)?|tackl(e|es|ing)|"
    r"against\s+(online\s+|digital\s+|cyber\s*)?(fraud(sters)?|scam(s|sters|mers)?|spam(mers)?|phishing|cybercrime)|"
    r"launch(es|ed|ing)?|unveils?|introduc(es|ed|ing)|"
    r"rolls?\s+out|blocks?|blocked|blocking|filters?|flags?|"
    r"crack(s|ed|ing)?\s*down|crackdown\s+on\s+(fraud|scam|spam)|curbs?|"
    r"warns?|warning|advisory|alerts?\s+(customers|users|subscribers)|"
    r"awareness|safeguards?|protect(s|ing|ion)?|secur(es|ing|ity\s+solution)|"
    r"anti.?(fraud|scam|spam|phishing)|"
    r"helps?\s+(fight|prevent|detect|stop)|partner(s|ed|ing)?\s+to\s+(fight|prevent|combat))\b",
    re.I,
)

# Legal-entity suffixes stripped before vendor-name matching
_NAME_SUFFIXES = re.compile(
    r"\b(private|pvt\.?|limited|ltd\.?|llp|llc|inc\.?|corp\.?|corporation|"
    r"company|co\.?|industries|enterprises|ventures|group|holdings?|"
    r"india|technologies|tech|solutions|services)\b\.?",
    re.I,
)

# Generic tokens that should never count as a vendor match on their own
_GENERIC_TOKENS = {
    "the", "and", "of", "for", "new", "all", "one", "global", "national",
    "international", "general", "first", "best", "digital", "data",
    "power", "energy", "finance", "financial", "capital", "trading",
}

# Query suffixes — global adverse terms that work for any person or company,
# in any geography (the third query keeps India-specific regulator coverage).
ADVERSE_QUERY_SUFFIXES = [
    "fraud OR scam OR lawsuit OR charged OR convicted OR arrested",
    "investigation OR probe OR penalty OR fined OR misconduct OR scandal",
    "sanctions OR money laundering OR indicted OR ED OR CBI OR SEBI",
]

_SEV_DOWNGRADE = {"HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}


def _core_name_tokens(name: str) -> tuple[str, list[str]]:
    """
    Return (core_phrase, distinctive_tokens) for a vendor name.
    "Bharti Airtel Limited" -> ("bharti airtel", ["bharti", "airtel"])
    """
    core = _NAME_SUFFIXES.sub(" ", name)
    core = re.sub(r"[^\w\s]", " ", core)
    core = re.sub(r"\s+", " ", core).strip().lower()
    tokens = [
        t for t in core.split()
        if len(t) >= 3 and t not in _GENERIC_TOKENS
    ]
    return core, tokens


# Match-confidence tiers. The screening engine must NEVER silently drop a name
# match on a guess (a false negative is the dangerous outcome for KYC/AML), so
# uncertain matches are surfaced as WEAK ("verify the entity") rather than
# discarded — only a genuine absence of the name returns None.
STRONG, WEAK = "STRONG", "WEAK"


def _match_confidence(name: str, text: str) -> str | None:
    """
    How confidently `text` refers to the vendor:
      STRONG — the full name appears: a multi-word core phrase ("Bharti
               Airtel"), all distinctive tokens, or a single-token name written
               AS a company ("Bala Corporation" / "Bala Corp").
      WEAK   — only a partial signal: a bare common token ("Bala"), or a
               minority of a multi-token name ("Airtel" alone). Surfaced for
               manual verification, but never used to auto-escalate to HIGH.
      None   — the name does not appear at all → not this entity, discard.
    """
    core, tokens = _core_name_tokens(name)
    if not core or not tokens:
        return None
    low = text.lower()

    if len(tokens) == 1:
        tok = re.escape(tokens[0])
        # Single-token name carrying a legal suffix (e.g. "Bala Corporation"):
        # STRONG only when written as a company — the token followed by one of
        # the same legal-entity suffixes this module strips (reused list).
        if _NAME_SUFFIXES.search(name) and re.search(
                rf"\b{tok}\s+{_NAME_SUFFIXES.pattern}", low, re.I):
            return STRONG
        # The bare token appears (word-boundary, no substrings). For a common
        # single word this is only a POSSIBLE match → WEAK, surface to verify.
        if re.search(rf"\b{tok}\b", low):
            return WEAK
        return None

    # Multi-token names — full core phrase, or every distinctive token present.
    if re.search(rf"\b{re.escape(core)}\b", low):
        return STRONG
    matched = sum(1 for t in tokens if re.search(rf"\b{re.escape(t)}\b", low))
    if matched == len(tokens):
        return STRONG
    if matched / len(tokens) >= 0.5:
        return WEAK
    return None


def _mentions_vendor(name: str, text: str) -> bool:
    """Back-compat boolean wrapper around :func:`_match_confidence`."""
    return _match_confidence(name, text) is not None


def _classify_severity(text: str) -> str:
    if _HIGH_KEYWORDS.search(text):
        return "HIGH"
    if _MEDIUM_KEYWORDS.search(text):
        return "MEDIUM"
    if _LOW_KEYWORDS.search(text):
        return "LOW"
    return "LOW"


def _is_adverse(text: str) -> bool:
    return bool(
        _HIGH_KEYWORDS.search(text)
        or _MEDIUM_KEYWORDS.search(text)
        or _LOW_KEYWORDS.search(text)
    )


def _normalise_title(title: str) -> str:
    """Normalised key for title-based dedup across sources."""
    t = re.sub(r"\s*[-–|]\s*[^-–|]+$", "", title)  # strip trailing " - Publisher"
    t = re.sub(r"[^\w\s]", "", t)
    return re.sub(r"\s+", " ", t).strip().lower()


# Volume / currency filler words removed before near-duplicate comparison so that
# the SAME story republished with different figures collapses to one finding —
# e.g. "Airtel receives Rs 6.78 Lakh DoT penalty" vs "…Rs 7.10 Lakh DoT penalty".
_DEDUP_FILLER = re.compile(
    r"\b(rs|inr|lakh|crore|cr|usd|million|billion|mn|bn|worth|receives?|"
    r"imposed|notices?|gets?|pays?|over|amid)\b",
    re.I,
)

# token_sort_ratio at/above this → treat as the same story.
_NEAR_DUP_THRESHOLD = 88


def _dedup_key(title: str) -> str:
    """Aggressive key for near-duplicate detection: drop the trailing publisher,
    digits, currency/volume words and punctuation so stories that differ only by
    a figure or minor wording reduce to the same key."""
    t = re.sub(r"\s*[-–|]\s*[^-–|]+$", "", title)   # strip trailing " - Publisher"
    t = _DEDUP_FILLER.sub(" ", t)
    t = re.sub(r"[^a-z\s]", " ", t.lower())          # drop digits & punctuation
    return re.sub(r"\s+", " ", t).strip()


def _clean_snippet(text: str) -> str:
    """Strip HTML/entities from a feed description so it can be shown as the
    evidence that explains *why* an article matched."""
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = re.sub(r"&[#0-9a-z]+;", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _evaluate_article(name: str, title: str, desc: str) -> tuple[str | None, str | None, str]:
    """
    Apply all relevance/context gates to one article.
    Returns (severity, match_confidence, "") if the article counts,
    or (None, None, skip_reason) if it must be discarded.
    """
    combined = f"{title} {desc}"

    # Gate 1 — must actually be adverse
    if not _is_adverse(combined):
        return None, None, "not_adverse"

    # Gate 2 — vendor must be mentioned in the article itself, not merely
    # associated by the search engine. Uncertain (WEAK) matches are kept and
    # flagged, NOT dropped — a missed real hit is worse than one to verify.
    conf = _match_confidence(name, combined)
    if conf is None:
        return None, None, "no_mention"

    # Gate 3 — exculpatory context in the title → vendor is the
    # solver/announcer, not the accused — skip entirely
    if _EXCULPATORY.search(title):
        return None, None, "exculpatory"

    sev = _classify_severity(combined)

    if _EXCULPATORY.search(desc):
        # Softer signal in snippet only — downgrade one level
        sev = _SEV_DOWNGRADE[sev]

    # A name-only (WEAK) match must never single-handedly drive a HIGH/REJECT —
    # cap it at MEDIUM so it surfaces for review without auto-rejecting on a
    # possible namesake.
    if conf == WEAK and sev == "HIGH":
        sev = "MEDIUM"

    return sev, conf, ""


# ---------------------------------------------------------------------------
# Google News RSS
# ---------------------------------------------------------------------------

_GNEWS_RSS = (
    "https://news.google.com/rss/search"
    "?q={q}&hl={hl}&gl={gl}&ceid={ceid}"
)

# Query both the India and the US/global Google News editions so the tool
# surfaces coverage for any entity — Indian vendors AND international
# companies / individuals. Duplicate stories are merged downstream.
_GNEWS_LOCALES = [
    {"hl": "en-IN", "gl": "IN", "ceid": "IN:en"},
    {"hl": "en-US", "gl": "US", "ceid": "US:en"},
]


def _fetch_gnews(query: str, locale: dict) -> list[dict]:
    url = _GNEWS_RSS.format(q=quote_plus(query), **locale)
    try:
        r = SESSION.get(url, timeout=12)
        r.raise_for_status()
        root = ET.fromstring(r.content)
        items = []
        for item in root.iter("item"):
            title = item.findtext("title") or ""
            link  = item.findtext("link") or ""
            desc  = item.findtext("description") or ""
            pub   = item.findtext("pubDate") or ""
            items.append({"title": title, "link": link, "desc": desc, "pub": pub})
        return items
    except Exception as exc:
        logger.warning("Google News RSS failed for '%s': %s", query, exc)
        return []


# ---------------------------------------------------------------------------
# DuckDuckGo HTML search (no API key needed)
# ---------------------------------------------------------------------------

_DDG_URL = "https://html.duckduckgo.com/html/"


def _fetch_ddg(query: str) -> list[dict]:
    try:
        r = SESSION.post(
            _DDG_URL,
            data={"q": query, "b": "", "kl": "in-en"},
            timeout=12,
        )
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "lxml")
        items = []
        for result in soup.select(".result__body")[:15]:
            a_tag = result.find("a", class_="result__a")
            snippet = result.find("a", class_="result__snippet")
            title = a_tag.get_text(" ", strip=True) if a_tag else ""
            href  = a_tag["href"] if a_tag and a_tag.get("href") else ""
            text  = snippet.get_text(" ", strip=True) if snippet else ""
            if title:
                items.append({"title": title, "link": href, "desc": text})
        return items
    except Exception as exc:
        logger.warning("DuckDuckGo search failed for '%s': %s", query, exc)
        return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def search_adverse_media(name: str) -> list[dict]:
    """
    Search multiple news sources for adverse coverage of `name`.
    Returns a list of adverse_media_findings dicts, each carrying a
    ``match_confidence`` (STRONG/WEAK) and an ``evidence`` snippet.

    An article is only counted if:
      • it contains at least one adverse keyword, AND
      • the vendor name appears in its title/snippet (STRONG if the full name /
        company form is present, WEAK if only a partial / bare-token match —
        WEAK is surfaced for verification, never silently dropped), AND
      • the title does not show exculpatory context (vendor-as-solver).
    """
    findings: list[dict] = []
    seen_links: set[str] = set()
    seen_titles: set[str] = set()
    seen_dedup_keys: list[str] = []
    skipped = {"no_mention": 0, "exculpatory": 0, "duplicate": 0, "not_adverse": 0}

    search_query = f'"{name}"'

    def _is_near_duplicate(key: str) -> bool:
        # Same story republished with a different figure / minor rewording.
        return bool(key) and any(
            fuzz.token_sort_ratio(key, s) >= _NEAR_DUP_THRESHOLD
            for s in seen_dedup_keys
        )

    def _consider(item: dict, hyperlink: str, pub: str) -> None:
        link = item["link"]
        title_key = _normalise_title(item["title"])
        dedup_key = _dedup_key(item["title"])
        if (link in seen_links
                or (title_key and title_key in seen_titles)
                or _is_near_duplicate(dedup_key)):
            skipped["duplicate"] += 1
            return

        sev, conf, reason = _evaluate_article(name, item["title"], item["desc"])
        if sev is None:
            if reason in skipped:
                skipped[reason] += 1
            return

        seen_links.add(link)
        if title_key:
            seen_titles.add(title_key)
        if dedup_key:
            seen_dedup_keys.append(dedup_key)

        # Evidence = the snippet text that mentions the entity, so a reviewer
        # can see WHY this matched (the title alone is often truncated and may
        # not contain the name).
        evidence = _clean_snippet(item.get("desc", ""))
        findings.append({
            "entity":           name,
            "severity":         sev,
            "match_confidence": conf,                    # STRONG | WEAK
            "summary":          item["title"][:200],
            "evidence":         evidence[:300],
            "source":           link,
            "search_hyperlink": hyperlink,
            "pub_date":         pub,
        })

    # 1. Google News RSS – each suffix across each locale (India + US/global)
    gnews_link = f"https://news.google.com/search?q={quote_plus(search_query)}"
    for suffix in ADVERSE_QUERY_SUFFIXES:
        q = f"{search_query} {suffix}"
        for locale in _GNEWS_LOCALES:
            for item in _fetch_gnews(q, locale):
                _consider(item, gnews_link, item.get("pub", ""))

    # 2. DuckDuckGo – one combined query (global adverse terms)
    ddg_q = f"{search_query} fraud OR scam OR lawsuit OR investigation OR arrested OR sanctioned"
    ddg_link = f"https://duckduckgo.com/?q={quote_plus(ddg_q)}"
    for item in _fetch_ddg(ddg_q):
        _consider(item, ddg_link, "")

    # Sort by severity (HIGH → LOW), then confirmed (STRONG) before to-verify.
    _sev_ord = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    _conf_ord = {STRONG: 0, WEAK: 1}
    findings.sort(key=lambda x: (_sev_ord.get(x["severity"], 3),
                                 _conf_ord.get(x.get("match_confidence"), 2)))

    strong = sum(1 for f in findings if f.get("match_confidence") == STRONG)
    weak = len(findings) - strong
    logger.info(
        "Adverse media for '%s': %d finding(s) [%d confirmed, %d to-verify] "
        "(skipped: %d no-mention, %d exculpatory, %d duplicate)",
        name, len(findings), strong, weak,
        skipped["no_mention"], skipped["exculpatory"], skipped["duplicate"],
    )
    return findings
