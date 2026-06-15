# ERM – Adverse Media & KYC/AML Screening Portal

**Team: ERM – Enterprise Risk Management**

A combined application that pairs:

- **the Threat Intel project's frontend** — Flask + the Paytm-style "Cyber Watch"
  design language (collapsing sidebar, sticky header, card system, light/dark
  theme toggle), **rebranded to ERM**; and
- **the adverse-screen functioning** — the pure-Python news-crawling engine.
  **No API key required.**

## What it does

Enter a vendor name (and optionally PAN, signatory PANs, directors, promoters,
UBO). The engine:

- **Crawls open-source adverse media** — Google News RSS + DuckDuckGo — and
  classifies each article by severity (HIGH / MEDIUM / LOW) with entity-mention
  and exculpatory-pattern filtering. Each hit carries a **match confidence**:
  **CONFIRMED** (the full company name appears) or **VERIFY** (name-only / partial
  match — surfaced with its evidence snippet, never silently dropped, and never
  allowed to auto-escalate to HIGH on its own). Common-name collisions are
  flagged for human entity-disambiguation rather than guessed at.
- **Screens 19 regulatory / sanctions / court sources** concurrently — OFAC
  SDN, UN & EU consolidated sanctions, ICIJ Offshore Leaks, SEBI, MCA
  Struck-Off, NCLT, IBBI, Indian Kanoon, and more. Sources that need a login
  or aren't machine-readable are returned as **UNVERIFIED** (flagged for manual
  review) rather than guessed at.
- **Scores risk across both signals** → **LOW / MEDIUM / HIGH** with a
  **PROCEED / CONDITIONAL / REJECT** recommendation. A confirmed watchlist HIT
  forces a REJECT.
- **Writes a deterministic, rule-based executive summary** of the findings.
- Renders the result in the ERM dashboard and saves a downloadable PDF.

## Run

```bash
./run.sh                 # creates .venv, installs deps, opens http://127.0.0.1:8080
# or
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py            # http://127.0.0.1:8080  (set PORT to change)
```

## Routes

| Route            | Purpose                                              |
|------------------|------------------------------------------------------|
| `GET /`          | Screening form + recent screenings (dashboard)       |
| `GET /history`   | All past screenings                                  |
| `GET /result`    | Rendered result for a screening (`?pdf=&vendor=&pan=`)|
| `POST /api/screen` | Run a screen → saves JSON + PDF, returns result URL |
| `GET /api/health`  | Health check                                       |
| `GET /output/<file>` | Serves generated JSON/PDF reports               |

## Structure

```
app.py                  Flask app (routes, history store, output serving)
screening/              Screening engine (from adverse-screen)
  screener.py             Orchestrator: media + checklist, scores risk, summarizes
  checklist.py            Runs all list-checkers concurrently (sanctions + regulatory)
  pdf_report.py           ERM-branded PDF report builder (reportlab)
  checkers/news.py        Adverse-media crawler + severity classifier
  checkers/sanctions.py   OFAC SDN, UN & EU consolidated sanctions
  checkers/india.py       SEBI, MCA, NCLT, IBBI, Indian Kanoon, ICIJ, …
  checkers/base.py        Shared HTTP, caching & fuzzy-match helpers
templates/              ERM frontend (Jinja2), reused from Threat Intel design
  base.html               Shell: sidebar + header + theme + component CSS
  index.html  result.html  history.html
static/erm-logo.svg     ERM brand mark
output/                 Generated reports (JSON + PDF) + history.json
```

## Notes

- It queries public news sources and registries live (concurrently), so
  screening takes ~15–45s and needs network access.
- Many official portals (RBI, CIBIL, CBI, Cybercrime, CBDT, Maharashtra GST,
  MCA MLM/Shell) require a login or aren't machine-readable — these are
  reported as **UNVERIFIED / manual check required**, never as a false CLEAR or
  HIT. The freely-accessible sources (OFAC, UN, EU, SEBI, MCA struck-off, NCLT,
  IBBI, Indian Kanoon, ICIJ) are checked automatically.
- **Entity disambiguation is the analyst's call.** Open-source news rarely
  lists a PAN/CIN, so a name match cannot by itself prove it's the same legal
  entity. The tool makes this explicit: anything not a full-name match is shown
  as **VERIFY** with its evidence snippet, and a name-only match never triggers
  an automatic HIGH/REJECT. Always confirm a hit against the vendor's
  PAN / proprietor / address before acting.
- OSINT-based assessment only; does not replace legal or credit-bureau data.
  **CONFIDENTIAL — internal use only.**
