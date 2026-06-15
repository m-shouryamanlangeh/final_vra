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
  and exculpatory-pattern filtering.
- **Scores risk from the media signal** → **LOW / MEDIUM / HIGH** with a
  **PROCEED / CONDITIONAL / REJECT** recommendation.
- **Writes a deterministic, rule-based executive summary** of the findings.
- Renders the result in the ERM dashboard and saves a downloadable PDF.

> The regulatory / sanctions checklist has been removed — this build focuses
> solely on the adverse-media check.

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
  screener.py             Orchestrator: crawls media, scores risk, summarizes
  pdf_report.py           ERM-branded PDF report builder (reportlab)
  checkers/news.py        Adverse-media crawler + severity classifier
  checkers/               base, sanctions, india (retained, no longer invoked)
templates/              ERM frontend (Jinja2), reused from Threat Intel design
  base.html               Shell: sidebar + header + theme + component CSS
  index.html  result.html  history.html
static/erm-logo.svg     ERM brand mark
output/                 Generated reports (JSON + PDF) + history.json
```

## Notes

- It crawls public news sources live, so screening takes ~10–40s and needs
  network access.
- OSINT-based assessment only; does not replace legal or credit-bureau data.
  **CONFIDENTIAL — internal use only.**
