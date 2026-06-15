"""
ERM – Enterprise Risk Management
Adverse Media & KYC/AML Screening Portal

Combines:
  • the Threat Intel project's Flask frontend / design language, and
  • the adverse-screen pure-Python screening engine (no API key required).

Run:  ./run.sh   (or)   python app.py
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import re
from pathlib import Path
from urllib.parse import quote_plus

# ── SSL fix for macOS (must happen before any outbound requests) ──────────────
import os as _os
try:
    import truststore as _truststore
    _truststore.inject_into_ssl()
except ImportError:
    pass
try:
    import certifi as _certifi
    _cert = _certifi.where()
    _os.environ.setdefault("SSL_CERT_FILE", _cert)
    _os.environ.setdefault("REQUESTS_CA_BUNDLE", _cert)
except Exception:
    pass

from flask import (
    Flask, render_template, request, jsonify, send_from_directory, abort,
)

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"
LOG_DIR = BASE_DIR / "logs"
HISTORY_FILE = OUTPUT_DIR / "history.json"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("erm.screen")

# Screening engine (pure Python) + PDF builder
from screening.screener import run_screen          # noqa: E402
from screening.pdf_report import build_pdf          # noqa: E402

app = Flask(__name__, template_folder="templates", static_folder="static")

TEAM = "ERM – Enterprise Risk Management"


# ── History store ─────────────────────────────────────────────────────────────
def load_history() -> list[dict]:
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except Exception:
            return []
    return []


def save_history(records: list[dict]) -> None:
    # Atomic write: serialise to a temp file in the same dir, then replace, so a
    # crash or concurrent write can never leave a truncated (unparseable) file
    # that would silently wipe the whole history on the next load.
    tmp = HISTORY_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(records, indent=2, ensure_ascii=False))
    _os.replace(tmp, HISTORY_FILE)


def _safe_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "vendor"


# ── Pages ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    history = load_history()
    high = sum(1 for r in history if str(r.get("risk_level", "")).upper() == "HIGH")
    return render_template(
        "index.html",
        active="screen",
        team=TEAM,
        prefill_name=request.args.get("name", ""),
        prefill_pan=request.args.get("pan", ""),
        total_screened=len(history),
        high_risk=high,
        recent=list(reversed(history))[:5],
    )


@app.route("/history")
def history_page():
    records = load_history()
    return render_template(
        "history.html",
        active="history",
        team=TEAM,
        records=list(reversed(records)),
    )


@app.route("/result")
def result_page():
    pdf = request.args.get("pdf", "")
    vendor = request.args.get("vendor", "")
    pan = request.args.get("pan", "")
    result = {}
    if pdf:
        json_path = OUTPUT_DIR / (Path(pdf).name.replace(".pdf", ".json"))
        if json_path.is_file():
            try:
                result = json.loads(json_path.read_text())
            except (ValueError, OSError) as exc:
                logger.warning("Could not load result JSON %s: %s", json_path.name, exc)
    return render_template(
        "result.html",
        active="screen",
        team=TEAM,
        vendor_name=vendor or result.get("vendor_name", ""),
        vendor_pan=pan or result.get("vendor_pan", ""),
        date_of_search=result.get("date_of_search", ""),
        pdf_url=f"/output/{pdf}" if pdf else "",
        result=result,
    )


# ── API ───────────────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    return jsonify(status="ok", engine="adverse-media", team=TEAM)


@app.route("/api/screen", methods=["POST"])
def screen_vendor():
    payload = request.get_json(silent=True) or {}
    vendor_name = (payload.get("vendor_name") or "").strip()
    if not vendor_name:
        return jsonify(ok=False, error="vendor_name is required"), 400

    req = {
        "vendor_name": vendor_name,
        "vendor_pan":  (payload.get("vendor_pan") or "").strip(),
        "sig1_pan":    (payload.get("sig1_pan") or "").strip(),
        "sig2_pan":    (payload.get("sig2_pan") or "").strip(),
        "sig3_pan":    (payload.get("sig3_pan") or "").strip(),
        "directors":   (payload.get("directors") or "").strip(),
        "promoters":   (payload.get("promoters") or "").strip(),
        "ubo":         (payload.get("ubo") or "").strip(),
    }

    logger.info("Screening requested for '%s'", vendor_name)
    result = run_screen(req)

    slug = _safe_slug(vendor_name)
    date = dt.date.today().strftime("%Y%m%d")
    pdf_name = f"{date}_{slug}.pdf"
    json_name = f"{date}_{slug}.json"

    (OUTPUT_DIR / json_name).write_text(json.dumps(result, indent=2, ensure_ascii=False))
    try:
        build_pdf(result, OUTPUT_DIR / pdf_name)
    except Exception as exc:
        logger.error("PDF build failed: %s", exc)

    es = result.get("executive_summary", {})
    records = load_history()
    records.append({
        "vendor_name":    vendor_name,
        "vendor_pan":     req["vendor_pan"],
        "date_of_search": result.get("date_of_search", date),
        "risk_level":     es.get("risk_level", "?"),
        "recommendation": es.get("recommendation", "?"),
        "risk_score":     es.get("risk_score", 0),
        "pdf_path":       pdf_name,
    })
    save_history(records)

    result_url = (
        f"/result?pdf={pdf_name}"
        f"&vendor={quote_plus(vendor_name)}"
        f"&pan={quote_plus(req['vendor_pan'])}"
    )
    return jsonify(ok=True, result_url=result_url, pdf_url=f"/output/{pdf_name}",
                   risk_level=es.get("risk_level"), recommendation=es.get("recommendation"))


def _delete_output_files(pdf_name: str) -> None:
    """Remove the PDF and its sibling JSON for a screening, if present."""
    pdf_name = Path(pdf_name or "").name
    if not pdf_name:
        return
    for fn in (pdf_name, pdf_name[:-4] + ".json" if pdf_name.endswith(".pdf") else pdf_name + ".json"):
        f = OUTPUT_DIR / Path(fn).name
        try:
            if f.is_file():
                f.unlink()
        except OSError as exc:
            logger.warning("Could not delete %s: %s", f.name, exc)


@app.route("/api/history/delete", methods=["POST"])
def history_delete():
    """Remove a single screening from history (and its generated files)."""
    payload = request.get_json(silent=True) or {}
    pdf_path = Path(payload.get("pdf_path") or "").name
    if not pdf_path:
        return jsonify(ok=False, error="pdf_path is required"), 400

    records = load_history()
    kept = [r for r in records if r.get("pdf_path") != pdf_path]
    removed = len(records) - len(kept)
    if removed:
        save_history(kept)
        _delete_output_files(pdf_path)
        logger.info("Deleted %d history record(s) for %s", removed, pdf_path)
    return jsonify(ok=True, removed=removed)


@app.route("/api/history/clear", methods=["POST"])
def history_clear():
    """Clear the entire screening history (and all generated files)."""
    records = load_history()
    for r in records:
        _delete_output_files(r.get("pdf_path", ""))
    save_history([])
    logger.info("Cleared %d history record(s)", len(records))
    return jsonify(ok=True, removed=len(records))


@app.route("/output/<path:filename>")
def serve_output(filename):
    safe = Path(filename).name
    if not (OUTPUT_DIR / safe).exists():
        abort(404)
    return send_from_directory(OUTPUT_DIR, safe)


if __name__ == "__main__":
    port = int(_os.environ.get("PORT", "8080"))
    print("─" * 52)
    print(f"  🛡️  {TEAM}")
    print("  Adverse Media & KYC/AML Screening Portal")
    print(f"  http://127.0.0.1:{port}")
    print("─" * 52)
    # Debug (Werkzeug interactive debugger + auto-reload) is OFF by default —
    # the debugger allows arbitrary code execution. Opt in with FLASK_DEBUG=1.
    debug = _os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=port, debug=debug)
