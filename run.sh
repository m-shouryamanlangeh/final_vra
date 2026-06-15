#!/bin/bash
# ── ERM – Enterprise Risk Management ──────────────────────────────────────────
#    Adverse Media & KYC/AML Screening Portal (Flask + pure-Python engine)
#    Usage: ./run.sh   →   http://127.0.0.1:8080
set -e
cd "$(dirname "$0")"

# Create venv on first run
if [ ! -d ".venv" ]; then
  echo "Creating virtual environment…"
  python3 -m venv .venv
  source .venv/bin/activate
  pip install --upgrade pip >/dev/null
  pip install -r requirements.txt
else
  source .venv/bin/activate
fi

# macOS / corporate TLS trust
CERT_PATH=$(python3 -c "import certifi; print(certifi.where())" 2>/dev/null || true)
if [ -n "$CERT_PATH" ]; then
  export SSL_CERT_FILE="$CERT_PATH"
  export REQUESTS_CA_BUNDLE="$CERT_PATH"
fi

mkdir -p output logs

PORT="${PORT:-8080}"
echo "────────────────────────────────────────────────"
echo "  🛡️  ERM – Enterprise Risk Management"
echo "  Adverse Media & KYC/AML Screening"
echo "  http://127.0.0.1:${PORT}"
echo "────────────────────────────────────────────────"

( sleep 2 && open "http://127.0.0.1:${PORT}" >/dev/null 2>&1 ) &

PORT="$PORT" python app.py
