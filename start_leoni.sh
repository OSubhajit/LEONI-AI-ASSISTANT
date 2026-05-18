#!/usr/bin/env bash
cd "$(dirname "$0")"
echo "  Starting LEONI backend..."
python3 backend/app.py &
BACKEND_PID=$!
sleep 2
if command -v xdg-open &>/dev/null; then xdg-open http://localhost:5000 &>/dev/null &
elif command -v open &>/dev/null; then open http://localhost:5000; fi
echo "  LEONI running at http://localhost:5000 (Ctrl+C to stop)"
wait $BACKEND_PID
