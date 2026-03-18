#!/usr/bin/env bash
set -e

# DDoS Shield — Start both backend and frontend
# Usage: ./start.sh

export SIMULATION_MODE="${SIMULATION_MODE:-true}"

echo "╔══════════════════════════════════════════╗"
echo "║        DDoS Shield — Starting Up         ║"
echo "║  Simulation Mode: $SIMULATION_MODE                ║"
echo "╚══════════════════════════════════════════╝"
echo ""

cleanup() {
    echo ""
    echo "Shutting down..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    wait $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT INT TERM

# --- Backend ---
echo "[1/2] Starting backend on port 8000..."
cd backend

# Create venv if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "     Creating Python virtual environment..."
    python3 -m venv .venv
fi
source .venv/bin/activate

pip install -r requirements.txt -q
python main.py &
BACKEND_PID=$!
cd ..

# Wait for backend to be ready
echo "     Waiting for backend..."
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8000/api/status > /dev/null 2>&1; then
        echo "     Backend ready!"
        break
    fi
    sleep 1
done

# --- Frontend ---
echo "[2/2] Starting frontend on port 5173..."
cd frontend
npm install --silent
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Backend:  http://localhost:8000         ║"
echo "║  Frontend: http://localhost:5173         ║"
echo "║  Login:    admin / ddos-shield-2024      ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Press Ctrl+C to stop both services."

wait
