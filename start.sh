#!/usr/bin/env bash
set -e

# DDoS Shield — Start both backend and frontend
# Usage:
#   ./start.sh              # Uses .env settings (defaults to simulation)
#   sudo ./start.sh         # Real mode with packet capture

# Load .env if present
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

export SIMULATION_MODE="${SIMULATION_MODE:-true}"

echo "╔══════════════════════════════════════════════════╗"
echo "║           DDoS Shield — Starting Up              ║"
echo "║  Mode: $([ "$SIMULATION_MODE" = "true" ] && echo "SIMULATION (safe)" || echo "REAL (live capture)")                    ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# --- Permission check for real mode ---
if [ "$SIMULATION_MODE" = "false" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        echo "⚠️  WARNING: Real mode requires root/sudo for packet capture!"
        echo ""
        echo "   Run with:  sudo ./start.sh"
        echo ""
        echo "   Or switch to simulation mode:"
        echo "   Set SIMULATION_MODE=true in .env"
        echo ""
        read -p "Continue anyway? (capture will fail) [y/N] " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Auto-detect and suggest interfaces
    echo "Detecting network interfaces..."
    echo ""

    OS_TYPE="$(uname -s)"
    if [ "$OS_TYPE" = "Darwin" ]; then
        # macOS: look for VM bridge interfaces
        echo "  macOS detected — looking for VM interfaces:"
        echo ""
        for iface in bridge0 bridge1 vmnet0 vmnet1 vmnet8 vboxnet0; do
            if ifconfig "$iface" >/dev/null 2>&1; then
                STATUS=$(ifconfig "$iface" | grep -c "UP" || true)
                if [ "$STATUS" -gt 0 ]; then
                    echo "  ✅ $iface (UP)"
                else
                    echo "  ⬚  $iface (DOWN)"
                fi
            fi
        done
        echo ""

        # Show all active interfaces
        echo "  All active interfaces:"
        ifconfig -l | tr ' ' '\n' | while read -r iface; do
            if ifconfig "$iface" 2>/dev/null | grep -q "status: active"; then
                IP=$(ifconfig "$iface" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
                echo "    $iface${IP:+ ($IP)}"
            fi
        done
        echo ""
    else
        # Linux
        echo "  Linux detected — looking for VM interfaces:"
        echo ""
        for iface in virbr0 docker0 br0 vboxnet0; do
            if [ -d "/sys/class/net/$iface" ]; then
                STATE=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
                echo "  ✅ $iface ($STATE)"
            fi
        done
        echo ""
    fi

    IFACE="${SNIFFER_INTERFACE:-}"
    if [ -n "$IFACE" ]; then
        echo "  Using configured interface: $IFACE"
    else
        echo "  No interface configured — will auto-detect"
    fi
    echo ""
fi

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
echo "╔══════════════════════════════════════════════════╗"
echo "║  Backend:  http://localhost:8000                  ║"
echo "║  Frontend: http://localhost:5173                  ║"
echo "║  Login:    admin / ddos-shield-2024               ║"
echo "║  API Docs: http://localhost:8000/docs              ║"
if [ "$SIMULATION_MODE" = "false" ]; then
echo "║                                                    ║"
echo "║  ⚡ REAL MODE — capturing live packets             ║"
echo "║  Interface: ${SNIFFER_INTERFACE:-auto-detect}                        ║"
fi
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Press Ctrl+C to stop both services."

wait
