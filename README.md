# DDoS Shield

Real-time DDoS attack monitoring, detection, and mitigation dashboard built for educational and lab environments.

![Dashboard](docs/screenshots/dashboard.png)

## Features

- **Real-Time Traffic Monitoring** — Live packet-per-second metrics via WebSocket
- **Dual-Layer Attack Detection** — Threshold-based + z-score statistical analysis
- **5 Attack Types** — SYN Flood, UDP Flood, ICMP Flood, HTTP Flood, ARP Spoofing
- **Auto-Mitigation** — Block, rate-limit, or isolate offending MAC addresses
- **Simulation Mode** — Synthetic traffic generator for classroom/demo use (no root required)
- **Educational Content** — Built-in attack encyclopedia explaining each attack type
- **Rescue Panel** — Manual controls to block/unblock/isolate devices
- **Network Topology** — Visual map of active devices and their status

![Alerts](docs/screenshots/alerts.png)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend (React)                      │
│   Dashboard │ Devices │ Alerts │ History │ Topology │ Learn  │
│                          │                                   │
│                    WebSocket + REST                           │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────┐
│                     Backend (FastAPI)                         │
│                                                              │
│  ┌──────────┐   ┌──────────┐   ┌────────────┐               │
│  │ Sniffer  │──▶│ Detector │──▶│ Mitigator  │               │
│  │ (Scapy / │   │ threshold│   │ ebtables / │               │
│  │  Sim)    │   │ + z-score│   │ iptables   │               │
│  └──────────┘   └──────────┘   └────────────┘               │
│       │                                                      │
│       ▼                                                      │
│  ┌──────────┐   ┌──────────────┐   ┌──────────────────┐     │
│  │ SQLite   │   │ WebSocket    │   │ REST API         │     │
│  │ (async)  │   │ Broadcaster  │   │ /api/*           │     │
│  └──────────┘   └──────────────┘   └──────────────────┘     │
└──────────────────────────────────────────────────────────────┘
```

### Detection Pipeline

1. **Capture** — Scapy sniffs raw Ethernet frames (or simulation engine generates synthetic traffic)
2. **Classify** — Each packet is categorized by protocol (SYN, UDP, ICMP, HTTP, ARP) per source MAC
3. **Aggregate** — Per-MAC packets-per-second rates are computed every analysis window (default: 10s)
4. **Detect** — Two detection layers run in parallel:
   - **Threshold**: Fixed PPS limits per protocol (e.g., >100 SYN pps = alert)
   - **Z-Score**: Statistical comparison against network baseline (z > 3.0 = anomaly)
5. **Mitigate** — Auto-block, rate-limit, or isolate (configurable; off by default)
6. **Broadcast** — Results pushed to all connected dashboards via WebSocket

## Tech Stack

| Layer    | Technology                                    |
|----------|-----------------------------------------------|
| Backend  | Python 3.12, FastAPI, SQLAlchemy (async), Scapy |
| Frontend | React 18, Vite, Tailwind CSS, Recharts        |
| Database | SQLite with WAL mode (async via aiosqlite)     |
| Auth     | JWT (python-jose) + bcrypt                     |
| Deploy   | Docker Compose, Nginx reverse proxy            |

## Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repo
git clone https://github.com/your-username/ddos-shield.git
cd ddos-shield

# Copy environment config
cp .env.example .env

# Start everything
docker compose up --build

# Open http://localhost:3000
# Login: admin / ddos-shield-2024
```

### Option 2: Local Development

**Prerequisites:** Python 3.11+, Node.js 18+

```bash
# --- Backend ---
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Start in simulation mode (no root needed)
SIMULATION_MODE=true uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

```bash
# --- Frontend (new terminal) ---
cd frontend
npm install
npm run dev

# Open http://localhost:5173
# Login: admin / ddos-shield-2024
```

### Option 3: Real Packet Capture (Linux, requires root)

```bash
cd backend
sudo SIMULATION_MODE=false SNIFFER_INTERFACE=eth0 \
  .venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
```

## Screenshots

> Replace these placeholders with actual screenshots of your deployment.

| View | Description |
|------|-------------|
| ![Dashboard](docs/screenshots/dashboard.png) | Main dashboard with live traffic chart and stats |
| ![Alerts](docs/screenshots/alerts.png) | Real-time attack alerts with severity badges |
| ![Devices](docs/screenshots/devices.png) | Network devices table with live PPS data |
| ![History](docs/screenshots/history.png) | Paginated attack log with search and filters |
| ![Topology](docs/screenshots/topology.png) | Visual network map of active devices |
| ![Learn](docs/screenshots/learn.png) | Attack encyclopedia with detailed explanations |
| ![Rescue](docs/screenshots/rescue.png) | Manual mitigation controls |

## Configuration

All settings are controlled via environment variables. See [`.env.example`](.env.example) for the full reference.

### Key Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SIMULATION_MODE` | `true` | Enable synthetic traffic (no root needed) |
| `SIM_DEVICE_COUNT` | `8` | Number of simulated devices |
| `SIM_ATTACK_PROB` | `0.15` | Probability of attack per tick |
| `AUTO_BLOCK` | `false` | Enable automatic MAC blocking |
| `THRESH_SYN_PPS` | `100` | SYN flood threshold (pps) |
| `ZSCORE_THRESHOLD` | `3.0` | Z-score anomaly threshold |
| `JWT_SECRET` | `change-me-in-production` | JWT signing secret |
| `DEFAULT_USER` | `admin` | Default login username |
| `DEFAULT_PASS` | `ddos-shield-2024` | Default login password |

## API Reference

The backend exposes a REST API at `/api/*` and a WebSocket at `/ws`.

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/login` | No | Authenticate and get JWT |
| GET | `/api/status` | No | System status overview |
| GET | `/api/devices` | No | List all network devices |
| GET | `/api/devices/{mac}` | No | Get device details |
| GET | `/api/traffic` | No | Live traffic counters |
| GET | `/api/attacks` | No | Query attack logs (paginated) |
| GET | `/api/attacks/stats` | No | Aggregated attack stats |
| POST | `/api/mitigate/block` | Yes | Block a MAC address |
| POST | `/api/mitigate/unblock` | Yes | Unblock a MAC address |
| POST | `/api/mitigate/rate-limit` | Yes | Rate-limit a MAC |
| POST | `/api/mitigate/isolate` | Yes | Fully isolate a MAC |
| GET | `/api/blocked` | No | List blocked MACs |
| GET | `/api/interfaces` | No | Detected network interfaces |
| GET | `/api/educational` | No | List attack types |
| GET | `/api/educational/{type}` | No | Detailed attack explanation |
| WS | `/ws` | No | Real-time traffic + alert stream |

### WebSocket Message Format

```json
{
  "type": "update",
  "timestamp": "2026-03-18T12:00:00Z",
  "traffic": [
    { "mac_address": "AA:BB:CC:00:11:22", "syn_pps": 5.2, "udp_pps": 12.0, "total_pps": 25.4 }
  ],
  "alerts": [
    { "mac_address": "AA:BB:CC:00:33:44", "attack_type": "SYN_FLOOD", "severity": "HIGH", "pps": 450.0 }
  ],
  "active_devices": 8,
  "ws_clients": 2
}
```

## Project Structure

```
ddos-shield/
├── backend/
│   ├── main.py              # FastAPI app + API routes + educational content
│   ├── config.py             # Frozen dataclass configuration
│   ├── models.py             # SQLAlchemy ORM models
│   ├── database.py           # Async SQLite setup
│   ├── auth.py               # JWT authentication
│   ├── detector.py           # Dual-layer detection engine
│   ├── sniffer.py            # Packet capture + simulation engine
│   ├── mitigator.py          # MAC blocking / rate-limiting
│   ├── mac_vendor.py         # OUI vendor lookup + VM detection
│   ├── vm_monitor.py         # Network interface detection
│   ├── websocket_manager.py  # WebSocket broadcast manager
│   ├── requirements.txt      # Python dependencies
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.jsx           # Main app routing
│   │   ├── main.jsx          # React entry point
│   │   ├── index.css         # Tailwind + cyber theme
│   │   ├── components/
│   │   │   ├── Dashboard.jsx        # Stats overview + traffic chart
│   │   │   ├── DeviceList.jsx       # Network devices table
│   │   │   ├── AttackAlerts.jsx     # Live alert feed
│   │   │   ├── AttackHistory.jsx    # Paginated attack log
│   │   │   ├── NetworkTopology.jsx  # Visual network map
│   │   │   ├── RescuePanel.jsx      # Manual mitigation controls
│   │   │   ├── EducationalPage.jsx  # Attack encyclopedia
│   │   │   ├── EducationalPopup.jsx # Detailed attack modal
│   │   │   ├── TrafficChart.jsx     # Recharts area chart
│   │   │   ├── LoginPage.jsx        # Authentication UI
│   │   │   └── Sidebar.jsx          # Navigation + status
│   │   ├── hooks/
│   │   │   └── useWebSocket.js      # WebSocket connection hook
│   │   └── utils/
│   │       └── api.js               # Centralized API client
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   ├── nginx.conf            # Production reverse proxy config
│   └── Dockerfile
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

## Educational Use

This project is designed for cybersecurity courses and lab environments. Key educational features:

- **Simulation mode** generates realistic attack traffic without needing real network access
- **Attack encyclopedia** explains each attack type with step-by-step breakdowns
- **Configurable thresholds** let students experiment with detection sensitivity
- **Dual detection** demonstrates both simple (threshold) and advanced (statistical) approaches
- **Code comments** throughout explain networking concepts and design decisions

### Suggested Lab Exercises

1. **Threshold Tuning** — Adjust `THRESH_*` values and observe false positive/negative rates
2. **Z-Score Analysis** — Change `ZSCORE_THRESHOLD` to see how statistical detection compares
3. **Attack Simulation** — Increase `SIM_ATTACK_PROB` to simulate a network under heavy attack
4. **Manual Mitigation** — Use the Rescue Panel to block/unblock devices and observe effects
5. **API Exploration** — Use the Swagger docs at `/docs` to interact with the REST API directly

## License

MIT
