# DDoS Attack Testing Tools

**FOR AUTHORIZED LAB/EDUCATIONAL USE ONLY**

These tools are designed for testing DDoS Shield in a controlled lab environment.
**Never use these against systems you don't own or have explicit authorization to test.**

## Prerequisites

```bash
pip install scapy
```

All tools except `slowloris.py` require **root/sudo** for raw packet crafting.

## Tools

### 1. SYN Flood (`syn_flood.py`)

Exploits the TCP three-way handshake by sending SYN packets without completing the handshake.

```bash
# Basic SYN flood to port 80
sudo python3 syn_flood.py 192.168.1.100

# High-rate flood to port 443
sudo python3 syn_flood.py 192.168.1.100 -p 443 -r 1000 -c 50000

# With spoofed source IPs
sudo python3 syn_flood.py 192.168.1.100 --spoof
```

**Detection:** DDoS Shield detects this via `THRESH_SYN_PPS` threshold and z-score anomaly.

### 2. UDP Flood (`udp_flood.py`)

Overwhelms the target with UDP datagrams to random or specific ports.

```bash
# Basic UDP flood (random ports, 1KB payload)
sudo python3 udp_flood.py 192.168.1.100

# High-bandwidth flood (large packets)
sudo python3 udp_flood.py 192.168.1.100 -s 4096 -r 1000

# Target specific port (DNS)
sudo python3 udp_flood.py 192.168.1.100 -p 53 -c 20000
```

**Detection:** DDoS Shield detects this via `THRESH_UDP_PPS` threshold.

### 3. ICMP Flood (`icmp_flood.py`)

Sends massive ICMP Echo Requests (pings) to consume bandwidth in both directions.

```bash
# Basic ping flood
sudo python3 icmp_flood.py 192.168.1.100

# Large payload pings (Ping of Death style)
sudo python3 icmp_flood.py 192.168.1.100 -s 1400 -r 1000
```

**Detection:** DDoS Shield detects this via `THRESH_ICMP_PPS` threshold.

### 4. Slowloris (`slowloris.py`)

Layer 7 attack that holds HTTP connections open with partial requests. Uses minimal bandwidth.

```bash
# Basic Slowloris (200 connections)
python3 slowloris.py 192.168.1.100

# Aggressive (500 connections, faster keep-alive)
python3 slowloris.py 192.168.1.100 -n 500 -t 10

# Target HTTPS
python3 slowloris.py 192.168.1.100 -p 443
```

**Note:** Does NOT require root/sudo.
**Detection:** DDoS Shield detects this via `THRESH_HTTP_PPS` threshold (many TCP connections to port 80/443).

## Lab Setup

### Recommended Architecture

```
┌──────────────┐        ┌──────────────┐
│  Attacker    │        │  Target VM   │
│  Machine     │───────▶│  (victim)    │
│              │  LAN   │              │
└──────────────┘        └──────────┬───┘
                                   │
                        ┌──────────┴───┐
                        │  Host Mac    │
                        │  running     │
                        │  DDoS Shield │
                        │  (monitors   │
                        │   bridge0)   │
                        └──────────────┘
```

### Step-by-Step

1. **Set up a VM** (VirtualBox, UTM, or VMware Fusion) with bridged networking
2. **Start DDoS Shield** on the host Mac:
   ```bash
   sudo ./start.sh
   ```
3. **Open the dashboard** at `http://localhost:5173`
4. **From the attacker machine**, run one of the attack tools:
   ```bash
   sudo python3 syn_flood.py <VM_IP> -r 500
   ```
5. **Watch the dashboard** detect the attack in real-time
6. **Click "Rescue"** in the dashboard to block the attacker

### Recommended Thresholds for Lab

In `.env`, use these sensitive thresholds to detect attacks quickly:

```env
THRESH_SYN_PPS=50
THRESH_UDP_PPS=200
THRESH_ICMP_PPS=100
THRESH_HTTP_PPS=80
ZSCORE_THRESHOLD=2.5
```

## Attack Comparison

| Attack | Layer | Bandwidth | Detection Difficulty | Root Required |
|--------|-------|-----------|---------------------|---------------|
| SYN Flood | L4 | Medium | Easy | Yes |
| UDP Flood | L4 | High | Easy | Yes |
| ICMP Flood | L3 | Medium | Easy | Yes |
| Slowloris | L7 | Very Low | Medium | No |

## Legal Notice

These tools are provided for **educational purposes only**. Unauthorized use against
systems you do not own or have explicit permission to test is **illegal** and may violate
computer fraud laws in your jurisdiction. Always obtain written authorization before
conducting any security testing.
