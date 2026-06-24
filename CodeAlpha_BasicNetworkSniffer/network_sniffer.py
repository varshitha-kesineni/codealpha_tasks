#!/usr/bin/env python3
"""
Basic Network Sniffer using Scapy
Works on Windows, Linux, and macOS.

Requirements:
    pip install scapy

On Windows: also install Npcap from https://npcap.com
            (check "WinPcap API compatibility mode" during install)

Usage:
    python network_sniffer.py          # capture until Ctrl-C
    python network_sniffer.py 20       # capture 20 packets then stop
"""

import sys
import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, Raw


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def separator(char="─", width=60):
    return char * width


def format_payload(data: bytes, max_bytes: int = 64) -> str:
    """Show payload as a hex + ASCII dump."""
    if not data:
        return "    (empty)"
    data = data[:max_bytes]
    lines = []
    for i in range(0, len(data), 16):
        chunk      = data[i:i + 16]
        hex_part   = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {i:04x}  {hex_part:<47}  {ascii_part}")
    if len(data) == max_bytes:
        lines.append("    ... (truncated)")
    return "\n".join(lines)


# ──────────────────────────────────────────────
# Packet handler — called for every captured packet
# ──────────────────────────────────────────────

packet_count = 0

def handle_packet(packet):
    global packet_count
    packet_count += 1
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    print(f"\n{separator()}")
    print(f"  Packet #{packet_count}  |  {ts}")

    # ── Ethernet layer ────────────────────────
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print(f"  [Ethernet]  src={eth.src}  →  dst={eth.dst}")

    # ── IP layer ──────────────────────────────
    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"  [IPv4]      src={ip.src}  →  dst={ip.dst}  |  TTL={ip.ttl}  proto={ip.proto}")

        # ── TCP ───────────────────────────────
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flag_map = {
                "F": "FIN", "S": "SYN", "R": "RST",
                "P": "PSH", "A": "ACK", "U": "URG",
            }
            flags_str = " ".join(
                flag_map[f] for f in flag_map if f in str(tcp.flags)
            ) or "NONE"
            print(f"  [TCP]       src_port={tcp.sport}  →  dst_port={tcp.dport}")
            print(f"              seq={tcp.seq}  ack={tcp.ack}  flags=[{flags_str}]")

        # ── UDP ───────────────────────────────
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print(f"  [UDP]       src_port={udp.sport}  →  dst_port={udp.dport}  len={udp.len}")

        # ── ICMP ──────────────────────────────
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
            type_name  = icmp_types.get(icmp.type, f"type={icmp.type}")
            print(f"  [ICMP]      {type_name}  code={icmp.code}")

    else:
        print("  (Non-IP packet)")

    # ── Payload ───────────────────────────────
    if packet.haslayer(Raw):
        raw_data = bytes(packet[Raw])
        print(f"  [Payload]   {len(raw_data)} bytes:")
        print(format_payload(raw_data))
    else:
        print("  [Payload]   (none)")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 0

    print(separator("═"))
    print("  🔍  Basic Network Sniffer (powered by Scapy)")
    if limit:
        print(f"  Capturing {limit} packets …")
    else:
        print("  Capturing packets … (press Ctrl-C to stop)")
    print(separator("═"))

    try:
        sniff(
            prn=handle_packet,
            count=limit,
            store=False
        )
    except KeyboardInterrupt:
        pass

    print(f"\n{separator('═')}")
    print(f"  Done — {packet_count} packet(s) captured.")
    print(separator("═"))
