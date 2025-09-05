#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf, wrpcap
import argparse
import time

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

def short_hex(b: bytes, n=32) -> str:
    if not b:
        return ""
    h = b[:n].hex(" ")
    return h + (" ..." if len(b) > n else "")

def on_packet(pkt, write_file=None, verbose=False):
    ts = time.strftime("%H:%M:%S")
    line_parts = [f"[{ts}]"]

    if IP in pkt:
        ip = pkt[IP]
        proto_name = PROTO_NAMES.get(ip.proto, str(ip.proto))
        line_parts.append(f"{ip.src} → {ip.dst} | {proto_name}")

        if TCP in pkt:
            t = pkt[TCP]
            line_parts.append(f"TCP {t.sport}→{t.dport} flags={t.flags}")
        elif UDP in pkt:
            u = pkt[UDP]
            line_parts.append(f"UDP {u.sport}→{u.dport}")
        elif ICMP in pkt:
            i = pkt[ICMP]
            line_parts.append(f"ICMP type={i.type} code={i.code}")
    else:
        line_parts.append("Non-IP packet")

    # Payload preview (safe + short)
    payload = b""
    if Raw in pkt:
        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            payload = b""

    if verbose and payload:
        line_parts.append(f"payload[{len(payload)}B]={short_hex(payload)}")

    print(" | ".join(line_parts))

    # Append to pcap if requested
    if write_file:
        wrpcap(write_file, pkt, append=True)

def main():
    p = argparse.ArgumentParser(description="Simple Scapy packet sniffer")
    p.add_argument("-i", "--iface", help="Interface to sniff on (e.g., eth0)")
    p.add_argument("-f", "--filter", default="ip", help="BPF filter (e.g., 'tcp or udp or icmp')")
    p.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    p.add_argument("-w", "--write", help="Write packets to pcap file")
    p.add_argument("-v", "--verbose", action="store_true", help="Show payload preview")
    args = p.parse_args()

    iface = args.iface or conf.iface  # scapy's default
    print(f"Sniffing on: {iface}")
    print(f"Filter: {args.filter}")
    if args.write:
        print(f"Writing to: {args.write}")
        # create/clear file by writing empty list once
        wrpcap(args.write, [])

    try:
        sniff(
            iface=iface,
            filter=args.filter,
            prn=lambda p: on_packet(p, write_file=args.write, verbose=args.verbose),
            store=False,
            count=args.count
        )
    except PermissionError:
        print("Permission denied. Run with sudo or give python CAP_NET_RAW.")
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    main()
