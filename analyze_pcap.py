#!/usr/bin/env python3
"""pcap dosyasından üç tür şüpheli davranışı tespit eder ve IOC listesi üretir.

  PORT_SCAN    : Tek kaynağın kısa sürede çok sayıda farklı porta SYN göndermesi
  ARP_SPOOFING : Aynı IP adresinin birden fazla MAC adresiyle görülmesi
  DNS_TUNNEL   : Çok uzun veya yüksek entropili DNS alt alan adları
"""
import argparse
import json
import math
import sys
from collections import defaultdict

from scapy.all import ARP, DNSQR, IP, TCP, rdpcap


def entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in freq.values())


def detect_port_scan(pkts, min_ports=20, window=10.0):
    syns = defaultdict(list)  # (src, dst) -> [(zaman, port)]
    for p in pkts:
        if p.haslayer(IP) and p.haslayer(TCP):
            f = int(p[TCP].flags)
            if f & 0x02 and not f & 0x10:  # SYN var, ACK yok
                syns[(p[IP].src, p[IP].dst)].append((float(p.time), p[TCP].dport))
    out = []
    for (src, dst), items in syns.items():
        items.sort()
        lo = 0
        best = set()
        for hi in range(len(items)):
            while items[hi][0] - items[lo][0] > window:
                lo += 1
            cur = {pt for _, pt in items[lo:hi + 1]}
            if len(cur) > len(best):
                best = cur
        if len(best) >= min_ports:
            out.append({"rule": "PORT_SCAN", "src": src, "dst": dst,
                        "distinct_ports": len(best),
                        "sample_ports": sorted(best)[:10]})
    return out


def detect_arp_spoof(pkts):
    ip_macs = defaultdict(set)
    for p in pkts:
        if p.haslayer(ARP) and p[ARP].op == 2:  # is-at (yanıt)
            ip_macs[p[ARP].psrc].add(p[ARP].hwsrc.lower())
    return [{"rule": "ARP_SPOOFING", "ip": ip, "macs": sorted(macs)}
            for ip, macs in ip_macs.items() if len(macs) > 1]


def detect_dns_tunnel(pkts, min_label=30, min_entropy=3.5):
    found = {}
    for p in pkts:
        if p.haslayer(DNSQR) and p.haslayer(IP):
            name = p[DNSQR].qname.decode(errors="replace").rstrip(".")
            first = name.split(".")[0]
            if len(first) >= min_label and entropy(first) >= min_entropy:
                dom = ".".join(name.split(".")[-3:])
                rec = found.setdefault((p[IP].src, dom), {"rule": "DNS_TUNNEL", "src": p[IP].src,
                                                          "domain": dom, "queries": 0,
                                                          "example": name})
                rec["queries"] += 1
    return list(found.values())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--min-ports", type=int, default=20)
    ap.add_argument("--json", metavar="DOSYA")
    a = ap.parse_args(argv)

    pkts = rdpcap(a.pcap)
    findings = detect_port_scan(pkts, a.min_ports) + detect_arp_spoof(pkts) + detect_dns_tunnel(pkts)
    print(f"{len(pkts)} paket incelendi, {len(findings)} bulgu.\n")
    for f in findings:
        if f["rule"] == "PORT_SCAN":
            print(f"[PORT_SCAN]    {f['src']} -> {f['dst']}  {f['distinct_ports']} farklı port, örnek: {f['sample_ports']}")
        elif f["rule"] == "ARP_SPOOFING":
            print(f"[ARP_SPOOFING] {f['ip']} birden fazla MAC ile görüldü: {f['macs']}")
        else:
            print(f"[DNS_TUNNEL]   {f['src']} -> *.{f['domain']}  {f['queries']} sorgu, örnek: {f['example'][:60]}...")
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(findings, fh, indent=2)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
