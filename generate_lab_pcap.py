#!/usr/bin/env python3
"""Lab için SENTETİK pcap üretir (ağa paket GÖNDERMEZ, yalnızca dosyaya yazar).

İçerik: normal DNS/HTTP trafiği + TCP SYN port taraması + ARP spoofing + DNS tünelleme
benzeri uzun/rastgele alt alan adı sorguları. Gerçek bir Nmap taramasının pcap'i de
aynı analiz scriptiyle incelenebilir (README'ye bakın).
"""
import random
import string

from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP, PcapWriter

random.seed(7)
OUT = "sample.pcap"
GW_IP, GW_MAC = "10.0.0.1", "aa:bb:cc:00:00:01"
ATT_IP, ATT_MAC = "10.0.0.66", "de:ad:be:ef:00:66"
CLI_IP, CLI_MAC = "10.0.0.15", "aa:bb:cc:00:00:15"
SRV_IP, SRV_MAC = "10.0.0.20", "aa:bb:cc:00:00:20"
DNS_IP = "10.0.0.2"

t = 1790000000.0  # sabit başlangıç zamanı
w = PcapWriter(OUT, sync=True)


def emit(pkt, dt=0.01):
    global t
    t += dt
    pkt.time = t
    w.write(pkt)


# 1) Normal trafik
for name in ["www.example.com", "update.example.org", "mail.example.net"] * 4:
    emit(Ether(src=CLI_MAC, dst=GW_MAC) / IP(src=CLI_IP, dst=DNS_IP) / UDP(sport=random.randint(40000, 60000), dport=53)
         / DNS(rd=1, qd=DNSQR(qname=name)), dt=0.4)
sp = 50100
emit(Ether(src=CLI_MAC, dst=SRV_MAC) / IP(src=CLI_IP, dst=SRV_IP) / TCP(sport=sp, dport=80, flags="S"))
emit(Ether(src=SRV_MAC, dst=CLI_MAC) / IP(src=SRV_IP, dst=CLI_IP) / TCP(sport=80, dport=sp, flags="SA"))
emit(Ether(src=CLI_MAC, dst=SRV_MAC) / IP(src=CLI_IP, dst=SRV_IP) / TCP(sport=sp, dport=80, flags="A"))

# 2) SYN port taraması: 10.0.0.66 -> 10.0.0.20 (sık kullanılan + ardışık portlar)
open_ports = {22, 80, 443}
ports = sorted(set([21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 8080] + list(range(1000, 1060))))
random.shuffle(ports)
t += 5
for p in ports:
    sport = 44444
    emit(Ether(src=ATT_MAC, dst=SRV_MAC) / IP(src=ATT_IP, dst=SRV_IP) / TCP(sport=sport, dport=p, flags="S"), dt=0.005)
    flags = "SA" if p in open_ports else "RA"
    emit(Ether(src=SRV_MAC, dst=ATT_MAC) / IP(src=SRV_IP, dst=ATT_IP) / TCP(sport=p, dport=sport, flags=flags), dt=0.001)

# 3) ARP spoofing: önce meşru yanıt, sonra saldırgan "ağ geçidi benim" der
t += 10
emit(Ether(src=GW_MAC, dst=CLI_MAC) / ARP(op=2, psrc=GW_IP, hwsrc=GW_MAC, pdst=CLI_IP, hwdst=CLI_MAC))
for _ in range(6):
    emit(Ether(src=ATT_MAC, dst=CLI_MAC) / ARP(op=2, psrc=GW_IP, hwsrc=ATT_MAC, pdst=CLI_IP, hwdst=CLI_MAC), dt=2)

# 4) DNS tünelleme benzeri: uzun, rastgele alt alan adları (.example.test sahte alan adı)
t += 8
for _ in range(15):
    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(40, 55)))
    emit(Ether(src=CLI_MAC, dst=GW_MAC) / IP(src=CLI_IP, dst=DNS_IP) / UDP(sport=random.randint(40000, 60000), dport=53)
         / DNS(rd=1, qd=DNSQR(qname=f"{label}.exfil.example.test")), dt=0.3)

w.close()
print("yazıldı:", OUT)
