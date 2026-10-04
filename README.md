# Ağ Trafiği Analizi ve Saldırı Tespiti

Bir pcap dosyasındaki trafiği inceleyip üç tipik saldırı davranışını tespit eden araç ve
bu davranışların Wireshark'ta nasıl görüldüğünü anlatan analiz notları.

**Teknolojiler:** Python 3, Scapy, Wireshark, Nmap, TCP/IP

## Tespit Edilen Davranışlar

| Kural | Mantık | MITRE ATT&CK |
|---|---|---|
| `PORT_SCAN` | Tek kaynağın 10 sn içinde 20+ farklı porta SYN (ACK'siz) göndermesi | T1046 Network Service Discovery |
| `ARP_SPOOFING` | Aynı IP'nin birden fazla MAC adresiyle ARP yanıtı vermesi | T1557.002 ARP Cache Poisoning |
| `DNS_TUNNEL` | Çok uzun (30+ karakter) ve yüksek entropili DNS alt alan adları | T1071.004 DNS (C2 / veri sızdırma) |

## Kullanım

```bash
pip install scapy pytest

# Sentetik lab pcap'i üret (ağa paket göndermez)
python3 generate_lab_pcap.py

# Analiz
python3 analyze_pcap.py sample.pcap --json findings.json

# Testler
python3 -m pytest -q tests
```

### Örnek çıktı

```
183 paket incelendi, 3 bulgu.

[PORT_SCAN]    10.0.0.66 -> 10.0.0.20  73 farklı port, örnek: [21, 22, 23, 25, 53, 80, 110, 139, 443, 445]
[ARP_SPOOFING] 10.0.0.1 birden fazla MAC ile görüldü: ['aa:bb:cc:00:00:01', 'de:ad:be:ef:00:66']
[DNS_TUNNEL]   10.0.0.15 -> *.exfil.example.test  15 sorgu, örnek: by1u5lzvuq48rxczx93knyaqgec1eio5cqt535kom58fgiirvjapn...
```

## IOC Çıktısı

| Tür | Değer | Açıklama |
|---|---|---|
| IP | 10.0.0.66 | Port tarayan ve ağ geçidi adına ARP yanıtı veren kaynak |
| MAC | de:ad:be:ef:00:66 | 10.0.0.1 adresini sahiplenen MAC |
| Alan adı | *.exfil.example.test | DNS tünelleme şüpheli alan adı |

## Kendi Lab Ortamında Gerçek Trafikle Çalışma

`sample.pcap` sentetiktir. Gerçek trafikle denemek için **yalnızca kendi sanal makinelerinizde**
(örneğin iki VM, host-only ağ) şunu yapın:

```bash
# Saldırgan VM'den hedef VM'ye SYN taraması (yalnızca KENDİ lab makineniz!)
sudo nmap -sS -p 1-1024 <hedef-vm-ip>

# Hedef tarafta ya da Wireshark ile yakalama sonrası dosyayı kaydedin: nmap_scan.pcapng
python3 analyze_pcap.py nmap_scan.pcapng
```

İzinsiz olarak başkalarının sistemlerini taramak yasa dışıdır.

## Wireshark Analiz Notları

Kullanışlı görüntüleme filtreleri:

```
# SYN taraması: yalnızca SYN içeren, ACK içermeyen paketler
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Kapalı portlara RST+ACK yanıtları (tarama izi)
tcp.flags.reset == 1

# Tek kaynağın taramasını izole et
ip.src == 10.0.0.66 && tcp.flags.syn == 1 && tcp.flags.ack == 0

# ARP yanıtları ve çakışma uyarısı
arp.opcode == 2
arp.duplicate-address-detected

# Uzun DNS sorguları
dns.qry.name.len > 40
```

Yararlı menüler: **Statistics > Conversations** (en çok bağlantı kuran IP), **Statistics > Endpoints**,
**Analyze > Expert Information** (ARP çakışması gibi uyarılar).

## Sınırlar

- Port taramada yavaş (düşük hızlı) taramalar 10 sn pencerenin dışında kalabilir; `--min-ports` ve pencere ayarlanabilir.
- Entropi eşiği meşru CDN/analitik alan adlarında yanlış pozitif üretebilir; bulgular analist doğrulaması gerektirir.
- ARP kuralı DHCP/yük dengeleyici gibi meşru MAC değişimlerinde alarm verebilir.
