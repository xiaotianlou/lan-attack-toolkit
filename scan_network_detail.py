from scapy.all import ARP, Ether, srp, IP, TCP, sr1
from mac_vendor_lookup import MacLookup
import socket

NETWORK = "192.168.2.0/24"
COMMON_PORTS = [80, 443, 22, 23, 53, 8080, 554, 5353, 62078]
PORT_NAMES = {
    22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP",
    443: "HTTPS", 554: "RTSP(Camera)", 5353: "mDNS",
    8080: "HTTP-Alt", 62078: "iDevice"
}

mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()
except:
    pass

print(f"Scanning {NETWORK} ...\n")

ans, _ = srp(
    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=NETWORK),
    timeout=3, verbose=False
)

devices = []
for sent, received in ans:
    ip = received.psrc
    mac = received.hwsrc
    try:
        vendor = mac_lookup.lookup(mac)
    except:
        vendor = "Unknown"
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        hostname = "-"
    devices.append((ip, mac, vendor, hostname))

devices.sort(key=lambda x: list(map(int, x[0].split("."))))

print("=" * 70)
for ip, mac, vendor, hostname in devices:
    print(f"IP:       {ip}")
    print(f"MAC:      {mac}")
    print(f"Vendor:   {vendor}")
    print(f"Hostname: {hostname}")

    open_ports = []
    for port in COMMON_PORTS:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=0.5, verbose=False)
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
            name = PORT_NAMES.get(port, str(port))
            open_ports.append(f"{port}({name})")

    if open_ports:
        print(f"Ports:    {', '.join(open_ports)}")
    else:
        print(f"Ports:    No common ports open")
    print("-" * 70)

print(f"\nTotal: {len(devices)} devices found.")
