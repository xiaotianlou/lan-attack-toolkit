from scapy.all import ARP, Ether, srp

NETWORK = "192.168.2.0/24"

print(f"Scanning {NETWORK} ...")
print()

ans, _ = srp(
    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=NETWORK),
    timeout=3,
    verbose=False
)

print(f"{'IP Address':<18}{'MAC Address':<20}")
print("-" * 38)
for sent, received in ans:
    print(f"{received.psrc:<18}{received.hwsrc:<20}")

print(f"\nTotal: {len(ans)} devices found.")
