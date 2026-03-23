# LAN Attack Toolkit

A collection of Python-based network security tools for **educational use** on your own LAN.

> **WARNING**: Only use these tools on your own devices in your own network. Unauthorized use against others' devices is illegal.

## Tools

| Tool | Description |
|------|-------------|
| `scan_network.py` | Quick ARP scan - discover all devices on your LAN |
| `scan_network_detail.py` | Detailed scan - device vendor, hostname, open ports |
| `arp_spoof.py` | ARP spoofing attack - redirect target's traffic / disconnect from network |

## Requirements

- Python 3.8+
- [Npcap](https://npcap.com/) (Windows) or native support (macOS/Linux)

```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Scan your network

```bash
# Quick scan
python scan_network.py

# Detailed scan (vendor, hostname, open ports)
python scan_network_detail.py
```

### 2. ARP Spoofing

Edit `arp_spoof.py` and set `TARGET_IP` and `GATEWAY_IP`, then:

```bash
python arp_spoof.py
```

Press `Ctrl+C` to stop and auto-restore the target's ARP table.

### How ARP Spoofing Works

```
Normal:
  Phone ARP table: Router IP -> Router MAC
  Phone -> Router -> Internet ✅

During attack:
  Script sends fake ARP: "Router IP is at Attacker's MAC"
  Phone ARP table: Router IP -> Attacker MAC (poisoned!)
  Phone -> Attacker PC (not forwarded) -> No internet ❌

After Ctrl+C:
  Script sends restore ARP: "Router IP is at Router's real MAC"
  Phone ARP table restored -> Internet works again ✅
```

## Platform Notes

| Platform | Extra Setup |
|----------|-------------|
| Windows | Install [Npcap](https://npcap.com/) |
| macOS | No extra setup. Use `sudo` |
| Linux | No extra setup. Use `sudo` |

## Legal Disclaimer

These tools are for **educational purposes only**. Only use them on devices you own, on networks you control. The author is not responsible for any misuse.
