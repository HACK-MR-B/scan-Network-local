# scan-Network-local

> A friendly, cross-platform **local network scanner and defensive monitor** with a live "neural map" of your devices.
> Works on **Windows, Linux and macOS**.

Author: [HACK-MR-B](https://github.com/HACK-MR-B)  ·  Repo: `https://github.com/HACK-MR-B/scan-Network-local`

---

## What does it do? (in simple words)

You start the program and it draws your router in the center and every device on your Wi-Fi / LAN around it.
Then it quietly watches the network and tells you:

- **Who is on my network?** Every device with its IP, MAC address, manufacturer, guessed type and operating system.
- **Who is a friend and who is a stranger?** Devices you trust are green, new unknown ones are yellow, dangerous ones are red.
- **Is anyone attacking the network?** It detects ARP spoofing, port scans, rogue DHCP servers, DNS tunnelling and more, and explains the *likely intention* of the attacker.
- **Who is using my internet?** Little triangles travel between the router and each device. **The faster a device uses the internet, the faster (and more numerous) its triangles move.** A ranking panel shows the top consumers and which devices are idle.
- **Is this device real?** It fingerprints the OS (from the packet TTL) and checks it against the manufacturer and device type; only verified devices get their proper icon, otherwise you see a `?`.

> It is a **defensive / monitoring** tool. It does not attack, crack or exploit anything.

---

## Features

| Area | What you get |
|------|--------------|
| Discovery | Active ARP scan of your own subnet (auto-detected), hostname lookup, vendor lookup |
| Trust model | Friendly / Unknown / Hostile, saved whitelist, one-click *Trust all* |
| Detection | ARP spoofing, gateway spoofing, IP conflict, ARP flood, port scan, network sweep, rogue DHCP, DNS tunnelling, traffic spikes, multiple IPs on one MAC, new devices |
| Behaviour | Per-device profile: top ports, recent DNS names, risk score 0-100, likely intent |
| Bandwidth | Triangle speed/count follow real traffic, per-device Idle / Light / Moderate / Heavy level, **TOP USER** badge, ranking panel, sort by bandwidth |
| Identity | OS fingerprint (TTL), genuine-device check, device icons generated as `.ico` |
| UI | Dark map with zoom / pan, search box, alert log, details panel |

---

## Requirements

- **Python 3.9 or newer** (3.10 – 3.12 recommended)
- Administrator / root rights (needed to send and capture raw network packets)
- These Python libraries (all installed automatically from `requirements.txt`):

| Library | Why it is needed |
|---------|------------------|
| `PySide6` | Modern Qt 6 graphical interface |
| `scapy` | ARP scanning, packet sniffing and analysis |
| `mac-vendor-lookup` | Converts a MAC address to the manufacturer name |
| `psutil` | Reads your network adapter settings and traffic counters |
| `Pillow` | Generates the device `.ico` icons |

Extra system requirement per OS:

| OS | Extra requirement |
|----|-------------------|
| Windows | **Npcap** (packet capture driver) |
| Linux | `libxcb-cursor0` (Qt) on Debian/Ubuntu; root privileges |
| macOS | nothing extra (libpcap is built in); root privileges |

---

## Installation

First download the project:

```bash
git clone https://github.com/HACK-MR-B/scan-Network-local.git
cd scan-Network-local
```

(No Git? Click the green **Code** button on GitHub → **Download ZIP**, extract it and open a terminal in that folder.)

### Windows 10 / 11

1. **Install Python** from <https://www.python.org/downloads/>.
   Tick **"Add python.exe to PATH"** on the first screen of the installer.
2. **Install Npcap** from <https://npcap.com/#download>.
   During setup tick **"Install Npcap in WinPcap API-compatible Mode"**.
3. Open **PowerShell as Administrator** (Start → type *PowerShell* → right-click → *Run as administrator*) and go to the project folder:

   ```powershell
   cd C:\path\to\scan-Network-local
   py -m venv venv
   venv\Scripts\python.exe -m pip install --upgrade pip
   venv\Scripts\python.exe -m pip install -r requirements.txt
   ```
4. Run it:

   ```powershell
   venv\Scripts\python.exe scan_network_local.py
   ```

### Linux (Debian / Ubuntu / Kali / Mint)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip libxcb-cursor0
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
sudo ./venv/bin/python scan_network_local.py
```

**Fedora**

```bash
sudo dnf install -y python3 python3-pip xcb-util-cursor
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
sudo ./venv/bin/python scan_network_local.py
```

**Arch / Manjaro**

```bash
sudo pacman -S --needed python python-pip xcb-util-cursor
python -m venv venv
./venv/bin/pip install -r requirements.txt
sudo ./venv/bin/python scan_network_local.py
```

### macOS (Intel and Apple Silicon)

```bash
# 1) Install Python (skip if you already have Python 3.9+)
brew install python
# 2) Install the libraries
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
# 3) Run (root is required for packet capture)
sudo ./venv/bin/python scan_network_local.py
```

If macOS asks for **Local Network** access, allow it for Terminal
(*System Settings → Privacy & Security → Local Network*).

### Install the libraries one by one (any OS)

If you prefer not to use `requirements.txt`:

```bash
pip install PySide6 scapy mac-vendor-lookup psutil Pillow
```

---

## First use (2 minutes)

1. Start the program as Administrator / root.
2. Wait 10-20 seconds while devices appear around the router in the middle.
3. Make sure these are really **your** devices, then press **Trust all**. They turn green and are remembered.
4. From now on any new device shows up in yellow with a *New device* alert, and anything suspicious turns red.
5. Click any device (on the map or in the list) to see its details: identity check, OS, internet usage, top ports, DNS names, detections and the likely intent.

---

## Reading the screen

| What you see | Meaning |
|--------------|---------|
| Green ring / `[OK]` | Friendly - trusted device |
| Yellow ring | Unknown - not trusted yet |
| Red ring with `!` | Hostile - risk score 50 or higher |
| `?` icon / `[?]` | Identity not verified (random MAC, unknown vendor, OS mismatch...) |
| Fast, many triangles | Device is using lots of internet |
| Slow, faint triangle | Device is idle |
| Triangle direction | Towards the device = download, towards the router = upload |
| `Idle / Light / Moderate / Heavy` | Usage level (< 1, < 50, < 500, 500+ KB/s) |
| **TOP USER** | Biggest bandwidth consumer right now |
| Faded device | Not seen for 90 seconds (probably offline) |
| Inner ring → outer ring | Friendly → Unknown → Hostile |

Mouse: scroll to zoom, drag to move the map, click a device to inspect it.
Buttons: **Trust / Untrust**, **Trust all**, **Clear alerts**, **Sort** (status ↔ bandwidth).

---

## What attacks and anomalies does it detect?

| Detection | How it is found | Likely intent shown |
|-----------|-----------------|---------------------|
| ARP spoofing | One IP suddenly answered by a different MAC | Man-in-the-Middle |
| Gateway spoofing | Someone claims the router's IP | Redirect all traffic |
| IP conflict | Two MACs claim the same IP | Misconfiguration or spoofing |
| ARP flood | > 40 ARP packets in 10 s from one MAC | ARP poisoning / disruption |
| Port scan | 15+ different ports probed in 10 s | Reconnaissance before exploiting |
| Network sweep | 12+ different hosts contacted in 10 s | Finding live hosts |
| Rogue DHCP | DHCP offers from a non-router | Forged DNS / gateway |
| DNS tunnelling | Very long names or > 80 queries in 10 s | Data exfiltration / C2 |
| Multiple IPs | One MAC using 4+ IP addresses | Identity spoofing |
| Traffic spike | Rate 6× above that device's normal | Big transfer / leak |
| New device | MAC not in your trusted list | Unverified newcomer |

Every alert is also appended to `alerts.log`.

---

## Where are my files?

Everything the program saves lives in **one folder in your home directory**:

| OS | Path |
|----|------|
| Windows | `C:\Users\<you>\.scan-network-local\` |
| Linux | `~/.scan-network-local/` (note: `/root/...` when started with `sudo`) |
| macOS | `~/.scan-network-local/` (note: `/var/root/...` when started with `sudo`) |

Contents: `trusted.json` (your whitelist), `alerts.log`, and `icons/` (generated `.ico` + `.png` icons).
Delete the folder to reset the program.

---

## Tuning

Open `scan_network_local.py` and edit the constants near the top:

```python
SCAN_PERIOD = 10                  # seconds between ARP scans
TH_PORTSCAN, TH_SWEEP = 15, 12    # port-scan / sweep thresholds
TH_ARP_FLOOD = 40                 # ARP packets per 10 s
MAX_FLOW_KBS = 12500              # traffic (KB/s) that gives maximum triangle speed
LEVELS = ((1, "Idle"), (50, "Light"), (500, "Moderate"))   # usage levels
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| **Windows:** "Packet capture failed" / no devices | Install **Npcap** (WinPcap-compatible mode) and run PowerShell **as Administrator** |
| **Windows:** `py` not found | Reinstall Python and tick *Add to PATH*, or use `python` instead of `py` |
| **Linux:** `Could not load the Qt platform plugin "xcb"` | `sudo apt install libxcb-cursor0` (Fedora/Arch: `xcb-util-cursor`) |
| **Linux (Wayland):** window does not open with `sudo` | `sudo env DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY QT_QPA_PLATFORM=xcb ./venv/bin/python scan_network_local.py` |
| **Linux:** `Operation not permitted` | You forgot `sudo` |
| **macOS:** nothing is discovered | Allow *Local Network* for Terminal and run with `sudo` |
| No device icons / `[icons] ... pip install pillow` | `pip install Pillow` |
| Vendor shows `Unknown` | First run needs internet once for the vendor list; many phones also use random MACs |
| Only a few devices send traffic | See *Limitations* below |
| Wrong network is scanned | Disconnect VPNs / virtual adapters, then restart |

---

## Limitations (please read)

- **Bandwidth and attack detection only see packets that reach the computer running the program.**
  On a normal switched/Wi-Fi network that means broadcast traffic plus your own traffic.
  For a complete picture run it on the **router/gateway**, or on a port set to **mirroring (SPAN)**.
- "Internet usage" means traffic exchanged with the gateway; device-to-device traffic is not counted.
- OS fingerprinting uses the packet **TTL** (64 = Linux/Android/iOS/macOS, 128 = Windows, 255 = network gear). It is a strong hint, not proof, and can be forged.
- Phones with *private/random MAC* will appear as **unverified** even when they are yours.
- Detections are rule-based and can produce false alarms (for example when DHCP re-assigns an IP). Tune the thresholds for your network.
- Wi-Fi deauthentication attacks need monitor mode and are not covered.

---

## Responsible use

Use this tool **only on networks you own or have written permission to monitor.**
Monitoring other people's networks without authorisation may be illegal in your country.
The author accepts no responsibility for misuse.

---

## Project structure

```
scan-Network-local/
├── scan_network_local.py   # the whole application
├── requirements.txt        # Python libraries
├── README.md               # this file
├── LICENSE                 # MIT
└── .gitignore
```

## Contributing

Issues and pull requests are welcome at <https://github.com/HACK-MR-B/scan-Network-local>.
Ideas: IPv6 support, CSV/JSON export, per-device history charts, desktop notifications, packaging with PyInstaller.

## License

[MIT](LICENSE) © 2026 HACK-MR-B

---

## ملخص سريع بالعربية

**scan-Network-local** برنامج يعرض شبكتك المحلية على شكل خريطة حيّة: الراوتر في المنتصف وحوله الأجهزة.
يعرف الجهاز الصديق (أخضر) من الغريب (أصفر) والخطِر (أحمر)، ويكشف هجمات الشبكة مثل انتحال ARP ومسح المنافذ، ويشرح نية المهاجم المحتملة.
المثلثات التي تتحرك بين الراوتر والجهاز **تسرع كلما زاد استهلاك الجهاز للإنترنت وتبطؤ إذا كان خاملاً**، وتوجد قائمة بأكثر الأجهزة استهلاكاً.

**التثبيت السريع**

- **ويندوز:** ثبّت Python (مع Add to PATH) ثم Npcap (وضع WinPcap)، افتح PowerShell كمسؤول ونفّذ:
  `py -m venv venv` ثم `venv\Scripts\python.exe -m pip install -r requirements.txt` ثم `venv\Scripts\python.exe scan_network_local.py`
- **لينكس (Ubuntu/Debian):**
  `sudo apt install python3 python3-venv libxcb-cursor0` ثم `python3 -m venv venv` ثم `./venv/bin/pip install -r requirements.txt` ثم `sudo ./venv/bin/python scan_network_local.py`
- **ماك:** `brew install python` ثم `python3 -m venv venv` ثم `./venv/bin/pip install -r requirements.txt` ثم `sudo ./venv/bin/python scan_network_local.py`

بعد التشغيل اضغط **Trust all** لتوثيق أجهزتك المعروفة.
استخدمه على شبكتك أو بإذن صاحبها فقط.
