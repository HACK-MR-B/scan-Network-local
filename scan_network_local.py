# -*- coding: utf-8 -*-
"""
scan-Network-local - defensive LAN monitor (PySide6 + scapy)
============================================================
Works on Windows, Linux and macOS (Python 3.9+).
Features
  * ARP discovery, passive packet analysis, attack / anomaly detection
  * Friendly / Unknown / Hostile classification with identity verification
  * Per-device internet bandwidth: animated triangles move faster for devices
    that move more data, and a ranking shows who consumes the connection.

Install : pip install -r requirements.txt   (Windows also needs Npcap)
Run     : Windows -> terminal "as Administrator";  Linux/macOS -> sudo
Use only on networks you own or are authorised to monitor.
"""
import os, re, sys, json, math, time, socket, random, ipaddress, subprocess
from collections import defaultdict, deque, Counter
from pathlib import Path

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QListWidget,
    QListWidgetItem, QLabel, QFrame, QLineEdit, QGraphicsScene, QGraphicsView,
    QGraphicsItem, QGraphicsEllipseItem, QStatusBar, QPushButton, QTextBrowser)
from PySide6.QtCore import (Qt, QThread, Signal, QTimer, QPointF, QRectF,
                            QLineF, QSize)
from PySide6.QtGui import (QColor, QBrush, QPen, QFont, QPolygonF,
                           QRadialGradient, QPainter, QIcon, QPixmap)

try:
    from scapy.all import (ARP, Ether, srp, sniff, IP, TCP, UDP, DNS, DNSQR,
                           DHCP, BOOTP, ICMP, sr1, conf, getmacbyip)
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    print("[!] scapy is not installed - scanning and sniffing are disabled.")
try:
    from mac_vendor_lookup import MacLookup
    _MAC = MacLookup()
except Exception:
    _MAC = None
try:
    import psutil
except ImportError:
    psutil = None

APP_NAME, APP_VERSION = "scan-Network-local", "5.0"
IS_WIN, IS_MAC = sys.platform.startswith("win"), sys.platform == "darwin"
SCAN_PERIOD, OFFLINE_AFTER, ALERT_COOLDOWN = 10, 90, 30
# Per-user data folder (same place on every OS): trusted devices, alert log, icons
DATA_DIR = Path.home() / ".scan-network-local"
try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    DATA_DIR = Path(".")
TRUST_FILE, LOG_FILE = DATA_DIR / "trusted.json", DATA_DIR / "alerts.log"

# Detection thresholds (tune for your network)
TH_PORTSCAN, TH_SWEEP, TH_ARP_FLOOD, TH_MULTI_IP = 15, 12, 40, 4
TH_DNS_RATE, TH_SPIKE_KBS = 80, 300

# Bandwidth model (KB/s). Triangle speed follows a log scale up to MAX_FLOW_KBS.
MAX_FLOW_KBS = 12500            # ~100 Mbit/s = full animation speed
LEVELS = ((1, "Idle"), (50, "Light"), (500, "Moderate"))   # else "Heavy"
TOP_MIN_KBS = 50                # minimum rate to be called "top consumer"

C_BG, C_SIDE, C_ACC = QColor(10, 12, 18), QColor(18, 21, 30), QColor(0, 255, 255)
C_LINE = QColor(80, 90, 120, 150)
STATUS = {"friendly": (QColor(46, 204, 113), "Friendly"),
          "unknown":  (QColor(241, 196, 15), "Unknown"),
          "hostile":  (QColor(231, 76, 60), "Hostile")}
LEVEL_COL = {"Idle": QColor(120, 130, 140), "Light": QColor(0, 190, 190),
             "Moderate": QColor(255, 200, 0), "Heavy": QColor(255, 110, 0)}
SEV_COL = {"critical": "#e74c3c", "high": "#e67e22", "medium": "#f1c40f", "low": "#7f8c8d"}
TYPE_COL = {"router": QColor(155, 89, 182), "phone": QColor(46, 204, 113),
            "laptop": QColor(52, 152, 219), "printer": QColor(241, 196, 15),
            "watch": QColor(230, 126, 34), "iot": QColor(231, 76, 60),
            "unknown": QColor(149, 165, 166)}
# kind: (label, weight, likely intent)
KINDS = {
    "arp_spoof":  ("ARP spoofing", 90, "Trying to intercept another device's traffic (Man-in-the-Middle)"),
    "gw_spoof":   ("Gateway spoofing", 100, "Impersonating the router to relay all network traffic through itself"),
    "rogue_dhcp": ("Rogue DHCP server", 85, "Handing out forged network settings (DNS/gateway) to redirect devices"),
    "port_scan":  ("Port scan", 70, "Probing a target for open services before exploiting a weakness"),
    "net_sweep":  ("Network sweep", 60, "Looking for live hosts and exposed services (reconnaissance)"),
    "arp_flood":  ("ARP flood", 60, "Poisoning ARP tables or disrupting the network"),
    "dns_tunnel": ("Suspected DNS tunnel", 65, "May be exfiltrating data or talking to a C2 server over DNS"),
    "multi_ip":   ("Multiple IPs on one device", 45, "Identity spoofing, or a device acting as a middleman"),
    "traffic_spike": ("Traffic spike", 35, "Unusually large transfer (big download or data leak)"),
    "ip_conflict": ("IP conflict", 80, "Two devices claim one address: misconfiguration or spoofing"),
    "new_device": ("New device", 20, "An unverified device joined the network"),
}
PORTS = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 23: "Telnet",
         445: "SMB", 3389: "RDP", 21: "FTP", 25: "SMTP", 123: "NTP"}


# ================= helpers =================
MAC_RE = re.compile(r"(?<![0-9a-fA-F:-])([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})(?![0-9a-fA-F:-])")


def norm_mac(m):
    """aa-bb-cc-1-2-3 / AA:BB:... -> aa:bb:cc:01:02:03"""
    return ":".join(x.zfill(2) for x in re.split(r"[:-]", m.strip().lower()))


def _run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=4,
                                       text=True, errors="ignore")
    except Exception:
        return ""


def is_admin():
    """True when running as root (Linux/macOS) or Administrator (Windows)."""
    try:
        if IS_WIN:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def parse_gateway(text):
    """Extract the default gateway from `route print` (Windows) / `route -n get default` (macOS)."""
    m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", text) or \
        re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", text)
    return m.group(1) if m else ""


def parse_arp_output(text, ip):
    """Find the MAC of `ip` in `arp -a` output (Windows dashes, macOS short octets, Linux)."""
    pat = re.compile(rf"(?<![\d.]){re.escape(ip)}(?![\d.])")
    for line in text.splitlines():
        if pat.search(line):
            m = MAC_RE.search(line)
            if m:
                return norm_mac(m.group(1))
    return ""


def get_gateway_ip():
    if SCAPY_OK:                      # scapy knows the routing table on every OS
        try:
            gw = conf.route.route("0.0.0.0")[2]
            if gw and gw != "0.0.0.0":
                return gw
        except Exception:
            pass
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    p = line.split()
                    if len(p) >= 3 and p[1] == "00000000" and p[2] != "00000000":
                        return socket.inet_ntoa(bytes.fromhex(p[2])[::-1])
        except OSError:
            pass
    elif IS_MAC:
        gw = parse_gateway(_run(["route", "-n", "get", "default"]))
        if gw:
            return gw
    elif IS_WIN:
        gw = parse_gateway(_run(["route", "print", "-4", "0.0.0.0"]))
        if gw:
            return gw
    return "192.168.1.1"


def get_mac_from_arp(ip):
    if SCAPY_OK:
        try:
            m = getmacbyip(ip)
            if m:
                return norm_mac(m)
        except Exception:
            pass
    mac = parse_arp_output(_run(["arp", "-a"]), ip)
    return mac or "ff:ff:ff:ff:ff:ff"


def get_local_network(gw_ip):
    """CIDR of the LAN that contains the gateway (falls back to a /24)."""
    fallback = ".".join(gw_ip.split(".")[:3]) + ".0/24"
    if not (SCAPY_OK and psutil):
        return fallback
    try:
        local_ip = conf.route.route(gw_ip)[1]
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET and a.address == local_ip and a.netmask:
                    net = ipaddress.ip_network(f"{local_ip}/{a.netmask}", strict=False)
                    if net.prefixlen < 22:          # never scan huge networks
                        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
                    return str(net)
    except Exception:
        pass
    return fallback


def guess_type(vendor, ip, host=""):
    v, h = (vendor or "").lower(), (host or "").lower()
    rules = (("phone", ("apple", "samsung", "xiaomi", "huawei", "oppo", "vivo", "oneplus", "motorola")),
             ("laptop", ("intel", "realtek", "broadcom", "dell", "lenovo", "hp ", "asus", "acer", "micro-star")),
             ("iot", ("espressif", "raspberry", "arduino", "tuya", "sonoff")),
             ("printer", ("canon", "epson", "brother", "xerox", "lexmark")),
             ("watch", ("garmin", "fitbit", "polar")))
    for t, keys in rules:
        if any(k in v for k in keys):
            return t
    if ip.endswith((".1", ".254")):
        return "router"
    return "phone" if ("android" in h or "iphone" in h) else "unknown"


def is_private(ip):
    return ip.startswith(("192.168.", "10.")) or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)


def fmt_rate(kbs):
    if kbs < 0.05:
        return "0 KB/s"
    return f"{kbs / 1024:.1f} MB/s" if kbs >= 1024 else f"{kbs:.1f} KB/s"


def usage_level(kbs):
    for limit, name in LEVELS:
        if kbs < limit:
            return name
    return "Heavy"


def flow_speed(kbs):
    """Triangle progress per animation tick: slow crawl when idle, fast when busy."""
    if kbs < 0.5:
        return 0.0015
    return 0.004 + 0.05 * min(1.0, math.log10(1 + kbs) / math.log10(1 + MAX_FLOW_KBS))


def flow_count(kbs):
    return 1 if kbs < 50 else 2 if kbs < 500 else 3 if kbs < 2000 else 4


# ================= icons / OS fingerprint / identity check =================
ICON_DIR = DATA_DIR / "icons"
ICON_KINDS = ("router", "laptop", "phone", "printer", "watch", "iot", "unknown")
_PM = {}


def _draw_icon(kind):
    from PIL import Image, ImageDraw
    S = 1024
    im = Image.new("RGBA", (S, S), (0, 0, 0, 0)); d = ImageDraw.Draw(im)
    K, W, B = (28, 28, 28, 255), (255, 255, 255, 255), (52, 152, 219, 255)
    if kind == "router":
        d.rounded_rectangle((60, 560, 964, 840), 70, fill=K)
        d.rectangle((470, 300, 540, 570), fill=K)
        for r in (100, 190, 280):
            d.arc((505 - r, 300 - r, 505 + r, 300 + r), 215, 325, fill=B, width=56)
        for x in (190, 300, 410, 520):
            d.rounded_rectangle((x, 672, x + 70, 722), 25, fill=W)
        d.ellipse((840, 650, 900, 710), fill=W)
    elif kind == "laptop":
        d.rounded_rectangle((170, 150, 854, 710), 60, fill=K)
        d.rectangle((240, 220, 784, 640), fill=W)
        d.rounded_rectangle((50, 760, 974, 860), 40, fill=K)
        d.rounded_rectangle((400, 760, 624, 800), 20, fill=W)
    elif kind == "phone":
        d.rounded_rectangle((300, 70, 724, 954), 90, fill=K)
        d.rectangle((350, 190, 674, 800), fill=W)
        d.ellipse((482, 845, 542, 905), fill=W)
    elif kind == "printer":
        d.rectangle((270, 110, 754, 400), fill=K); d.rectangle((320, 160, 704, 400), fill=W)
        d.rounded_rectangle((90, 380, 934, 760), 80, fill=K)
        d.rectangle((270, 640, 754, 930), fill=K); d.rectangle((320, 690, 704, 880), fill=W)
        d.ellipse((780, 470, 850, 540), fill=W)
    elif kind == "watch":
        d.rectangle((380, 60, 644, 300), fill=K); d.rectangle((380, 724, 644, 964), fill=K)
        d.ellipse((220, 220, 804, 804), fill=K); d.ellipse((290, 290, 734, 734), fill=W)
        d.line((512, 512, 512, 380), fill=K, width=44); d.line((512, 512, 620, 512), fill=K, width=44)
    elif kind == "iot":
        for i in range(4):
            o = 360 + i * 100
            d.rectangle((o, 170, o + 40, 330), fill=K); d.rectangle((o, 694, o + 40, 854), fill=K)
            d.rectangle((170, o, 330, o + 40), fill=K); d.rectangle((694, o, 854, o + 40), fill=K)
        d.rounded_rectangle((290, 290, 734, 734), 50, fill=K); d.rectangle((400, 400, 624, 624), fill=W)
    else:
        d.ellipse((120, 120, 904, 904), outline=K, width=60)
        d.arc((390, 270, 634, 500), 180, 450, fill=K, width=60)
        d.line((512, 500, 512, 620), fill=K, width=60)
        d.ellipse((478, 700, 546, 768), fill=K)
    return im.resize((256, 256), Image.LANCZOS)


def ensure_icons():
    """Generate .ico (and .png for HTML) device icons into ./icons on first run."""
    try:
        ICON_DIR.mkdir(exist_ok=True)
        for k in ICON_KINDS:
            ico, png = ICON_DIR / f"{k}.ico", ICON_DIR / f"{k}.png"
            if ico.exists() and png.exists():
                continue
            im = _draw_icon(k)
            im.save(png)
            im.save(ico, format="ICO", sizes=[(s, s) for s in (16, 32, 48, 64, 128, 256)])
    except Exception as e:
        print(f"[icons] {e}  ->  pip install pillow")


def get_pm(kind):
    if kind not in _PM:
        p = ICON_DIR / f"{kind}.png"
        _PM[kind] = QPixmap(str(p)) if p.exists() else None
    return _PM[kind]


def guess_os(vendor, host, ttl):
    v, h = (vendor or "").lower(), (host or "").lower()
    if "iphone" in h or "ipad" in h: return "iOS"
    if "android" in h: return "Android"
    if any(k in h for k in ("macbook", "imac")): return "macOS"
    if "desktop-" in h: return "Windows"
    if ttl > 128: return "Network OS"
    if ttl > 64: return "Windows"
    if ttl > 0: return "iOS/macOS" if "apple" in v else "Linux/Android"
    return "?"


OS_OK = {"laptop": ("Windows", "Linux", "macOS"), "phone": ("Android", "iOS", "Linux"),
         "router": ("Network", "Linux"), "printer": ("Network", "Linux"),
         "iot": ("Linux", "Network"), "watch": ("Linux", "Android", "iOS")}


def verify(d):
    """Is the device / OS genuine? Returns (ok, reasons for doubt)."""
    if d.gateway:
        return True, []
    r = []
    if int(d.mac[:2], 16) & 2:
        r.append("Random/locally-administered MAC (phone privacy feature or spoofing)")
    if not d.vendor or d.vendor == "Unknown":
        r.append("Unknown manufacturer")
    if d.dtype == "unknown":
        r.append("Unknown device type")
    if d.os == "?":
        r.append("OS not fingerprinted (no ICMP reply)")
    elif d.dtype in OS_OK and not any(k in d.os for k in OS_OK[d.dtype]):
        r.append(f"OS {d.os} does not match device type {d.dtype}")
    if d.score >= 50 or any(k in d.flags for k in ("arp_spoof", "gw_spoof", "ip_conflict")):
        r.append("Suspicious behaviour / spoofing detected")
    return not r, r


# ================= threads =================
class ActiveScanner(QThread):
    device_found = Signal(str, str, str, str, int)    # ip, mac, vendor, host, ttl
    error = Signal(str)

    def __init__(self, gw_ip):
        super().__init__()
        self.net = get_local_network(gw_ip)
        self._reported = False
        self._run, self._host = True, {}
        self._ttl, self._tries = {}, defaultdict(int)

    def run(self):
        while self._run and SCAPY_OK:
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.net),
                             timeout=2, verbose=False)
                for _s, r in ans:
                    ip, mac = r.psrc, r.hwsrc.lower()
                    if mac not in self._host:
                        try:
                            vendor = _MAC.lookup(mac) if _MAC else "Unknown"
                        except Exception:
                            vendor = "Unknown"
                        try:
                            host = socket.gethostbyaddr(ip)[0]
                        except Exception:
                            host = "-"
                        self._host[mac] = (vendor, host)
                    v, h = self._host[mac]
                    if not self._ttl.get(mac) and self._tries[mac] < 3:
                        self._tries[mac] += 1
                        try:   # TTL hints at the OS family: 64 Linux/Android/iOS, 128 Windows, 255 network gear
                            rp = sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=False)
                            self._ttl[mac] = int(rp[IP].ttl) if rp else 0
                        except Exception:
                            self._ttl[mac] = 0
                    self.device_found.emit(ip, mac, v, h, self._ttl.get(mac, 0))
            except Exception as e:
                print(f"[scanner] {e}")
                if not self._reported:
                    self._reported = True
                    self.error.emit(f"ARP scan failed: {e}")
            for _ in range(SCAN_PERIOD * 10):
                if not self._run:
                    break
                time.sleep(0.1)

    def stop(self):
        self._run = False
        self.wait(3000)


class Analyzer(QThread):
    """Sniffs packets, measures per-device internet usage and detects anomalies."""
    alert = Signal(str, str, str, str, str)   # severity, mac, ip, kind, text
    profiles = Signal(dict)
    flash = Signal(str)
    error = Signal(str)

    def __init__(self, gw_ip, gw_mac):
        super().__init__()
        self._reported = False
        self.gw_ip, self.gw_mac = gw_ip, gw_mac
        self.ip_mac = {}
        self.mac_ips = defaultdict(set)
        self.arp_t = defaultdict(deque)
        self.syn = defaultdict(deque)
        self.dns_t = defaultdict(deque)
        self.up, self.down = defaultdict(int), defaultdict(int)   # bytes to / from the gateway
        self.last_up, self.last_down = defaultdict(int), defaultdict(int)
        self.pkts, self.base = defaultdict(int), defaultdict(float)
        self.ports = defaultdict(Counter)
        self.ttl = {}
        self.names = defaultdict(lambda: deque(maxlen=6))
        self._run = True

    def run(self):
        if not SCAPY_OK:
            return
        while self._run:
            try:
                sniff(prn=self._handle, store=0, timeout=2)
            except Exception as e:
                print(f"[analyzer] {e}")
                if not self._reported:
                    self._reported = True
                    self.error.emit(f"Packet capture failed: {e}")
                time.sleep(2)
            self._report()

    @staticmethod
    def _prune(dq, now, win=10):
        while dq and (now - (dq[0][0] if isinstance(dq[0], tuple) else dq[0])) > win:
            dq.popleft()

    def _handle(self, pkt):
        try:
            if Ether not in pkt:
                return
            now = time.time()
            src, dst, n = pkt[Ether].src.lower(), pkt[Ether].dst.lower(), len(pkt)
            self.pkts[src] += 1
            # Internet usage = traffic exchanged with the gateway
            if dst == self.gw_mac:
                self.up[src] += n
            elif src == self.gw_mac and not (int(dst[:2], 16) & 1):
                self.down[dst] += n
            if ARP in pkt:
                self._arp(pkt[ARP], now)
            elif IP in pkt:
                self._ip(pkt, src, now)
        except Exception:
            pass

    def _arp(self, a, now):
        ip, mac = a.psrc, a.hwsrc.lower()
        if ip == "0.0.0.0":
            return
        known = self.ip_mac.get(ip)
        if known is None:
            self.ip_mac[ip] = mac
        elif known != mac:
            if ip == self.gw_ip:
                self.alert.emit("critical", mac, ip, "gw_spoof",
                                f"{mac} claims to be the gateway {ip} (original: {known})")
            else:
                self.alert.emit("critical", mac, ip, "arp_spoof",
                                f"{mac} claims {ip}, which belongs to {known}")
        self.mac_ips[mac].add(ip)
        if len(self.mac_ips[mac]) >= TH_MULTI_IP and mac != self.gw_mac:
            self.alert.emit("medium", mac, ip, "multi_ip",
                            f"{mac} is using {len(self.mac_ips[mac])} IP addresses")
        dq = self.arp_t[mac]
        dq.append(now)
        self._prune(dq, now)
        if len(dq) > TH_ARP_FLOOD:
            self.alert.emit("high", mac, ip, "arp_flood",
                            f"{len(dq)} ARP packets in 10 s from {mac}")
        self.flash.emit(mac)

    def _ip(self, pkt, mac, now):
        src, dst = pkt[IP].src, pkt[IP].dst
        if pkt.haslayer(DHCP):
            opts = dict(o for o in pkt[DHCP].options if isinstance(o, tuple))
            if opts.get("message-type") in (2, 5) and mac != self.gw_mac:
                self.alert.emit("critical", mac, src, "rogue_dhcp",
                                f"{mac} sends DHCP offers but is not the gateway")
        if not is_private(src):
            return
        self.ttl[mac] = pkt[IP].ttl
        if TCP in pkt:
            t = pkt[TCP]
            self.ports[mac][t.dport] += 1
            if int(t.flags) & 0x12 == 0x02:      # SYN without ACK
                dq = self.syn[src]
                dq.append((now, dst, t.dport))
                self._prune(dq, now)
                ports, hosts = {p for _, _, p in dq}, {h for _, h, _ in dq}
                if len(ports) >= TH_PORTSCAN and len(hosts) <= 3:
                    self.alert.emit("high", mac, src, "port_scan",
                                    f"{src} probed {len(ports)} ports on {len(hosts)} target(s)")
                elif len(hosts) >= TH_SWEEP:
                    self.alert.emit("high", mac, src, "net_sweep",
                                    f"{src} contacted {len(hosts)} different hosts in 10 s")
        elif UDP in pkt:
            self.ports[mac][pkt[UDP].dport] += 1
            if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                self.names[mac].append(name)
                dq = self.dns_t[mac]
                dq.append(now)
                self._prune(dq, now)
                longest = max((len(l) for l in name.split(".")), default=0)
                if len(dq) > TH_DNS_RATE or longest > 45:
                    self.alert.emit("high", mac, src, "dns_tunnel",
                                    f"Abnormal DNS queries from {src}: {name[:60]}")

    def _report(self):
        out = {}
        for mac in set(self.up) | set(self.down) | set(self.pkts):
            up = (self.up[mac] - self.last_up[mac]) / 2 / 1024
            dn = (self.down[mac] - self.last_down[mac]) / 2 / 1024
            self.last_up[mac], self.last_down[mac] = self.up[mac], self.down[mac]
            total, b = up + dn, self.base[mac]
            if total > TH_SPIKE_KBS and total > 6 * max(b, 1):
                self.alert.emit("low", mac, "", "traffic_spike",
                                f"{mac}: {total:.0f} KB/s versus a usual {b:.0f} KB/s")
            self.base[mac] = 0.8 * b + 0.2 * total
            out[mac] = {"up_kbs": up, "down_kbs": dn,
                        "total_kb": (self.up[mac] + self.down[mac]) / 1024,
                        "pkts": self.pkts[mac], "ttl": self.ttl.get(mac, 0),
                        "ports": self.ports[mac].most_common(5),
                        "dns": list(self.names[mac])}
        self.profiles.emit(out)

    def stop(self):
        self._run = False
        self.wait(4000)


class TrafficMonitor(QThread):
    traffic_updated = Signal(float, float)

    def __init__(self):
        super().__init__()
        self._run = True

    def run(self):
        if not psutil:
            return
        last = psutil.net_io_counters()
        while self._run:
            time.sleep(1)
            cur = psutil.net_io_counters()
            self.traffic_updated.emit((cur.bytes_sent - last.bytes_sent) / 1024,
                                      (cur.bytes_recv - last.bytes_recv) / 1024)
            last = cur

    def stop(self):
        self._run = False
        self.wait(2500)


# ================= graphics =================
class GridBackground(QGraphicsItem):
    def __init__(self, scene):
        super().__init__()
        self._scene, self._off = scene, 0.0
        self.setZValue(-100)

    def tick(self):
        self._off = (self._off + 0.5) % 40
        self.update()

    def boundingRect(self):
        return self._scene.sceneRect()

    def paint(self, p, o, w):
        r = self.boundingRect()
        p.fillRect(r, C_BG)
        p.setPen(QPen(QColor(30, 35, 45), 1))
        x = int(r.left())
        while x < r.right():
            y = int(r.top())
            while y < r.bottom():
                p.drawPoint(QPointF(x + math.sin((x + self._off) * .02) * 1.5,
                                    y + math.cos((y + self._off) * .02) * 1.5))
                y += 40
            x += 40


class DeviceNode(QGraphicsItem):
    def __init__(self, ip, mac, vendor, host, gateway=False):
        super().__init__()
        self.ip, self.mac, self.vendor, self.host = ip, mac, vendor, host
        self.gateway = gateway
        self.dtype = "router" if gateway else guess_type(vendor, ip, host)
        self.radius = 52 if gateway else 26
        self.flags, self.score, self.trusted = Counter(), 0, gateway
        self.profile = {}
        self.ttl, self.os, self.verified, self.reasons = 0, "?", gateway, []
        self.up = self.down = 0.0          # smoothed internet rates (KB/s)
        self.top = False                   # biggest bandwidth consumer
        self.first_seen = self.last_seen = time.time()
        self.current_pos, self.target_pos = QPointF(0, 0), QPointF(0, 0)
        self._pulse = 0.0
        self.setZValue(10)
        self.setFlag(QGraphicsItem.ItemIsSelectable, not gateway)

    @property
    def status(self):
        if self.gateway:
            return "friendly"
        if self.score >= 50:
            return "hostile"
        return "friendly" if self.trusted else "unknown"

    @property
    def rate(self):
        return self.up + self.down

    @property
    def level(self):
        return usage_level(self.rate)

    @property
    def icon_kind(self):
        return "router" if self.gateway else (self.dtype if self.verified else "unknown")

    def recalc(self):
        ws = sorted((KINDS[k][1] for k in self.flags), reverse=True)
        self.score = min(100, int(ws[0] + 0.3 * sum(ws[1:]))) if ws else 0

    def evaluate(self):
        self.os = guess_os(self.vendor, self.host, self.ttl)
        self.verified, self.reasons = verify(self)

    def tick(self):
        self._pulse = (self._pulse + (0.2 if self.status == "hostile" else 0.08)) % (2 * math.pi)
        self.update()

    def boundingRect(self):
        r = self.radius + 48
        return QRectF(-r, -r, 2 * r, 2 * r)

    def paint(self, p, o, w):
        p.setRenderHint(QPainter.Antialiasing)
        col, scol = TYPE_COL.get(self.dtype, TYPE_COL["unknown"]), STATUS[self.status][0]
        gr = self.radius + 12 + math.sin(self._pulse) * 4
        g = QRadialGradient(0, 0, gr)
        g.setColorAt(0, QColor(scol.red(), scol.green(), scol.blue(), 120))
        g.setColorAt(1, QColor(scol.red(), scol.green(), scol.blue(), 0))
        p.setBrush(QBrush(g)); p.setPen(Qt.NoPen)
        p.drawEllipse(QPointF(0, 0), gr, gr)
        b = QRadialGradient(-self.radius * .4, -self.radius * .4, self.radius * 1.6)
        b.setColorAt(0, col.lighter(150)); b.setColorAt(.5, col); b.setColorAt(1, col.darker(190))
        p.setBrush(QBrush(b)); p.setPen(QPen(scol, 3))
        p.drawEllipse(QPointF(0, 0), self.radius, self.radius)
        if self.isSelected():
            p.setBrush(Qt.NoBrush); p.setPen(QPen(Qt.white, 1, Qt.DashLine))
            p.drawEllipse(QPointF(0, 0), self.radius + 6, self.radius + 6)
        pm = get_pm(self.icon_kind)
        if pm:
            s = self.radius * 0.6
            p.setRenderHint(QPainter.SmoothPixmapTransform)
            p.setPen(Qt.NoPen); p.setBrush(QBrush(QColor(245, 245, 245)))
            p.drawEllipse(QPointF(0, 0), self.radius * 0.8, self.radius * 0.8)
            p.drawPixmap(QRectF(-s, -s, 2 * s, 2 * s), pm, QRectF(pm.rect()))
        if self.status == "hostile":
            p.setFont(QFont("Arial", 11, QFont.Bold)); p.setPen(scol)
            p.drawText(QRectF(self.radius - 6, -self.radius - 8, 20, 20), Qt.AlignCenter, "!")
        p.setPen(Qt.white); p.setFont(QFont("Arial", 8, QFont.Bold))
        p.drawText(QRectF(-70, self.radius + 6, 140, 16), Qt.AlignCenter, self.ip)
        if not self.gateway:
            p.setPen(LEVEL_COL[self.level]); p.setFont(QFont("Arial", 7, QFont.Bold))
            p.drawText(QRectF(-70, self.radius + 21, 140, 14), Qt.AlignCenter,
                       f"{self.level} - {fmt_rate(self.rate)}")
            if self.top:
                p.setPen(LEVEL_COL["Heavy"]); p.setFont(QFont("Arial", 8, QFont.Bold))
                p.drawText(QRectF(-40, -self.radius - 22, 80, 14), Qt.AlignCenter, "TOP USER")


class ConnectionLine(QGraphicsItem):
    def __init__(self, a, b):
        super().__init__()
        self.a, self.b, self._glow = a, b, 0.0
        self.setZValue(1)

    def trigger(self):
        self._glow = 1.0

    def tick(self):
        self._glow = max(0.0, self._glow - 0.05)
        self.prepareGeometryChange(); self.update()

    def boundingRect(self):
        return QRectF(self.a.current_pos, self.b.current_pos).normalized().adjusted(-12, -12, 12, 12)

    def paint(self, p, o, w):
        p.setRenderHint(QPainter.Antialiasing)
        ln = QLineF(self.a.current_pos, self.b.current_pos)
        if self._glow > 0:
            p.setPen(QPen(QColor(0, 255, 255, int(255 * self._glow)), 3 + 4 * self._glow))
            p.drawLine(ln)
        lc = LEVEL_COL[self.b.level]
        width = 1.5 + min(4.0, math.log10(1 + self.b.rate))
        if self.b.status == "hostile":
            p.setPen(QPen(QColor(231, 76, 60, 190), width))
        else:
            p.setPen(QPen(QColor(lc.red(), lc.green(), lc.blue(), 110 if self.b.rate >= 1 else 60), width))
        p.drawLine(ln)


class DataFlow(QGraphicsItem):
    """Triangles travelling along a link. Their speed and count follow the
    device's real internet rate; direction follows the dominant direction
    (download = gateway -> device, upload = device -> gateway)."""

    def __init__(self, gw, node):
        super().__init__()
        self.a, self.b = gw, node
        self.t, self.v = random.random(), 0.0015
        self.setZValue(20)

    def tick(self):
        target = flow_speed(self.b.rate)
        self.v += (target - self.v) * 0.12                  # smooth speed changes
        step = self.v if self.b.down >= self.b.up else -self.v
        self.t = (self.t + step) % 1.0
        self.prepareGeometryChange(); self.update()

    def boundingRect(self):
        return QRectF(self.a.current_pos, self.b.current_pos).normalized().adjusted(-14, -14, 14, 14)

    def paint(self, p, o, w):
        p.setRenderHint(QPainter.Antialiasing)
        a, b = self.a.current_pos, self.b.current_pos
        dx, dy = b.x() - a.x(), b.y() - a.y()
        if dx == 0 and dy == 0:
            return
        ang = math.degrees(math.atan2(dy, dx)) + 90
        if self.b.down < self.b.up:
            ang += 180                                       # point towards the gateway
        c = STATUS["hostile"][0] if self.b.status == "hostile" else LEVEL_COL[self.b.level]
        p.setOpacity(0.4 if self.b.rate < 1 else 1.0)
        n = flow_count(self.b.rate)
        size = 5 + min(4.0, math.log10(1 + self.b.rate))
        tri = QPolygonF([QPointF(0, -size), QPointF(size, size), QPointF(-size, size)])
        p.setBrush(QBrush(c)); p.setPen(QPen(c.darker(130), 1))
        for i in range(n):
            t = (self.t + i / n) % 1.0
            p.save()
            p.translate(a.x() + dx * t, a.y() + dy * t)
            p.rotate(ang)
            p.drawPolygon(tri)
            p.restore()


class MapView(QGraphicsView):
    def __init__(self, scene):
        super().__init__(scene)
        self.setRenderHint(QPainter.Antialiasing)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setStyleSheet("border:none;background:transparent;")
        self._cur = 1.0

    def wheelEvent(self, ev):
        f = 1.15 if ev.angleDelta().y() > 0 else 1 / 1.15
        if .1 < self._cur * f < 5:
            self.scale(f, f); self._cur *= f


# ================= main window =================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.resize(1600, 940)
        self.setStyleSheet(f"QMainWindow{{background:{C_BG.name()};}}QWidget{{color:#e0e0e0;font-family:Arial;}}")
        self.gateway_ip = get_gateway_ip()
        self.gateway_mac = get_mac_from_arp(self.gateway_ip)
        self.devices, self.lines, self.flows = {}, {}, {}
        self.ip_owner, self._last, self._sel = {}, {}, None
        self.sort_bw = False
        self.trusted = self._load_trusted()
        self._build_ui()

        self.scanner = ActiveScanner(self.gateway_ip)
        self.scanner.device_found.connect(self._on_device)
        self.analyzer = Analyzer(self.gateway_ip, self.gateway_mac)
        self.analyzer.alert.connect(self._raise)
        self.analyzer.profiles.connect(self._on_profiles)
        self.analyzer.flash.connect(self._flash)
        self.scanner.error.connect(self._on_capture_error)
        self.analyzer.error.connect(self._on_capture_error)
        self.traffic = TrafficMonitor()
        self.traffic.traffic_updated.connect(
            lambda u, d: self.lbl_traffic.setText(f"This host: up {u:.1f} KB/s   down {d:.1f} KB/s"))
        for t in (self.scanner, self.analyzer, self.traffic):
            t.start()

        for iv, fn in ((30, self._tick_all), (2500, self._arrange), (4000, self._housekeep)):
            tm = QTimer(self); tm.timeout.connect(fn); tm.start(iv)

        if not is_admin():
            self.statusBar().showMessage(
                "WARNING: run as Administrator so scanning and sniffing can work" if IS_WIN else
                "WARNING: run with sudo so scanning and sniffing can work", 0)
        elif not self.trusted:
            self.statusBar().showMessage("First run: press 'Trust all' once discovery finishes to whitelist your devices", 0)

    def _on_capture_error(self, msg):
        hint = (" - install Npcap (https://npcap.com, WinPcap-compatible mode) and run as Administrator"
                if IS_WIN else " - run with sudo (root) and make sure libpcap is available")
        self.statusBar().showMessage(msg + hint, 0)

    # ---- trust store ----
    def _load_trusted(self):
        try:
            with open(TRUST_FILE) as f:
                return set(json.load(f))
        except Exception:
            return set()

    def _save_trusted(self):
        try:
            with open(TRUST_FILE, "w") as f:
                json.dump(sorted(self.trusted), f)
        except OSError:
            pass

    # ---- UI ----
    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QHBoxLayout(central); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)
        self.scene = QGraphicsScene(); self.scene.setSceneRect(-1800, -1800, 3600, 3600)
        self.scene.selectionChanged.connect(self._on_scene_sel)
        self.view = MapView(self.scene); root.addWidget(self.view, 4)
        self.grid = GridBackground(self.scene); self.scene.addItem(self.grid)
        for r in (170, 270, 370):
            e = QGraphicsEllipseItem(-r, -r, 2 * r, 2 * r)
            e.setPen(QPen(QColor(60, 70, 100, 60), 1, Qt.DashLine)); e.setZValue(-50)
            self.scene.addItem(e)
        self.gw = DeviceNode(self.gateway_ip, self.gateway_mac, "Gateway", "Router", True)
        self.scene.addItem(self.gw)

        side = QFrame(); side.setFixedWidth(440)
        side.setStyleSheet(f"""
            QFrame{{background:{C_SIDE.name()};border-left:2px solid #1f2535;}}
            QLabel{{color:{C_ACC.name()};font-weight:bold;}}
            QListWidget,QTextBrowser{{background:{C_BG.name()};border:1px solid #1f2535;border-radius:5px;}}
            QListWidget::item{{padding:4px;border-bottom:1px solid #1a1e2b;}}
            QListWidget::item:selected{{background:#1a2a40;}}
            QLineEdit{{background:{C_BG.name()};border:1px solid #1f2535;border-radius:5px;padding:5px;color:white;}}
            QPushButton{{background:#1f2535;border:1px solid #2a3445;border-radius:5px;padding:6px;color:white;}}
            QPushButton:hover{{background:#2a3445;}}""")
        sl = QVBoxLayout(side); sl.setContentsMargins(12, 12, 12, 12)
        sl.addWidget(QLabel(f"{APP_NAME}", styleSheet="font-size:18px;"))
        sl.addWidget(QLabel(f"Gateway: {self.gateway_ip}  |  {self.gateway_mac}  |  {get_local_network(self.gateway_ip)}",
                            styleSheet="color:#888;font-weight:normal;font-size:11px;"))
        self.lbl_traffic = QLabel("This host: up 0 KB/s   down 0 KB/s")
        self.lbl_traffic.setStyleSheet("color:#888;font-size:11px;")
        sl.addWidget(self.lbl_traffic)
        self.lbl_stats = QLabel(); sl.addWidget(self.lbl_stats)
        self.search = QLineEdit(); self.search.setPlaceholderText("Search: IP / MAC / type / status / level...")
        self.search.textChanged.connect(lambda _: self._refresh_list())
        sl.addWidget(self.search)
        self.list = QListWidget(); self.list.setIconSize(QSize(30, 30))
        self.list.currentItemChanged.connect(self._on_list_sel)
        sl.addWidget(self.list, 3)
        self.lbl_bw = QLabel("Bandwidth ranking"); sl.addWidget(self.lbl_bw)
        self.bw = QListWidget(); self.bw.itemClicked.connect(lambda it: self._select(it.data(Qt.UserRole)))
        sl.addWidget(self.bw, 2)
        self.details = QTextBrowser(); sl.addWidget(self.details, 3)
        sl.addWidget(QLabel("Alerts"))
        self.alerts = QListWidget(); sl.addWidget(self.alerts, 2)
        row = QHBoxLayout()
        for txt, fn in (("Trust / Untrust", self._toggle_trust), ("Trust all", self._trust_all),
                        ("Clear alerts", self.alerts.clear)):
            b = QPushButton(txt); b.clicked.connect(fn); row.addWidget(b)
        self.btn_sort = QPushButton("Sort: Status"); self.btn_sort.clicked.connect(self._toggle_sort)
        row.addWidget(self.btn_sort)
        sl.addLayout(row)
        root.addWidget(side, 1)
        self.setStatusBar(QStatusBar())
        self._update_stats()

    # ---- device handling ----
    def _on_device(self, ip, mac, vendor, host, ttl=0):
        now = time.time()
        if ip == self.gateway_ip:
            self.gateway_mac = self.gw.mac = mac
            self.analyzer.gw_mac = mac
        self.analyzer.ip_mac.setdefault(ip, mac)
        owner = self.ip_owner.get(ip)
        if owner and owner != mac:
            self._raise("critical", mac, ip, "ip_conflict", f"{mac} and {owner} both claim {ip}")
        self.ip_owner.setdefault(ip, mac)
        if mac in self.devices:
            d = self.devices[mac]; d.last_seen = now
            if d.ip != ip:
                d.ip = ip
            if ttl and ttl != d.ttl:
                d.ttl = ttl; d.evaluate()
            return
        if ip == self.gateway_ip:
            return
        d = DeviceNode(ip, mac, vendor, host)
        d.trusted = mac in self.trusted
        d.ttl = ttl; d.evaluate()
        self.devices[mac] = d; self.scene.addItem(d)
        ln = ConnectionLine(self.gw, d); self.lines[mac] = ln; self.scene.addItem(ln)
        fl = DataFlow(self.gw, d); self.flows[mac] = fl; self.scene.addItem(fl)
        if not d.trusted:
            self._raise("low", mac, ip, "new_device", f"New unverified device: {ip} ({vendor})")
        self._arrange(); self._refresh_list()

    def _raise(self, sev, mac, ip, kind, text):
        mac, now = mac.lower(), time.time()
        if now - self._last.get((kind, mac), 0) < ALERT_COOLDOWN:
            return
        self._last[(kind, mac)] = now
        if mac != self.gateway_mac and mac not in self.devices:
            self._on_device(ip or "0.0.0.0", mac, "Unknown", "-")
        d = self.devices.get(mac)
        if d and not (kind == "new_device" and d.trusted):
            d.flags[kind] += 1; d.recalc(); d.evaluate()
        label = KINDS[kind][0]
        it = QListWidgetItem(f"[{time.strftime('%H:%M:%S')}] {label}\n{text}")
        it.setForeground(QColor(SEV_COL[sev])); it.setData(Qt.UserRole, mac)
        self.alerts.insertItem(0, it)
        while self.alerts.count() > 300:
            self.alerts.takeItem(self.alerts.count() - 1)
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%F %T')} [{sev}] {kind} {mac} {text}\n")
        except OSError:
            pass
        if sev in ("critical", "high"):
            self.statusBar().showMessage(f"ALERT {label}: {text}", 8000)
        self._refresh_list()

    def _on_profiles(self, data):
        now = time.time()
        for mac, d in self.devices.items():
            p = data.get(mac)
            if p:
                d.profile = p
                if p.get("ttl") and p["ttl"] != d.ttl:
                    d.ttl = p["ttl"]; d.evaluate()
            up, dn = (p["up_kbs"], p["down_kbs"]) if p else (0.0, 0.0)
            d.up, d.down = 0.5 * d.up + 0.5 * up, 0.5 * d.down + 0.5 * dn   # smoothing
            if d.rate > 0.5:
                d.last_seen = now
        self._update_bandwidth()
        if self._sel:
            self._show(self._sel)

    def _update_bandwidth(self):
        devs = list(self.devices.values())
        total = sum(d.rate for d in devs)
        ranked = sorted(devs, key=lambda d: -d.rate)
        for d in devs:
            d.top = False
        if ranked and ranked[0].rate >= TOP_MIN_KBS:
            ranked[0].top = True
        self.bw.clear()
        for i, d in enumerate(ranked[:8]):
            share = d.rate / total * 100 if total > 0 else 0
            blocks = round(share / 10)
            it = QListWidgetItem(f"{i + 1}. {d.ip}  {'#' * blocks}{'.' * (10 - blocks)} {share:.0f}%\n"
                                 f"     down {fmt_rate(d.down)}  up {fmt_rate(d.up)}  [{d.level}]")
            it.setForeground(LEVEL_COL[d.level]); it.setData(Qt.UserRole, d.mac)
            self.bw.addItem(it)
        idle = sum(1 for d in devs if d.level == "Idle")
        self.lbl_bw.setText(f"Bandwidth ranking  |  down {fmt_rate(sum(d.down for d in devs))}  "
                            f"up {fmt_rate(sum(d.up for d in devs))}  |  active {len(devs) - idle}  idle {idle}")
        if self.sort_bw:
            self._refresh_list()

    def _flash(self, mac):
        if mac in self.lines:
            self.lines[mac].trigger()
            self.devices[mac].last_seen = time.time()

    def _toggle_trust(self):
        d = self.devices.get(self._sel)
        if not d:
            return
        if d.mac in self.trusted:
            self.trusted.discard(d.mac); d.trusted = False
        else:
            self.trusted.add(d.mac); d.trusted = True; d.flags.clear(); d.recalc(); d.evaluate()
        self._save_trusted(); self._arrange(); self._refresh_list(); self._show(d.mac)

    def _trust_all(self):
        for d in self.devices.values():
            if d.score < 50:
                d.trusted = True; self.trusted.add(d.mac)
                d.flags.pop("new_device", None); d.recalc(); d.evaluate()
        self._save_trusted(); self._arrange(); self._refresh_list()
        self.statusBar().showMessage("Non-hostile devices trusted (hostile ones were left untouched)", 5000)

    def _toggle_sort(self):
        self.sort_bw = not self.sort_bw
        self.btn_sort.setText("Sort: Bandwidth" if self.sort_bw else "Sort: Status")
        self._refresh_list()

    # ---- selection / views ----
    def _on_scene_sel(self):
        s = self.scene.selectedItems()
        if s and isinstance(s[0], DeviceNode):
            self._select(s[0].mac, from_scene=True)

    def _on_list_sel(self, cur, _prev):
        if cur:
            self._select(cur.data(Qt.UserRole), from_list=True)

    def _select(self, mac, from_scene=False, from_list=False):
        self._sel = mac
        if not from_scene and mac in self.devices:
            self.scene.blockSignals(True); self.scene.clearSelection()
            self.devices[mac].setSelected(True); self.scene.blockSignals(False)
        if not from_list:
            for i in range(self.list.count()):
                if self.list.item(i).data(Qt.UserRole) == mac:
                    self.list.blockSignals(True); self.list.setCurrentRow(i); self.list.blockSignals(False)
        self._show(mac)

    def _show(self, mac):
        d = self.devices.get(mac)
        if not d:
            return
        col, name = STATUS[d.status]
        p = d.profile
        ports = ", ".join(f"{PORTS.get(pt, pt)} x{c}" for pt, c in p.get("ports", [])) or "-"
        dns = "<br>".join(p.get("dns", [])) or "-"
        total = sum(x.rate for x in self.devices.values())
        share = d.rate / total * 100 if total > 0 else 0
        lc = LEVEL_COL[d.level].name()
        if d.level == "Idle":
            use = "Not consuming internet bandwidth right now."
        else:
            use = f"Consuming bandwidth: {share:.0f}% of all device traffic" + (" (TOP USER)." if d.top else ".")
        if d.flags:
            ks = sorted(d.flags, key=lambda k: -KINDS[k][1])
            det = "".join(f"<li><b>{KINDS[k][0]}</b> x{d.flags[k]} - {KINDS[k][2]}</li>" for k in ks)
            verdict = f"Likely intent: <b style='color:#e74c3c'>{KINDS[ks[0]][2]}</b>"
        else:
            det = "<li>None</li>"
            verdict = ("Normal behaviour." if d.trusted else
                       "Unverified device with no hostile behaviour seen. Review it, then trust it if it is yours.")
        png = ICON_DIR / f"{d.icon_kind}.png"
        img = f'<img src="{png.as_uri()}" width="56" height="56">' if png.exists() else ""
        if d.gateway:
            ident = "<span style='color:#2ecc71'>Gateway (router)</span>"
        elif d.verified:
            ident = "<span style='color:#2ecc71'>Verified: genuine device and OS</span>"
        else:
            ident = ("<span style='color:#f1c40f'>Identity NOT verified:</span><ul>"
                     + "".join(f"<li>{x}</li>" for x in d.reasons) + "</ul>")
        self.details.setHtml(f"""
        {img}<h3 style="color:{col.name()}">{d.ip} - {name} (risk {d.score}/100)</h3>
        {ident}
        MAC: {d.mac}<br>Vendor: {d.vendor}<br>Host: {d.host} | Type: {d.dtype}<br>
        OS: <b>{d.os}</b> (TTL={d.ttl or '-'})<br>
        First seen: {time.strftime('%H:%M:%S', time.localtime(d.first_seen))} |
        Last activity: {time.strftime('%H:%M:%S', time.localtime(d.last_seen))}<br>
        <b style="color:{lc}">Internet: {d.level}</b> - down {fmt_rate(d.down)}, up {fmt_rate(d.up)}
        (total {p.get('total_kb', 0):.0f} KB)<br>{use}<br>
        Top ports: {ports}<br>Recent DNS queries:<br>{dns}
        <p><b>Detections:</b></p><ul>{det}</ul><p>{verdict}</p>""")

    def _refresh_list(self):
        q = self.search.text().lower()
        self.list.blockSignals(True); self.list.clear()
        order = {"hostile": 0, "unknown": 1, "friendly": 2}
        key = (lambda x: (-x.rate, x.ip)) if self.sort_bw else (lambda x: (order[x.status], x.ip))
        for d in sorted(self.devices.values(), key=key):
            col, name = STATUS[d.status]
            text = (f"{'[OK]' if d.verified else '[?]'} {name} | {d.ip} | {d.level} {fmt_rate(d.rate)}\n"
                    f"{d.mac} - {d.vendor} [{d.dtype} / {d.os}]")
            if q and q not in text.lower():
                continue
            it = QListWidgetItem(text); it.setForeground(col); it.setData(Qt.UserRole, d.mac)
            ico = ICON_DIR / f"{d.icon_kind}.ico"
            if ico.exists():
                it.setIcon(QIcon(str(ico)))
            self.list.addItem(it)
            if d.mac == self._sel:
                self.list.setCurrentItem(it)
        self.list.blockSignals(False)
        self._update_stats()

    def _update_stats(self):
        c = Counter(d.status for d in self.devices.values())
        self.lbl_stats.setText(f"Friendly {c['friendly']}   Unknown {c['unknown']}   "
                               f"Hostile {c['hostile']}   |   Total {len(self.devices)}")

    def _housekeep(self):
        now = time.time()
        for d in self.devices.values():
            d.setOpacity(1.0 if now - d.last_seen < OFFLINE_AFTER else 0.35)
        self._refresh_list()

    # ---- layout / animation ----
    def _arrange(self):
        groups = {"friendly": [], "unknown": [], "hostile": []}
        for d in self.devices.values():
            groups[d.status].append(d)
        for ring, key in ((170, "friendly"), (270, "unknown"), (370, "hostile")):
            nodes = sorted(groups[key], key=lambda x: x.mac)
            for i, n in enumerate(nodes):
                a = 2 * math.pi * i / len(nodes) + ring
                n.target_pos = QPointF(ring * math.cos(a), ring * math.sin(a))

    def _tick_all(self):
        self.grid.tick(); self.gw.tick()
        for n in self.devices.values():
            n.tick()
            dx, dy = n.target_pos.x() - n.current_pos.x(), n.target_pos.y() - n.current_pos.y()
            if abs(dx) > .5 or abs(dy) > .5:
                n.current_pos += QPointF(dx * .12, dy * .12); n.setPos(n.current_pos)
        for l in self.lines.values():
            l.tick()
        for f in self.flows.values():
            f.tick()

    def closeEvent(self, ev):
        for t in (self.scanner, self.analyzer, self.traffic):
            t.stop()
        super().closeEvent(ev)


def main():
    app = QApplication(sys.argv)
    ensure_icons()
    app.setWindowIcon(QIcon(str(ICON_DIR / "router.ico")))
    w = MainWindow(); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
