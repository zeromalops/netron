#!/usr/bin/env python3
"""
Netron - Advanced Network Management & Security Dashboard

Install:
    pip install scapy psutil netifaces requests flask flask-socketio python-nmap

Run:
    sudo python3 netron.py        # full features
    python3 netron.py             # limited (no raw capture)

Open http://localhost:5000 in your browser (override with the
NETRON_HOST / NETRON_PORT environment variables).
"""

import functools, os, queue, secrets, shutil, sys, re, time, socket, threading, subprocess, ipaddress
import hashlib, json, logging, math, platform, ssl, statistics, struct
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Root detection (safe on Windows too) ──────────────────────────────────────
IS_ROOT = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

# ── Third-party imports ───────────────────────────────────────────────────────
try:
    import psutil
except ImportError:
    sys.exit("Missing: pip install psutil")
try:
    import netifaces
except ImportError:
    sys.exit("Missing: pip install netifaces")
try:
    from flask import (Flask, render_template_string, jsonify, request, Response,
                       send_from_directory)
    from flask_socketio import SocketIO, emit
except ImportError:
    sys.exit("Missing: pip install flask flask-socketio")
try:
    import nmap
    NMAP_OK = True
except ImportError:
    nmap = None
    NMAP_OK = False
try:
    import requests as _http
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# Scapy – optional, silence all its startup noise before importing
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
logging.getLogger("scapy.loading").setLevel(logging.CRITICAL)
try:
    import scapy.config
    scapy.config.conf.verb = 0          # suppress scapy output
    from scapy.all import (sniff, ARP, Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR,
                           DNSRR, BOOTP, DHCP, Dot1Q, Raw, srp)
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

logging.basicConfig(level=logging.WARNING, format="%(message)s")
log = logging.getLogger("netron")
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("engineio").setLevel(logging.ERROR)
logging.getLogger("socketio").setLevel(logging.ERROR)

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
VERSION        = "3.0.1"
APP_HOST       = os.environ.get("NETRON_HOST", "0.0.0.0")
APP_PORT       = int(os.environ.get("NETRON_PORT", "5000"))
SCAN_INTERVAL  = 15          # seconds between full sweeps (fast for quick detection)
VULN_INTERVAL  = int(os.environ.get("NETRON_VULN_INTERVAL", "60"))
# Full identification (PTR/mDNS/NetBIOS name, banner, OS, vendor API) is the
# expensive part of a scan, so it is refreshed on this slower cadence. Ports
# and vulnerabilities are refreshed by the parallel sweep (VULN_INTERVAL).
ID_INTERVAL    = int(os.environ.get("NETRON_ID_INTERVAL", "300"))
SCAN_WORKERS   = int(os.environ.get("NETRON_SCAN_WORKERS", "24"))   # concurrent deep scans
VULN_WORKERS   = int(os.environ.get("NETRON_VULN_WORKERS", "16"))   # concurrent vuln scans
MAX_PKTS       = 400         # per-device packet log size
PKT_FEED_MAX   = 3000        # global Wireshark-style packet feed size
ANOMALY_THRESH = 50          # SYN packets before flood alert
ARP_GRACE_SECS = 90          # keep a device "online" this long after its last ARP sighting
EMIT_RATE_PPS  = 25          # max live_packet/topo_packet socket events per second
DEVICE_RETENTION_SECS = 3600 # drop devices offline longer than this (memory bound)
SITE_ICONS_ENABLED = os.environ.get("NETRON_SITE_ICONS", "0") == "1"
SPEEDTEST_CACHE_SECS = 60    # reuse a speed-test result for this long

# Shared TCP connect-scan pool. A per-call pool inside the deep-scan pool
# would allow workers × ports threads at once; this caps it globally.
_TCP_POOL = ThreadPoolExecutor(max_workers=96, thread_name_prefix="tcp")
# Shared pool for the fast ARP-cache registration path (reused instead of
# spawning a new pool every 3-second ARP poll).
_ARP_POOL  = ThreadPoolExecutor(max_workers=4, thread_name_prefix="seed")
# Consecutive empty port sweeps per host.  One empty re-scan does not prove a
# host's ports closed (Wi-Fi hosts drop probes while asleep), so the last
# observed ports are kept until three sweeps in a row come back empty.
_VULN_EMPTY: Dict[str, int] = {}
# How long a port that was seen open stays on screen when a later sweep misses
# it (a Wi-Fi host answers unevenly).  After this it is dropped: the UI never
# shows a port as open that nothing has confirmed for this long.
PORT_RETENTION_SECS = int(os.environ.get("NETRON_PORT_RETENTION", "900"))

# ── RustScan (optional port-discovery front end) ──────────────────────────────
# rustscan probes a port range far faster than nmap, then nmap runs -sV on just
# the ports it reported, so service names still come from a real nmap probe.
# Timeout/tries are not tunable-by-default for speed: measured on the live Wi-Fi
# LAN, rustscan's default -t 1500 silently missed open ports (a host that answers
# 22,53,80,9000-9006 came back as [22,53,80] one run and [9004] the next), which
# would have dropped real findings.  -t 3000 --tries 2 returned the full set on
# every run, so those values are fixed here.
RUSTSCAN_BIN      = os.environ.get("NETRON_RUSTSCAN_BIN") or shutil.which("rustscan") or ""
RUSTSCAN_OK       = bool(RUSTSCAN_BIN)
RUSTSCAN_BATCH    = "4500"
RUSTSCAN_TIMEOUT  = "3000"      # ms, per probe
RUSTSCAN_TRIES    = "2"
# Extra range probed on top of SCAN_PORTS.  Empty = SCAN_PORTS only (the fast
# 60 s sweep).  Set e.g. NETRON_RUSTSCAN_RANGE=1-2000 to widen discovery; a full
# 1-65535 scan of one host measured ~91 s on this Wi-Fi, so it is opt-in.
RUSTSCAN_RANGE    = (os.environ.get("NETRON_RUSTSCAN_RANGE", "") or "").strip()
# Hard ceiling for one rustscan invocation: SCAN_PORTS takes ~3 s, a full-range
# scan ~91 s; anything beyond this is treated as a failed scan, not "no ports".
RUSTSCAN_DEADLINE = float(os.environ.get("NETRON_RUSTSCAN_TIMEOUT", "180"))

_RUSTSCAN_FAILURES = 0


def _rustscan_failed(reason: str) -> None:
    """Report a rustscan failure and stop using it after three in a row.

    A broken binary must not make every host look portless: after three failures
    the scanner falls back to the nmap path for the rest of the run.
    """
    global RUSTSCAN_OK, _RUSTSCAN_FAILURES
    _RUSTSCAN_FAILURES += 1
    if _RUSTSCAN_FAILURES <= 3:
        print(f"[Netron] rustscan failed ({reason}) — falling back to nmap")
    if _RUSTSCAN_FAILURES >= 3:
        RUSTSCAN_OK = False

VULNERABLE_PORTS = {
    21:   ("FTP",          "MEDIUM",   "Unencrypted file transfer – credentials in plaintext"),
    22:   ("SSH",          "LOW",      "Secure Shell – check for weak passwords / old versions"),
    23:   ("Telnet",       "HIGH",     "Unencrypted remote access – severe credential exposure"),
    25:   ("SMTP",         "MEDIUM",   "Mail server – potential open relay"),
    53:   ("DNS",          "LOW",      "DNS resolver – check for open recursion"),
    80:   ("HTTP",         "MEDIUM",   "Unencrypted web – susceptible to MITM"),
    110:  ("POP3",         "MEDIUM",   "Unencrypted email – credentials exposed"),
    135:  ("MS-RPC",       "HIGH",     "Windows RPC – known exploit surface"),
    139:  ("NetBIOS",      "HIGH",     "NetBIOS – SMB enumeration & relay attacks"),
    143:  ("IMAP",         "MEDIUM",   "Unencrypted email – credentials exposed"),
    161:  ("SNMP",         "HIGH",     "SNMP v1/v2 – community string brute-force"),
    389:  ("LDAP",         "MEDIUM",   "Directory service – enumeration risk"),
    443:  ("HTTPS",        "LOW",      "Encrypted web – check TLS version & cert"),
    445:  ("SMB",          "CRITICAL", "EternalBlue / WannaCry attack surface"),
    512:  ("rexec",        "CRITICAL", "Remote exec – legacy, no encryption"),
    513:  ("rlogin",       "CRITICAL", "Remote login – plaintext credentials"),
    514:  ("rsh",          "CRITICAL", "Remote shell – no authentication"),
    1433: ("MSSQL",        "HIGH",     "SQL Server – brute-force / injection risk"),
    1521: ("Oracle",       "HIGH",     "Oracle DB – exposed to network"),
    2375: ("Docker API",   "CRITICAL", "Docker daemon API – often unauthenticated, remote code execution"),
    3306: ("MySQL",        "HIGH",     "MySQL – exposed to network"),
    3389: ("RDP",          "HIGH",     "Remote Desktop – BlueKeep / brute-force"),
    5432: ("PostgreSQL",   "HIGH",     "PostgreSQL – exposed to network"),
    5900: ("VNC",          "HIGH",     "VNC – weak authentication, unencrypted"),
    5984: ("CouchDB",      "CRITICAL", "CouchDB HTTP API – often unauthenticated, remote code exec via _config"),
    5985: ("WinRM",        "HIGH",     "Windows Remote Management (HTTP) – remote-exec / credential surface"),
    5986: ("WinRM-TLS",    "HIGH",     "Windows Remote Management (HTTPS) – remote-exec / credential surface"),
    6379: ("Redis",        "CRITICAL", "Redis – often no auth, remote code exec"),
    8080: ("HTTP-Alt",     "MEDIUM",   "Alternate HTTP – unencrypted"),
    8086: ("InfluxDB",     "HIGH",     "InfluxDB HTTP API – often unauthenticated"),
    11211:("Memcached",    "HIGH",     "Memcached – unauthenticated, data exposure / amplification"),
    8443: ("HTTPS-Alt",    "LOW",      "Alternate HTTPS"),
    9200: ("Elasticsearch","CRITICAL", "Elasticsearch – often unauthenticated"),
    27017:("MongoDB",      "CRITICAL", "MongoDB – often unauthenticated"),
}

# Ports every scan probes. One list for both nmap and the TCP-connect fallback,
# so a host's findings never depend on which scanner happened to run. It is the
# union of the service ports the UI reports and every port assess_vulns() knows
# how to rate.
SCAN_PORTS: Tuple[int, ...] = tuple(sorted({
    21, 22, 23, 25, 53, 80, 81, 82, 83, 84, 85, 86, 87, 88, 110, 111, 135,
    137, 139, 143, 161, 389, 443, 445, 512, 513, 514, 515, 548, 554, 587,
    623, 631, 636, 873, 902, 993, 995, 1080, 1433, 1521, 1883, 1935, 2049,
    2375, 3128, 3268, 3269, 3306, 3389, 4840, 5060, 5353, 5432, 5555, 5683,
    5900, 5901, 5902, 5984, 5985, 5986, 62078, 6379, 7474, 8000, 8008, 8080,
    8081, 8086, 8087, 8088, 8090, 8443, 8554, 8883, 8888, 8899, 9000, 9090,
    9100, 9200, 9443, 11211, 27017, 28017,
}))

# Fallback service labels for ports where neither nmap nor socket.getservbyport
# yields a name (the TCP-connect fallback runs without nmap, and /etc/services
# is missing many modern ports).  These are the IANA/registered names, not
# guesses, and are only used when the scan produced no name of its own.
PORT_SERVICES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 81: "http", 82: "http", 83: "http", 84: "http",
    85: "http", 86: "http", 87: "http", 88: "kerberos", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    512: "exec", 513: "login", 514: "shell", 515: "printer", 548: "afp",
    554: "rtsp", 587: "submission", 623: "asf-rmcp", 631: "ipp",
    636: "ldaps", 873: "rsync", 902: "vmware-auth", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "ms-sql-s", 1521: "oracle",
    1883: "mqtt", 1935: "rtmp", 2049: "nfs", 2375: "docker",
    3128: "squid-http", 3268: "ldap-gc", 3269: "ldaps-gc", 3306: "mysql",
    3389: "ms-wbt-server", 4840: "opcua", 5060: "sip", 5353: "mdns",
    5432: "postgresql", 5555: "adb", 5683: "coap", 5900: "vnc",
    5901: "vnc-1", 5902: "vnc-2", 5984: "couchdb", 5985: "wsman",
    5986: "wsmans", 62078: "iphone-sync", 6379: "redis", 7474: "neo4j",
    8000: "http-alt", 8008: "http", 8080: "http-alt", 8081: "http",
    8086: "influxdb", 8087: "http", 8088: "http", 8090: "http",
    8443: "https-alt", 8554: "rtsp-alt", 8883: "mqtts", 8888: "http",
    8899: "http", 9000: "cslistener", 9090: "zeus-admin", 9100: "jetdirect",
    9200: "elasticsearch", 9443: "https-alt", 11211: "memcache",
    27017: "mongod", 28017: "mongod-http",
}


def service_label(port: int, detected: str = "") -> str:
    """Service name for a port: what the scan identified, else the registered
    name for that port number.  Never invents a product or version."""
    detected = (detected or "").strip()
    if detected and detected.lower() not in ("unknown", "tcp", "udp", "?"):
        return detected
    return PORT_SERVICES.get(port, "unknown")

# ── OUI vendor table  (expanded – 120+ entries) ─────────────────────────────
# Format: OUI → (vendor, device_type, brand)
# device_type must match the DEVICE_ICON_MAP keys in JS for correct icon rendering
OUI_TABLE: Dict[str, Tuple[str,str,str]] = {
    # ── Apple ──────────────────────────────────────────────────────────────
    "00:03:93":("Apple","Mac","Apple"),        "00:05:02":("Apple","Mac","Apple"),
    "00:0A:27":("Apple","Mac","Apple"),        "00:0A:95":("Apple","Mac","Apple"),
    "00:11:24":("Apple","Mac","Apple"),        "00:14:51":("Apple","Mac","Apple"),
    "00:16:CB":("Apple","Mac","Apple"),        "00:17:F2":("Apple","Mac","Apple"),
    "00:19:E3":("Apple","Mac","Apple"),        "00:1B:63":("Apple","Mac","Apple"),
    "00:1C:B3":("Apple","Mac","Apple"),        "00:1D:4F":("Apple","Mac","Apple"),
    "00:1E:52":("Apple","Mac","Apple"),        "00:1E:C2":("Apple","Mac","Apple"),
    "00:1F:5B":("Apple","Mac","Apple"),        "00:1F:F3":("Apple","Mac","Apple"),
    "00:21:E9":("Apple","Mac","Apple"),        "00:22:41":("Apple","Mac","Apple"),
    "00:23:12":("Apple","Mac","Apple"),        "00:23:32":("Apple","Mac","Apple"),
    "00:23:6C":("Apple","Mac","Apple"),        "00:23:69":("Apple","iPhone","Apple"),
    "00:23:DF":("Apple","Mac","Apple"),        "00:24:36":("Apple","Mac","Apple"),
    "00:25:00":("Apple","Mac","Apple"),        "00:25:4B":("Apple","Mac","Apple"),
    "00:25:BC":("Apple","Mac","Apple"),        "00:26:08":("Apple","Mac","Apple"),
    "00:26:4A":("Apple","Mac","Apple"),        "00:26:B0":("Apple","Mac","Apple"),
    "00:26:BB":("Apple","Mac","Apple"),        "00:30:65":("Apple","Mac","Apple"),
    "3C:22:FB":("Apple","Mac","Apple"),        "AC:DE:48":("Apple","Mac","Apple"),
    "A4:C3:F0":("Apple","iPhone","Apple"),     "F8:FF:C2":("Apple","iPhone","Apple"),
    "00:88:65":("Apple","iPhone","Apple"),     "04:F1:3E":("Apple","iPhone","Apple"),
    "10:41:7F":("Apple","iPhone","Apple"),     "14:5A:05":("Apple","iPhone","Apple"),
    "18:AF:61":("Apple","iPhone","Apple"),     "1C:1A:C0":("Apple","iPhone","Apple"),
    "20:76:8F":("Apple","iPhone","Apple"),     "24:A2:E1":("Apple","iPhone","Apple"),
    "28:37:37":("Apple","iPhone","Apple"),     "2C:1F:23":("Apple","iPhone","Apple"),
    "30:35:AD":("Apple","iPhone","Apple"),     "34:08:BC":("Apple","iPhone","Apple"),
    "34:C0:59":("Apple","iPhone","Apple"),     "38:0F:4A":("Apple","iPhone","Apple"),
    "3C:15:C2":("Apple","iPhone","Apple"),     "40:83:DE":("Apple","iPhone","Apple"),
    "44:4C:0C":("Apple","iPhone","Apple"),     "48:A1:95":("Apple","iPad","Apple"),
    "4C:57:CA":("Apple","iPad","Apple"),       "50:EA:D6":("Apple","iPad","Apple"),
    "54:72:4F":("Apple","iPhone","Apple"),     "58:E2:8F":("Apple","iPhone","Apple"),
    "5C:59:48":("Apple","iPad","Apple"),       "60:C5:47":("Apple","iPhone","Apple"),
    "64:A3:CB":("Apple","iPhone","Apple"),     "68:96:7B":("Apple","iPhone","Apple"),
    "6C:40:08":("Apple","iPhone","Apple"),     "70:3E:AC":("Apple","Mac","Apple"),
    "74:E2:F5":("Apple","iPhone","Apple"),     "78:6C:1C":("Apple","Mac","Apple"),
    "7C:C3:A1":("Apple","iPhone","Apple"),     "80:00:6E":("Apple","iPhone","Apple"),
    "84:38:35":("Apple","iPhone","Apple"),     "88:19:08":("Apple","iPhone","Apple"),
    "8C:2D:AA":("Apple","iPhone","Apple"),     "90:72:40":("Apple","iPhone","Apple"),
    "94:BF:2D":("Apple","iPhone","Apple"),     "98:9E:63":("Apple","iPhone","Apple"),
    "9C:F3:87":("Apple","iPhone","Apple"),     "A0:D7:95":("Apple","iPhone","Apple"),
    "A4:B8:05":("Apple","iPhone","Apple"),     "A8:51:AB":("Apple","iPhone","Apple"),
    "AC:3C:0B":("Apple","iPhone","Apple"),     "B0:19:C6":("Apple","iPhone","Apple"),
    "B4:18:D1":("Apple","iPhone","Apple"),     "B8:53:AC":("Apple","iPhone","Apple"),
    "BC:52:B7":("Apple","iPhone","Apple"),     "C0:9F:42":("Apple","iPhone","Apple"),
    "C4:2C:03":("Apple","iPhone","Apple"),     "C8:D0:83":("Apple","iPhone","Apple"),
    "CC:25:EF":("Apple","iPhone","Apple"),     "D0:03:4B":("Apple","iPhone","Apple"),
    "D4:9A:20":("Apple","iPad","Apple"),       "D8:00:4D":("Apple","iPhone","Apple"),
    "DC:2B:2A":("Apple","iPhone","Apple"),     "E0:AC:CB":("Apple","iPhone","Apple"),
    "E4:CE:8F":("Apple","iPhone","Apple"),     "E8:04:0B":("Apple","iPhone","Apple"),
    "EC:35:86":("Apple","iPhone","Apple"),     "F0:DB:E2":("Apple","iPhone","Apple"),
    "F4:5C:89":("Apple","iPhone","Apple"),     "F8:27:93":("Apple","iPhone","Apple"),
    "FC:25:3F":("Apple","Mac","Apple"),        "F0:18:98":("Apple","iPhone","Apple"),
    # ── Samsung ────────────────────────────────────────────────────────────
    "00:12:47":("Samsung","Mobile Phone","Samsung"), "00:15:B9":("Samsung","Mobile Phone","Samsung"),
    "00:17:D5":("Samsung","Mobile Phone","Samsung"), "00:1A:8A":("Samsung","Mobile Phone","Samsung"),
    "00:1C:43":("Samsung","Mobile Phone","Samsung"), "00:1D:25":("Samsung","Mobile Phone","Samsung"),
    "00:1E:7D":("Samsung","Mobile Phone","Samsung"), "00:1F:CC":("Samsung","Mobile Phone","Samsung"),
    "00:21:19":("Samsung","Mobile Phone","Samsung"), "00:23:39":("Samsung","Mobile Phone","Samsung"),
    "00:24:54":("Samsung","Mobile Phone","Samsung"), "00:25:66":("Samsung","Mobile Phone","Samsung"),
    "00:26:37":("Samsung","Mobile Phone","Samsung"), "00:26:5F":("Samsung","Mobile Phone","Samsung"),
    "FC:F8:AE":("Samsung","Mobile Phone","Samsung"), "78:4B:87":("Samsung","Mobile Phone","Samsung"),
    "8C:C8:4B":("Samsung","Mobile Phone","Samsung"), "A0:82:1F":("Samsung","Mobile Phone","Samsung"),
    "BC:20:A4":("Samsung","Mobile Phone","Samsung"), "C0:BD:D1":("Samsung","Mobile Phone","Samsung"),
    "E4:12:1D":("Samsung","Mobile Phone","Samsung"), "50:01:BB":("Samsung","Smart TV","Samsung"),
    "78:BD:BC":("Samsung","Smart TV","Samsung"),     "CC:6E:A4":("Samsung","Smart TV","Samsung"),
    "D0:22:BE":("Samsung","Smart TV","Samsung"),     "F4:42:8F":("Samsung","Smart TV","Samsung"),
    "34:14:5F":("Samsung","Smart TV","Samsung"),     "10:D3:8A":("Samsung","Smart TV","Samsung"),
    # ── Xiaomi ─────────────────────────────────────────────────────────────
    "54:C9:DF":("Xiaomi","Mobile Phone","Xiaomi"),   "AC:C1:EE":("Xiaomi","Mobile Phone","Xiaomi"),
    "00:EC:0A":("Xiaomi","Mobile Phone","Xiaomi"),   "04:CF:8C":("Xiaomi","Mobile Phone","Xiaomi"),
    "10:2A:B3":("Xiaomi","Mobile Phone","Xiaomi"),   "14:F6:5A":("Xiaomi","Mobile Phone","Xiaomi"),
    "18:59:36":("Xiaomi","Mobile Phone","Xiaomi"),   "28:6C:07":("Xiaomi","Mobile Phone","Xiaomi"),
    "34:80:B3":("Xiaomi","Mobile Phone","Xiaomi"),   "38:A4:ED":("Xiaomi","Mobile Phone","Xiaomi"),
    "50:64:2B":("Xiaomi","Mobile Phone","Xiaomi"),   "58:44:98":("Xiaomi","Mobile Phone","Xiaomi"),
    "64:09:80":("Xiaomi","Mobile Phone","Xiaomi"),   "74:51:BA":("Xiaomi","Mobile Phone","Xiaomi"),
    "8C:BE:BE":("Xiaomi","Mobile Phone","Xiaomi"),   "98:FA:E3":("Xiaomi","Mobile Phone","Xiaomi"),
    "A0:86:C6":("Xiaomi","Mobile Phone","Xiaomi"),   "B4:0B:44":("Xiaomi","Mobile Phone","Xiaomi"),
    "C4:0B:CB":("Xiaomi","Mobile Phone","Xiaomi"),   "D4:97:0B":("Xiaomi","Mobile Phone","Xiaomi"),
    "F4:8B:32":("Xiaomi","Mobile Phone","Xiaomi"),   "FC:64:BA":("Xiaomi","Mobile Phone","Xiaomi"),
    "28:E3:1F":("Xiaomi","Router/AP","Xiaomi"),      "50:EC:50":("Xiaomi","Router/AP","Xiaomi"),
    # ── Huawei ─────────────────────────────────────────────────────────────
    "40:B0:34":("Huawei","Mobile Phone","Huawei"),   "00:9A:CD":("Huawei","Router/AP","Huawei"),
    "00:18:82":("Huawei","Router/AP","Huawei"),      "00:E0:FC":("Huawei","Router/AP","Huawei"),
    "04:75:03":("Huawei","Mobile Phone","Huawei"),   "04:BD:70":("Huawei","Mobile Phone","Huawei"),
    "08:19:A6":("Huawei","Mobile Phone","Huawei"),   "0C:37:96":("Huawei","Mobile Phone","Huawei"),
    "10:1F:74":("Huawei","Mobile Phone","Huawei"),   "10:47:80":("Huawei","Router/AP","Huawei"),
    "18:C5:8A":("Huawei","Mobile Phone","Huawei"),   "1C:8E:5C":("Huawei","Mobile Phone","Huawei"),
    "20:F3:A3":("Huawei","Mobile Phone","Huawei"),   "28:31:52":("Huawei","Mobile Phone","Huawei"),
    "2C:55:D3":("Huawei","Mobile Phone","Huawei"),   "30:D1:7E":("Huawei","Mobile Phone","Huawei"),
    "34:6B:D3":("Huawei","Mobile Phone","Huawei"),   "38:F8:89":("Huawei","Mobile Phone","Huawei"),
    "3C:FA:06":("Huawei","Mobile Phone","Huawei"),   "44:C3:46":("Huawei","Mobile Phone","Huawei"),
    "48:AD:08":("Huawei","Mobile Phone","Huawei"),   "4C:54:99":("Huawei","Mobile Phone","Huawei"),
    "50:A7:2B":("Huawei","Mobile Phone","Huawei"),   "54:51:1B":("Huawei","Mobile Phone","Huawei"),
    "58:2A:F7":("Huawei","Mobile Phone","Huawei"),   "5C:C3:07":("Huawei","Mobile Phone","Huawei"),
    "60:8E:ED":("Huawei","Mobile Phone","Huawei"),   "64:A6:51":("Huawei","Mobile Phone","Huawei"),
    "68:13:24":("Huawei","Mobile Phone","Huawei"),   "6C:83:36":("Huawei","Mobile Phone","Huawei"),
    # ── Dell ───────────────────────────────────────────────────────────────
    "00:14:22":("Dell","PC","Dell"),  "00:1A:4B":("Dell","PC","Dell"),
    "00:1D:09":("Dell","PC","Dell"),  "00:21:9B":("Dell","PC","Dell"),
    "00:22:19":("Dell","PC","Dell"),  "00:23:AE":("Dell","PC","Dell"),
    "00:24:E8":("Dell","PC","Dell"),  "00:26:B9":("Dell","PC","Dell"),
    "00:23:24":("Dell","PC","Dell"),  "B8:CA:3A":("Dell","PC","Dell"),
    "00:B0:D0":("Dell","Server","Dell"), "14:FE:B5":("Dell","PC","Dell"),
    "18:03:73":("Dell","PC","Dell"),  "18:66:DA":("Dell","PC","Dell"),
    "20:47:47":("Dell","PC","Dell"),  "24:B6:FD":("Dell","PC","Dell"),
    "28:92:4A":("Dell","PC","Dell"),  "34:17:EB":("Dell","PC","Dell"),
    "44:A8:42":("Dell","PC","Dell"),  "50:9A:4C":("Dell","PC","Dell"),
    "54:BF:64":("Dell","PC","Dell"),  "5C:F9:DD":("Dell","PC","Dell"),
    "60:36:DD":("Dell","PC","Dell"),  "6C:2B:59":("Dell","PC","Dell"),
    "74:86:7A":("Dell","PC","Dell"),  "78:2B:CB":("Dell","PC","Dell"),
    "84:7B:EB":("Dell","PC","Dell"),  "90:B1:1C":("Dell","PC","Dell"),
    "A4:1F:72":("Dell","PC","Dell"),  "B0:83:FE":("Dell","PC","Dell"),
    # ── HP / Hewlett-Packard ────────────────────────────────────────────────
    "00:0F:20":("HP","PC","HP"),     "00:13:21":("HP","PC","HP"),
    "00:15:60":("HP","PC","HP"),     "00:17:A4":("HP","PC","HP"),
    "00:19:BB":("HP","PC","HP"),     "00:1B:78":("HP","PC","HP"),
    "00:1E:0B":("HP","PC","HP"),     "00:21:5A":("HP","PC","HP"),
    "00:23:7D":("HP","PC","HP"),     "00:24:81":("HP","PC","HP"),
    "00:25:B3":("HP","Printer","HP"),"30:8D:99":("HP","Printer","HP"),
    "3C:D9:2B":("HP","PC","HP"),
    "A0:D3:C1":("HP","PC","HP"),     "68:B5:99":("HP","PC","HP"),
    "70:5A:0F":("HP","PC","HP"),     "84:34:97":("HP","PC","HP"),
    "94:57:A5":("HP","PC","HP"),     "9C:B6:54":("HP","PC","HP"),
    # ── Lenovo ─────────────────────────────────────────────────────────────
    "00:21:CC":("Lenovo","Laptop","Lenovo"),  "00:26:C6":("Lenovo","Laptop","Lenovo"),
    "28:D2:44":("LCFC (Lenovo)","Laptop","Lenovo"),  "40:2C:F4":("Lenovo","Laptop","Lenovo"),
    "44:37:E6":("Lenovo","Laptop","Lenovo"),  "54:05:DB":("Lenovo","Laptop","Lenovo"),
    "60:02:B4":("Lenovo","Laptop","Lenovo"),
    "70:5A:B6":("Lenovo","Laptop","Lenovo"),  "74:DF:BF":("Lenovo","Laptop","Lenovo"),
    "84:7A:88":("Lenovo","Laptop","Lenovo"),  "88:79:7E":("Lenovo","Laptop","Lenovo"),
    "98:FA:9B":("Lenovo","Laptop","Lenovo"),
    "A4:4C:C8":("Dell","PC","Dell"),
    "B8:AC:6F":("Lenovo","Laptop","Lenovo"),  "C8:5B:76":("Lenovo","Laptop","Lenovo"),
    "D4:81:D7":("Lenovo","Laptop","Lenovo"),  "E8:39:DF":("Lenovo","Laptop","Lenovo"),
    # ── Asus ────────────────────────────────────────────────────────────────
    "00:11:2F":("Asus","PC","Asus"),  "00:13:D4":("Asus","PC","Asus"),
    "00:15:F2":("Asus","PC","Asus"),  "00:17:31":("Asus","PC","Asus"),
    "00:1A:92":("Asus","Router/AP","Asus"), "00:1B:FC":("Asus","PC","Asus"),
    "00:1D:60":("Asus","PC","Asus"),  "00:1E:8C":("Asus","PC","Asus"),
    "00:22:15":("Asus","PC","Asus"),  "00:23:54":("Asus","PC","Asus"),
    "00:24:8C":("Asus","PC","Asus"),  "00:26:18":("Asus","PC","Asus"),
    "74:D0:2B":("Asus","PC","Asus"),  "60:A4:4C":("Asus","PC","Asus"),
    "04:D4:C4":("Asus","Router/AP","Asus"), "14:DD:A9":("Asus","Router/AP","Asus"),
    "2C:FD:A1":("Asus","Router/AP","Asus"), "30:5A:3A":("Asus","Router/AP","Asus"),
    "40:16:7E":("Asus","Router/AP","Asus"), "50:46:5D":("Asus","Router/AP","Asus"),
    "AC:9E:17":("Asus","Router/AP","Asus"), "BC:AE:C5":("Asus","Router/AP","Asus"),
    # ── Cisco ───────────────────────────────────────────────────────────────
    "00:00:0C":("Cisco","Router/AP","Cisco"), "00:01:42":("Cisco","Router/AP","Cisco"),
    "00:01:63":("Cisco","Router/AP","Cisco"), "00:01:96":("Cisco","Router/AP","Cisco"),
    "00:01:C7":("Cisco","Router/AP","Cisco"), "00:02:17":("Cisco","Router/AP","Cisco"),
    "00:03:6B":("Cisco","Router/AP","Cisco"), "00:03:E3":("Cisco","Router/AP","Cisco"),
    "00:04:6D":("Cisco","Router/AP","Cisco"), "00:04:9A":("Cisco","Router/AP","Cisco"),
    "00:05:32":("Cisco","Router/AP","Cisco"), "00:06:28":("Cisco","Router/AP","Cisco"),
    "00:0A:41":("Cisco","Router/AP","Cisco"), "00:0A:8A":("Cisco","Router/AP","Cisco"),
    "00:0B:BE":("Cisco","Router/AP","Cisco"), "00:0C:CE":("Cisco","Router/AP","Cisco"),
    "00:0D:28":("Cisco","Router/AP","Cisco"), "00:0E:38":("Cisco","Router/AP","Cisco"),
    "00:0F:8F":("Cisco","Router/AP","Cisco"), "00:1A:2B":("Cisco","Router/AP","Cisco"),
    "00:1A:6D":("Cisco","Router/AP","Cisco"), "00:1B:D5":("Cisco","Router/AP","Cisco"),
    "58:AC:78":("Cisco","Router/AP","Cisco"),
    # ── TP-Link ─────────────────────────────────────────────────────────────
    "00:18:0A":("TP-Link","Router/AP","TP-Link"),
    "AC:84:C6":("TP-Link","Router/AP","TP-Link"), "50:C7:BF":("TP-Link","Router/AP","TP-Link"),
    "00:1D:0F":("TP-Link","Router/AP","TP-Link"), "14:CC:20":("TP-Link","Router/AP","TP-Link"),
    "18:A6:F7":("TP-Link","Router/AP","TP-Link"), "1C:3B:F3":("TP-Link","Router/AP","TP-Link"),
    "20:DC:E6":("TP-Link","Router/AP","TP-Link"), "24:69:68":("TP-Link","Router/AP","TP-Link"),
    "28:87:BA":("TP-Link","Router/AP","TP-Link"), "2C:D0:5A":("TP-Link","Router/AP","TP-Link"),
    "30:B5:C2":("TP-Link","Router/AP","TP-Link"), "34:60:F9":("TP-Link","Router/AP","TP-Link"),
    "38:EA:A7":("TP-Link","Router/AP","TP-Link"), "3C:84:6A":("TP-Link","Router/AP","TP-Link"),
    "40:3F:8C":("TP-Link","Router/AP","TP-Link"), "40:8D:5C":("GIGA-BYTE","PC","GIGA-BYTE"),
    "48:8D:36":("TP-Link","Router/AP","TP-Link"),
    "50:3E:AA":("TP-Link","Router/AP","TP-Link"), "54:E6:FC":("TP-Link","Router/AP","TP-Link"),
    "58:D5:6E":("TP-Link","Router/AP","TP-Link"), "5C:63:BF":("TP-Link","Router/AP","TP-Link"),
    "60:32:B1":("TP-Link","Router/AP","TP-Link"), "64:70:02":("TP-Link","Router/AP","TP-Link"),
    "70:4F:57":("TP-Link","Router/AP","TP-Link"),
    "74:DA:88":("TP-Link","Router/AP","TP-Link"), "7C:8B:CA":("TP-Link","Router/AP","TP-Link"),
    "80:35:C1":("TP-Link","Router/AP","TP-Link"), "84:16:F9":("TP-Link","Router/AP","TP-Link"),
    "8C:21:0A":("TP-Link","Router/AP","TP-Link"), "90:F6:52":("TP-Link","Router/AP","TP-Link"),
    "94:D9:B3":("TP-Link","Router/AP","TP-Link"), "98:DE:D0":("TP-Link","Router/AP","TP-Link"),
    "9C:A6:15":("TP-Link","Router/AP","TP-Link"), "A0:F3:C1":("TP-Link","Router/AP","TP-Link"),
    "A4:2B:B0":("TP-Link","Router/AP","TP-Link"), "A8:57:4E":("TP-Link","Router/AP","TP-Link"),
    "B0:48:7A":("TP-Link","Router/AP","TP-Link"),
    "B8:08:CF":("TP-Link","Router/AP","TP-Link"), "BC:46:99":("TP-Link","Router/AP","TP-Link"),
    "C0:4A:00":("TP-Link","Router/AP","TP-Link"), "C4:6E:1F":("TP-Link","Router/AP","TP-Link"),
    "C8:D3:A3":("TP-Link","Router/AP","TP-Link"), "CC:32:E5":("TP-Link","Router/AP","TP-Link"),
    "D4:6E:0E":("TP-Link","Router/AP","TP-Link"), "D8:15:0D":("TP-Link","Router/AP","TP-Link"),
    "DC:FE:18":("TP-Link","Router/AP","TP-Link"), "E0:28:6D":("TP-Link","Router/AP","TP-Link"),
    "E4:D3:32":("TP-Link","Router/AP","TP-Link"), "E8:94:F6":("TP-Link","Router/AP","TP-Link"),
    "EC:08:6B":("TP-Link","Router/AP","TP-Link"), "F0:9F:C2":("TP-Link","Router/AP","TP-Link"),
    "F4:EC:38":("TP-Link","Router/AP","TP-Link"), "F8:1A:67":("TP-Link","Router/AP","TP-Link"),
    # ── Ubiquiti ─────────────────────────────────────────────────────────────
    "00:27:22":("Ubiquiti","Router/AP","Ubiquiti"),  "04:18:D6":("Ubiquiti","Router/AP","Ubiquiti"),
    "0C:62:A6":("Ubiquiti","Router/AP","Ubiquiti"),  "18:E8:29":("Ubiquiti","Router/AP","Ubiquiti"),
    "24:A4:3C":("Ubiquiti","Router/AP","Ubiquiti"),  "44:D9:E7":("Ubiquiti","Router/AP","Ubiquiti"),
    "64:16:66":("Ubiquiti","Router/AP","Ubiquiti"),  "68:72:51":("Ubiquiti","Router/AP","Ubiquiti"),
    "74:83:C2":("Ubiquiti","Router/AP","Ubiquiti"),  "80:2A:A8":("Ubiquiti","Router/AP","Ubiquiti"),
    "B4:FB:E4":("Ubiquiti","Router/AP","Ubiquiti"),  "DC:9F:DB":("Ubiquiti","Router/AP","Ubiquiti"),
    "E0:63:DA":("Ubiquiti","Router/AP","Ubiquiti"),  "F4:92:BF":("Ubiquiti","Router/AP","Ubiquiti"),
    "F4:E2:C6":("Ubiquiti","Router/AP","Ubiquiti"),  "FC:EC:DA":("Ubiquiti","Router/AP","Ubiquiti"),
    # ── Netgear ─────────────────────────────────────────────────────────────
    "00:09:5B":("Netgear","Router/AP","Netgear"), "00:0F:B5":("Netgear","Router/AP","Netgear"),
    "00:14:6C":("Netgear","Router/AP","Netgear"), "00:18:4D":("Netgear","Router/AP","Netgear"),
    "00:1B:2F":("Netgear","Router/AP","Netgear"), "00:1E:2A":("Netgear","Router/AP","Netgear"),
    "00:22:3F":("Netgear","Router/AP","Netgear"), "00:24:B2":("Netgear","Router/AP","Netgear"),
    "00:26:F2":("Netgear","Router/AP","Netgear"), "04:A1:51":("Netgear","Router/AP","Netgear"),
    "20:E5:2A":("Netgear","Router/AP","Netgear"), "2C:B0:5D":("Netgear","Router/AP","Netgear"),
    "30:46:9A":("Netgear","Router/AP","Netgear"), "44:94:FC":("Netgear","Router/AP","Netgear"),
    "6C:B0:CE":("Netgear","Router/AP","Netgear"), "A0:21:B7":("Netgear","Router/AP","Netgear"),
    "C0:FF:D4":("Netgear","Router/AP","Netgear"), "E4:F4:C6":("Netgear","Router/AP","Netgear"),
    # ── Google / Android / Nest ─────────────────────────────────────────────
    "B0:4E:26":("Google","Chromecast","Google"),  "54:60:09":("Google","Chromecast","Google"),
    "6C:AD:F8":("Google","Chromecast","Google"),  "F4:F5:E8":("Google","Chromecast","Google"),
    "18:B4:30":("Nest","Smart Home","Google"),    "20:7B:D2":("Google","Google Home","Google"),
    "3C:28:6D":("Google","Pixel Phone","Google"),
    "D0:E7:82":("Google","Pixel Phone","Google"), "F4:F5:D8":("Google","Pixel Phone","Google"),
    # ── Amazon ──────────────────────────────────────────────────────────────
    "F0:27:65":("Amazon","Echo","Amazon"),  "44:65:0D":("Amazon","Echo","Amazon"),
    "40:B4:CD":("Amazon","Echo","Amazon"),  "A4:08:01":("Amazon","Echo","Amazon"),
    "68:37:E9":("Amazon","FireTV","Amazon"),"74:75:48":("Amazon","FireTV","Amazon"),
    "84:D6:D0":("Amazon","FireTV","Amazon"),"FC:A6:67":("Amazon","FireTV","Amazon"),
    # ── LG ──────────────────────────────────────────────────────────────────
    "64:B5:C6":("LG","Smart TV","LG Electronics"),  "A8:23:FE":("LG","Smart TV","LG Electronics"),
    "BC:F5:AC":("LG","Smart TV","LG Electronics"),  "CC:2D:8C":("LG","Smart TV","LG Electronics"),
    "F8:95:C7":("LG","Smart TV","LG Electronics"),  "00:E0:91":("LG","Mobile Phone","LG Electronics"),
    "10:68:3F":("LG","Mobile Phone","LG Electronics"),"30:CD:A7":("LG","Mobile Phone","LG Electronics"),
    # ── Sony ────────────────────────────────────────────────────────────────
    "E0:1C:FC":("Sony","PlayStation","Sony"),  "00:13:A9":("Sony","PlayStation","Sony"),
    "00:24:BE":("Sony","PlayStation","Sony"),  "00:D9:D1":("Sony","PlayStation","Sony"),
    "70:A5:BF":("Sony","Smart TV","Sony"),     "AC:9B:0A":("Sony","Smart TV","Sony"),
    "F8:16:54":("Sony","Smart TV","Sony"),     "B8:8A:60":("Sony","Smart TV","Sony"),
    # ── Raspberry Pi ─────────────────────────────────────────────────────────
    "B8:27:EB":("Raspberry Pi","IoT/SBC","Raspberry Pi"), "DC:A6:32":("Raspberry Pi","IoT/SBC","Raspberry Pi"),
    "E4:5F:01":("Raspberry Pi","IoT/SBC","Raspberry Pi"),
    # ── VMs ─────────────────────────────────────────────────────────────────
    "00:0C:29":("VMware","Virtual Machine","VMware"),   "00:50:56":("VMware","Virtual Machine","VMware"),
    "00:1C:14":("VMware","Virtual Machine","VMware"),   "00:16:3E":("Xen","Virtual Machine","Xen"),
    "52:54:00":("QEMU","Virtual Machine","QEMU"),       "08:00:27":("VirtualBox","Virtual Machine","Oracle"),
    "0A:00:27":("VirtualBox","Virtual Machine","Oracle"),
    # ── Intel (PC NICs) ─────────────────────────────────────────────────────
    "00:1B:21":("Intel","PC","Intel"),  "00:1F:3B":("Intel","PC","Intel"),
    "00:22:FB":("Intel","PC","Intel"),  "00:24:D7":("Intel","PC","Intel"),
    "10:02:B5":("Intel","PC","Intel"),
    "1C:69:7A":("Intel","PC","Intel"),  "24:77:03":("Intel","PC","Intel"),
    "34:13:E8":("Intel","PC","Intel"),
    "4C:EB:42":("Intel","PC","Intel"),
    "50:7B:9D":("Intel","PC","Intel"),  "54:27:1E":("Intel","PC","Intel"),
    "6C:88:14":("Intel","PC","Intel"),  "7C:67:A2":("Intel","PC","Intel"),
    "80:86:F2":("Intel","PC","Intel"),  "8C:8D:28":("Intel","PC","Intel"),
    "94:65:9C":("Intel","PC","Intel"),  "A0:A8:CD":("Intel","PC","Intel"),
    "B8:03:05":("Intel","PC","Intel"),  "C0:3F:D5":("Intel","PC","Intel"),
    "C4:65:16":("Intel","PC","Intel"),  "CC:3D:82":("Intel","PC","Intel"),
    "D0:50:99":("Intel","PC","Intel"),  "D4:BE:D9":("Intel","PC","Intel"),
    "E0:94:67":("Intel","PC","Intel"),  "E4:B3:18":("Intel","PC","Intel"),
    "E8:6A:64":("Intel","PC","Intel"),  "EC:F4:BB":("Intel","PC","Intel"),
    # ── Liteon (PC NICs / optical) ──────────────────────────────────────────
    "AC:B5:7D":("Liteon","PC","Liteon"),
    # ── IP Cameras / NVR ────────────────────────────────────────────────────
    "00:12:12":("Hikvision","IP Camera","Hikvision"), "BC:AD:28":("Hikvision","IP Camera","Hikvision"),
    "C0:56:E3":("Hikvision","IP Camera","Hikvision"), "44:19:B6":("Hikvision","IP Camera","Hikvision"),
    "54:C4:15":("Hikvision","IP Camera","Hikvision"),
    "00:1D:E5":("Dahua","IP Camera","Dahua"),          "3C:EF:8C":("Dahua","IP Camera","Dahua"),
    "90:02:A9":("Axis","IP Camera","Axis"),             "00:40:8C":("Axis","IP Camera","Axis"),
    "AC:CC:8E":("Wyze","IP Camera","Wyze"),             "2C:AA:8E":("Wyze","IP Camera","Wyze"),
    "20:F4:1B":("Reolink","IP Camera","Reolink"),
    # ── Printers ────────────────────────────────────────────────────────────
    "00:00:48":("Epson","Printer","Epson"),  "00:26:AB":("Epson","Printer","Epson"),
    "00:04:00":("Lexmark","Printer","Lexmark"), "00:00:AA":("Xerox","Printer","Xerox"),
    "00:00:74":("Ricoh","Printer","Ricoh"),  "08:00:37":("HP","Printer","HP"),
    "28:80:23":("Canon","Printer","Canon"),  "00:1E:8F":("Canon","Printer","Canon"),
    "08:92:04":("Brother","Printer","Brother"),
    # ── Game Consoles ─────────────────────────────────────────────────────
    "00:13:15":("Sony","PlayStation","Sony"),  "00:19:C5":("Sony","PlayStation","Sony"),
    "00:1F:A7":("Sony","PlayStation","Sony"),  "70:9E:29":("Sony","PlayStation","Sony"),
    "00:E0:4C":("Realtek","PC","Realtek"),     "7C:BB:8A":("Microsoft","Xbox","Microsoft"),
    "00:25:AE":("Microsoft","Xbox","Microsoft"),"00:22:48":("Microsoft","Xbox","Microsoft"),
    "00:1D:D8":("Microsoft","Xbox","Microsoft"),"98:5F:D3":("Microsoft","Xbox","Microsoft"),
    "00:09:BF":("Nintendo","Nintendo Switch","Nintendo"), "98:B6:E9":("Nintendo","Nintendo Switch","Nintendo"),
    "E0:F6:B4":("Nintendo","Nintendo Switch","Nintendo"), "9C:AA:1B":("Nintendo","Nintendo Switch","Nintendo"),
    "A4:C0:E1":("Nintendo","Nintendo Switch","Nintendo"),
}


# ── Hostname → OS mapping (the key accuracy improvement) ─────────────────────
# Each entry: regex pattern → (os_name, os_family, confidence)
HOSTNAME_OS_PATTERNS: List[Tuple[re.Pattern, str, str, str]] = [
    # Windows – broad hostname match (DESKTOP-, WIN-, generic PC names)
    (re.compile(r"DESKTOP-|WIN-|WIN10|WIN11|WINDOWS", re.I),
     "Windows", "Windows", "High"),
    (re.compile(r"-PC$|-LAPTOP$|-WORKSTATION$", re.I),
     "Windows", "Windows", "Medium"),
    # Generic PC / computer hostnames (kali, parrot treated separately below
    # as Linux distros, but plain "PC", "COMPUTER", "DESKTOP", "CUSTOMER" etc.)
    (re.compile(r"^PC[-_]?\d*$|^COMPUTER$|^DESKTOP$|^WORKSTATION$|^CUSTOMER[-_]?\d*$|^CLIENT[-_]?\d*$|^USER[-_]?\d*$|^HOST[-_]?\d*$", re.I),
     "Windows", "Windows", "Medium"),
    # macOS / Apple
    (re.compile(r"MacBook|iMac|Mac-Pro|Mac-Mini|macOS", re.I),
     "macOS", "macOS", "High"),
    (re.compile(r"\.local$", re.I),                          # mDNS .local is almost always Apple/Linux
     "macOS/Linux", "Unix", "Low"),
    # iOS
    (re.compile(r"iPhone|iPad|iPod", re.I),
     "iOS", "iOS", "High"),
    # Android
    (re.compile(r"android|ANDROID|Galaxy|SAMSUNG|HUAWEI|Pixel|OnePlus|Xiaomi|Redmi|"
                r"Poco|Realme|OPPO|Vivo|Infinix|TECNO|Itel|Motorola|Nokia|HTC|ZTE|"
                r"Meizu|Nubia|Gionee|Blackview|Ulefone|Doogee|Fairphone|Nothing",
                re.I),
     "Android", "Android", "High"),
    # Linux distros
    (re.compile(r"ubuntu|debian|fedora|centos|arch|manjaro|mint|kali|parrot", re.I),
     "Linux", "Linux", "High"),
    (re.compile(r"raspberrypi|raspi|rpi", re.I),
     "Linux (Raspberry Pi OS)", "Linux", "High"),
    (re.compile(r"nas|synology|qnap|freenas|truenas", re.I),
     "Linux/BSD (NAS)", "Linux", "High"),
    # Network gear
    (re.compile(r"router|gateway|modem|dsl|fiber|ont|fritzbox|openwrt|dd-wrt|tomato", re.I),
     "Router/Embedded Linux", "Embedded", "High"),
    (re.compile(r"cisco|juniper|mikrotik|ubnt|unifi|edgerouter|zyxel|netgear|dlink", re.I),
     "Network OS (Cisco/Linux)", "Network", "High"),
    # Smart TV / streaming
    (re.compile(r"samsung.*tv|LG.*TV|bravia|VIZIO|hisense|tcl.*tv|firetv|appletv|roku|chromecast", re.I),
     "Smart TV OS", "Embedded", "High"),
    # Game consoles
    (re.compile(r"PS[345]|PlayStation|Xbox|Nintendo|Switch", re.I),
     "Console OS", "Console", "High"),
    # IoT / printers
    (re.compile(r"printer|HP.*LaserJet|EPSON|Canon|Brother|Xerox", re.I),
     "Printer Firmware", "Embedded", "High"),
    (re.compile(r"ESP[0-9]|arduino|tasmota|esphome|home-assistant", re.I),
     "Embedded/IoT Firmware", "Embedded", "High"),
    # Windows Server
    (re.compile(r"SERVER|SRV|DC[0-9]|PDC|BDC|EXCHANGE|SHAREPOINT", re.I),
     "Windows Server", "Windows", "High"),
]

# TTL → OS family (fallback when no hostname hint available)
def _os_from_ttl(ttl: int) -> Tuple[str, str]:
    """Return (os_guess, confidence)"""
    if ttl <= 0:   return "Unknown", ""
    if ttl <= 64:  return "Linux / Android / macOS", "Low (TTL≤64)"
    if ttl <= 128: return "Windows", "Low (TTL≤128)"
    return "Network Device (Cisco/BSD)", "Low (TTL>128)"

# ─────────────────────────────────────────────────────────────────────────────
#  IN-MEMORY STORES  (all protected by _lock)
# ─────────────────────────────────────────────────────────────────────────────
devices:      Dict[str, dict]           = {}
traffic_data: Dict[str, deque]          = defaultdict(lambda: deque(maxlen=120))
packet_log:   Dict[str, deque]          = defaultdict(lambda: deque(maxlen=MAX_PKTS))
alerts:       deque                     = deque(maxlen=500)
pkt_feed:     deque                     = deque(maxlen=PKT_FEED_MAX)  # every captured packet, all devices
SYN_WINDOW_SECS = 10            # SYN-flood detection window
SYN_MAX_SOURCES = 4096          # hard cap so spoofed sources can't grow the dict forever
net_stats = dict(total_in=0, total_out=0, pps=0, scan_count=0, alert_count=0)
_lock = threading.RLock()
# Consecutive sweeps in which a device was NOT seen by nmap (device is only
# flipped to offline when this reaches 2 AND the ARP grace period has passed).
missed_scans: Dict[str, int]  = defaultdict(int)
# Last time each IP was present in the OS ARP table (unix seconds).
_arp_seen_ts: Dict[str, float] = {}

# ─────────────────────────────────────────────────────────────────────────────
#  UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
def _ts()  -> str: return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def _parse_ts(s) -> float:
    """Epoch seconds for a `_ts()` string; 0.0 when absent or malformed."""
    try:
        return datetime.strptime(str(s), "%Y-%m-%d %H:%M:%S").timestamp()
    except (TypeError, ValueError):
        return 0.0
def _sts() -> str: return datetime.now().strftime("%H:%M:%S")

def merge_scan_ports(ip: str, prev: dict, fresh: dict) -> Tuple[dict, bool]:
    """The open-port set to show after one scan of `ip`.

    Every scan path (deep identification, vulnerability sweep, re-scan) goes
    through here, so the Ports panel, the Vulnerabilities panel and the alerts
    all describe the same set of ports.

    A scan returning nothing is not proof that ports closed -- a sleeping or
    busy Wi-Fi host drops probes -- so the last observed ports are kept until
    three consecutive empty sweeps, and any single port that was confirmed
    open within PORT_RETENTION_SECS survives a sweep that missed it.  A port is
    only ever shown as open because a scan saw it open, never inferred.

    Returns (ports, carried).  `carried` is True when a shown port was not
    confirmed by this scan, so the caller re-assesses findings over the whole
    displayed set instead of only the freshly probed ports.
    """
    now  = time.time()
    prev = prev or {}
    kept: Dict[int, dict] = {}
    for p, info in (fresh or {}).items():
        if not isinstance(info, dict) or info.get("state") != "open":
            continue
        try:
            num = int(p)
        except (TypeError, ValueError):
            continue
        kept[num] = {**info,
                     "service": service_label(num, info.get("service", "")),
                     "version": info.get("version", "") or "",
                     "seen":    _ts()}
    if kept:
        _VULN_EMPTY.pop(ip, None)
        carried = False
        for p, info in prev.items():
            if not isinstance(info, dict):
                continue
            try:
                num = int(p)
            except (TypeError, ValueError):
                continue
            if num in kept:
                continue
            if not info.get("seen"):
                # Legacy entry: start its retention clock now.
                info = {**info, "seen": _ts()}
            age = now - _parse_ts(info.get("seen"))
            if 0 <= age <= PORT_RETENTION_SECS:
                kept[num] = info
                carried = True
        return kept, carried
    # Nothing answered at all this time.
    streak = _VULN_EMPTY.get(ip, 0) + 1
    _VULN_EMPTY[ip] = streak
    if streak >= 3 or not prev:
        return {}, bool(prev)
    return prev, True

def _fmt(b: int) -> str:
    if b < 1024:       return f"{b}B"
    if b < 1_048_576:  return f"{b/1024:.1f}KB"
    return f"{b/1_048_576:.1f}MB"

def get_local_network() -> Tuple[str, str]:
    gws = netifaces.gateways().get("default", {}).get(netifaces.AF_INET)
    if not gws:
        return "192.168.1.1", "192.168.1.0/24"
    gw_ip, iface = gws[0], gws[1]
    addr = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [{}])[0]
    ip, mask = addr.get("addr", ""), addr.get("netmask", "255.255.255.0")
    try:
        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return gw_ip, str(net)
    except Exception:
        # Keep the advertised network consistent with the real gateway instead
        # of pairing a live gateway with a made-up 192.168.1.0/24.
        try:
            return gw_ip, str(ipaddress.IPv4Network(
                gw_ip.rsplit(".", 1)[0] + ".0/24", strict=False))
        except Exception:
            return gw_ip, "192.168.1.0/24"

def get_local_ips() -> set:
    ips = {"127.0.0.1"}
    try:
        for _, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET:
                    ips.add(a.address)
    except Exception:
        pass
    return ips

def _primary_local_ip() -> str:
    """Best-effort primary LAN IPv4 (never loopback). Re-resolved on each call
    so DHCP/VPN changes are picked up.

    Uses a UDP connect (no packets are sent) to let the OS pick the address of
    the outbound interface – taking an arbitrary interface's address used to
    attribute all NIC traffic to a Docker/VPN address.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass
    try:
        return next(iter(get_local_ips() - {"127.0.0.1"}), "0.0.0.0")
    except Exception:
        return "0.0.0.0"

def oui(mac: str) -> str:
    if not mac or mac in ("N/A", ""):
        return ""
    return ":".join(mac.upper().replace("-",":").split(":")[:3])

# ─────────────────────────────────────────────────────────────────────────────
#  VENDOR LOOKUP  – 4-source cascade, thread-safe, fully cached
# ─────────────────────────────────────────────────────────────────────────────
_vendor_cache:  Dict[str, Tuple[str,str,str]] = {}   # OUI prefix → (vendor, dtype, brand)
_vendor_fail_ts: Dict[str, float]      = {}   # OUI prefix → time of last failed lookup
_VENDOR_RETRY_SECS   = 3600            # wait 1 h before retrying a failed lookup
_VENDOR_MIN_INTERVAL = 1.0             # macvendors.com free tier: 1 request/second
_vendor_rate_lock    = threading.Lock()
_last_vendor_query   = 0.0

def _vendor_rate_limit() -> None:
    """Block until the vendor-API rate limit allows another request."""
    global _last_vendor_query
    with _vendor_rate_lock:
        wait = _last_vendor_query + _VENDOR_MIN_INTERVAL - time.time()
        if wait > 0:
            time.sleep(wait)
        _last_vendor_query = time.time()

# Clean company name – strip legal suffixes that clutter the UI.
# A suffix is only stripped when preceded by a comma or whitespace, so a
# company actually NAMED e.g. "Networks" survives intact.
_CORP_RE = re.compile(
    r"(?:,\s*|\s+)(?:Inc\.?|LLC\.?|Ltd\.?|Co\.?|Corp\.?|GmbH|S\.A\.?|B\.V\.?|PTE\.?|"
    r"Technology|Technologies|Communications|Electronics|International|"
    r"Solutions|Systems|Networks|Group|Holdings|Manufacturing)\.?$",
    re.I
)
def _clean_company(name: str) -> str:
    if not name:
        return name
    cleaned = name
    for _ in range(3):   # strip stacked suffixes, e.g. "... Technologies Inc."
        new = _CORP_RE.sub("", cleaned).strip(" ,.")
        if not new or new == cleaned:
            break
        cleaned = new
    return cleaned if cleaned else name   # keep original if cleaning made it empty

# API endpoints tried in order – all return company name from MAC/OUI prefix
_OUI_API_ENDPOINTS = [
    # macvendors.com – fast, free, no key, 1 request/s rate limit
    "https://api.macvendors.com/{mac}",
    # maclookup.app – JSON response with company field
    "https://api.maclookup.app/v2/macs/{mac}",
]

def _query_oui_api(mac: str, prefix: str) -> Tuple[str,str,str]:
    """Try each vendor API endpoint and return the first good result."""
    if not REQUESTS_OK:
        return ("Unknown","Unknown","Unknown")
    for tpl in _OUI_API_ENDPOINTS:
        url = tpl.format(mac=mac, prefix=prefix)
        try:
            _vendor_rate_limit()   # respect the free-tier 1 req/s limit
            r = _http.get(url, timeout=3)
            if r.status_code != 200:
                continue
            # macvendors returns plain text; maclookup returns JSON
            if "maclookup" in url:
                company = r.json().get("company","")
                found   = r.json().get("found", True)
                if not found:
                    continue
            else:
                company = r.text.strip()
            company = _clean_company(company)
            if company and company.lower() not in ("","unknown","private","not found"):
                dtype = _guess_type(company)
                return (company, dtype, company)
        except Exception:
            continue
    return ("Unknown","Unknown","Unknown")

# Live vendor-API work runs on one background thread fed by a queue, so a scan
# worker never sits in the 1-request/second rate limiter.  The answer is written
# into the cache and pushed to the matching devices when it arrives.
_vendor_queue: "queue.Queue[Tuple[str, str]]" = queue.Queue()
_vendor_queued: set = set()
_vendor_worker_lock   = threading.Lock()
_vendor_worker_started = False

def _enqueue_vendor_lookup(mac: str) -> None:
    """Queue a live vendor lookup for this MAC (deduplicated, non-blocking)."""
    global _vendor_worker_started
    prefix = oui(mac)
    if not prefix or not REQUESTS_OK:
        return
    if prefix in _vendor_queued or prefix in _vendor_cache:
        return
    _vendor_queued.add(prefix)
    _vendor_queue.put((prefix, mac))
    with _vendor_worker_lock:
        if not _vendor_worker_started:
            _vendor_worker_started = True
            threading.Thread(target=_vendor_worker, daemon=True,
                             name="vendor-api").start()

def _vendor_worker() -> None:
    while True:
        prefix, mac = _vendor_queue.get()
        try:
            vendor, dtype, brand = _query_oui_api(mac, prefix)
            if vendor and vendor.lower() != "unknown":
                _vendor_cache[prefix] = (vendor, dtype, brand)
                _vendor_fail_ts.pop(prefix, None)
                _apply_vendor_result(prefix, vendor, dtype, brand)
            else:
                _vendor_fail_ts[prefix] = time.time()
        except Exception:
            log.warning("Vendor lookup failed for %s", prefix, exc_info=True)
        finally:
            _vendor_queued.discard(prefix)
            _vendor_queue.task_done()

def _apply_vendor_result(prefix: str, vendor: str, dtype: str, brand: str) -> None:
    """Attach a late vendor-API answer to the devices already on screen.

    Only fields that are still empty are filled: anything learned from the
    device itself (banner title, ports, OS) outranks a manufacturer guess.
    """
    updated = []
    with _lock:
        for d in devices.values():
            if oui(d.get("mac", "")) != prefix:
                continue
            if not d.get("vendor"):
                d["vendor"] = vendor
            if not d.get("brand"):
                d["brand"] = brand
            if not d.get("device_type"):
                refined = _refine_dtype(dtype, d.get("vendor", ""), d.get("os", ""),
                                        d.get("open_ports") or {}, d.get("hostname", ""))
                if refined and refined.lower() != "unknown":
                    d["device_type"] = refined
            updated.append(dict(d))
    for snap in updated:
        socketio.emit("device_update", snap)

def lookup_vendor(mac: str) -> Tuple[str,str,str]:
    """
    Return (vendor_name, device_type, brand) from MAC address.
    Lookup order:
      1. Built-in OUI_TABLE (instant, authoritative)
      2. In-memory cache of earlier API answers
      3. macvendors.com / maclookup.app — queued on a background thread, so the
         caller gets "Unknown" now and the device is updated when it answers
    Results are cached. A failed lookup is retried only after
    _VENDOR_RETRY_SECS so offline hosts don't hammer the free APIs.
    """
    prefix = oui(mac)
    if not prefix:
        return "Unknown", "Unknown", "Unknown"
    # Built-in OUI table (authoritative, never expires)
    if prefix in OUI_TABLE:
        entry = OUI_TABLE[prefix]
        _vendor_cache[prefix] = entry
        return entry
    # Successful live lookup → cache it
    cached = _vendor_cache.get(prefix)
    if cached is not None:
        return cached
    # Recent failure → serve "Unknown" until the retry window has passed.
    # Failures are deliberately NOT written to _vendor_cache, otherwise the
    # cache check above would make the retry window unreachable forever.
    fail_ts = _vendor_fail_ts.get(prefix)
    if fail_ts is not None and (time.time() - fail_ts) < _VENDOR_RETRY_SECS:
        return ("Unknown","Unknown","Unknown")
    _enqueue_vendor_lookup(mac)
    return ("Unknown","Unknown","Unknown")

def _guess_type(v: str) -> str:
    """Device type implied by a *manufacturer name alone* (vendor-API results).

    Only vendors whose OUIs are product-homogeneous may map to a type.  Big
    multi-category vendors (Apple, Samsung, HP, LG, Sony, Lenovo, Microsoft,
    Google, Amazon, ...) are deliberately NOT mapped: an Apple OUI can be a
    MacBook, an iPhone or an iPad, so calling it a phone would be a guess, and
    a wrong guess is worse than "Unknown" here.  Those devices get their type
    from the OUI table, hostname, ports and OS instead.
    """
    v = (v or "").lower()
    if not v:
        return "Unknown"

    def has(*names: str) -> bool:
        return any(re.search(r"\b" + re.escape(n) + r"\b", v) for n in names)

    if has("raspberry", "raspberrypi", "arduino", "espressif", "particle",
           "beagleboard", "odroid", "hardkernel", "pine64", "espressif systems"):
        return "IoT / SBC"
    if has("vmware", "virtualbox", "qemu", "xen", "parallels", "innotek"):
        return "Virtual Machine"
    if has("hikvision", "dahua", "axis", "axis communications", "wyze",
           "reolink", "amcrest", "foscam", "annke", "lorex", "uniview"):
        return "IP Camera"
    if has("cisco", "ubiquiti", "mikrotik", "netgear", "tp-link", "d-link",
           "zyxel", "juniper", "aruba", "ruckus", "fortinet", "sonicwall",
           "watchguard", "extreme networks", "meraki", "avm"):
        return "Router / Switch"
    if has("brother", "lexmark", "kyocera", "ricoh", "xerox", "konica",
           "oki", "zebra technologies", "seiko epson"):
        return "Printer"
    if has("sonos", "roku", "nest labs", "ecobee", "ring", "tuya", "shelly",
           "allterco", "lifx", "signify", "philips lighting"):
        return "Smart Device"
    if has("vizio", "hisense", "sagemcom"):
        return "Smart TV"
    return "Unknown"

# ─────────────────────────────────────────────────────────────────────────────
#  HOSTNAME RESOLUTION  –  PTR → mDNS → NetBIOS, cached, never raises
# ─────────────────────────────────────────────────────────────────────────────
# Most home/SMB subnets have no reverse DNS, so a PTR lookup alone leaves the
# device name blank.  Apple/IoT/Android hosts answer mDNS and Windows/Samba
# hosts answer a NetBIOS node-status query, so those two sources are tried
# after PTR.  Everything is cached (including failures) for _HOST_CACHE_TTL so
# repeated sweeps do not re-probe the same host.
_HOST_CACHE: Dict[str, Tuple[float, str]] = {}
_HOST_CACHE_TTL = 1800

def _valid_hostname(name: str, ip: str = "") -> bool:
    """Reject lookup results that are not usable device names."""
    n = (name or "").strip().strip(".").strip()
    if not n or len(n) > 253 or len(n) < 2:
        return False
    low = n.lower()
    if low in ("localhost", "localhost.localdomain", "unknown", "n/a", "none",
               "broadcasthost", "_gateway", "gateway"):
        return False
    if ip and n == ip:
        return False
    if re.fullmatch(r"[\d.]+", n):        # bare IP address
        return False
    return True

def _ptr_name(ip: str) -> str:
    """Reverse DNS (PTR).  Empty string when the resolver has no answer."""
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    return name if _valid_hostname(name, ip) else ""

def _mdns_name(ip: str, timeout: float = 0.8) -> str:
    """Ask the host itself for its mDNS reverse (PTR) record.

    Sends a unicast-response (QU) PTR query for <reversed-ip>.in-addr.arpa to
    the mDNS group and accepts only answers that come *from the target IP* and
    end in .local — so another device's advertisement can never be attributed
    to this host.
    """
    if not SCAPY_OK:
        return ""
    try:
        qname = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        query = bytes(DNS(id=0, rd=0, qd=DNSQR(qname=qname, qtype="PTR",
                                              qclass=32769)))
    except Exception:
        return ""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        s.settimeout(timeout)
        s.sendto(query, ("224.0.0.251", 5353))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(4096)
            except (socket.timeout, OSError):
                break
            if addr[0] != ip:          # only the target's own answer counts
                continue
            try:
                resp = DNS(data)
            except Exception:
                continue
            for i in range(int(getattr(resp, "ancount", 0) or 0)):
                try:
                    rr = resp.an[i]
                except Exception:
                    break
                if getattr(rr, "type", None) != 12:      # PTR
                    continue
                raw = rr.rdata
                name = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                name = (name or "").strip().rstrip(".")
                if name.lower().endswith(".local") and _valid_hostname(name, ip):
                    return name
    except Exception:
        return ""
    finally:
        if s is not None:
            s.close()
    return ""

def _nbns_name(ip: str, timeout: float = 0.6) -> str:
    """NetBIOS node-status (NBSTAT) query — the usual name source on Windows."""
    if not SCAPY_OK:
        return ""
    try:
        from scapy.layers.netbios import (NBNSNodeStatusRequest,
                                          NBNSNodeStatusResponse)
        request = bytes(NBNSNodeStatusRequest(QUESTION_NAME="*"))
    except Exception:
        return ""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(request, (ip, 137))
        data, _ = s.recvfrom(2048)
    except Exception:
        return ""
    finally:
        if s is not None:
            s.close()
    try:
        resp = NBNSNodeStatusResponse(data)
    except Exception:
        return ""
    # Suffix 0x00 is the workstation service, 0x20 the file-server service.
    best = ""
    for entry in getattr(resp, "NODE_NAME", []) or []:
        try:
            # scapy's NBNSNodeStatusResponseService exposes the 16-byte name
            # as NETBIOS_NAME (older code read a non-existent NODE_NAME).
            raw = getattr(entry, "NETBIOS_NAME", None)
            if raw is None:
                raw = getattr(entry, "NODE_NAME", "")
            name = raw.decode("ascii", "replace") if isinstance(raw, bytes) else str(raw)
            name = name.strip()
            suffix = int(getattr(entry, "SUFFIX", -1))
        except Exception:
            continue
        if suffix == 0 and _valid_hostname(name, ip):
            return name
        if suffix == 0x20 and _valid_hostname(name, ip) and not best:
            best = name
    return best

def resolve_hostname(ip: str) -> str:
    """Best name this process can get for a host: PTR → mDNS → NetBIOS.

    Returns "" when no source answers; the UI then shows the IP address.  The
    result is cached for _HOST_CACHE_TTL so a sweep never re-probes the same
    host every few seconds.
    """
    now = time.time()
    hit = _HOST_CACHE.get(ip)
    if hit and now - hit[0] < _HOST_CACHE_TTL:
        return hit[1]
    name = _ptr_name(ip) or _mdns_name(ip) or _nbns_name(ip)
    if len(_HOST_CACHE) > 4096:
        _HOST_CACHE.clear()
    _HOST_CACHE[ip] = (now, name)
    return name


def add_alert(ip: str, title: str, detail: str, severity: str = "MEDIUM",
              **meta):
    """Create an alert.

    `meta` carries the detection-engine fields (rule, attack, action, src, dst,
    incident, confidence, enrichment, count, last_ts).  They are optional so
    the scan/vulnerability code paths keep working unchanged.
    """
    with _lock:
        a = {
            "id": os.urandom(4).hex(),   # unique per alert (md5(ts) collided)
            "ip": ip, "title": title, "detail": detail,
            "severity": severity, "ts": _ts(), "ack": False,
            "last_ts": _ts(), "count": 1,
        }
        a.update({k: v for k, v in meta.items() if v is not None})
        alerts.appendleft(a)
        net_stats["alert_count"] += 1
    socketio.emit("new_alert", a)
    return a


# Ports an alert may name.  Only numbers in the known port universe count, so a
# count or a year in an alert's detail is never mistaken for a port.
_KNOWN_PORT_UNIVERSE = set(SCAN_PORTS) | set(VULNERABLE_PORTS)


def alert_ports_for(ip: str) -> set:
    """Port numbers that live alerts for `ip` currently name.

    Used to re-verify those ports with a second, independent probe, so a port an
    alert announced can never quietly drop out of the Ports/Vulnerabilities
    panels because one scanner's burst missed it.
    """
    out: set = set()
    with _lock:
        rows = list(alerts)
    for a in rows:
        if a.get("ip") != ip or a.get("ack"):
            continue
        for n in re.findall(r"(?<![\d.])(\d{1,5})(?![\d.])", a.get("detail") or ""):
            p = int(n)
            if p in _KNOWN_PORT_UNIVERSE:
                out.add(p)
    return out

# ─────────────────────────────────────────────────────────────────────────────
#  VENDOR → OS  (authoritative lookup before any scanning)
# ─────────────────────────────────────────────────────────────────────────────

# Android-only brands — these devices run Android regardless of model
_ANDROID_VENDORS: Tuple[str, ...] = (
    "samsung", "xiaomi", "redmi", "poco", "huawei", "honor",
    "oppo", "realme", "oneplus", "vivo", "iqoo", "infinix",
    "tecno", "itel", "gionee", "alcatel", "nokia mobile",
    "motorola", "lenovo mobile", "zte", "lg mobile", "htc",
    "meizu", "nubia", "blackview", "ulefone", "doogee",
    "oukitel", "umidigi", "cubot", "blu products", "wiko", "micromax",
    "lava", "karbonn", "symphony", "walton", "pixel", "fairphone",
    "nothing phone", "onyx boox", "sony mobile", "sharp mobile",
)

# Apple device_type values from OUI_TABLE → OS mapping
_APPLE_DTYPE_OS: Dict[str, str] = {
    "iPhone":  "iOS",
    "iPad":    "iPadOS",
    "MacBook": "macOS",
    "Mac":     "macOS",
    "iMac":    "macOS",  # handled by hostname but belt+suspenders
}

def infer_os_from_vendor(vendor: str, device_type: str) -> Tuple[str, str]:
    """
    Return (os_string, confidence) purely from vendor name + OUI device_type.
    Called as the FIRST signal in _deep_scan before any network probing,
    so known devices get the right OS immediately.
    Returns ("", "") when no confident inference is possible.
    """
    v = vendor.lower().strip()
    dt = (device_type or "").lower()

    # ── Apple ──────────────────────────────────────────────────────────────────
    if "apple" in v:
        # Use the device_type from OUI table to distinguish iPhone vs Mac
        if "iphone" in dt:
            return "iOS", "High (Apple iPhone OUI)"
        if "ipad" in dt:
            return "iPadOS", "High (Apple iPad OUI)"
        if any(x in dt for x in ("macbook", "mac", "imac", "desktop", "laptop", "pc")):
            return "macOS", "High (Apple Mac OUI)"
        # Fallback: if we can't tell phone vs mac, use hostname patterns later
        return "iOS / macOS", "Medium (Apple OUI)"

    # ── Pure Android brands ────────────────────────────────────────────────────
    # Whole-word brand match: "vivo" must not match Vivotek, "pixel" must not
    # match an unrelated company name containing that substring.
    if any(re.search(r"\b" + re.escape(brand) + r"\b", v) for brand in _ANDROID_VENDORS):
        # Confirm it's a phone/tablet, not a TV (Samsung makes both)
        if any(x in dt for x in ("smart tv", "television", "tv")):
            return "Android TV / Tizen", "High (vendor+type)"
        if any(x in dt for x in ("chromecast", "streaming", "firetv")):
            return "Android / Cast OS", "High (vendor+type)"
        return "Android", "High (vendor OUI)"

    # ── Google Pixel ───────────────────────────────────────────────────────────
    if "google" in v:
        if "pixel" in dt:
            return "Android", "High (Google Pixel OUI)"
        if any(x in dt for x in ("chromecast", "home", "hub")):
            return "Cast OS / Android", "High (Google OUI)"

    # ── Microsoft Xbox ──────────────────────────────────────────────────────────
    if "microsoft" in v and "xbox" in dt:
        return "Xbox OS", "High (Microsoft Xbox OUI)"

    # ── Sony PlayStation ────────────────────────────────────────────────────────
    if "sony" in v and "playstation" in dt:
        return "PlayStation OS", "High (Sony OUI)"

    # ── Nintendo ────────────────────────────────────────────────────────────────
    if "nintendo" in v:
        return "Nintendo Switch OS", "High (Nintendo OUI)"

    # ── Raspberry Pi ────────────────────────────────────────────────────────────
    if "raspberry" in v:
        return "Linux (Raspberry Pi OS)", "High (RPi OUI)"

    # ── VMs ─────────────────────────────────────────────────────────────────────
    if any(x in v for x in ("vmware", "virtualbox", "qemu", "xen", "parallels")):
        return "Linux / Windows (VM)", "High (VM OUI)"

    # ── Printers ────────────────────────────────────────────────────────────────
    if any(x in v for x in ("hp", "canon", "epson", "brother", "xerox",
                             "ricoh", "lexmark", "kyocera", "konica")):
        if "printer" in dt or "print" in v:
            return "Printer Firmware", "High (vendor OUI)"

    # ── IP Cameras ──────────────────────────────────────────────────────────────
    if any(x in v for x in ("hikvision", "dahua", "axis", "wyze", "reolink",
                             "amcrest", "foscam", "annke", "lorex")):
        return "Embedded Linux (IP Camera)", "High (vendor OUI)"

    # ── Network gear ────────────────────────────────────────────────────────────
    if any(x in v for x in ("cisco", "ubiquiti", "mikrotik", "netgear", "tp-link",
                             "d-link", "zyxel", "juniper", "aruba", "ruckus")):
        return "Network OS (Embedded Linux)", "High (vendor OUI)"

    return "", ""   # no confident inference


# ─────────────────────────────────────────────────────────────────────────────
#  OS DETECTION  (vendor-first, then hostname, ports, TTL)
# ─────────────────────────────────────────────────────────────────────────────
def detect_os(ip: str, hostname: str, mac: str,
              vendor: str, device_type: str,
              open_ports: dict, ttl: int) -> Tuple[str, str]:
    """
    Returns (os_string, confidence).
    Priority:
      1. Vendor+device_type (authoritative for known brands)
      2. Hostname regex patterns
      3. Open port fingerprint
      4. TTL heuristic
    """
    # 1. Vendor-based inference (most accurate for consumer devices)
    os_v, conf_v = infer_os_from_vendor(vendor, device_type)
    if os_v and "unknown" not in os_v.lower():
        return os_v, conf_v

    # 2. Hostname pattern matching
    h = hostname or ""
    for pattern, os_name, _, confidence in HOSTNAME_OS_PATTERNS:
        if pattern.search(h):
            return os_name, confidence

    # 3. Port-based fingerprint
    open_set = {p for p, i in open_ports.items() if i.get("state") == "open"}
    if {135, 139, 445} & open_set:
        return "Windows", "Medium (SMB ports)"
    if {3389} & open_set:
        return "Windows", "Medium (RDP port)"
    if {22} & open_set and not ({80, 443} & open_set):
        return "Linux / Unix", "Low (SSH only)"
    if {548, 5353} & open_set:
        return "macOS", "Medium (AFP/mDNS)"
    if {62078} & open_set:
        return "iOS", "High (lockdownd port)"
    if {5555} & open_set:
        return "Android", "High (ADB port)"

    # 4. MAC OUI fallback (generic)
    v_low = vendor.lower()
    if any(x in v_low for x in ["raspberry", "espressif", "arduino"]):
        return "Linux (Embedded)", "Low (IoT OUI)"
    if any(x in v_low for x in ["vmware", "virtualbox", "qemu"]):
        return "Linux / Windows (VM)", "Low (VM OUI)"

    # 5. TTL fallback
    if ttl > 0:
        return _os_from_ttl(ttl)

    return "Unknown", ""


# ─────────────────────────────────────────────────────────────────────────────
#  NETWORK SCANNER
# ─────────────────────────────────────────────────────────────────────────────
class NetworkScanner:
    def __init__(self):
        # NOTE: python-nmap stores scan results on the PortScanner instance, so
        # a single shared scanner is NOT thread-safe. Every scan gets its own
        # instance via _scanner(); this attribute is kept only for readiness
        # checks ("is the nmap module usable at all").
        self.nm = nmap.PortScanner() if NMAP_OK else None
        self._strategy: Optional[str] = None   # cached working strategy

    @staticmethod
    def _scanner():
        """Fresh, per-call PortScanner (see note above)."""
        return nmap.PortScanner() if NMAP_OK else None

    # ── Discovery ─────────────────────────────────────────────────────────────

    def discover(self, network: str) -> List[dict]:
        """Try all strategies; return first non-empty result. Never raises."""
        strategies = []
        if SCAPY_OK and IS_ROOT:
            strategies.append(("scapy_arp",  self._scapy_arp))
        strategies += [
            ("nmap_arp",   self._nmap_arp),
            ("nmap_ping",  self._nmap_ping),
            ("arp_table",  self._arp_table),
        ]
        # Try cached strategy first
        if self._strategy:
            strategies.sort(key=lambda s: 0 if s[0] == self._strategy else 1)

        for name, fn in strategies:
            try:
                result = fn(network)
                if result:
                    if self._strategy != name:
                        print(f"[Netron] Discovery via '{name}' → {len(result)} hosts")
                        self._strategy = name
                    return result
            except Exception:
                pass

        # Absolute fallback: return gateway only
        gw = network.split("/")[0].rsplit(".", 1)[0] + ".1"
        return [{"ip": gw, "mac": "N/A"}]

    def _scapy_arp(self, network: str) -> List[dict]:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        ans, _ = srp(pkt, timeout=2, verbose=False)
        return [{"ip": r.psrc, "mac": r.hwsrc.upper()} for _, r in ans]

    def _nmap_arp(self, network: str) -> List[dict]:
        nm = self._scanner()
        if not nm:
            return []
        nm.scan(hosts=network, arguments="-sn -PR -n --host-timeout 3s -T5 --min-parallelism 32")
        return [{"ip": h, "mac": nm[h]["addresses"].get("mac","N/A")}
                for h in nm.all_hosts()]

    def _nmap_ping(self, network: str) -> List[dict]:
        nm = self._scanner()
        if not nm:
            return []
        nm.scan(hosts=network, arguments="-sn -PE -PS22,80,443,8080 -n --host-timeout 3s -T5 --min-parallelism 32")
        return [{"ip": h, "mac": nm[h]["addresses"].get("mac","N/A")}
                for h in nm.all_hosts()]

    def _arp_table(self, network: str) -> List[dict]:
        found: Dict[str, dict] = {}
        try:
            net_obj = ipaddress.IPv4Network(network, strict=False)
        except Exception:
            net_obj = None

        def _in_net(ip_s: str) -> bool:
            try:
                return net_obj is None or ipaddress.ip_address(ip_s) in net_obj
            except Exception:
                return False

        # Linux /proc/net/arp
        if os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp") as f:
                    for line in f.readlines()[1:]:
                        p = line.split()
                        if len(p) >= 4 and p[3] not in ("00:00:00:00:00:00", ""):
                            ip_s = p[0]
                            if _in_net(ip_s):
                                found[ip_s] = {"ip": ip_s, "mac": p[3].upper()}
            except Exception:
                pass

        # Cross-platform `arp -a` – only when /proc/net/arp is unavailable or
        # returned nothing. Never fork a subprocess on every 3 s poll.
        if not found:
            try:
                out = subprocess.check_output(
                    ["arp", "-a"], stderr=subprocess.DEVNULL, timeout=8
                ).decode(errors="ignore")
                for line in out.splitlines():
                    # Linux/BSD: "? (192.168.1.10) at aa:bb:cc:dd:ee:ff [ether] on eth0"
                    m = re.search(
                        r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-fA-F:]{17})", line)
                    if not m:
                        # Windows: " 192.168.1.10        aa-bb-cc-dd-ee-ff     dynamic"
                        m = re.match(
                            r"\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"
                            r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", line)
                    if m:
                        ip_s = m.group(1)
                        mac  = m.group(2).replace("-", ":").upper()
                        # Skip incomplete entries (00:…:00 / ff:ff:ff:ff:ff:ff)
                        if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                            continue
                        if _in_net(ip_s):
                            found[ip_s] = {"ip": ip_s, "mac": mac}
            except Exception:
                pass

        return list(found.values())

    # ── Port scan ─────────────────────────────────────────────────────────────

    # ── RustScan discovery ────────────────────────────────────────────────────

    def rustscan(self, ip: str, ports=None, port_range: str = "") -> Optional[set]:
        """Open TCP ports rustscan actually reported, or None if it did not run.

        None means "the scan did not happen" (binary missing, timeout, non-zero
        exit) so the caller can fall back to nmap.  An empty set means rustscan
        ran and saw nothing open, which is a real result.
        """
        if not RUSTSCAN_OK:
            return None
        cmd = [RUSTSCAN_BIN, "-n", "--no-banner", "-g", "-a", ip,
               "-b", RUSTSCAN_BATCH, "-t", RUSTSCAN_TIMEOUT,
               "--tries", RUSTSCAN_TRIES]
        if port_range:
            cmd += ["-r", port_range]
        else:
            cmd += ["-p", ",".join(str(p) for p in (ports or SCAN_PORTS))]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=RUSTSCAN_DEADLINE)
        except Exception as exc:
            _rustscan_failed(str(exc))
            return None
        if proc.returncode != 0:
            _rustscan_failed((proc.stderr or proc.stdout or "").strip()[-200:])
            return None
        found: set = set()
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            # greppable: "192.168.2.1 -> [22,53,80]"
            m = re.search(r"\[([0-9,\s]*)\]\s*$", line)
            if m:
                found |= {int(n) for n in re.findall(r"\d+", m.group(1))}
                continue
            # plain: "Open 192.168.2.1:22"
            m = re.search(r":(\d{1,5})\s*$", line)
            if m and ("Open" in line or "open" in line):
                found.add(int(m.group(1)))
        return {p for p in found if 0 < p < 65536}

    def _nmap_services(self, ip: str, ports: List[int]) -> Optional[dict]:
        """nmap probe of exactly `ports` for service names / versions."""
        nm = self._scanner()
        if not nm or not ports:
            return None
        timing = ("-n -Pn -T5 --max-retries 2 --min-parallelism 16 "
                  "--initial-rtt-timeout 250ms --max-rtt-timeout 1s "
                  "--host-timeout 30s")
        args  = (f"-sV --version-light {timing}" if IS_ROOT else f"-sT {timing}")
        try:
            nm.scan(ip, ",".join(str(p) for p in sorted(ports)), arguments=args)
            if ip not in nm.all_hosts():
                return None
            out: dict = {}
            for proto in nm[ip].all_protocols():
                for port, info in nm[ip][proto].items():
                    if info.get("state") != "open":
                        continue
                    out[int(port)] = {
                        "state":    "open",
                        "service":  info.get("name", ""),
                        "version":  f"{info.get('product','')} {info.get('version','')}".strip(),
                        "protocol": proto,
                    }
            return out
        except Exception:
            return None

    def port_scan(self, ip: str) -> dict:
        """Returns {port: {state, service, version, protocol}}"""
        # ── 1. Discovery ──────────────────────────────────────────────────────
        # rustscan finds the open ports (fast); it always probes SCAN_PORTS so
        # every port an alert or finding can name is covered, and optionally a
        # wider range.  nmap then names the services on what was found.
        found: set = set()
        used_rustscan = False
        if RUSTSCAN_OK:
            base = self.rustscan(ip, ports=SCAN_PORTS)
            if base is not None:
                used_rustscan = True
                found |= base
                if RUSTSCAN_RANGE:
                    extra = self.rustscan(ip, port_range=RUSTSCAN_RANGE)
                    if extra:
                        found |= extra
        if used_rustscan:
            svc = self._nmap_services(ip, sorted(found)) or {}
            # Union: a port rustscan saw open stays open even if nmap's single
            # pass on that port disagreed; nmap can also surface a port a busy
            # rustscan burst dropped.
            result: dict = dict(svc)
            for port in found:
                result.setdefault(port, {
                    "state": "open", "service": "", "version": "", "protocol": "tcp"})
            # ── Verify alert / previously-open ports ─────────────────────────
            # A fast burst can drop a SYN, and a dropped SYN would remove a real
            # port from the panels while its alert stays.  Re-probe exactly the
            # ports an alert names or this device had open with nmap, and keep
            # whatever that independent pass confirms.
            must = set(alert_ports_for(ip))
            with _lock:
                must |= {int(p) for p in ((devices.get(ip) or {}).get("open_ports") or {})
                         if str(p).isdigit()}
            missing = sorted(must - set(result))
            if missing:
                again = self._nmap_services(ip, missing) or {}
                for port, info in again.items():
                    result.setdefault(port, info)
                if again:
                    print(f"[Netron] verified {ip} port(s) a burst scan missed: "
                          f"{', '.join(str(p) for p in sorted(again))}")
            return result

        # ── 2. nmap-only path (rustscan absent or failed) ─────────────────────
        nm = self._scanner()
        if not nm:
            return self._tcp_fallback(ip)
        ports = ",".join(str(p) for p in SCAN_PORTS)
        # -n                : no per-host reverse DNS (the caller resolves once)
        # -Pn               : discovery already proved the host is up
        # --min-parallelism stays modest (16): the sweep runs one nmap per host,
        # so 16 hosts x 64 simultaneous probes saturated the Wi-Fi link and made
        # hosts answer nothing at all (false 'all ports closed' results).
        # --max-retries 2   : a filtered port costs two retransmits, not the
        #                     default ten
        # --version-light   : real version detection, fewer probe groups (nmap
        #                     -sV's default probe set is the biggest cost here)
        # RTT timeouts stay generous (250 ms initial / 1 s max): shrinking them
        # further would start reporting slow-but-open ports as filtered on
        # Wi-Fi, i.e. it would hide findings to win a second.
        timing = ("-n -Pn -T5 --max-retries 2 --min-parallelism 16 "
                  "--initial-rtt-timeout 250ms --max-rtt-timeout 1s "
                  "--host-timeout 12s")
        args  = (f"-sV --version-light {timing}" if IS_ROOT else f"-sT {timing}")
        try:
            nm.scan(ip, ports, arguments=args)
            if ip not in nm.all_hosts():
                return self._tcp_fallback(ip)
            result = {}
            for proto in nm[ip].all_protocols():
                for port, info in nm[ip][proto].items():
                    # nmap reports every scanned port; only listening ports are
                    # kept, otherwise the UI would count closed/filtered ports
                    # as open (and disagree with the Ports panel).
                    if info.get("state") != "open":
                        continue
                    result[port] = {
                        "state":    info.get("state", ""),
                        "service":  info.get("name", ""),
                        "version":  f"{info.get('product','')} {info.get('version','')}".strip(),
                        "protocol": proto,
                    }
            return result
        except Exception:
            return self._tcp_fallback(ip)

    def _tcp_fallback(self, ip: str) -> dict:
        """
        Pure-Python parallel TCP connect scan (no root needed).
        Probes SCAN_PORTS with a 0.35-second connect timeout, all at once.
        """
        deduped = SCAN_PORTS

        result: dict = {}
        def probe(port: int):
            try:
                with socket.create_connection((ip, port), timeout=0.35):
                    svc = ""
                    try: svc = socket.getservbyport(port, "tcp")
                    except Exception: pass
                    return port, {"state":"open","service":svc,"version":"","protocol":"tcp"}
            except Exception:
                return port, None

        # Shared, module-level pool: a per-call pool inside the 12-worker scan
        # pool would allow 12 × 48 = 576 threads at once.
        for port, info in _TCP_POOL.map(probe, deduped):
            if info:
                result[port] = info
        return result

    # ── TTL ping ──────────────────────────────────────────────────────────────

    def ping_ttl(self, ip: str) -> int:
        windows = platform.system().lower() == "windows"
        # Windows needs -w 1000: the default reply timeout is 4 s, which would
        # outlive the 2 s subprocess timeout and always yield TTL 0.
        cmd = (["ping", "-n", "1", "-w", "1000"] if windows
               else ["ping", "-c", "1", "-W", "1"])
        cmd.append(ip)
        try:
            out = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, timeout=2
            ).decode(errors="ignore")
            m = re.search(r"ttl[= ](\d+)", out, re.I)
            return int(m.group(1)) if m else 0
        except Exception:
            return 0

    # ── nmap OS (root only) ───────────────────────────────────────────────────

    def nmap_os(self, ip: str) -> Tuple[str, str]:
        nm = self._scanner()
        if not IS_ROOT or not nm:
            return "", ""
        try:
            nm.scan(ip, arguments="-O -n --host-timeout 8s -T5 --max-retries 2 --max-os-tries 1")
            if ip in nm.all_hosts():
                matches = nm[ip].get("osmatch", [])
                if matches:
                    m = matches[0]
                    return m.get("name",""), f"{m.get('accuracy','')}%"
        except Exception:
            pass
        return "", ""

    # ── Vulnerability assessment ──────────────────────────────────────────────

    def assess_vulns(self, open_ports: dict) -> List[dict]:
        seen, vulns, open_nums = set(), [], set()
        for port, info in open_ports.items():
            if not isinstance(info, dict) or info.get("state") != "open":
                continue
            # Port keys are ints from nmap and the TCP fallback, but a JSON
            # round-trip turns them into strings. Coerce so a finding can
            # never silently disappear because of the key type.
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            open_nums.add(port)
            if port in VULNERABLE_PORTS and port not in seen:
                seen.add(port)
                name, sev, desc = VULNERABLE_PORTS[port]
                # Prefer the service name the scan actually saw ("domain"), so
                # the finding, the Ports panel and the alert use one label.
                label = service_label(port, info.get("service", "")) or name
                vulns.append({"port":port,"service":label,"severity":sev,
                               "description":desc,"version":info.get("version","")})
        # NoSQL trifecta check
        exposed = [p for p in (6379,27017,9200) if p in open_nums]
        if exposed:
            vulns.append({"port":0,"service":"Unauthenticated DB","severity":"CRITICAL",
                          "description":f"NoSQL ports reachable on this host: {exposed} – Netron does not verify whether authentication is enforced",
                          "version":""})
        return vulns


# ─────────────────────────────────────────────────────────────────────────────
#  PACKET CAPTURE  (Scapy when root, psutil always)
# ─────────────────────────────────────────────────────────────────────────────
# Well-known ports → application protocol label. This is PORT-BASED
# identification only (no payload inspection) – it's a best-effort hint for
# the traffic view, not a guarantee.
_APP_PORTS = {
    # TCP services
    (20,  "tcp"): "FTP-DATA",   (21,  "tcp"): "FTP",
    (22,  "tcp"): "SSH",        (23,  "tcp"): "Telnet",
    (25,  "tcp"): "SMTP",       (53,  "tcp"): "DNS",
    (80,  "tcp"): "HTTP",       (110, "tcp"): "POP3",
    (143, "tcp"): "IMAP",       (443, "tcp"): "TLS/HTTPS",
    (465, "tcp"): "SMTPS",      (587, "tcp"): "SMTP",
    (993, "tcp"): "IMAPS",      (995, "tcp"): "POP3S",
    (1433,"tcp"): "MSSQL",      (1521,"tcp"): "Oracle",
    (3306,"tcp"): "MySQL",      (3389,"tcp"): "RDP",
    (5432,"tcp"): "PostgreSQL", (5900,"tcp"): "VNC",
    (6379,"tcp"): "Redis",      (8080,"tcp"): "HTTP",
    (8443,"tcp"): "HTTPS",      (9200,"tcp"): "Elasticsearch",
    (27017,"tcp"): "MongoDB",
    # UDP services
    (53,  "udp"): "DNS",        (67,  "udp"): "DHCP",
    (68,  "udp"): "DHCP",       (69,  "udp"): "TFTP",
    (123, "udp"): "NTP",        (137, "udp"): "NetBIOS",
    (161, "udp"): "SNMP",       (514, "udp"): "Syslog",
    (443, "udp"): "QUIC",       (1900,"udp"): "SSDP",
    (3478,"udp"): "STUN",       (5060,"udp"): "SIP",
    (5353,"udp"): "mDNS",       (5355,"udp"): "LLMNR",
}

def _app_proto(sport, dport, transp) -> str:
    """Best-effort application label for a flow (destination port first)."""
    for p in (dport, sport):
        hit = _APP_PORTS.get((p, transp))
        if hit:
            return hit
    return ""

# ═════════════════════════════════════════════════════════════════════──────
#  VoIP PROTOCOL CLASSIFICATION
# ═════════════════════════════════════════════════════════════════════──────
# Ports assigned to a VoIP protocol by its own standard / IANA.  A label taken
# from this table is a fact about the port, not a guess about the contents.
VOIP_PORTS: Dict[Tuple[int, str], str] = {
    (5060, "udp"): "SIP",      (5060, "tcp"): "SIP",
    (5061, "udp"): "SIP/TLS",  (5061, "tcp"): "SIP/TLS",
    (1719, "udp"): "H.323 RAS", (1720, "tcp"): "H.323",
    (2427, "udp"): "MGCP",     (2727, "udp"): "MGCP",
    (2000, "udp"): "SCCP",     (2000, "tcp"): "SCCP",
    (4569, "udp"): "IAX2",
    (3478, "udp"): "STUN",     (3478, "tcp"): "STUN",
}

# First token of a SIP request, or the status line of a SIP response.
_SIP_TOKENS: Tuple[bytes, ...] = (
    b"INVITE", b"ACK", b"BYE", b"CANCEL", b"OPTIONS", b"REGISTER",
    b"PRACK", b"SUBSCRIBE", b"NOTIFY", b"PUBLISH", b"INFO", b"REFER",
    b"MESSAGE", b"UPDATE", b"SIP/2.0",
)

# UDP ports that carry a different protocol; a frame on one of these is never
# relabelled RTP/RTCP even if its first byte happens to look like a header.
_NOT_RTP_PORTS = frozenset({
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 3478,
    3702, 4500, 5353, 5355, 5060, 5061,
})


def voip_label(sport, dport, transp, payload: bytes = b"") -> str:
    """VoIP protocol for one packet, or "" when it is not VoIP traffic.

    Two independent kinds of evidence are accepted:

    * **Port evidence** – the port belongs to a VoIP protocol (works in psutil
      socket-table mode too, where no payload is available).
    * **Payload evidence** – a real SIP request/status line, or a well-formed
      RTP/RTCP header (version 2, a registered payload type, consistent length).

    RTP and RTCP use dynamic ports, so they are only ever reported from a header
    check on captured bytes -- never from a port range alone.
    """
    s = int(sport or 0)
    d = int(dport or 0)
    t = (transp or "").lower()
    for p in (d, s):
        hit = VOIP_PORTS.get((p, t))
        if hit:
            return hit
    if not payload:
        return ""
    head = payload[:16].lstrip()
    for tok in _SIP_TOKENS:
        if head.startswith(tok):
            return "SIP"
    if t != "udp" or len(payload) < 8:
        return ""
    if (payload[0] >> 6) != 2:          # RTP/RTCP version field must be 2
        return ""
    if s <= 1024 and d <= 1024:
        return ""
    if s in _NOT_RTP_PORTS or d in _NOT_RTP_PORTS:
        return ""
    pt = payload[1]
    if 192 <= pt <= 223:                # RTCP packet type range
        declared = (int.from_bytes(payload[2:4], "big") + 1) * 4
        if 8 <= declared <= len(payload):
            return "RTCP"
        return ""
    payload_type = pt & 0x7F
    # Registered RTP payload types: 0-34 static, 96-127 dynamic.  35-95 are
    # unassigned, so such a frame is not confidently RTP and is left unlabelled.
    if payload_type <= 34 or 96 <= payload_type <= 127:
        return "RTP"
    return ""

# ═════════════════════════════════════════════════════════════════════════════
#  DETECTION ENGINE
# ═════════════════════════════════════════════════════════════════════════════
#  Design rules this module follows:
#
#   * A rule is only emitted from telemetry Netron actually observes.  Every
#     rule declares its data source (`requires`); /api/detections reports the
#     live status of each source, so "no alert" never silently means "no
#     detection capability".
#   * Per-host baselines (bytes/minute) and per-role thresholds instead of one
#     global fixed threshold.  Servers, workstations and IoT devices are
#     classified and treated differently.
#   * Alerts are enriched (hostname, vendor, role, criticality, VLAN, TI) and
#     scored, then correlated per source into incidents: a scan followed by
#     auth failures and a login is one incident, not three unrelated alerts.
#   * Dedupe + rate-limit: repeated hits inside a cooldown update the existing
#     alert's count instead of creating a new one, and each rule has an hourly
#     emission cap so one noisy host cannot flood the list.
#   * Every alert carries an ATT&CK technique id and a response action.
#
#  Not implemented (and therefore never reported as active): detections that
#  need decrypted auth protocols or Windows Domain Controller audit logs --
#  SSH/RDP/SMB/LDAP/Kerberos/VPN failed-login events can only come from host or
#  DC logs; Netron reads Linux auth logs when available and says so.

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default

DET_SCAN_WINDOW    = 60      # seconds
DET_SCAN_HOSTS     = _env_int("NETRON_SCAN_HOSTS", 10)
DET_SCAN_PORTS     = _env_int("NETRON_SCAN_PORTS", 15)
DET_SCAN_BREADTH   = 3       # max ports per host for a horizontal scan
DET_RST_WINDOW     = 30
DET_RST_BURST      = 30
DET_ICMP_WINDOW    = 30
DET_ICMP_BURST     = 20
DET_ICMP_BIG       = 1200    # payload bytes before an ICMP packet looks tunnelled
DET_ARP_WINDOW     = 10
DET_ARP_FLOOD      = 20
DET_DNS_WINDOW     = 60
DET_DNS_ENT_MINLEN = 30      # label length that starts looking like encoding
DET_DNS_ENT_BITS   = 3.3    # hex-encoded labels sit around 3.5-3.9 bits/char
DET_DNS_ENT_COUNT  = 3
DET_DNS_TXT_COUNT  = 20
DET_DNS_NX_COUNT   = 25
DET_DNS_BIG_UDP    = 1000    # bytes (512 + EDNS/DNSSEC stays below this)
DET_SMB_OPS        = 200
DET_SMB_SESSIONS   = 10
DET_KRB_TGS        = 20
DET_AUTH_WINDOW    = 300
DET_AUTH_FAILS     = 8
DET_AUTH_USERS     = 5
DET_AUTH_SRCS      = 5
DET_BW_MIN_BYTES   = 5 * 1024 * 1024
DET_BW_FACTOR      = 4.0
DET_BW_WINDOW      = 60
DET_BEACON_MIN     = 6
DET_BEACON_IV_CV   = 0.10
DET_BEACON_SIZE_CV = 0.15
DET_LONG_FLOW_SECS = 1800
BUSINESS_START     = _env_int("NETRON_BUSINESS_START", 7)
BUSINESS_END       = _env_int("NETRON_BUSINESS_END", 19)

# Known DoH resolver hostnames.  "Sanctioned" resolvers are configured with
# NETRON_APPROVED_DOH (comma separated suffixes; empty = none sanctioned).
DOH_HOSTS = frozenset({
    "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.google",
    "dns.quad9.net", "doh.opendns.com", "dns.adguard-dns.com",
    "dns.nextdns.io", "doh.cleanbrowsing.org", "dns.mullvad.net",
    "doh.libredns.gr", "doh.dns.sb", "dns.google.com",
})
# Commercial remote-management / tunnelling service domains.  Approved ones are
# set with NETRON_APPROVED_RMM.
RMM_HOSTS = frozenset({
    "anydesk.com", "teamviewer.com", "screenconnect.com", "logmein.com",
    "splashtop.com", "gotomypc.com", "rustdesk.com", "ngrok.io",
    "ngrok-free.app", "zohoassist.com", "remoteutilities.com", "supremo.com",
    "dwservice.net", "iperiusremote.com",
})
MINING_HOSTS = frozenset({
    "pool.minexmr.com", "xmrpool.eu", "nanopool.org", "2miners.com",
    "ethermine.org", "flexpool.io", "miningpoolhub.com", "braiins.com",
    "antpool.com", "f2pool.com", "poolin.com", "viabtc.com",
    "hashvault.pro", "moneroocean.stream", "supportxmr.com",
})
CLOUD_UPLOAD_HOSTS = frozenset({
    "dropbox.com", "drive.google.com", "onedrive.live.com", "sharepoint.com",
    "box.com", "mega.nz", "mediafire.com", "pastebin.com", "hastebin.com",
    "transfer.sh", "file.io", "wetransfer.com", "gofile.io", "0x0.st",
    "catbox.moe", "litterbox.catbox.moe", "paste.ee", "clbin.com",
})
HTTP_PORTS = frozenset({80, 8080, 8000, 8008, 8081, 8082, 8083, 8084, 8085,
                        8086, 8087, 8088, 8090, 8888, 9000, 9090, 3128, 443})
ADMIN_PORTS = {3389: "RDP", 445: "SMB", 23: "Telnet", 5900: "VNC",
               5985: "WinRM", 5986: "WinRM-TLS", 22: "SSH"}
DB_PORTS = frozenset({1433, 1521, 3306, 5432, 6379, 9200, 27017, 5984, 8086})
DC_PORTS = frozenset({88, 389, 636, 3268, 3269})
MAIL_PORTS = frozenset({25, 587, 465, 110, 143, 993, 995})
IOT_TYPES = frozenset({"IoT / SBC", "Smart Device", "IP Camera", "Smart TV",
                       "Printer", "Smart Speaker", "Smart Home"})
DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR",
              15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}

SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def _sev_up(sev: str, steps: int = 1) -> str:
    try:
        i = SEV_ORDER.index(sev)
    except ValueError:
        return sev
    return SEV_ORDER[min(len(SEV_ORDER) - 1, i + steps)]

def _domain_match(name: str, suffixes) -> str:
    n = (name or "").strip().lower().rstrip(".")
    if not n:
        return ""
    for s in suffixes:
        if n == s or n.endswith("." + s):
            return s
    return ""

def _dns_base(qname: str) -> str:
    labels = [l for l in (qname or "").rstrip(".").split(".") if l]
    return ".".join(labels[-2:]) if len(labels) >= 2 else (qname or "")

def _entropy_bits(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def _is_public_ip(ip: str) -> bool:
    """True only for globally routable unicast addresses."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or
                a.is_multicast or a.is_reserved or a.is_unspecified)

def _is_random_mac(mac: str) -> bool:
    """Locally-administered bit set -> randomised (phone privacy) MAC."""
    try:
        return bool(int(str(mac).replace("-", ":").split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False

# ── Asset inventory (new-MAC detection + optional owner/criticality) ──────────
_STATE_DIR     = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")
INVENTORY_PATH = os.environ.get("NETRON_INVENTORY", os.path.join(_STATE_DIR, "netron-inventory.json"))
_inv_lock      = threading.Lock()
_inv: Dict[str, dict] = {}
_inv_loaded    = False
_inv_last_save = 0.0

def inventory_load() -> None:
    global _inv_loaded
    with _inv_lock:
        if _inv_loaded:
            return
        _inv_loaded = True
        try:
            with open(INVENTORY_PATH, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data.get("macs"), dict):
                _inv.update({str(k).upper(): v for k, v in data["macs"].items()
                             if isinstance(v, dict)})
        except (FileNotFoundError, ValueError, OSError):
            pass

def inventory_save(force: bool = False) -> None:
    global _inv_last_save
    with _inv_lock:
        now = time.time()
        if not force and now - _inv_last_save < 30:
            return
        _inv_last_save = now
        try:
            os.makedirs(os.path.dirname(INVENTORY_PATH), exist_ok=True)
            tmp = INVENTORY_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "macs": _inv}, fh, indent=1, sort_keys=True)
            os.replace(tmp, INVENTORY_PATH)
        except OSError as e:
            log.warning("[Netron] inventory save failed: %s", e)

def inventory_get(mac: str) -> dict:
    inventory_load()
    with _inv_lock:
        return dict(_inv.get(str(mac).upper(), {}))

def inventory_mark(mac: str, ip: str, vendor: str = "") -> bool:
    """Record a MAC in the inventory.  Returns True if it was newly added."""
    inventory_load()
    mac = str(mac).upper()
    if len(mac) < 11 or mac in ("N/A", ""):
        return False
    with _inv_lock:
        ent = _inv.get(mac)
        new  = ent is None
        if ent is None:
            ent = {"first_seen": _ts(), "randomized": _is_random_mac(mac)}
            if vendor:
                ent["vendor"] = vendor
            _inv[mac] = ent
        ent["last_ip"]   = ip
        ent["last_seen"] = _ts()
    if not new:
        inventory_save()
    else:
        inventory_save(force=True)
    return new

# ── Rule catalog ──────────────────────────────────────────────────────────────
# requires: capture (network-wide packet capture), authlog (readable Linux
# auth log), inventory (local asset DB), dnsfeed (optional internet feed).
def _R(title, family, requires, severity, attack, action, cooldown=600, rate=6):
    return {"title": title, "family": family, "requires": requires,
            "severity": severity, "attack": attack, "action": action,
            "cooldown": cooldown, "rate": rate}

RULES: Dict[str, dict] = {
    # ── Reconnaissance ────────────────────────────────────────────────────────
    "PORT_SCAN_HORIZONTAL": _R("Horizontal port scan", "recon", "capture", "HIGH",
        "T1046 Network Service Discovery", "Investigate source host; block at perimeter", 600),
    "PORT_SCAN_VERTICAL": _R("Vertical port scan", "recon", "capture", "HIGH",
        "T1046 Network Service Discovery", "Investigate source host; rate-limit on switch", 600),
    "IOT_TELNET_SCAN": _R("IoT device scanning Telnet", "recon", "capture", "CRITICAL",
        "T1595.001 Active Scanning: IP Blocks", "Isolate the IoT device; it is likely infected", 900),
    "RST_BURST": _R("RST reply burst", "recon", "capture", "MEDIUM",
        "T1046 Network Service Discovery", "Identify the host probing closed ports", 900),
    "ICMP_UNREACH_BURST": _R("ICMP unreachable burst", "recon", "capture", "MEDIUM",
        "T1046 Network Service Discovery", "Identify the host sweeping the network", 900),
    "ICMP_LARGE_PAYLOAD": _R("Oversized ICMP payload", "c2", "capture", "MEDIUM",
        "T1095 Non-Application Layer Protocol", "Inspect the ICMP payload for tunnelling", 900),
    # ── Layer 2 poisoning ─────────────────────────────────────────────────────
    "ARP_IP_CONFLICT": _R("One IP claimed by multiple MACs", "l2", "capture", "CRITICAL",
        "T1557.002 ARP Cache Poisoning", "Investigate both hosts; clear ARP caches", 300),
    "ARP_GATEWAY_CHANGE": _R("Gateway MAC address changed", "l2", "capture", "CRITICAL",
        "T1557.002 ARP Cache Poisoning", "Verify gateway; contain the spoofing host", 300),
    "ARP_GRATUITOUS_FLOOD": _R("Gratuitous ARP flood", "l2", "capture", "HIGH",
        "T1557.002 ARP Cache Poisoning", "Contain source; check for ARP spoofing tooling", 300),
    "DHCP_ROGUE_SERVER": _R("Rogue DHCP server", "l2", "capture", "CRITICAL",
        "T1557.003 DHCP Spoofing", "Block the rogue server; renew leases", 600),
    "DHCP_FINGERPRINT_CHANGE": _R("DHCP fingerprint changed for host", "l2", "capture", "MEDIUM",
        "T1557.003 DHCP Spoofing", "Verify the device identity (possible spoofed host)", 1800),
    "VLAN_RESTRICTED": _R("Device on restricted VLAN", "l2", "capture", "HIGH",
        "T1599 Network Boundary Bridging", "Verify VLAN assignment on the access port", 1800),
    # ── Name resolution ───────────────────────────────────────────────────────
    "LLMNR_RESPONSE": _R("LLMNR/NBT-NS response from unexpected host", "dns", "capture", "HIGH",
        "T1557.001 LLMNR/NBT-NS Poisoning", "Disable LLMNR/NBT-NS or contain the responder", 900),
    "HONEYPOT_QUERY": _R("Honeypot name queried", "dns", "capture", "MEDIUM",
        "T1071 Application Layer Protocol", "Identify the host resolving decoy names", 600),
    "HONEYPOT_ANSWERED": _R("Honeypot name answered by unauthorised responder", "dns", "capture", "CRITICAL",
        "T1557.001 LLMNR/NBT-NS Poisoning", "Contain responder; it is impersonating the resolver", 600),
    "DNS_ENTROPY": _R("High-entropy DNS subdomains", "dns", "capture", "HIGH",
        "T1071.004 DNS", "Check host for DNS tunnelling or DGA malware", 900),
    "DNS_TXT_VOLUME": _R("High TXT/NULL query volume per domain", "dns", "capture", "MEDIUM",
        "T1071.004 DNS", "Inspect DNS payloads for tunnelled data", 900),
    "DNS_NXDOMAIN_BURST": _R("NXDOMAIN burst", "dns", "capture", "MEDIUM",
        "T1008 Fallback Channels", "Check host for DGA activity or resolver issues", 900),
    "DNS_LARGE_PAYLOAD": _R("Oversized DNS payload", "dns", "capture", "MEDIUM",
        "T1071.004 DNS", "Inspect DNS payload for tunnelling", 900),
    "NEW_DOMAIN": _R("Newly registered domain resolved", "dns", "dnsfeed", "MEDIUM",
        "T1583.001 Acquire Infrastructure: Domains", "Treat destination as untrusted; verify business need", 3600),
    # ── SMB / Windows ────────────────────────────────────────────────────────
    "SMB_ADMIN_SHARE": _R("Administrative share accessed (C$/ADMIN$)", "lateral", "capture", "HIGH",
        "T1021.002 SMB/Windows Admin Shares", "Investigate the source account and host", 600),
    "SMB_MASS_FILE_OPS": _R("Mass SMB file operations", "lateral", "capture", "HIGH",
        "T1021.002 SMB/Windows Admin Shares", "Check for ransomware staging or bulk exfil", 600),
    "SMB_SESSION_SPIKE": _R("SMB session spike", "lateral", "capture", "MEDIUM",
        "T1021.002 SMB/Windows Admin Shares", "Identify the host opening many SMB sessions", 600),
    "SMB_SIGNING_DISABLED": _R("SMB signing not enabled on target", "lateral", "capture", "MEDIUM",
        "T1557 Adversary-in-the-Middle", "Enable SMB signing on the target", 3600),
    "DCERPC_DRSUAPI": _R("DRSUAPI replication call from non-DC", "cred", "capture", "CRITICAL",
        "T1003.006 DCSync", "Contain source host; rotate krbtgt if confirmed", 300),
    "KRB_RC4": _R("Kerberos RC4 (etype 23) ticket", "cred", "capture", "MEDIUM",
        "T1558 Steal or Forge Kerberos Tickets", "Disable RC4 for the account/domain", 1800),
    "KRB_TGS_BURST": _R("Kerberos TGS request burst", "cred", "capture", "HIGH",
        "T1558.003 Kerberoasting", "Review requested SPNs and the source account", 600),
    # ── Web / C2 / policy ────────────────────────────────────────────────────
    "WEB_ODD_PORT": _R("HTTP on non-standard port", "policy", "capture", "LOW",
        "T1571 Non-Standard Port", "Confirm the service is sanctioned", 1800),
    "MINING_STRATUM": _R("Cryptomining traffic", "c2", "capture", "HIGH",
        "T1496 Resource Hijacking", "Block pool destination; clean the host", 900),
    "TOR_EXIT": _R("Connection to Tor exit node", "c2", "capture", "HIGH",
        "T1090.003 Multi-hop Proxy", "Block destination; investigate the host", 900),
    "RMM_REMOTE_ACCESS": _R("Remote-management tool traffic", "c2", "capture", "MEDIUM",
        "T1219 Remote Access Software", "Confirm the tool is approved for this host", 1800),
    "DOH_UNSANCTIONED": _R("DNS-over-HTTPS to unsanctioned resolver", "c2", "capture", "MEDIUM",
        "T1572 Protocol Tunneling", "Enforce approved resolvers at the firewall", 1800),
    "CLOUD_UPLOAD": _R("Large upload to cloud storage/paste site", "exfil", "capture", "HIGH",
        "T1567.002 Exfiltration to Cloud Storage", "Verify the transfer with the user", 900),
    "SMTP_OUTBOUND": _R("Outbound SMTP from non-mail host", "exfil", "capture", "MEDIUM",
        "T1048 Exfiltration Over Alternative Protocol", "Block direct SMTP; require the relay", 1800),
    "LATERAL_W2W": _R("Workstation-to-workstation admin protocol", "lateral", "capture", "MEDIUM",
        "T1021 Remote Services", "Confirm the admin action; most estates baseline this at zero", 600),
    "INBOUND_EXTERNAL_ADMIN": _R("Inbound admin-port connection from outside", "exposure", "capture", "HIGH",
        "T1133 External Remote Services", "Block at the perimeter; verify port-forwarding", 600),
    # ── Behavioural / baseline ───────────────────────────────────────────────
    "BW_OUTLIER": _R("Outbound volume above host baseline", "exfil", "capture", "HIGH",
        "T1030 Data Transfer Size Limits", "Verify the transfer; check destination reputation", 900),
    "BW_OFF_HOURS": _R("Off-hours large transfer", "exfil", "capture", "HIGH",
        "T1029 Scheduled Transfer", "Verify with the asset owner", 900),
    "FLOW_BEACON": _R("Periodic beaconing", "c2", "capture", "HIGH",
        "T1071 Application Layer Protocol", "Capture full packets for the destination", 1800),
    "FLOW_LONG_LOW_VOLUME": _R("Long-lived low-volume session", "c2", "capture", "MEDIUM",
        "T1071 Application Layer Protocol", "Inspect the session payload", 1800),
    "SYN_FLOOD": _R("SYN flood", "dos", "capture", "HIGH",
        "T1498 Network Denial of Service", "Rate-limit source; check target health", 300),
    # ── Authentication (host auth log) ───────────────────────────────────────
    "AUTH_BRUTE_FORCE": _R("Authentication brute force", "auth", "authlog", "HIGH",
        "T1110.001 Password Guessing", "Block source; lock targeted accounts", 600),
    "AUTH_PASSWORD_SPRAY": _R("Password spray (one source, many accounts)", "auth", "authlog", "HIGH",
        "T1110.003 Password Spraying", "Block source; reset affected accounts", 600),
    "AUTH_DISTRIBUTED": _R("One account tried from many sources", "auth", "authlog", "HIGH",
        "T1110.004 Credential Stuffing", "Lock the account; block the sources", 600),
    "AUTH_SUCCESS_AFTER_FAIL": _R("Successful login after failures", "auth", "authlog", "CRITICAL",
        "T1078 Valid Accounts", "Verify with the user; consider session revocation", 300),
    # ── Asset inventory ─────────────────────────────────────────────────────
    "NEW_MAC": _R("New MAC address on the network", "inventory", "inventory", "LOW",
        "T1200 Hardware Additions", "Confirm the device belongs to the estate", 3600),
    "NEW_DEVICE_PORT": _R("New admin service exposed by device", "exposure", "scan", "MEDIUM",
        "T1133 External Remote Services", "Confirm the service is required and patched", 3600),
}

class DetectionEngine:
    """Stateful detection over the telemetry Netron actually observes.

    Thread-safety: `_lk` guards engine state and is never held while taking
    `_lock` (the device/alerts lock) because device registration calls into
    the engine.  Emitting takes `_em_lk` for dedupe/rate-limit bookkeeping only.
    """

    def __init__(self):
        self._lk     = threading.RLock()
        self._em_lk  = threading.Lock()
        self.started = time.time()
        self.gateway = ""
        self._net: Optional[ipaddress.IPv4Network] = None
        try:
            self.gateway, _netstr = get_local_network()
            self._net = ipaddress.ip_network(_netstr, strict=False)
        except Exception:
            pass
        # Per-rule observation buffers (all bounded)
        self._syn       = {}   # src → deque[(ts, dst, dport)]
        self._syn_all   = {}   # src → deque[ts]  (any SYN, for flood detection)
        self._rst       = {}   # src → deque[(ts, dst)]
        self._rst_rx    = {}   # dst → deque[(ts, src)]
        self._icmp      = {}   # src → deque[ts]
        self._icmp_big  = {}   # src → deque[ts] of oversized ICMP
        self._arp_ip    = {}   # ip → {mac: last_ts}
        self._gw_mac    = None
        self._garp      = {}   # src → deque[ts]
        self._dhcp_fp   = {}   # mac → option signature
        self._dns       = {}   # src → deque[(ts, base, label, qtype)]
        self._nx        = {}   # client → deque[ts]
        self._llmnr     = {}   # responder → deque[ts]
        self._smb_ops   = {}   # src → deque[ts]
        self._smb_sess  = {}   # src → deque[ts]
        self._smb_sign  = {}   # target → (ts, signing_enabled)
        self._krb_tgs   = {}   # src → deque[ts]
        self._flows     = {}   # 5-tuple → flow record
        self._bw        = {}   # ip → byte bucket/baseline
        self._auth      = {}   # src → deque[(ts, user, ok)]
        self._auth_user = {}   # user → {src: deque[ts]}
        self._auth_distr = {}  # user → last distributed-spray alert ts
        self._ports_seen = {}  # ip → set(open ports)
        self._host_vlan = {}   # ip → vlan id
        # Alert bookkeeping
        self._suppress  = {}   # (rule, src, dst) → {alert, last, count}
        self._rate      = {}   # rule → deque[ts]
        self._inc_src   = {}   # src → incident state
        self._suppressed = 0
        # Feeds / config
        self._tor       = set()
        self._tor_status = "not loaded"
        self._tor_ts    = 0.0
        self._tor_enabled = os.environ.get("NETRON_TOR_FEED", "1") != "0"
        self._ti_nets: List[ipaddress.IPv4Network] = []
        self._ti_status = "not configured"
        self._geo_enabled = os.environ.get("NETRON_GEO", "0") == "1"
        self._geo_cache: Dict[str, str] = {}
        self._geo_queue: deque = deque(maxlen=200)
        self._rdap_enabled = os.environ.get("NETRON_RDAP", "0") == "1"
        self._rdap_cache: Dict[str, Optional[int]] = {}
        self._rdap_queue: deque = deque(maxlen=200)
        self._rdap_status = "disabled"
        self._approved_doh = frozenset(s.strip().lower() for s in
                                       os.environ.get("NETRON_APPROVED_DOH", "").split(",") if s.strip())
        self._approved_rmm = frozenset(s.strip().lower() for s in
                                       os.environ.get("NETRON_APPROVED_RMM", "").split(",") if s.strip())
        self._honeypots = frozenset(s.strip().lower() for s in
                                    os.environ.get("NETRON_HONEYPOT_NAMES", "").split(",") if s.strip())
        self._llmnr_ok = frozenset(s.strip() for s in
                                   os.environ.get("NETRON_LLMNR_RESPONDERS", "").split(",") if s.strip())
        self._dhcp_ok = set(s.strip() for s in
                            os.environ.get("NETRON_DHCP_SERVERS", "").split(",") if s.strip())
        try:
            self._restricted_vlans = {int(v) for v in
                                      os.environ.get("NETRON_RESTRICTED_VLANS", "").split(",") if v.strip()}
        except ValueError:
            self._restricted_vlans = set()
        self._role_cache: Dict[str, Tuple[float, str]] = {}
        self._rules_fired: Dict[str, int] = defaultdict(int)
        self._obs = defaultdict(int)
        self.capture_seen = False
        self._packets     = 0
        self.flow_count   = 0
        # Inventory warm baseline: only alert on new MACs once we already had one
        inventory_load()
        self._inv_preexisting = len(_inv)
        self._load_ti()

    # ── Config / feeds ───────────────────────────────────────────────────────
    def _load_ti(self) -> None:
        path = os.environ.get("NETRON_TI_LIST", "")
        if not path:
            return
        try:
            nets = []
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    try:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        continue
            self._ti_nets = nets
            self._ti_status = f"{len(nets)} entries from {path}"
        except OSError as e:
            self._ti_status = f"unreadable: {e}"

    def refresh_feeds(self) -> None:
        if not self._tor_enabled or not REQUESTS_OK:
            if not REQUESTS_OK:
                self._tor_status = "requests not installed"
            return
        now = time.time()
        if now - self._tor_ts < 86400 and self._tor:
            return
        self._tor_ts = now
        threading.Thread(target=self._fetch_tor, daemon=True, name="tor-feed").start()

    def _fetch_tor(self) -> None:
        """The Tor Project publishes exit nodes, not guard/entry nodes."""
        cache = os.path.join(_STATE_DIR, "tor-exits.txt")
        try:
            text = ""
            source = ""
            if os.path.exists(cache) and time.time() - os.path.getmtime(cache) < 86400:
                with open(cache, "r", encoding="utf-8") as fh:
                    text = fh.read()
                source = "cached list"
            if not text:
                r = _http.get("https://check.torproject.org/torbulkexitlist", timeout=8)
                r.raise_for_status()
                text = r.text
                os.makedirs(_STATE_DIR, exist_ok=True)
                with open(cache, "w", encoding="utf-8") as fh:
                    fh.write(text)
                source = "live list"
            ips = {ln.strip() for ln in text.splitlines()
                   if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ln.strip())}
            if not ips:
                raise ValueError("empty list")
            with self._lk:
                self._tor = ips
            self._tor_status = f"{source}: {len(ips)} exit nodes"
        except Exception as e:
            self._tor_status = f"unavailable ({type(e).__name__})"

    # ── Address helpers ──────────────────────────────────────────────────────
    def is_local(self, ip: str) -> bool:
        try:
            if ip in get_local_ips():
                return True
            return bool(self._net and ipaddress.ip_address(ip) in self._net)
        except (ValueError, TypeError):
            return False

    def _role(self, ip: str) -> str:
        now = time.time()
        hit = self._role_cache.get(ip)
        if hit and now - hit[0] < 60:
            return hit[1]
        with _lock:
            d = devices.get(ip) or {}
            ports = {p for p, i in (d.get("open_ports") or {}).items()
                     if isinstance(i, dict) and i.get("state") == "open"}
            dtype = (d.get("device_type") or "")
        role = "unknown"
        if ip and ip == self.gateway:
            role = "gateway"
        elif len(ports & DC_PORTS) >= 2:
            role = "dc"
        elif ports & DB_PORTS:
            role = "server"
        elif 25 in ports or 587 in ports:
            role = "mail"
        elif "server" in dtype.lower() or "nas" in dtype.lower():
            role = "server"
        elif dtype in IOT_TYPES:
            role = "iot"
        elif ports & {135, 445, 3389} or any(x in dtype.lower() for x in ("pc", "laptop", "desktop")):
            role = "workstation"
        elif ports & {22, 80, 443}:
            role = "server"
        self._role_cache[ip] = (now, role)
        return role

    def _criticality(self, ip: str) -> str:
        role = self._role(ip)
        with _lock:
            d = devices.get(ip) or {}
            ports = {p for p, i in (d.get("open_ports") or {}).items()
                     if isinstance(i, dict) and i.get("state") == "open"}
            vulns = d.get("vulnerabilities") or []
        if role in ("gateway", "dc"):
            return "CRITICAL"
        if any(v.get("severity") == "CRITICAL" for v in vulns):
            return "HIGH"
        if ports & {23, 3389, 5900}:
            return "HIGH"
        if role in ("server", "mail"):
            return "MEDIUM"
        return "LOW"

    def _ti_hit(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self._ti_nets if n.version == a.version)

    def _geo(self, ip: str) -> str:
        """Opt-in enrichment (NETRON_GEO=1).  Cached result only; lookups are
        performed asynchronously so an alert never blocks on a network call."""
        if not self._geo_enabled or not _is_public_ip(ip):
            return ""
        hit = self._geo_cache.get(ip)
        if hit is not None:
            return hit
        if ip not in self._geo_queue:
            self._geo_queue.append(ip)
        return ""

    def _geo_worker(self) -> None:
        if not REQUESTS_OK or not self._geo_queue:
            return
        ip = self._geo_queue.popleft()
        try:
            r = _http.get(f"http://ip-api.com/json/{ip}", timeout=5,
                          params={"fields": "status,country,countryCode,as"})
            j = r.json()
            val = ""
            if j.get("status") == "success":
                asn = (j.get("as") or "").strip()
                val = ", ".join(x for x in (j.get("country"), asn) if x)
            self._geo_cache[ip] = val
        except Exception:
            self._geo_cache[ip] = ""

    def bandwidth_baselines(self) -> Dict[str, dict]:
        """Per-host 60 s byte totals and the learned baseline, for the UI."""
        now = time.time()
        out: Dict[str, dict] = {}
        with self._lk:
            for ip, b in self._bw.items():
                w_out = b["out"] + sum(o for t, o, _i in b["closed"] if t > now - DET_BW_WINDOW)
                w_in  = b["in"]  + sum(i for t, _o, i in b["closed"] if t > now - DET_BW_WINDOW)
                out[ip] = {"window_out": w_out, "window_in": w_in,
                           "baseline_out": int((b["ewma"] or 0.0) * (DET_BW_WINDOW / 10.0)),
                           "samples": b["samples"]}
        return out

    def top_flows(self, limit: int = 12) -> List[dict]:
        with self._lk:
            rows = [dict(f) for f in self._flows.values()
                    if f["bytes_out"] + f["bytes_in"] > 0]
        rows.sort(key=lambda f: f["bytes_out"] + f["bytes_in"], reverse=True)
        out = []
        for f in rows[:limit]:
            out.append({"src": f["src"], "dst": f["dst"], "dport": f["dport"],
                        "proto": f["proto"], "bytes_in": f["bytes_in"],
                        "bytes_out": f["bytes_out"], "packets": f["pkts"],
                        "first": f["first"], "last": f["last"],
                        "domain": f.get("domain", "")})
        return out

    # ── Inventory / scan hooks ───────────────────────────────────────────────
    def observe_host(self, ip: str, mac: str, vendor: str = "") -> None:
        if not mac or mac.upper() in ("N/A", ""):
            return
        new = inventory_mark(mac, ip, vendor)
        if not new or not self._inv_preexisting:
            return
        if time.time() - self.started < 180:
            return                       # warm-up: existing devices are not "new"
        if _is_random_mac(mac):
            return                       # privacy-randomised client MAC: noise
        inv = inventory_get(mac)
        self._emit("NEW_MAC", ip, "",
                   f"MAC {mac.upper()} ({vendor or 'unknown vendor'}) not in the asset "
                   f"inventory; first seen {inv.get('first_seen','now')}")

    def observe_ports(self, ip: str, open_ports: dict) -> None:
        # Port keys arrive as ints from the scanners and as strings after a
        # JSON round-trip; normalise once so set arithmetic never mixes types.
        seen: Dict[int, dict] = {}
        for p, i in (open_ports or {}).items():
            if not isinstance(i, dict) or i.get("state") != "open":
                continue
            try:
                seen[int(p)] = i
            except (TypeError, ValueError):
                continue
        ports = set(seen)
        with self._lk:
            prev = self._ports_seen.get(ip)
            self._ports_seen[ip] = ports
        if prev is None:
            return
        risky = ports & (set(ADMIN_PORTS) | DB_PORTS | {23, 2375, 11211})
        new_risky = risky - prev
        if new_risky:
            # Name the service each port answers with, so the alert matches the
            # Open Ports panel instead of quoting bare numbers.
            self._emit("NEW_DEVICE_PORT", ip, "",
                       "previously closed admin/database port(s) now open: " +
                       ", ".join(f"{p} {service_label(p, seen[p].get('service',''))}"
                                 for p in sorted(new_risky)))

    # ── Packet ingestion ─────────────────────────────────────────────────────
    def on_packet(self, ev: dict) -> None:
        now = float(ev.get("ts") or time.time())
        pending: List[tuple] = []
        with self._lk:
            self._packets += 1
            self.capture_seen = True
            self._account_bytes(ev, now)
            self._check_scan(ev, now, pending)
            self._check_l2(ev, now, pending)
            self._check_dns(ev, now, pending)
            self._check_windows(ev, now, pending)
            self._check_policy(ev, now, pending)
            self._check_flows(ev, now, pending)
        for p in pending:
            self._emit(*p)

    def _account_bytes(self, ev: dict, now: float) -> None:
        size = int(ev.get("size") or 0)
        if not size:
            return
        for ip, field in ((ev.get("src"), "out"), (ev.get("dst"), "in")):
            if not ip or not self.is_local(ip):
                continue
            b = self._bw.get(ip)
            if b is None:
                if len(self._bw) > 4096:
                    return
                b = {"start": now, "out": 0, "in": 0, "closed": deque(maxlen=360),
                     "ewma": None, "samples": 0}
                self._bw[ip] = b
            b[field] += size

    def _check_scan(self, ev: dict, now: float, pending: List[tuple]) -> None:
        proto = ev.get("proto")
        src, dst = ev.get("src", ""), ev.get("dst", "")
        flags = int(ev.get("flags") or 0)
        if proto == "TCP" and (flags & 0x02) and not (flags & 0x10):
            fq = self._syn_all.get(src)
            if fq is None:
                if len(self._syn_all) > SYN_MAX_SOURCES:
                    self._syn_all = {k: v for k, v in self._syn_all.items()
                                     if v and v[-1] > now - SYN_WINDOW_SECS}
                    if len(self._syn_all) > SYN_MAX_SOURCES:
                        return
                fq = self._syn_all[src] = deque(maxlen=ANOMALY_THRESH * 8)
            fq.append(now)
            fn = sum(1 for t in fq if t > now - SYN_WINDOW_SECS)
            if fn and fn % ANOMALY_THRESH == 0:
                pending.append(("SYN_FLOOD", src, "",
                                f"{fn} SYN packets in {SYN_WINDOW_SECS}s"))
            dq = self._syn.get(src)
            if dq is None:
                if len(self._syn) > 4096:
                    return
                dq = self._syn[src] = deque(maxlen=4096)
            dq.append((now, dst, int(ev.get("dport") or 0)))
            if len(dq) % 3:
                return
            win = [x for x in dq if x[0] > now - DET_SCAN_WINDOW]
            hosts: Dict[str, set] = {}
            for _t, h, p in win:
                hosts.setdefault(h, set()).add(p)
            if not hosts:
                return
            total_ports = sum(len(v) for v in hosts.values())
            if len(hosts) >= DET_SCAN_HOSTS and total_ports / len(hosts) <= DET_SCAN_BREADTH:
                pending.append(("PORT_SCAN_HORIZONTAL", src, "",
                                f"{len(hosts)} hosts contacted on {total_ports} ports in "
                                f"{DET_SCAN_WINDOW}s (SYN)"))
            vertical = [(h, len(p)) for h, p in hosts.items() if len(p) >= DET_SCAN_PORTS]
            if vertical:
                h, n = max(vertical, key=lambda x: x[1])
                pending.append(("PORT_SCAN_VERTICAL", src, h,
                                f"{n} distinct ports probed on {h} in {DET_SCAN_WINDOW}s (SYN)"))
            if self._role(src) == "iot":
                telnet_hosts = {h for h, p in hosts.items() if p & {23, 2323}}
                if len(telnet_hosts) >= 5:
                    pending.append(("IOT_TELNET_SCAN", src, "",
                                    f"IoT-role host sent Telnet SYNs to {len(telnet_hosts)} hosts "
                                    f"in {DET_SCAN_WINDOW}s"))
        if proto == "TCP" and (flags & 0x04):
            dq = self._rst.get(src)
            if dq is None:
                if len(self._rst) > 4096:
                    return
                dq = self._rst[src] = deque(maxlen=2048)
            dq.append((now, dst))
            win = [x for x in dq if x[0] > now - DET_RST_WINDOW]
            if len(win) >= DET_RST_BURST and len({d for _t, d in win}) >= 5:
                pending.append(("RST_BURST", src, "",
                                f"{len(win)} RST packets to {len({d for _t, d in win})} hosts "
                                f"in {DET_RST_WINDOW}s (probe pattern)"))
            rx = self._rst_rx.get(dst)
            if rx is None:
                if len(self._rst_rx) > 4096:
                    return
                rx = self._rst_rx[dst] = deque(maxlen=2048)
            rx.append((now, src))
            win_rx = [x for x in rx if x[0] > now - DET_RST_WINDOW]
            if len(win_rx) >= DET_RST_BURST and len({s for _t, s in win_rx}) >= 5:
                pending.append(("RST_BURST", dst, "",
                                f"{len(win_rx)} RST replies from {len({s for _t, s in win_rx})} "
                                f"sources in {DET_RST_WINDOW}s -- host is being probed"))
        if proto == "ICMP":
            size = int(ev.get("size") or 0)
            if size >= DET_ICMP_BIG:
                dq = self._icmp_big.get(src)
                if dq is None:
                    if len(self._icmp_big) > 2048:
                        return
                    dq = self._icmp_big[src] = deque(maxlen=256)
                dq.append(now)
                if sum(1 for t in dq if t > now - 60) == 1:
                    pending.append(("ICMP_LARGE_PAYLOAD", src, dst,
                                    f"{size} byte ICMP packet (possible ICMP tunnel)"))
        if proto == "ICMP" and int((ev.get("icmp") or {}).get("type", -1)) == 3:
            dq = self._icmp.get(src)
            if dq is None:
                if len(self._icmp) > 2048:
                    return
                dq = self._icmp[src] = deque(maxlen=2048)
            dq.append(now)
            n = sum(1 for t in dq if t > now - DET_ICMP_WINDOW)
            if n >= DET_ICMP_BURST:
                pending.append(("ICMP_UNREACH_BURST", src, "",
                                f"{n} ICMP unreachable messages in {DET_ICMP_WINDOW}s"))

    def _check_l2(self, ev: dict, now: float, pending: List[tuple]) -> None:
        arp = ev.get("arp")
        if arp:
            ip, mac = arp.get("psrc", ""), (arp.get("hwsrc") or "").upper()
            if ip and mac:
                seen = self._arp_ip.setdefault(ip, {})
                seen[mac] = now
                fresh = [m for m, t in seen.items() if now - t < 120]
                if len(fresh) >= 2:
                    pending.append(("ARP_IP_CONFLICT", ip, "",
                                    f"IP answered by MACs {', '.join(sorted(fresh))}"))
                if self.gateway and ip == self.gateway:
                    if self._gw_mac is None and self._role(ip) != "unknown":
                        self._gw_mac = mac
                    elif self._gw_mac and mac != self._gw_mac:
                        old, self._gw_mac = self._gw_mac, mac
                        pending.append(("ARP_GATEWAY_CHANGE", ip, "",
                                        f"gateway MAC {old} -> {mac}"))
            if arp.get("gratuitous"):
                dq = self._garp.get(ip)
                if dq is None:
                    if len(self._garp) > 2048:
                        return
                    dq = self._garp[ip] = deque(maxlen=1024)
                dq.append(now)
                n = sum(1 for t in dq if t > now - DET_ARP_WINDOW)
                if n >= DET_ARP_FLOOD:
                    pending.append(("ARP_GRATUITOUS_FLOOD", ip, "",
                                    f"{n} gratuitous ARP frames in {DET_ARP_WINDOW}s"))
            vlan = ev.get("vlan")
            if vlan and self._restricted_vlans:
                self._host_vlan[ip] = int(vlan)
                if int(vlan) in self._restricted_vlans:
                    pending.append(("VLAN_RESTRICTED", ip, "",
                                    f"host seen on restricted VLAN {vlan}"))
        dhcp = ev.get("dhcp")
        if dhcp:
            mac = (dhcp.get("mac") or "").upper()
            fp = dhcp.get("opts") or ""
            if mac and fp:
                prev = self._dhcp_fp.get(mac)
                self._dhcp_fp[mac] = fp
                if prev and prev != fp:
                    pending.append(("DHCP_FINGERPRINT_CHANGE", ev.get("src", ""), "",
                                    f"DHCP option fingerprint changed for {mac}: {prev} -> {fp}"))
            if int(dhcp.get("msg_type") or 0) in (2, 5):
                src = ev.get("src", "")
                allowed = set(self._dhcp_ok)
                if self.gateway:
                    allowed.add(self.gateway)
                allowed |= get_local_ips()
                if src and src not in allowed:
                    gw = dhcp.get("router") or ""
                    pending.append(("DHCP_ROGUE_SERVER", src, "",
                                    f"DHCP {'OFFER' if dhcp.get('msg_type') == 2 else 'ACK'} from "
                                    f"unauthorised server" + (f" (offers router {gw})" if gw else "")))

    def _check_dns(self, ev: dict, now: float, pending: List[tuple]) -> None:
        dns = ev.get("dns")
        if not dns:
            return
        src, dst = ev.get("src", ""), ev.get("dst", "")
        qname = (dns.get("qname") or "").lower().rstrip(".")
        if dns.get("nbtns"):
            if dns.get("response") and src not in self._llmnr_ok:
                self._llmnr_note(src, now, pending, f"NBT-NS response from {src}")
            return
        response = bool(dns.get("response"))
        if not response:
            if qname and self._honeypots and qname in self._honeypots:
                pending.append(("HONEYPOT_QUERY", src, "",
                                f"decoy name '{qname}' queried"))
            qtype = int(dns.get("qtype") or 0)
            labels = [l for l in qname.split(".") if l]
            base = _dns_base(qname)
            label = max(labels, key=len) if labels else ""
            dq = self._dns.get(src)
            if dq is None:
                if len(self._dns) > 4096:
                    return
                dq = self._dns[src] = deque(maxlen=600)
            dq.append((now, base, label, qtype))
            win = [x for x in dq if x[0] > now - DET_DNS_WINDOW]
            if qtype in (16, 10):
                n = sum(1 for _t, b, _l, qt in win if b == base and qt in (16, 10))
                if n >= DET_DNS_TXT_COUNT:
                    pending.append(("DNS_TXT_VOLUME", src, "",
                                    f"{n} {DNS_QTYPES.get(qtype, qtype)} queries for {base} "
                                    f"in {DET_DNS_WINDOW}s"))
            if len(labels) >= 3 and len(label) >= DET_DNS_ENT_MINLEN \
                    and _entropy_bits(label) >= DET_DNS_ENT_BITS:
                subs = {l for _t, b, l, _q in win if b == base and len(l) >= DET_DNS_ENT_MINLEN}
                if len(subs) >= DET_DNS_ENT_COUNT:
                    pending.append(("DNS_ENTROPY", src, "",
                                    f"{len(subs)} high-entropy subdomains under {base} in "
                                    f"{DET_DNS_WINDOW}s (example: {label[:40]}...)"))
            if self._rdap_enabled and base and len(labels) >= 2:
                if base not in self._rdap_cache and len(self._rdap_queue) < 200:
                    if base not in {b for b, _c, _t in self._rdap_queue}:
                        self._rdap_queue.append((base, src, now))
        else:
            if int(dns.get("rcode") or 0) == 3:
                dq = self._nx.get(dst)
                if dq is None:
                    if len(self._nx) > 4096:
                        return
                    dq = self._nx[dst] = deque(maxlen=600)
                dq.append(now)
                n = sum(1 for t in dq if t > now - DET_DNS_WINDOW)
                if n >= DET_DNS_NX_COUNT:
                    pending.append(("DNS_NXDOMAIN_BURST", dst, "",
                                    f"{n} NXDOMAIN responses to this host in {DET_DNS_WINDOW}s"))
            if qname and self._honeypots and qname in self._honeypots:
                if src not in get_local_ips() and src not in self._dhcp_ok and src != self.gateway:
                    pending.append(("HONEYPOT_ANSWERED", src, dst,
                                    f"decoy name '{qname}' answered by {src}"))
            if int(ev.get("sport") or 0) == 5355:
                if src not in self._llmnr_ok:
                    self._llmnr_note(src, now, pending, f"LLMNR response from {src}")
            if int(dns.get("size") or 0) > DET_DNS_BIG_UDP:
                pending.append(("DNS_LARGE_PAYLOAD", dst or src, "",
                                f"{int(dns['size'])} byte DNS response for {qname or '?'}"))

    def _llmnr_note(self, src: str, now: float, pending: List[tuple], detail: str) -> None:
        dq = self._llmnr.get(src)
        if dq is None:
            if len(self._llmnr) > 2048:
                return
            dq = self._llmnr[src] = deque(maxlen=64)
        dq.append(now)
        pending.append(("LLMNR_RESPONSE", src, "",
                        detail + " (legitimate responders: configure NETRON_LLMNR_RESPONDERS)"))

    def _check_windows(self, ev: dict, now: float, pending: List[tuple]) -> None:
        src, dst = ev.get("src", ""), ev.get("dst", "")
        smb = ev.get("smb")
        if smb:
            cmd = int(smb.get("cmd") or -1)
            if cmd in (5, 9, 17):                       # CREATE / WRITE / SET_INFO
                dq = self._smb_ops.get(src)
                if dq is None:
                    if len(self._smb_ops) > 2048:
                        return
                    dq = self._smb_ops[src] = deque(maxlen=4096)
                dq.append(now)
                n = sum(1 for t in dq if t > now - 60)
                if n >= DET_SMB_OPS:
                    pending.append(("SMB_MASS_FILE_OPS", src, dst,
                                    f"{n} SMB create/write/metadata operations in 60s"))
            share = (smb.get("share") or "").upper()
            if share in ("C$", "ADMIN$"):
                pending.append(("SMB_ADMIN_SHARE", src, dst,
                                f"tree connect to \\\\{dst or '?'}\\{share}"))
            if smb.get("signing_enabled") is False:
                prev = self._smb_sign.get(dst)
                self._smb_sign[dst] = (now, False)
                if not prev or now - prev[0] > 3600:
                    pending.append(("SMB_SIGNING_DISABLED", dst, "",
                                    "SMB2 negotiate reports signing not enabled"))
        if ev.get("proto") == "TCP" and int(ev.get("dport") or 0) == 445 \
                and (int(ev.get("flags") or 0) & 0x02) and not (int(ev.get("flags") or 0) & 0x10):
            dq = self._smb_sess.get(src)
            if dq is None:
                if len(self._smb_sess) > 2048:
                    return
                dq = self._smb_sess[src] = deque(maxlen=1024)
            dq.append(now)
            n = sum(1 for t in dq if t > now - 60)
            if n >= DET_SMB_SESSIONS:
                pending.append(("SMB_SESSION_SPIKE", src, "",
                                f"{n} new SMB sessions in 60s"))
        krb = ev.get("krb")
        if krb:
            mtype = int(krb.get("msg_type") or 0)
            if mtype == 13:                             # TGS-REQ
                dq = self._krb_tgs.get(src)
                if dq is None:
                    if len(self._krb_tgs) > 2048:
                        return
                    dq = self._krb_tgs[src] = deque(maxlen=1024)
                dq.append(now)
                n = sum(1 for t in dq if t > now - 60)
                if n >= DET_KRB_TGS:
                    pending.append(("KRB_TGS_BURST", src, "",
                                    f"{n} Kerberos TGS requests in 60s"))
            if 23 in (krb.get("etypes") or []):
                pending.append(("KRB_RC4", src, dst,
                                f"Kerberos message type {mtype} requests RC4 (etype 23)"))
        if ev.get("rpc") == "drsuapi" and self._role(src) != "dc":
            pending.append(("DCERPC_DRSUAPI", src, dst,
                            "DCE/RPC bind to the DRSUAPI interface from a non-DC host"))

    def _check_policy(self, ev: dict, now: float, pending: List[tuple]) -> None:
        src, dst = ev.get("src", ""), ev.get("dst", "")
        dport = int(ev.get("dport") or 0)
        name = (ev.get("sni") or "").lower().rstrip(".")
        dns = ev.get("dns")
        if dns and not dns.get("response") and not dns.get("nbtns"):
            name = name or (dns.get("qname") or "").lower().rstrip(".")
        is_syn = ev.get("proto") == "TCP" and (int(ev.get("flags") or 0) & 0x02) \
            and not (int(ev.get("flags") or 0) & 0x10)
        if name:
            hit = _domain_match(name, MINING_HOSTS)
            if hit or ev.get("stratum"):
                pending.append(("MINING_STRATUM", src, dst,
                                f"mining protocol/host '{name or hit}'"))
            hit = _domain_match(name, RMM_HOSTS)
            if hit and not _domain_match(name, self._approved_rmm or frozenset()):
                pending.append(("RMM_REMOTE_ACCESS", src, dst,
                                f"remote-management service '{hit}' contacted ({name})"))
            hit = _domain_match(name, DOH_HOSTS)
            if hit and not _domain_match(name, self._approved_doh or frozenset()):
                pending.append(("DOH_UNSANCTIONED", src, dst,
                                f"DNS-over-HTTPS endpoint '{hit}' ({name})"))
            hit = _domain_match(name, CLOUD_UPLOAD_HOSTS)
            if hit and ev.get("sni"):
                pending.append(("CLOUD_UPLOAD", src, dst,
                                f"TLS session to cloud/paste service '{hit}' -- volume checked",
                                {"severity": "LOW", "confidence": "low"}))
        if ev.get("http") and dport and dport not in HTTP_PORTS:
            pending.append(("WEB_ODD_PORT", src, dst,
                            f"HTTP {ev['http']} request on non-standard port {dport}"))
        if is_syn and _is_public_ip(dst) and dst in self._tor:
            pending.append(("TOR_EXIT", src, dst, f"TCP connection to Tor exit node {dst}"))
        if is_syn and dport in (25, 587) and self._role(src) not in ("mail",):
            pending.append(("SMTP_OUTBOUND", src, dst,
                            f"direct SMTP connection to {dst}:{dport} from a non-mail host"))
        if is_syn and dport in (445, 3389, 5985, 5986, 22) and src != dst:
            rs, rd = self._role(src), self._role(dst)
            if rs == "workstation" and rd == "workstation":
                sev = "LOW" if dport == 22 else "MEDIUM"
                pending.append(("LATERAL_W2W", src, dst,
                                f"workstation-to-workstation {ADMIN_PORTS.get(dport, dport)} "
                                f"connection to {dst}:{dport}", {"severity": sev}))
        if is_syn and _is_public_ip(src) and self.is_local(dst) \
                and dport in (set(ADMIN_PORTS) | DB_PORTS | {8080, 8443}):
            pending.append(("INBOUND_EXTERNAL_ADMIN", src, dst,
                            f"inbound {ADMIN_PORTS.get(dport, dport)} to {dst}:{dport} from "
                            f"public address {src}"))

    def _check_flows(self, ev: dict, now: float, pending: List[tuple]) -> None:
        proto = ev.get("proto")
        src, dst = ev.get("src", ""), ev.get("dst", "")
        if not src or not dst or proto not in ("TCP", "UDP"):
            return
        key = (src, dst, int(ev.get("sport") or 0), int(ev.get("dport") or 0), proto)
        f = self._flows.get(key)
        if f is None:
            if len(self._flows) > 20000:
                return
            f = {"src": src, "dst": dst, "sport": key[2], "dport": key[3],
                 "proto": proto, "first": now, "last": now, "pkts": 0,
                 "bytes_out": 0, "bytes_in": 0, "session_bytes": 0,
                 "starts": deque(maxlen=16), "sizes": deque(maxlen=16),
                 "domain": ""}
            self._flows[key] = f
            self.flow_count += 1
        f["last"] = now
        f["pkts"] += 1
        size = int(ev.get("size") or 0)
        if src == key[0]:
            f["bytes_out"] += size
            f["session_bytes"] += size
        else:
            f["bytes_in"] += size
        if ev.get("sni"):
            f["domain"] = ev["sni"].lower()
        flags = int(ev.get("flags") or 0)
        if proto == "TCP" and (flags & 0x02) and not (flags & 0x10):
            if f["session_bytes"] > 0:
                f["sizes"].append(f["session_bytes"])
            f["session_bytes"] = 0
            f["starts"].append(now)

    # ── Authentication log events ────────────────────────────────────────────
    def observe_auth(self, src: str, user: str, ok: bool, service: str = "SSH") -> None:
        if not src:
            return
        now = time.time()
        pending: List[tuple] = []
        with self._lk:
            self._obs["auth_events"] += 1
            dq = self._auth.get(src)
            if dq is None:
                if len(self._auth) > 4096:
                    return
                dq = self._auth[src] = deque(maxlen=400)
            dq.append((now, user, ok))
            recent = [x for x in dq if now - x[0] <= DET_AUTH_WINDOW]
            if ok:
                fails = [u for t, u, o in recent if not o]
                if len(fails) >= 5:
                    who = ", ".join(sorted(set(fails))[:4])
                    pending.append(("AUTH_SUCCESS_AFTER_FAIL", src, "",
                                    f"{service} login for '{user}' succeeded after "
                                    f"{len(fails)} failed attempts ({who})"))
            else:
                users: Dict[str, int] = defaultdict(int)
                for _t, u, o in recent:
                    if not o:
                        users[u] += 1
                total = sum(users.values())
                if total >= DET_AUTH_FAILS:
                    pending.append(("AUTH_BRUTE_FORCE", src, "",
                                    f"{total} failed {service} logins in {DET_AUTH_WINDOW}s"))
                if len(users) >= DET_AUTH_USERS:
                    pending.append(("AUTH_PASSWORD_SPRAY", src, "",
                                    f"failed logins for {len(users)} distinct accounts in "
                                    f"{DET_AUTH_WINDOW}s"))
            ud = self._auth_user.get(user)
            if ud is None:
                if len(self._auth_user) > 4096:
                    return
                ud = self._auth_user[user] = {}
            sd = ud.get(src)
            if sd is None:
                sd = ud[src] = deque(maxlen=64)
            sd.append(now)
            if not ok:
                srcs = [s for s, d in ud.items() if any(t > now - 600 for t in d)]
                if len(srcs) >= DET_AUTH_SRCS:
                    # One alert per account per 10 minutes: the condition is
                    # account-wide, so re-firing for every additional source
                    # would just duplicate the same finding.
                    if now - self._auth_distr.get(user, 0.0) > 600:
                        if len(self._auth_distr) > 4096:
                            self._auth_distr.clear()
                        self._auth_distr[user] = now
                        pending.append(("AUTH_DISTRIBUTED", src, "",
                                        f"account '{user}' targeted from {len(srcs)} sources in 10m"))
        for p in pending:
            self._emit(*p)

    # ── Periodic evaluation (baselines, beacons, feeds) ──────────────────────
    def tick(self) -> None:
        now = time.time()
        pending: List[tuple] = []
        with self._lk:
            for ip, b in list(self._bw.items()):
                while now - b["start"] >= 10:
                    b["closed"].append((b["start"], b["out"], b["in"]))
                    prev = b["ewma"]
                    b["ewma"] = b["out"] if prev is None else (0.9 * prev + 0.1 * b["out"])
                    b["samples"] += 1
                    b["start"] += 10
                    b["out"] = b["in"] = 0
                if b["samples"] < 6:
                    continue
                w_out = b["out"] + sum(o for t, o, _i in b["closed"] if t > now - DET_BW_WINDOW)
                exp   = (b["ewma"] or 0.0) * (DET_BW_WINDOW / 10.0)
                big   = w_out >= DET_BW_MIN_BYTES
                if not big or (exp > 0 and w_out < DET_BW_FACTOR * exp):
                    continue
                peer = self._top_peer(ip, now)
                hour = datetime.now().hour
                off  = hour < BUSINESS_START or hour >= BUSINESS_END
                rule = "BW_OFF_HOURS" if off else "BW_OUTLIER"
                pending.append((rule, ip, "",
                                f"{_fmt(w_out)} outbound in {DET_BW_WINDOW}s vs baseline "
                                f"{exp/1048576:.1f} MB/{DET_BW_WINDOW}s; top peer "
                                f"{peer or 'n/a'}"))
            for key, f in list(self._flows.items()):
                if f["last"] < now - 900:
                    del self._flows[key]
                    continue
                dom = f.get("domain") or ""
                if dom and _domain_match(dom, CLOUD_UPLOAD_HOSTS) and f["bytes_out"] >= 2 * 1024 * 1024:
                    pending.append(("CLOUD_UPLOAD", f["src"], f["dst"],
                                    f"{_fmt(f['bytes_out'])} uploaded to {dom} "
                                    f"({f['dst']}:{f['dport']})"))
                if (f["last"] - f["first"] >= DET_LONG_FLOW_SECS
                        and f["bytes_out"] + f["bytes_in"] < 1024 * 1024
                        and _is_public_ip(f["dst"])):
                    pending.append(("FLOW_LONG_LOW_VOLUME", f["src"], f["dst"],
                                    f"session to {f['dst']}:{f['dport']} open "
                                    f"{(f['last']-f['first'])/60:.0f} min with "
                                    f"{_fmt(f['bytes_out']+f['bytes_in'])}"))
                starts = list(f["starts"])
                sizes  = [s for s in f["sizes"] if s > 0]
                if len(starts) >= DET_BEACON_MIN and _is_public_ip(f["dst"]):
                    gaps = [b - a for a, b in zip(starts, starts[1:])]
                    if len(gaps) >= 4:
                        mean = statistics.mean(gaps)
                        sd   = statistics.pstdev(gaps)
                        cv   = sd / mean if mean > 0 else 9.0
                        msz  = statistics.mean(sizes) if len(sizes) >= 4 else 0.0
                        scv  = (statistics.pstdev(sizes) / msz) if msz > 0 else 9.0
                        if cv <= DET_BEACON_IV_CV and scv <= DET_BEACON_SIZE_CV:
                            pending.append(("FLOW_BEACON", f["src"], f["dst"],
                                            f"{len(starts)} connections to {f['dst']}:{f['dport']} "
                                            f"every {mean:.1f}s (jitter {sd:.2f}s), "
                                            f"{msz:.0f}B avg session"))
            if len(self._flows) > 20000:
                keep = sorted(self._flows.items(), key=lambda kv: kv[1]["last"], reverse=True)[:15000]
                self._flows = dict(keep)
            # bound the dedupe table
            for k in [k for k, v in self._suppress.items() if now - v["last"] > 7200]:
                self._suppress.pop(k, None)
        for p in pending:
            self._emit(*p)
        # optional enrichment feeds (never block the capture path)
        if self._geo_enabled and self._geo_queue:
            threading.Thread(target=self._geo_worker, daemon=True, name="geo").start()
        if self._rdap_enabled and self._rdap_queue:
            threading.Thread(target=self._rdap_tick, daemon=True, name="rdap").start()

    def _top_peer(self, ip: str, now: float) -> str:
        best, best_b = "", 0
        for f in self._flows.values():
            if f["src"] == ip and f["last"] > now - 600 and f["bytes_out"] > best_b:
                best, best_b = f"{f['dst']}:{f['dport']}", f["bytes_out"]
        return best

    def _rdap_tick(self) -> None:
        if not self._rdap_queue or not REQUESTS_OK:
            return
        base, client, _seen = self._rdap_queue.popleft()
        try:
            r = _http.get(f"https://rdap.org/domain/{base}", timeout=6,
                          headers={"Accept": "application/rdap+json"})
            if r.status_code != 200:
                self._rdap_cache[base] = None
                self._rdap_status = f"HTTP {r.status_code} from RDAP"
                return
            events = r.json().get("events") or []
            reg = next((e.get("eventDate") for e in events
                        if e.get("eventAction") == "registration"), None)
            if not reg:
                self._rdap_cache[base] = None
                return
            dt = datetime.fromisoformat(reg.replace("Z", "+00:00"))
            age = (datetime.now(dt.tzinfo) - dt).days
            self._rdap_cache[base] = age
            self._rdap_status = "ok"
            if 0 <= age <= 30:
                self._emit("NEW_DOMAIN", client, "",
                           f"{base} was registered {age} day(s) ago ({reg})")
        except Exception as e:
            self._rdap_cache[base] = None
            self._rdap_status = f"unavailable ({type(e).__name__})"

    # ── Alert emission: dedupe, rate-limit, correlate, enrich ────────────────
    def _incident(self, src: str, family: str, now: float) -> Tuple[str, bool]:
        ent = self._inc_src.get(src)
        if ent and now - ent["last"] <= 900:
            ent["families"].add(family)
            ent["last"] = now
            return ent["id"], len(ent["families"]) >= 2
        iid = "INC-" + os.urandom(3).hex().upper()
        self._inc_src[src] = {"id": iid, "families": {family}, "first": now, "last": now}
        if len(self._inc_src) > 500:
            oldest = min(self._inc_src.items(), key=lambda kv: kv[1]["last"])[0]
            self._inc_src.pop(oldest, None)
        return iid, False

    def _emit(self, rule_id: str, src: str, dst: str = "", detail: str = "",
              extra: Optional[dict] = None) -> None:
        rule = RULES.get(rule_id)
        if not rule:
            return
        extra = dict(extra or {})
        now   = time.time()
        key   = (rule_id, src, dst or "")
        with self._em_lk:
            sup = self._suppress.get(key)
            if sup and now - sup["last"] < rule["cooldown"]:
                sup["last"] = now
                sup["count"] += 1
                aid, count = sup["alert"], sup["count"]
                update = True
            else:
                dq = self._rate.setdefault(rule_id, deque(maxlen=128))
                while dq and dq[0] < now - 3600:
                    dq.popleft()
                if len(dq) >= rule["rate"]:
                    self._suppressed += 1
                    return
                dq.append(now)
                update = False
                aid, count = "", 1
            incident, correlated = self._incident(src, rule["family"], now)
        if update:
            self._bump_alert(aid, count)
            return
        sev = extra.pop("severity", None) or rule["severity"]
        if correlated:
            sev = _sev_up(sev)
        enrich = self._enrich(src)
        if dst:
            enrich["peer"] = self._enrich(dst)
        a = add_alert(src or dst or "network", rule["title"], detail, sev,
                      rule=rule_id, attack=rule["attack"], action=rule["action"],
                      family=rule["family"], src=src, dst=dst,
                      incident=incident, correlated=bool(correlated),
                      confidence=extra.get("confidence", "high"),
                      enrich=enrich)
        with self._em_lk:
            self._suppress[key] = {"alert": a["id"], "last": now, "count": 1}
        self._rules_fired[rule_id] += 1
        self._obs["alerts"] += 1

    @staticmethod
    def _bump_alert(alert_id: str, count: int) -> None:
        with _lock:
            for a in alerts:
                if a.get("id") == alert_id:
                    a["count"] = count
                    a["last_ts"] = _ts()
                    break
        socketio.emit("alert_update", {"id": alert_id, "count": count,
                                       "last_ts": _ts()})

    def _enrich(self, ip: str) -> dict:
        if not ip:
            return {}
        with _lock:
            d = devices.get(ip) or {}
            info = {"hostname": d.get("hostname") or "",
                    "vendor": d.get("vendor") or "",
                    "type": d.get("device_type") or "",
                    "mac": (d.get("mac") or "").upper()}
        info["role"]    = self._role(ip)
        info["crit"]    = self._criticality(ip)
        info["vlan"]    = self._host_vlan.get(ip, "unknown")
        info["owner"]   = ""
        info["geo"]     = self._geo(ip)
        ti = []
        if ip in self._tor:
            ti.append("Tor exit node")
        if self._ti_hit(ip):
            ti.append("TI blocklist")
        info["ti"] = ", ".join(ti)
        if info["mac"]:
            inv = inventory_get(info["mac"])
            info["owner"] = inv.get("owner", "")
            if inv.get("criticality"):
                info["crit"] = inv["criticality"]
            info["inventory"] = bool(inv)
        return info

    # ── Status for the dashboard ─────────────────────────────────────────────
    def status(self) -> dict:
        capture = SCAPY_OK and IS_ROOT
        auth    = AUTHLOG.status()
        rules = []
        for rid, r in RULES.items():
            active, reason = True, ""
            req = r["requires"]
            if req == "capture":
                if not capture:
                    active, reason = False, "needs root + scapy (network-wide capture)"
                elif not self.capture_seen:
                    reason = "waiting for the first packet"
            elif req == "authlog":
                if not auth["active"]:
                    active, reason = False, auth["reason"]
            elif req == "dnsfeed":
                if not self._rdap_enabled:
                    active, reason = False, "disabled (set NETRON_RDAP=1)"
                elif self._rdap_status not in ("ok", "disabled"):
                    active, reason = False, self._rdap_status
            elif req == "inventory":
                if not self._inv_preexisting:
                    active, reason = True, "baseline being learned (no alerts until populated)"
            rules.append({"id": rid, "title": r["title"], "severity": r["severity"],
                          "attack": r["attack"], "action": r["action"],
                          "family": r["family"], "requires": req,
                          "active": active, "reason": reason,
                          "hits": self._rules_fired.get(rid, 0)})
        return {
            "capture": {"mode": "scapy" if capture else "psutil",
                        "network_wide": bool(capture),
                        "reason": "" if capture else "run as root with scapy/libpcap for network-wide rules"},
            "authlog": auth,
            "tor": {"enabled": self._tor_enabled, "status": self._tor_status,
                    "nodes": len(self._tor)},
            "ti": {"status": self._ti_status, "entries": len(self._ti_nets)},
            "geo": {"enabled": self._geo_enabled},
            "rdap": {"enabled": self._rdap_enabled, "status": self._rdap_status},
            "counters": {"packets": self._packets, "flows": len(self._flows),
                         "alerts": self._obs.get("alerts", 0),
                         "suppressed": self._suppressed,
                         "auth_events": self._obs.get("auth_events", 0)},
            "rules": rules,
        }


class AuthLogWatcher(threading.Thread):
    """Tails a Linux authentication log and forwards SSH auth outcomes.

    Scope: sshd lines only.  RDP/SMB/LDAP/Kerberos/VPN failures live in Windows
    event logs or DC audit logs, which this process cannot read; those rules are
    reported as inactive rather than guessed from network traffic.
    """

    PATHS = ("/var/log/auth.log", "/var/log/secure")
    _RE_FAIL   = re.compile(r"Failed [\w\-/]+ for (?:invalid user )?(\S+) from (\S+)")
    _RE_ACCEPT = re.compile(r"Accepted \S+ for (\S+) from (\S+)")
    _RE_MAX    = re.compile(r"maximum authentication attempts exceeded for "
                            r"(?:invalid user )?(\S+) from (\S+)")

    def __init__(self, engine: "DetectionEngine"):
        super().__init__(daemon=True, name="authlog")
        self.engine  = engine
        self.path    = ""
        self.active  = False
        self.reason  = "not started"
        self.events  = 0
        self._fh     = None
        self._ino    = None

    def status(self) -> dict:
        return {"active": self.active, "reason": self.reason,
                "path": self.path, "events": self.events}

    def _pick(self) -> str:
        cands = [os.environ.get("NETRON_AUTH_LOG", "")] + list(self.PATHS)
        for p in cands:
            if p and os.path.isfile(p) and os.access(p, os.R_OK):
                return p
        return ""

    def run(self) -> None:
        self.path = self._pick()
        if not self.path:
            self.reason = ("no readable auth log - run as root or point "
                           "NETRON_AUTH_LOG at /var/log/auth.log")
            return
        try:
            self._fh = open(self.path, "r", errors="replace")
            self._fh.seek(0, os.SEEK_END)      # only new events, never replay history
            self._ino = os.fstat(self._fh.fileno()).st_ino
        except OSError as e:
            self.reason = f"cannot open {self.path}: {e}"
            return
        self.active = True
        self.reason = f"tailing {self.path}"
        while True:
            line = self._fh.readline()
            if line:
                self._handle(line)
                continue
            time.sleep(1.0)
            # reopen after log rotation
            try:
                if not os.path.exists(self.path) or os.stat(self.path).st_ino != self._ino:
                    self._fh.close()
                    self._fh = open(self.path, "r", errors="replace")
                    self._ino = os.fstat(self._fh.fileno()).st_ino
                    self.reason = f"reopened {self.path}"
            except OSError:
                pass

    def _handle(self, line: str) -> None:
        if "sshd" not in line:
            return
        m = self._RE_ACCEPT.search(line)
        if m:
            self.events += 1
            self.engine.observe_auth(m.group(2), m.group(1), True, "SSH")
            return
        m = self._RE_FAIL.search(line) or self._RE_MAX.search(line)
        if m:
            self.events += 1
            self.engine.observe_auth(m.group(2), m.group(1), False, "SSH")


DETECT = DetectionEngine()
AUTHLOG = AuthLogWatcher(DETECT)


class PacketCapture:
    def __init__(self):
        self._running     = False
        self._pkt_count   = 0
        self._pps_win     = deque()   # timestamps of packets in the last second
        self._local_ips   = get_local_ips()
        self._seen_conns: set   = set()
        self._seen_ts:    float = time.time()
        self._prev_nic:   dict  = {}
        # Socket-event throttle (token bucket): cap live_packet/topo_packet at
        # EMIT_RATE_PPS events/second so a busy LAN can't flood the browser.
        self._emit_budget   = float(EMIT_RATE_PPS)
        self._emit_last     = time.time()
        self._pkt_seq       = 0
        self._obs_err_logged = False
        # Tor Project exit-node list (official public list).  Fetched in the
        # background; detection says "unavailable" when it cannot be loaded.
        DETECT.refresh_feeds()

    def start(self, iface: Optional[str] = None):
        self._running   = True
        self._local_ips = get_local_ips()
        if SCAPY_OK and IS_ROOT:
            threading.Thread(target=self._scapy_loop, args=(iface,),
                             daemon=True, name="cap-scapy").start()
            print("[Netron] Capture: Scapy deep-capture (root)")
        else:
            threading.Thread(target=self._conn_loop, daemon=True, name="cap-conn").start()
            threading.Thread(target=self._nic_loop,  daemon=True, name="cap-nic").start()
            print("[Netron] Capture: psutil poll (no-root mode)")

    def stop(self): self._running = False

    # ── Scapy mode ────────────────────────────────────────────────────────────
    def _scapy_loop(self, iface):
        try:
            # Capture the whole Internet protocol suite we can see on the wire:
            # IPv4, IPv6 and ARP (BPF filter keeps non-IP frames out cheaply).
            sniff(iface=iface, prn=self._on_pkt, store=False,
                  stop_filter=lambda _: not self._running,
                  filter="ip or ip6 or arp")
        except Exception as e:
            print(f"[Netron] Scapy stopped ({e}), switching to psutil")
            threading.Thread(target=self._conn_loop, daemon=True, name="cap-conn-fb").start()
            threading.Thread(target=self._nic_loop,  daemon=True, name="cap-nic-fb").start()

    def _on_pkt(self, pkt):
        # Hand the frame to the detection engine first: every parser is
        # best-effort and must never break the display pipeline.
        self._observe(pkt)
        # ── ARP (link-layer neighbour discovery, RFC 826) ─────────────────────
        if pkt.haslayer(ARP):
            a = pkt[ARP]
            if a.op == 1:      # request
                info = f"who-has {a.pdst}?  tell {a.psrc}"
            elif a.op == 2:    # reply
                info = f"{a.psrc} is-at {a.hwsrc}"
            else:
                info = f"op={a.op}  {a.psrc} → {a.pdst}"
            self._emit(a.psrc, a.pdst, "ARP", len(pkt), info, None, None)
            return

        # ── Internet layer: IPv4 or IPv6 ──────────────────────────────────────
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
            nh = pkt[IP].proto            # next header / protocol number
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
            nh = pkt[IPv6].nh
        else:
            return                        # non-IP frame (kept out by the BPF filter)
        length = len(pkt)
        proto, info, sport, dport = "OTHER", "", None, None

        if pkt.haslayer(TCP):                                  # works over v4 and v6
            proto  = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            flags  = int(pkt[TCP].flags)
            svc = (_app_proto(sport, dport, "tcp")
                   or self._svc_name(dport, "tcp"))
            info = f":{sport} → :{dport}" + (f" [{svc}]" if svc else "") + f"  f={flags}"
            # VoIP signalling runs over TCP too (SIP/TLS on 5061, H.323 on 1720).
            try:
                voip = voip_label(sport, dport, "tcp", bytes(pkt[TCP].payload)[:64])
            except Exception:
                voip = ""
            if voip:
                info = f"{voip}  " + info
        elif pkt.haslayer(UDP):
            proto  = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            try:
                voip = voip_label(sport, dport, "udp", bytes(pkt[UDP].payload)[:64])
            except Exception:
                voip = ""
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    q = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                    info = f"DNS  {q}"
                except Exception:
                    info = f":{sport} → :{dport}"
            else:
                svc = (_app_proto(sport, dport, "udp")
                       or self._svc_name(dport, "udp"))
                info = f":{sport} → :{dport}" + (f" [{svc}]" if svc else "")
                if voip:
                    info = f"{voip}  " + info
        elif nh == 1:                                          # ICMPv4
            proto = "ICMP"
            if pkt.haslayer(ICMP):
                info = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
            else:
                info = f"proto={nh}"
        elif nh == 58:                                         # ICMPv6
            proto = "ICMPv6"
            # type/code are the first two bytes of the IPv6 payload
            raw = bytes(pkt[IPv6].payload)
            info = f"type={raw[0]} code={raw[1]}" if len(raw) >= 2 else f"proto=58"
        elif nh == 6 or nh == 17:
            # TCP/UDP payload scapy couldn't reassemble (e.g. odd offsets)
            proto = "TCP" if nh == 6 else "UDP"
            info  = f"proto={nh}"
        else:
            # Any other Internet protocol (e.g. SCTP 132, GRE 47, ESP 50,
            # IPv6 Hop-by-Hop 0, Fragment 44) – show the protocol number
            proto = "IPv6" if pkt.haslayer(IPv6) else "OTHER"
            info  = f"proto={nh}"

        self._emit(src, dst, proto, length, info, sport, dport,
                   {"voip": voip} if ("voip" in locals() and voip) else None)

    # ── Detection parsing ────────────────────────────────────────────────────
    # DCE/RPC interface UUID for DRSUAPI (DCSync): e3514235-4b06-11d1-ab04-00c04fc2dcd2
    # in on-the-wire little-endian form.
    DRSUAPI_UUID = bytes.fromhex("354251e3064bd111ab0400c04fc2dcd2")

    def _observe(self, pkt):
        """Parse a frame for detection.  Never raises into the capture loop."""
        if not SCAPY_OK:
            return
        try:
            ev = self._parse_pkt(pkt)
            if ev:
                DETECT.on_packet(ev)
        except Exception:
            if not self._obs_err_logged:
                self._obs_err_logged = True
                log.warning("[Netron] detection parser error", exc_info=True)

    @staticmethod
    def _payload_bytes(p) -> bytes:
        try:
            return bytes(p)[:2048]
        except Exception:
            return b""

    def _parse_pkt(self, pkt) -> Optional[dict]:
        ev = {"ts": time.time()}
        try:
            if pkt.haslayer(Dot1Q):
                ev["vlan"] = int(pkt[Dot1Q].vlan)
        except Exception:
            pass
        if pkt.haslayer(ARP):
            a = pkt[ARP]
            ev.update(src=a.psrc, dst=a.pdst, proto="ARP", size=len(pkt),
                      arp={"op": int(a.op), "psrc": a.psrc, "pdst": a.pdst,
                           "hwsrc": str(a.hwsrc).upper(),
                           "hwdst": str(a.hwdst).upper(),
                           "gratuitous": a.psrc == a.pdst})
            return ev
        if pkt.haslayer(IP):
            src, dst, nh = pkt[IP].src, pkt[IP].dst, pkt[IP].proto
        elif pkt.haslayer(IPv6):
            src, dst, nh = pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6].nh
        else:
            return None
        ev.update(src=src, dst=dst, size=len(pkt))

        if pkt.haslayer(TCP):
            t = pkt[TCP]
            sport, dport = int(t.sport), int(t.dport)
            ev.update(proto="TCP", sport=sport, dport=dport, flags=int(t.flags))
            load = self._payload_bytes(t.payload)
            if load:
                ev["payload_len"] = len(load)
                if 445 in (sport, dport):
                    smb = self._parse_smb(load)
                    if smb:
                        ev["smb"] = smb
                if 88 in (sport, dport):
                    krb = self._parse_krb(load)
                    if krb:
                        ev["krb"] = krb
                if self.DRSUAPI_UUID in load:
                    ev["rpc"] = "drsuapi"
                if load[:1] == b"\x16":
                    sni = self._parse_tls_sni(load)
                    if sni:
                        ev["sni"] = sni
                m = re.match(rb"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) /\S* HTTP/\d", load)
                if m:
                    ev["http"] = m.group(1).decode()
                if b"mining.subscribe" in load or b"mining.authorize" in load:
                    ev["stratum"] = True
            if 53 in (sport, dport) and load:
                try:
                    n = int.from_bytes(load[:2], "big")
                    if n and n <= len(load) - 2:
                        d = DNS(load[2:2 + n])
                        ev["dns"] = self._dns_dict(d, len(load) - 2)
                except Exception:
                    pass
            return ev

        if pkt.haslayer(UDP):
            u = pkt[UDP]
            sport, dport = int(u.sport), int(u.dport)
            ev.update(proto="UDP", sport=sport, dport=dport)
            load = self._payload_bytes(u.payload)
            if pkt.haslayer(DNS):
                d = pkt[DNS]
                ev["dns"] = self._dns_dict(d, len(load))
                return ev
            if 137 in (sport, dport) and len(load) >= 12:
                flags = int.from_bytes(load[2:4], "big")
                ev["dns"] = {"nbtns": True, "response": bool(flags & 0x8000)}
                return ev
            if pkt.haslayer(BOOTP):
                b = pkt[BOOTP]
                msg_type, sig, router = 0, [], ""
                if pkt.haslayer(DHCP):
                    for opt in (pkt[DHCP].options or []):
                        if not isinstance(opt, tuple) or len(opt) < 2:
                            continue
                        key, val = opt[0], opt[1]
                        try:
                            if key == "message-type":
                                msg_type = int(val)
                            elif key in ("param_req_list", 55):
                                sig = list(val) if isinstance(val, (bytes, list)) else []
                            elif key == "router":
                                router = ".".join(str(x) for x in val) if isinstance(val, (list, tuple)) else str(val)
                        except (TypeError, ValueError):
                            continue
                ev["dhcp"] = {"msg_type": msg_type,
                              "mac": bytes(b.chaddr[:6]).hex(":").upper(),
                              "opts": ",".join(str(int(x)) for x in sig),
                              "router": router, "size": len(load)}
            return ev

        if nh == 1 and pkt.haslayer(ICMP):
            ev.update(proto="ICMP", icmp={"type": int(pkt[ICMP].type),
                                          "code": int(pkt[ICMP].code)})
        elif nh == 58:
            ev.update(proto="ICMPv6")
        else:
            ev.update(proto="OTHER")
        return ev

    def _dns_dict(self, d, size: int) -> dict:
        qd = d.qd
        if isinstance(qd, list):
            qd = qd[0] if qd else None
        qname, qtype = "", 0
        try:
            if qd is not None:
                qname = qd.qname.decode(errors="ignore").rstrip(".")
                qtype = int(qd.qtype)
        except Exception:
            pass
        def _num(v) -> int:
            try:
                return int(v or 0)
            except (TypeError, ValueError):
                return 0
        return {"qname": qname, "qtype": qtype, "rcode": _num(d.rcode),
                "response": bool(d.qr), "ancount": _num(d.ancount), "size": size}

    def _parse_smb(self, load: bytes) -> Optional[dict]:
        if len(load) < 64 or load[:4] != b"\xfeSMB":
            return None
        cmd = int.from_bytes(load[12:14], "little")
        flags = int.from_bytes(load[16:20], "little")
        info = {"cmd": cmd, "response": bool(flags & 0x01)}
        body = load[64:]
        if cmd == 3:                                  # TREE_CONNECT
            for share in ("ADMIN$", "C$"):
                if share.encode("utf-16-le") in body:
                    info["share"] = share
                    break
        if cmd == 0 and info["response"] and len(load) >= 68:
            sec_mode = int.from_bytes(load[66:68], "little")
            info["signing_enabled"] = bool(sec_mode & 0x02)
        return info

    @staticmethod
    def _der_items(b: bytes) -> List[Tuple[int, bytes]]:
        out, i = [], 0
        while i < len(b):
            tag = b[i]; i += 1
            if i >= len(b):
                break
            ln = b[i]; i += 1
            if ln & 0x80:
                n = ln & 0x7f
                if n == 0 or n > 4 or i + n > len(b):
                    break
                ln = int.from_bytes(b[i:i + n], "big"); i += n
            if i + ln > len(b):
                break
            out.append((tag, b[i:i + ln])); i += ln
        return out

    @staticmethod
    def _der_seq(b: bytes) -> List[Tuple[int, bytes]]:
        if len(b) < 2 or b[0] != 0x30:
            return []
        i, ln = 2, b[1]
        if ln & 0x80:
            n = ln & 0x7f
            if n == 0 or n > 4 or i + n > len(b):
                return []
            ln = int.from_bytes(b[i:i + n], "big"); i += n
        return PacketCapture._der_items(b[i:i + ln])

    @staticmethod
    def _der_ints(b: bytes) -> List[int]:
        """INTEGERs inside a DER element (a SEQUENCE, or an implicit tag whose
        content is directly a SEQUENCE OF INTEGER, e.g. Kerberos etype [0])."""
        if not b:
            return []
        items = PacketCapture._der_seq(b) if b[0] == 0x30 else PacketCapture._der_items(b)
        out: List[int] = []
        for t, v in items:
            if t == 0x02:
                out.append(int.from_bytes(v, "big"))
            elif t in (0x30, 0xa0):
                out.extend(PacketCapture._der_ints(v))
        return out

    def _parse_krb(self, load: bytes) -> Optional[dict]:
        b = load
        if len(b) >= 4:
            n = int.from_bytes(b[:4], "big")
            if b[0] == 0 and n == len(b) - 4:
                b = b[4:]                             # TCP length prefix
        if not b:
            return None
        mtype = {0x6a: 10, 0x6b: 11, 0x6c: 12, 0x6d: 13}.get(b[0])
        if not mtype:
            return None
        i = 1
        if i >= len(b):
            return None
        ln = b[i]; i += 1
        if ln & 0x80:
            n = ln & 0x7f
            if n == 0 or n > 4 or i + n > len(b):
                return None
            ln = int.from_bytes(b[i:i + n], "big"); i += n
        body = b[i:i + ln]
        etypes: List[int] = []
        for tag, val in self._der_seq(body):
            if tag == 0xa4 and mtype in (10, 12):     # KDC-REQ-BODY
                for t2, v2 in self._der_seq(val):
                    if t2 == 0xa7:                    # etype [7] SEQUENCE OF INTEGER
                        etypes.extend(self._der_ints(v2))
            elif tag == 0xa6 and mtype in (11, 13):   # EncryptedData
                for t2, v2 in self._der_seq(val):
                    if t2 == 0xa0:                    # etype [0]
                        etypes.extend(self._der_ints(v2))
        return {"msg_type": mtype, "etypes": etypes}

    @staticmethod
    def _parse_tls_sni(load: bytes) -> str:
        """Minimal TLS ClientHello server_name (SNI) extractor."""
        try:
            if len(load) < 6 or load[0] != 0x16 or load[5] != 0x01:
                return ""
            p = 5 + 4 + 2 + 32          # record + handshake header + version + random
            if p >= len(load):
                return ""
            p += 1 + load[p]            # session id
            p += 2 + int.from_bytes(load[p:p + 2], "big")      # cipher suites
            if p >= len(load):
                return ""
            p += 1 + load[p]            # compression methods
            if p + 2 > len(load):
                return ""
            end = min(len(load), p + 2 + int.from_bytes(load[p:p + 2], "big"))
            p += 2
            while p + 4 <= end:
                etype = int.from_bytes(load[p:p + 2], "big")
                elen  = int.from_bytes(load[p + 2:p + 4], "big")
                p += 4
                if etype == 0 and p + 5 <= end:          # server_name
                    # server_name_list: 2-byte length, then entries of
                    # name_type(1 byte) + length(2 bytes) + name.
                    q = p + 2
                    nlen = int.from_bytes(load[q + 1:q + 3], "big")
                    name = load[q + 3:q + 3 + nlen].decode("ascii", errors="ignore")
                    return name.lower().rstrip(".")
                p += elen
        except Exception:
            pass
        return ""

    @staticmethod
    def _svc_name(port: int, transp: str) -> str:
        try:
            return socket.getservbyport(port, transp) if port < 1024 else ""
        except Exception:
            return ""

    # ── psutil connection poll (fallback) ─────────────────────────────────────
    # Limitation (by design, not a bug): psutil reads the OS socket table, so
    # this mode can only report TCP and UDP connections. Full capture of
    # ICMP/ICMPv6/ARP/other protocols requires root + scapy mode.
    def _conn_loop(self):
        PMAP = {socket.SOCK_STREAM: "TCP", socket.SOCK_DGRAM: "UDP"}
        while self._running:
            now = time.time()
            # Flush seen-set every 8 seconds so flows reappear
            if now - self._seen_ts > 8:
                self._seen_conns.clear()
                self._seen_ts = now
            try:
                for c in psutil.net_connections(kind="inet"):
                    if not c.raddr:
                        continue
                    laddr, raddr = c.laddr, c.raddr
                    src   = laddr.ip   if laddr else "0.0.0.0"
                    dst   = raddr.ip
                    sport = laddr.port if laddr else 0
                    dport = raddr.port
                    proto = PMAP.get(c.type, "TCP")
                    key   = (src, sport, dst, dport, proto)
                    if key in self._seen_conns:
                        continue
                    self._seen_conns.add(key)
                    svc = ""
                    try: svc = socket.getservbyport(dport, proto.lower())
                    except Exception: pass
                    info = f":{sport} → :{dport}" + (f"  [{svc}]" if svc else "")
                    # VoIP is labelled from the socket's ports only: without the
                    # payload there is no evidence for RTP/RTCP dynamic ports, so
                    # those stay unlabelled in this mode instead of being guessed.
                    voip = voip_label(sport, dport, proto.lower())
                    if voip:
                        info = f"{voip}  " + info
                    # Byte size is genuinely unknown from the socket table: report
                    # 0 rather than inventing a packet length that would then be
                    # summed into per-device bandwidth and charts.
                    self._emit(src, dst, proto, 0, info, sport, dport,
                               {"voip": voip} if voip else None)
            except Exception:
                pass
            time.sleep(1)

    # ── NIC byte-counter poll ─────────────────────────────────────────────────
    def _nic_loop(self):
        while self._running:
            try:
                # Re-resolve the primary local IP every pass – DHCP leases and
                # VPN interfaces can change while we're running.
                local_ip = _primary_local_ip()
                for nic, s in psutil.net_io_counters(pernic=True).items():
                    if nic.startswith("lo"):
                        continue
                    prev = self._prev_nic.get(nic)
                    if prev:
                        d_in  = max(0, s.bytes_recv   - prev.bytes_recv)
                        d_out = max(0, s.bytes_sent    - prev.bytes_sent)
                        p_in  = max(0, s.packets_recv  - prev.packets_recv)
                        p_out = max(0, s.packets_sent  - prev.packets_sent)
                        if d_in > 0:
                            self._emit("(network)", local_ip, "RECV", d_in,
                                       f"{nic}  ↓{_fmt(d_in)}/s  {p_in}p", None, None)
                        if d_out > 0:
                            self._emit(local_ip, "(internet)", "SEND", d_out,
                                       f"{nic}  ↑{_fmt(d_out)}/s  {p_out}p", None, None)
                        # NIC counters are the single source of truth for the
                        # global totals – _emit() only updates per-device bytes,
                        # otherwise every byte was counted twice.
                    self._prev_nic[nic] = s
            except Exception:
                pass
            time.sleep(1)

    # ── Shared emit ───────────────────────────────────────────────────────────
    def _emit(self, src, dst, proto, length, info, sport, dport, extra=None):
        rec = {"ts":_sts(),"src":src,"dst":dst,"proto":proto,
               "len":length,"info":info,"sport":sport,"dport":dport}
        if extra:
            rec.update(extra)
        with _lock:
            # Global feed: every captured packet, regardless of whether both
            # endpoints are known devices (that is what a packet list must show).
            self._pkt_seq += 1
            rec["seq"] = self._pkt_seq
            pkt_feed.appendleft(rec)
            for ip in (src, dst):
                if ip in devices:
                    packet_log[ip].appendleft(rec)
                    if ip == src:
                        devices[ip]["bytes_out"] = devices[ip].get("bytes_out",0) + length
                    else:
                        devices[ip]["bytes_in"]  = devices[ip].get("bytes_in", 0) + length
            # net_stats totals are owned exclusively by _nic_loop().
            self._pkt_count += 1
            # Instantaneous packets-per-second (1-second sliding window)
            now = time.time()
            self._pps_win.append(now)
            while self._pps_win and self._pps_win[0] < now - 1.0:
                self._pps_win.popleft()
            net_stats["pps"] = len(self._pps_win)
            # Token-bucket throttle for socket events: counters above stay
            # exact, only the browser event stream is rate-limited.
            elapsed  = max(0.0, now - self._emit_last)
            self._emit_last = now
            self._emit_budget = min(float(EMIT_RATE_PPS),
                                    self._emit_budget + elapsed * EMIT_RATE_PPS)
            should_send = self._emit_budget >= 1.0
            if should_send:
                self._emit_budget -= 1.0
        if should_send:
            socketio.emit("live_packet", rec)
            # Lightweight topology event for the network graph
            socketio.emit("topo_packet", {"src":src,"dst":dst,"proto":proto,"len":length})


# ─────────────────────────────────────────────────────────────────────────────
#  NETWORK MONITOR  (orchestrator)
# ─────────────────────────────────────────────────────────────────────────────
class NetworkMonitor:
    def __init__(self):
        self.scanner = NetworkScanner()
        self.capture = PacketCapture()
        self.gateway, self.network = get_local_network()
        self._running = False
        # Thread pool for parallel deep-scans (limit concurrency)
        self._scan_pool = ThreadPoolExecutor(max_workers=max(4, SCAN_WORKERS),
                                             thread_name_prefix="deep")
        # IPs queued/running in the deep-scan pool + a hard cap on outstanding
        # work, so a slow sweep can never grow the queue without bound.
        self._inflight: set = set()
        self._inflight_lock = threading.Lock()
        self._MAX_INFLIGHT = max(64, SCAN_WORKERS * 3)

    def start(self):
        self._running = True
        # Step 1: instant ARP-cache seed (shows devices in ~1s)
        threading.Thread(target=self._quick_arp_seed, daemon=True, name="arp-seed").start()
        # Step 1b: fast ongoing ARP watch so newly-connected devices appear immediately
        threading.Thread(target=self._arp_watch_loop, daemon=True, name="arp-watch").start()
        # Step 2: full nmap scan (slower, fills in ports/OS/vulns)
        threading.Thread(target=self._full_scan,      daemon=True, name="scan0").start()
        threading.Thread(target=self._scan_loop,       daemon=True, name="scan-loop").start()
        # Parallel vulnerability sweep: every online device is assessed
        # concurrently instead of waiting its turn in the deep-scan queue.
        threading.Thread(target=self._vuln_loop,       daemon=True, name="vuln-loop").start()
        threading.Thread(target=self._bw_loop,         daemon=True, name="bw-loop").start()
        # Detection: tail the local auth log (SSH only) and evaluate baselines
        # on a fixed cadence.  Both threads say they are inactive when the
        # telemetry they need is missing -- they never fake coverage.
        if not AUTHLOG.is_alive():
            AUTHLOG.start()
        threading.Thread(target=self._detect_loop, daemon=True, name="detect-tick").start()
        self.capture.start()

    def _detect_loop(self):
        while self._running:
            time.sleep(5)
            try:
                DETECT.tick()
            except Exception:
                log.warning("Detection tick failed", exc_info=True)

    def _scan_loop(self):
        while self._running:
            time.sleep(SCAN_INTERVAL)
            self._full_scan()

    # ── Vulnerability sweep ──────────────────────────────────────────────────
    # Port + exposure assessment for EVERY online device, all hosts at once.
    # The deep-scan queue also produces findings, but it serialises hostname,
    # TTL, banner, OS and vendor lookups per host, so on a busy network the
    # vulnerabilities panel used to fill in one device at a time.  This sweep
    # only does what the panel needs (port scan → assess_vulns) and runs the
    # hosts concurrently, bounded by VULN_WORKERS.
    def _vuln_loop(self):
        # First sweep shortly after start so the panel fills quickly, then on
        # the configured cadence.
        time.sleep(4)
        while self._running:
            try:
                self._vuln_sweep()
            except Exception:
                log.warning("Vulnerability sweep failed", exc_info=True)
            time.sleep(max(10, VULN_INTERVAL))

    def _vuln_scan_host(self, ip: str):
        """One host: fresh port scan, then the exposure assessment."""
        ports = self.scanner.port_scan(ip)
        return ip, ports, self.scanner.assess_vulns(ports)

    def _vuln_sweep(self):
        now = time.time()
        try:
            local_ips = set(get_local_ips())
        except Exception:
            local_ips = set()
        with _lock:
            candidates = [ip for ip, d in devices.items()
                          if d.get("status") == "online" and ip not in local_ips]
            # A host the deep scan just refreshed does not need scanning again
            # this round -- `vuln_scanned` records when its ports were read.
            targets = [ip for ip in candidates
                       if now - _parse_ts(devices[ip].get("vuln_scanned")) >= VULN_INTERVAL]
        if not targets:
            return
        # Don't double-scan a host the deep-scan pool is working on.
        with self._inflight_lock:
            busy = set(self._inflight)
        targets = [ip for ip in targets if ip not in busy]
        if not targets:
            return
        workers = max(2, min(len(targets), VULN_WORKERS))
        results = []
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vuln") as ex:
            try:
                futs = [ex.submit(self._vuln_scan_host, ip) for ip in targets]
            except RuntimeError:
                # Pool down (interpreter shutting down) – nothing to sweep.
                return
            for f in as_completed(futs):
                try:
                    results.append(f.result())
                except Exception as e:
                    log.warning("Vulnerability scan failed: %s", e)
        for ip, ports, vulns in results:
            self._apply_vuln_scan(ip, ports, vulns)

    def _apply_vuln_scan(self, ip: str, ports: dict, vulns: list) -> None:
        """Merge one host's findings, then push the device to the UI."""
        with _lock:
            dev = devices.get(ip)
            if dev is None or dev.get("status") != "online":
                return
            prev_ports = dev.get("open_ports") or {}
            # Same merge rule as the deep scan: an empty or partial sweep keeps
            # the ports we already observed open (see merge_scan_ports).
            merged, carried = merge_scan_ports(ip, prev_ports, ports)
            if carried:
                # Re-assess what is still displayed (including ports this
                # sweep did not re-probe) so findings and ports never diverge.
                try:
                    vulns = self.scanner.assess_vulns(merged)
                except Exception:
                    vulns = dev.get("vulnerabilities") or []
            dev["open_ports"]      = merged
            dev["vuln_count"]       = len(vulns)
            dev["vuln_scanned"]     = _ts()
            dev["last_seen"]        = _ts()
            snap = dict(dev)
        DETECT.observe_ports(ip, merged)
        socketio.emit("device_update", snap)

    def _register_arp_host(self, ip: str, mac: str, announce: bool = False) -> Optional[dict]:
        """
        Fast registration of a host discovered from the OS ARP table.
        Adds it to `devices` (if absent) and emits device_update so the UI
        reflects it immediately. Returns the entry (or None if unchanged).
        Also flips a previously-offline device back to online (reconnect) so
        it reappears in the UI without waiting for the full nmap sweep.
        Vendor lookup + a quick TTL ping fill in the first-pass details; the
        full nmap deep-scan later refines open ports / OS / vulnerabilities.
        """
        mac = (mac or "N/A").upper()
        # Never register the monitoring host itself as a network device.
        # Its own IP(s) appear in the OS ARP table and would otherwise show up
        # as bogus "Unknown" nodes on the graph.
        try:
            if ip in get_local_ips():
                return None
        except Exception:
            pass
        reconnect = None
        with _lock:
            existing = devices.get(ip)
            if existing is not None and existing.get("status") == "online":
                return None
            if existing is not None and existing.get("status") == "offline":
                # Reconnect: bring it back online immediately
                existing["status"]  = "online"
                existing["last_seen"] = _ts()
                if mac != "N/A":
                    existing["mac"] = mac
                missed_scans[ip] = 0
                _arp_seen_ts[ip] = time.time()
                reconnect = existing
        if reconnect is not None:
            socketio.emit("device_update", reconnect)
            return reconnect
        vendor, dtype, brand = lookup_vendor(mac)
        ttl      = self.scanner.ping_ttl(ip)
        os_hint  = ("Linux / Android / macOS"   if 0 < ttl <= 64  else
                    "Windows / Android"          if ttl <= 128     else
                    "iOS / Network Device"       if ttl > 128      else
                    "Linux / Android / iOS / macOS")
        # Unknown values stay empty (the UI falls back to the IP for labels).
        # An IP address must never be stored as a vendor/brand/device type.
        dv  = vendor if vendor and vendor.lower() not in ("unknown","") else ""
        db  = brand  if brand  and brand.lower()  not in ("unknown","") else ""
        ddt = dtype  if dtype  and dtype.lower()  not in ("unknown","") else ""
        entry = {
            "ip": ip, "mac": mac, "hostname": "",
            "vendor": dv, "brand": db, "device_type": ddt,
            "os": os_hint, "os_accuracy": "ARP (fast scan pending)",
            "ttl": ttl, "open_ports": {}, "vulnerabilities": [],
            "vuln_count": 0, "status": "online", "blocked": False,
            "first_seen": _ts(), "last_seen": _ts(),
            "bytes_in": 0, "bytes_out": 0,
            "is_gateway": (ip == self.gateway),
        }
        with _lock:
            if ip not in devices:     # double-check after lock
                devices[ip] = entry
                missed_scans[ip] = 0
                _arp_seen_ts[ip] = time.time()
            else:
                return None
        socketio.emit("device_update", devices[ip])
        # Alert only for live discoveries (announce=True), never for the
        # startup ARP seed – otherwise booting the app spams one alert per host.
        if announce:
            add_alert(ip, "New Device Joined",
                      f"{dv} ({ddt}) at {ip} — vendor from OUI, deep scan pending",
                      "INFO")
        DETECT.observe_host(ip, mac, dv)
        return devices[ip]

    def _quick_arp_seed(self):
        """
        Phase 1 of startup: read the OS ARP table and emit devices immediately
        so they appear in the UI within ~1 second.
        Also fires a parallel vendor API lookup for any unrecognised MACs so
        that by the time the slow nmap scan finishes, vendors are already cached.
        """
        hosts = self.scanner._arp_table(self.network)
        if not hosts:
            return
        # Seed all devices in parallel. The vendor APIs are rate-limited to
        # ~1 req/s, so a small pool avoids a thundering herd of threads that
        # would all just sit in the rate-limiter.
        list(_ARP_POOL.map(
            lambda h: self._register_arp_host(h["ip"], h.get("mac", "N/A")), hosts))

    def _arp_watch_loop(self):
        """
        Fast ongoing detection of newly-connected devices (and re-detection of
        devices that left the ARP cache). Polls the OS ARP table every few
        seconds (cheap, no nmap) so a device that joins the network shows up in
        the UI almost immediately – well before the next full 15s sweep.
        """
        while self._running:
            try:
                hosts = self.scanner._arp_table(self.network)
                if hosts:
                    # Starter hosts only: skip ones we already track (online).
                    # Snapshot under the lock – `devices` is mutated by other threads.
                    with _lock:
                        new = [h for h in hosts
                               if h["ip"] not in devices
                               or devices[h["ip"]].get("status") != "online"]
                    if new:
                        list(_ARP_POOL.map(
                            lambda h: self._register_arp_host(
                                h["ip"], h.get("mac", "N/A"), announce=True),
                            new))
            except Exception:
                pass
            time.sleep(3)

    def _full_scan(self):
        hosts = self.scanner.discover(self.network)
        with _lock:
            net_stats["scan_count"] += 1
        seen = set()
        # The monitoring host itself is not a device to display
        local_ips = set()
        try:
            local_ips = get_local_ips()
        except Exception:
            pass
        now = time.time()
        # Snapshot what is already known so the sweep can spend its workers on
        # devices that need work instead of re-identifying every host every
        # cycle.  Identification (PTR/mDNS/NetBIOS, banner, OS, vendor) is
        # expensive; ports and vulnerabilities are kept fresh by the parallel
        # vulnerability sweep.
        with _lock:
            known = {ip: (d.get("identified_ts"), d.get("mac"))
                     for ip, d in devices.items()}
        for h in hosts:
            ip, mac = h["ip"], h.get("mac","N/A")
            if ip in local_ips:
                continue   # never show/track the machine running Netron
            seen.add(ip)
            prev = known.get(ip)
            if (prev and prev[1] == mac
                    and 0 <= now - _parse_ts(prev[0]) < ID_INTERVAL):
                continue   # identified recently – nothing to redo yet
            # Don't queue more work than the pool can reasonably drain; the
            # next sweep retries anything skipped here.
            with self._inflight_lock:
                if len(self._inflight) >= self._MAX_INFLIGHT:
                    continue
            # lookup_vendor is fast if cached; _deep_scan will re-query if needed
            vendor, dtype, brand = lookup_vendor(mac)
            try:
                self._scan_pool.submit(
                    self._deep_scan_guarded, ip, mac, vendor, dtype, brand
                )
            except RuntimeError:
                # Pool already torn down (interpreter shutting down) – the sweep
                # is worthless at that point, so stop quietly instead of
                # dumping a traceback.
                return
        # Queue vendor-API work for MACs the built-in OUI table does not know.
        # This only enqueues: the single background worker does the HTTP calls
        # at the API's rate limit and pushes the answer to the device later.
        for h in hosts:
            m = h.get("mac", "N/A")
            if oui(m) and oui(m) not in _vendor_cache and oui(m) not in OUI_TABLE:
                lookup_vendor(m)
        # Mark offline — but only when a device was missed by TWO consecutive
        # sweeps AND hasn't been seen in the OS ARP cache within the grace
        # window. A single missed nmap result (Wi-Fi power-save, scan timeout)
        # otherwise makes devices flap online/offline in the UI.
        now = time.time()
        to_emit = []
        with _lock:
            for ip in list(devices):
                dev = devices[ip]
                if ip in seen:
                    missed_scans[ip] = 0
                    _arp_seen_ts[ip] = now
                    continue
                if dev.get("status") != "online":
                    continue
                missed_scans[ip] += 1
                arp_age = now - _arp_seen_ts.get(ip, 0)
                if missed_scans[ip] >= 2 and arp_age > ARP_GRACE_SECS:
                    dev["status"] = "offline"
                    dev["last_seen"] = _ts()
                    to_emit.append(dev)
        for dev in to_emit:
            socketio.emit("device_update", dev)
        # Prune long-gone devices and their per-device logs so memory stays
        # bounded (blocked devices are kept so the block survives reconnects).
        cutoff = now - DEVICE_RETENTION_SECS
        with _lock:
            gone = [ip for ip, d in devices.items()
                    if d.get("status") == "offline" and not d.get("blocked")
                    and _arp_seen_ts.get(ip, 0) < cutoff]
            for ip in gone:
                devices.pop(ip, None)
                packet_log.pop(ip, None)
                traffic_data.pop(ip, None)
                missed_scans.pop(ip, None)
                _arp_seen_ts.pop(ip, None)
        for ip in gone:
            socketio.emit("device_removed", {"ip": ip})

    # ── HTTP banner grab ─────────────────────────────────────────────────────
    @staticmethod
    def _http_banner(ip: str, open_ports: dict) -> dict:
        """
        Fetch HTTP/HTTPS headers from the device's web server (if any).
        Returns a dict with useful fields: server, model, product, auth_realm.
        Many routers, cameras, printers and smart devices expose their model
        in the Server: header or HTML <title>.
        """
        info: dict = {}
        candidates = []
        for port, pdata in open_ports.items():
            if pdata.get("state") != "open":
                continue
            if port in (80, 8080, 8008, 8888):
                candidates.append((f"http://{ip}:{port}", port))
            elif port in (443, 8443, 8843):
                candidates.append((f"https://{ip}:{port}", port))
        if not candidates:
            return info
        import urllib.request as _ur, ssl as _ssl
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE
        for url, port in candidates[:2]:    # try up to 2 ports
            try:
                req = _ur.Request(url, headers={"User-Agent":"Netron/3"})
                r   = _ur.urlopen(req, timeout=2, context=ctx if "https" in url else None)
                hdrs = dict(r.headers)
                # Server header (e.g. "lighttpd/1.4.45", "mini_httpd", "GoAhead")
                srv = hdrs.get("Server","") or hdrs.get("server","")
                if srv:
                    info["server"] = srv[:80]
                # WWW-Authenticate realm – often contains model name
                auth = hdrs.get("WWW-Authenticate","") or hdrs.get("www-authenticate","")
                if auth:
                    m = re.search(r'realm="([^"]+)"', auth)
                    if m:
                        info["auth_realm"] = m.group(1)[:60]
                # Read a small slice of the HTML body for <title>
                try:
                    body = r.read(4096).decode("utf-8","replace")
                    tm = re.search(r"<title[^>]*>([^<]{3,80})</title>", body, re.I)
                    if tm:
                        info["title"] = tm.group(1).strip()[:60]
                except Exception:
                    pass
                if info:
                    break
            except Exception:
                continue
        return info

    def _deep_scan_guarded(self, ip, mac, vendor, dtype, brand):
        """
        _deep_scan wrapper that runs in the thread pool: deduplicates in-flight
        scans of the same host, and contains any unexpected error instead of
        silently killing the worker.
        """
        with self._inflight_lock:
            if ip in self._inflight:
                return
            self._inflight.add(ip)
        try:
            self._deep_scan(ip, mac, vendor, dtype, brand)
        except Exception as e:
            log.warning("Deep scan failed for %s: %s", ip, e)
        finally:
            with self._inflight_lock:
                self._inflight.discard(ip)

    def _deep_scan(self, ip, mac, vendor, dtype, brand):
        """
        Full per-device scan pipeline:
          1. Reverse DNS / mDNS hostname
          2. TTL ping (fast, determines OS family)
          3. Port scan  (nmap SYN/connect or TCP fallback)
          4. HTTP banner grab (router/printer/camera model from web server)
          5. nmap OS detection (root only) or multi-signal heuristic
          6. Vendor deep-lookup (OUI table → macvendors API → maclookup API)
          7. Refine device_type using ALL signals
          8. Vulnerability assessment
        """
        # 1. Hostname: PTR, then the host's own mDNS / NetBIOS answer (cached).
        hostname = resolve_hostname(ip)

        # 2. TTL (quick – run before port scan so OS family is known early)
        ttl = self.scanner.ping_ttl(ip)

        # 3. Port scan
        open_ports = self.scanner.port_scan(ip)

        # 4. HTTP banner – fetch before OS detection so banner can inform it
        banner = self._http_banner(ip, open_ports)

        # 4b. The HTTP Server/auth-realm strings name *software* or a product
        #     line ("mini_httpd", "lighttpd", "GoAhead"), not the manufacturer,
        #     and a model name in a realm is not a company name either.  Using
        #     them as vendor/brand would invent a manufacturer, so banner data
        #     only feeds device_type below.

        # 4c. Deep vendor re-lookup if still unknown (tries live API)
        if not vendor or vendor.lower() in ("unknown",""):
            vendor, dtype, brand = lookup_vendor(mac)

        # 5. OS detection — vendor OUI first, then nmap, then hostname/ports/TTL.
        #    A High-confidence vendor answer is authoritative for consumer gear
        #    (nmap -O is unreliable on phones, printers and IoT), and skipping
        #    the nmap probe when it is not needed saves the most expensive
        #    identification step.
        os_v, conf_v = infer_os_from_vendor(vendor, dtype)
        vendor_confident = bool(os_v) and conf_v.startswith("High")
        nmap_os, nmap_acc = ("", "")
        if not vendor_confident:
            nmap_os, nmap_acc = self.scanner.nmap_os(ip)
        if vendor_confident:
            final_os, os_acc = os_v, conf_v
        elif nmap_os:
            final_os, os_acc = nmap_os, f"nmap {nmap_acc}"
        else:
            # Build a richer hostname by combining DNS + banner title/realm
            rich_hostname = hostname
            if not rich_hostname and banner.get("auth_realm"):
                rich_hostname = banner["auth_realm"]
            elif not rich_hostname and banner.get("title"):
                rich_hostname = banner["title"]
            final_os, os_acc = detect_os(
                ip, rich_hostname, mac, vendor, dtype, open_ports, ttl
            )
            # Banner server field can confirm OS (e.g. "lighttpd" → Linux)
            if os_acc in ("","Low") and banner.get("server",""):
                sv = banner["server"].lower()
                if any(x in sv for x in ("linux","ubuntu","debian","openwrt","dd-wrt")):
                    final_os, os_acc = "Linux (Embedded)", "Medium (HTTP Server)"
                elif "windows" in sv:
                    final_os, os_acc = "Windows", "Medium (HTTP Server)"
                elif any(x in sv for x in ("ios","apple","darwin")):
                    final_os, os_acc = "iOS / macOS", "Medium (HTTP Server)"

        # 6. Refine device_type with all signals (vendor, OS, ports, banner)
        final_dtype = _refine_dtype(dtype, vendor, final_os, open_ports, hostname)
        # The host that answers as this subnet's default gateway is, by
        # definition, a router/gateway — that is an observation, not a guess.
        if self.gateway and ip == self.gateway and final_dtype in ("Unknown", "", ip):
            final_dtype = "Router / Switch"
        # Banner title/server can disambiguate type further
        if banner and final_dtype in ("Unknown", ip, ""):
            for field in ("auth_realm","title","server"):
                val = banner.get(field,"").lower()
                if any(x in val for x in ("camera","cam","nvr","dvr","ipcam")):
                    final_dtype = "IP Camera"; break
                if any(x in val for x in ("printer","laserjet","inkjet","mfp")):
                    final_dtype = "Printer"; break
                if any(x in val for x in ("router","gateway","modem","ap ","access point")):
                    final_dtype = "Router / Switch"; break
                if any(x in val for x in ("tv","television","android tv","smart tv")):
                    final_dtype = "Smart TV"; break
                if any(x in val for x in ("nas","storage","diskstation","readynas")):
                    final_dtype = "NAS / Server"; break

        # 7. Vulnerabilities
        vulns = self.scanner.assess_vulns(open_ports)

        with _lock:
            existing = devices.get(ip, {})
            # One merge rule for every scan path, so this panel, the
            # Vulnerabilities panel and the alerts always agree.
            open_ports, carried = merge_scan_ports(
                ip, existing.get("open_ports") or {}, open_ports)
            if carried:
                vulns = self.scanner.assess_vulns(open_ports)
            # Preserve blocked state across rescans
            currently_blocked = existing.get("blocked", False) or (ip in blocked_devices)

            # ── OS fallback: TTL-based guess when unknown ─────────────────────
            display_os = final_os if (final_os and final_os.lower() not in ("unknown", "")) else ""
            if not display_os:
                if   ttl > 0   and ttl <= 64:  display_os = "Linux / Android / macOS"
                elif ttl > 64  and ttl <= 128:  display_os = "Windows / Android"
                elif ttl > 128:                 display_os = "iOS / Network Device"
                else:                           display_os = "Linux / Android / iOS / macOS"

            # Unknown values stay empty; the UI falls back to the IP for labels
            # and prints "Unknown" in detail views.
            display_dtype  = final_dtype if (final_dtype and final_dtype.lower() not in ("unknown", "")) else existing.get("device_type", "")
            display_vendor = vendor if (vendor and vendor.lower() not in ("unknown", "")) else existing.get("vendor", "")
            display_brand  = brand  if (brand  and brand.lower()  not in ("unknown", "")) else existing.get("brand", "")
            # Never let a previous IP-as-vendor placeholder survive
            if display_vendor == ip: display_vendor = ""
            if display_brand  == ip: display_brand  = ""
            if display_dtype  == ip: display_dtype  = ""

            devices[ip] = {
                **existing,
                "ip":          ip,
                "mac":         mac,
                "hostname":    hostname,
                "vendor":      display_vendor,
                "brand":       display_brand,
                "device_type": display_dtype,
                "os":          display_os,
                "os_accuracy": os_acc,
                "ttl":         ttl,
                "open_ports":  open_ports,
                "vulnerabilities": vulns,
                "vuln_count":  len(vulns),
                "vuln_scanned": _ts(),
                # When the expensive identification last completed, so the
                # sweep can skip re-identifying this device every cycle.
                "identified_ts": _ts(),
                "status":      "blocked" if currently_blocked else "online",
                "blocked":     currently_blocked,
                "first_seen":  existing.get("first_seen", _ts()),
                "last_seen":   _ts(),
                "bytes_in":    existing.get("bytes_in", 0),
                "bytes_out":   existing.get("bytes_out", 0),
                "is_gateway":  (ip == self.gateway),
            }
            missed_scans[ip]   = 0     # a successful scan is positive evidence
            _arp_seen_ts[ip]   = time.time()
            entry = devices[ip]

        # Port-open alerts are derived from the same set the panels show.
        DETECT.observe_ports(ip, open_ports)

        crit = [v for v in vulns if v["severity"] in ("CRITICAL","HIGH")]
        if crit:
            add_alert(ip, "Critical Vulnerabilities",
                      "; ".join(f":{v['port']} {v['service']}" for v in crit[:3]),
                      "CRITICAL")

        socketio.emit("device_update", entry)

    def _bw_loop(self):
        """Push per-device bandwidth deltas to the graphs every second."""
        prev: dict = {}
        while self._running:
            time.sleep(1)
            ts_now = _sts()
            snap   = {}
            with _lock:
                for ip, dev in devices.items():
                    bi, bo = dev.get("bytes_in",0), dev.get("bytes_out",0)
                    pb, po = prev.get(ip, (bi, bo))
                    di, do = max(0, bi-pb), max(0, bo-po)
                    prev[ip] = (bi, bo)
                    traffic_data[ip].append({"ts":ts_now,"in":di,"out":do})
                    snap[ip] = {"in":di,"out":do}
            socketio.emit("traffic_update", {"ts":ts_now,"data":snap})
            # Push the real aggregate counters periodically – without this the
            # header/Pkt-s cards never change after initial_state.
            if not hasattr(self, "_stats_tick"):
                self._stats_tick = 0
            self._stats_tick += 1
            if self._stats_tick % 5 == 0:
                with _lock:
                    stats = {**net_stats, "gateway": self.gateway,
                             "network": self.network,
                             "device_count": len(devices),
                             "online": sum(1 for d in devices.values()
                                           if d.get("status") == "online")}
                socketio.emit("stats_update", stats)


# Hostnames that definitively mean "this is a PC / desktop computer"
_PC_HOSTNAME_RE = re.compile(
    r"^(kali|parrot|ubuntu|debian|fedora|centos|arch|manjaro|mint|"
    r"pc|desktop|computer|workstation|laptop|notebook|client|customer|"
    r"user|host|machine|node|box|tower|station|office|corp|"
    r"win|windows)[-_.\d]*$",
    re.I
)

def _hostname_implies_pc(hostname: str) -> bool:
    """Return True if the hostname strongly implies a PC/laptop/desktop."""
    if not hostname:
        return False
    h = hostname.split(".")[0]   # strip domain suffix
    return bool(_PC_HOSTNAME_RE.match(h))


def _refine_dtype(dtype: str, vendor: str, os_str: str, ports: dict,
                  hostname: str = "") -> str:
    """
    Return a precise device_type string using vendor, OS, hostname and open ports.
    This runs AFTER OS detection so it can use the final OS string.
    """
    os_l  = (os_str or "").lower()
    v_l   = (vendor or "").lower()
    dt_l  = (dtype  or "").lower()
    open_set = {p for p, i in ports.items() if i.get("state") == "open"}

    def vendor_has(*names: str) -> bool:
        # Whole-word match: "vivo" must not match Vivotek, "hp" must not match
        # a substring of some unrelated company name.
        return any(re.search(r"\b" + re.escape(n) + r"\b", v_l) for n in names)

    # A TTL-only OS guess lists several candidates, e.g. "Linux / Android / macOS".
    # Such a guess must never decide the device type on its own: it would turn a
    # router into a Mac or a TV into a phone.  Only an unambiguous OS string is
    # allowed to pick an OS-specific type; otherwise the type stays Unknown.
    os_strong = os_l if (os_l and "/" not in os_l and " or " not in os_l) else ""

    # ── Strong port signals first ─────────────────────────────────────────────
    # A listening raw-print service is a printer even when its hostname looks
    # like a PC.  CUPS (631) alone is common on desktops, so 631 only counts
    # together with a printer vendor.
    if open_set & {9100, 515}:
        return "Printer"
    if 631 in open_set and vendor_has("hp", "hewlett", "canon", "epson", "brother",
                                      "xerox", "ricoh", "lexmark", "kyocera",
                                      "konica", "oki", "samsung"):
        return "Printer"
    # AFP (548) or NFS (2049) means this host serves files to the network.
    if open_set & {548, 2049}:
        return "NAS / Server"
    # RTSP is used by cameras/NVRs; do not claim it for a Windows/macOS host.
    if (open_set & {554, 8554}) and "windows" not in os_l and "macos" not in os_l \
            and "windows" not in dt_l and "mac" not in dt_l:
        return "IP Camera"
    # A host exposing a database port is serving, but a developer laptop
    # running MySQL is still a laptop: only call it a server when the OS is not
    # a desktop/mobile platform.
    if open_set & DB_PORTS and not any(x in os_strong for x in
                                      ("macos", "windows", "ios", "android")):
        return "Server"

    # ── Hostname-based PC detection (highest priority for generic names) ───────
    if _hostname_implies_pc(hostname):
        # Determine if Linux or Windows PC from OS string
        if any(x in os_strong for x in ("kali", "parrot", "linux", "ubuntu",
                                         "debian", "fedora", "centos", "arch",
                                         "manjaro", "mint")):
            return "Linux PC"
        if "windows" in os_strong or "win" in os_strong:
            return "Windows PC"
        if "macos" in os_strong:
            return "Mac"
        # Default: treat generic hostnames as PC
        return "PC"

    # ── Self-reported platform in the hostname ────────────────────────────────
    # A device advertising "Android-4.local" over mDNS is naming its own OS.
    if "android" in (hostname or "").lower():
        return "Mobile Phone"

    # ── iOS / iPadOS ──────────────────────────────────────────────────────────
    if "ipados" in os_strong:
        return "iPad"
    if os_strong == "ios" or ("ios" in os_strong and "macos" not in os_strong):
        # Differentiate iPhone vs iPad by vendor device_type if available
        if "ipad" in dt_l:
            return "iPad"
        return "iPhone"

    # ── macOS ─────────────────────────────────────────────────────────────────
    if "macos" in os_strong:
        if "macbook" in dt_l:
            return "MacBook (Laptop)"
        if any(x in dt_l for x in ("imac", "mac pro", "mac mini")):
            return "Mac Desktop"
        return "Mac"

    # ── Android ───────────────────────────────────────────────────────────────
    if "android tv" in os_l or "tizen" in os_l:
        return "Smart TV"
    if "android" in os_strong:
        if "tablet" in dt_l:
            return "Android Tablet"
        return "Mobile Phone"

    # ── Windows ───────────────────────────────────────────────────────────────
    if "windows server" in os_strong:
        return "Windows Server"
    if "windows" in os_strong:
        if 3389 in open_set:
            return "Windows PC (RDP)"   # remote desktop exposed
        return "Windows PC"

    # ── Linux ─────────────────────────────────────────────────────────────────
    if "raspberry pi" in os_strong:
        return "IoT / SBC"
    # ── Network / Router ──────────────────────────────────────────────────────
    # Router/AP firmware commonly self-reports "Network OS" or "Embedded
    # Linux", so this check must come BEFORE any IoT classification.
    if "embedded linux" in os_l and "camera" in os_l:
        return "IP Camera"
    if ("network os" in os_l or "router" in os_l
            or "embedded linux" in os_l or "openwrt" in os_l):
        return "Router / Switch"

    # ── Gaming Consoles ───────────────────────────────────────────────────────
    if "playstation" in os_l:
        return "PlayStation"
    if "xbox" in os_l:
        return "Xbox"
    if "nintendo" in os_l:
        return "Nintendo Switch"
    if "console" in os_l:
        return "Gaming Console"

    # ── Other specialised types ───────────────────────────────────────────────
    if "printer" in os_l or "printer" in dt_l:
        return "Printer"
    if "smart tv" in os_l or "smart tv" in dt_l:
        return "Smart TV"
    if "cast os" in os_l or "chromecast" in dt_l:
        return "Streaming Device"
    if "virtual machine" in dt_l or "vm" in dt_l:
        return "Virtual Machine"

    # ── Vendor-based fallback (when OS is still Unknown) ──────────────────────
    if vendor_has(*_ANDROID_VENDORS):
        return "Mobile Phone"
    if vendor_has("apple"):
        return "Apple Device"
    if vendor_has("cisco", "ubiquiti", "mikrotik", "netgear", "tp-link",
                  "d-link", "zyxel"):
        return "Router / Switch"
    if vendor_has("hikvision", "dahua", "axis", "wyze", "reolink", "vivotek"):
        return "IP Camera"
    if vendor_has("epson", "canon", "hp", "hewlett", "brother", "xerox"):
        return "Printer"

    return dtype or "Unknown"



# ─────────────────────────────────────────────────────────────────────────────
#  DEVICE ACTIVITIES ENGINE  – real-time per-device traffic analysis
# ─────────────────────────────────────────────────────────────────────────────

def get_device_activities(ip: str) -> dict:
    """
    Process packet_log for a device and return structured activity data:
    - requests_over_time: [{ts, count}] for the graph
    - sites_visited: [{domain, ip, count}] (from DNS queries + direct connections)
    - endpoints: [{port, service, count}] top endpoints contacted
    - connections: [{src, dst, sport, dport, proto, ts, info}] recent connections
    - summary: {total_requests, total_bytes, unique_destinations, protocol_breakdown}
    """
    with _lock:
        pkts = list(packet_log.get(ip, []))

    if not pkts:
        return {"ip": ip, "connections": [], "sites_visited": [],
                "endpoints": [], "requests_over_time": [], "summary": {}}

    # ── Process packets ──────────────────────────────────────────────────────
    dest_counter: Dict[str, int] = defaultdict(int)
    endpoint_counter: Dict[Tuple[int, str], int] = defaultdict(int)  # (port, proto) → hits
    dns_queries: Dict[str, str] = {}         # domain → "" (answer IP is not observable here)
    connections: list = []
    ts_buckets: Dict[str, int] = defaultdict(int)  # "HH:MM" → count
    proto_counter: Dict[str, int] = defaultdict(int)
    total_bytes = 0

    for pkt in pkts:
        src     = pkt.get("src", "")
        dst     = pkt.get("dst", "")
        proto   = pkt.get("proto", "")
        length  = pkt.get("len", 0)
        info    = pkt.get("info", "")
        sport   = pkt.get("sport")
        dport   = pkt.get("dport")
        ts_str  = pkt.get("ts", "")

        total_bytes += length
        proto_counter[proto] += 1

        # Determine the "other end" of the connection
        other = dst if src == ip else src
        if other and other != ip:
            dest_counter[other] += 1

        # Extract endpoint (port) – keep the port numeric and the protocol
        # separate; resolve the service name with the *actual* protocol.
        if dport:
            endpoint_counter[(int(dport), (proto or "TCP").lower())] += 1

        # Detect DNS queries from info field. The packet log only carries the
        # query name, not the answer, so the resolved IP is unknown ("") –
        # storing the resolver IP here made the DNS server look like the site.
        if info.startswith("DNS"):
            domain = info.replace("DNS", "", 1).strip()
            if domain:
                dns_queries[domain] = ""

        # Time bucket (group by second for the graph)
        if ts_str:
            ts_buckets[ts_str] += 1

        # Build connection record
        connections.append({
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "proto": proto, "ts": ts_str, "info": info, "len": length,
        })

    # ── Build requests_over_time (sorted by time) ───────────────────────────
    requests_over_time = [{"ts": k, "count": v} for k, v in sorted(ts_buckets.items())]
    # Keep last 60 data points max
    requests_over_time = requests_over_time[-60:]

    # ── Build sites_visited (merge DNS + direct connections) ─────────────────
    sites_map: Dict[str, dict] = {}
    for domain, resolved_ip in dns_queries.items():
        key = domain
        if key not in sites_map:
            sites_map[key] = {"domain": domain, "ip": resolved_ip, "count": 0}
        sites_map[key]["count"] += 1

    # Add non-DNS destinations as sites too (HTTP/HTTPS connections)
    for dest_ip, count in dest_counter.items():
        # Skip if it's the device itself or gateway-local
        if dest_ip == ip:
            continue
        # Check if this IP already appears from DNS
        already_dns = any(s["ip"] == dest_ip for s in sites_map.values())
        if not already_dns:
            sites_map[dest_ip] = {"domain": dest_ip, "ip": dest_ip, "count": count}

    sites_visited = sorted(sites_map.values(), key=lambda x: -x["count"])[:30]

    # ── Build endpoints (sorted by frequency) ───────────────────────────────
    def _svc(port: int, proto: str) -> str:
        try:
            return socket.getservbyport(port, proto)
        except Exception:
            return ""

    endpoints = [{"port": port, "proto": proto.upper(),
                  "service": _svc(port, proto), "count": n}
                 for (port, proto), n in
                 sorted(endpoint_counter.items(), key=lambda kv: -kv[1])[:20]]

    # ── Summary ──────────────────────────────────────────────────────────────
    summary = {
        "total_requests": sum(proto_counter.values()),
        "total_bytes": total_bytes,
        "unique_destinations": len(dest_counter),
        "protocol_breakdown": dict(proto_counter),
    }

    return {
        "ip": ip,
        "connections": connections[:100],     # last 100 connections
        "sites_visited": sites_visited,
        "endpoints": endpoints,
        "requests_over_time": requests_over_time,
        "summary": summary,
    }


def get_all_activities_summary() -> dict:
    """Return a summary of activity counts for all devices (for the device grid)."""
    result = {}
    with _lock:
        for ip, pkts in packet_log.items():
            pkt_list = list(pkts)
            result[ip] = {
                "total_requests": len(pkt_list),
                "last_activity": pkt_list[0].get("ts", "") if pkt_list else "",
            }
    return result

# ─────────────────────────────────────────────────────────────────────────────
#  FLASK + SOCKET.IO
# ─────────────────────────────────────────────────────────────────────────────
app      = Flask(__name__)
# Random per-run session key – never reuse a hardcoded secret.
app.config["SECRET_KEY"] = secrets.token_hex(32)
# Same-origin only (default). The dashboard is served by this app, so no
# cross-origin browser clients are needed; "*" would let any website open a
# socket to this host while a user has the dashboard open.
socketio = SocketIO(app, async_mode="threading",
                    logger=False, engineio_logger=False)
monitor  = NetworkMonitor()

# ── CSRF protection for mutating API routes ─────────────────────────────────
# A random token is embedded in the dashboard page each run; state-changing
# calls must echo it in the X-NS-Auth header. Other origins can't read the
# page (same-origin policy), so they can't learn the token – this stops
# other websites from silently POSTing block/unblock/rescan on behalf of a
# logged-in user. It is NOT a login: anyone who can open the dashboard page
# on the LAN can read the token from it.
AUTH_TOKEN = secrets.token_hex(16)

def require_auth(fn):
    """Reject mutating API requests that don't carry the dashboard token."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if request.headers.get("X-NS-Auth", "") != AUTH_TOKEN:
            return jsonify({"error": "unauthorized – missing/invalid X-NS-Auth token"}), 403
        return fn(*args, **kwargs)
    return wrapper

@app.route("/api/devices")
def api_devices():
    with _lock: return jsonify(list(devices.values()))

@app.route("/api/device/<ip>")
def api_device(ip):
    with _lock:
        d = devices.get(ip)
        if not d: return jsonify({"error":"not found"}),404
        return jsonify({**d,
                        "traffic": list(traffic_data[ip]),
                        "packets": list(packet_log[ip])[:60]})

@app.route("/api/alerts")
def api_alerts():
    with _lock: return jsonify(list(alerts))

@app.route("/api/alerts/ack/<aid>", methods=["POST"])
@require_auth
def api_ack(aid):
    with _lock:
        for a in alerts:
            if a["id"] == aid: a["ack"] = True
    return jsonify({"ok":True})

@app.route("/api/stats")
def api_stats():
    with _lock:
        return jsonify({**net_stats,
                        "device_count": len(devices),
                        "online": sum(1 for d in devices.values() if d.get("status")=="online"),
                        "gateway": monitor.gateway,
                        "network": monitor.network})

# In-memory set of blocked IPs (ip → mac mapping kept for cleanup)
blocked_devices: Dict[str, str] = {}   # ip → mac

# tc state so we never stack duplicate qdiscs and know when to remove them
_tc_qdisc_created: set = set()         # interfaces where we added a root qdisc
_tc_filter_count:  Dict[str, int] = {} # interface → active DROP filters

def _run(cmd: List[str], timeout: int = 6) -> Tuple[bool, str]:
    """Run a shell command, return (success, output)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except Exception as e:
        return False, str(e)

def _get_gateway_mac() -> str:
    """
    Resolve the REAL MAC of the default gateway from the local ARP/neighbour
    table. Returns "" when it cannot be determined.
    """
    # Preferred: ip neigh (iproute2, Linux)
    try:
        out = subprocess.check_output(["ip", "neigh", "show"],
                                      stderr=subprocess.DEVNULL, timeout=3
                                      ).decode(errors="ignore")
        for line in out.splitlines():
            p = line.split()
            if len(p) >= 5 and p[0] == monitor.gateway and p[-1] not in ("FAILED", "INCOMPLETE"):
                m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
                if m and m.group(1).upper() != "00:00:00:00:00:00":
                    return m.group(1).upper()
    except Exception:
        pass
    # Fallback: /proc/net/arp (Linux)
    try:
        with open("/proc/net/arp") as fh:
            for line in fh.readlines()[1:]:
                p = line.split()
                if len(p) >= 4 and p[0] == monitor.gateway and \
                   p[3] not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                    return p[3].upper()
    except Exception:
        pass
    return ""

# Bogus MAC used for ARP-poisoning the blocked device. It must be a valid
# UNICAST, LOCALLY-ADMINISTERED address (first byte even = unicast, second
# hex digit 6 = locally administered) so stacks actually cache it —
# ff:ff:ff:ff:ff:ff is multicast/broadcast and most ARP implementations
# refuse to cache it, which made the old poison a no-op.
POISON_MAC = "06:00:5a:53:4e:31"   # locally administered, unicast

def _block_device(ip: str, mac: str) -> Tuple[bool, List[str]]:
    """
    Disconnect a device from the network using all available methods.
    Returns (any_method_succeeded, list_of_messages).
    """
    msgs   = []
    ok_any = False
    mac_u  = mac.upper() if mac and mac != "N/A" else ""

    # ── Method 1: iptables – drop all forwarded traffic to/from this IP ───────
    for args in [
        ["iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"],
        ["iptables", "-I", "FORWARD", "1", "-d", ip, "-j", "DROP"],
        ["iptables", "-I", "INPUT",   "1", "-s", ip, "-j", "DROP"],
    ]:
        ok, out = _run(args)
        if ok:
            ok_any = True
            msgs.append(f"iptables rule added ({args[5]}→{args[-2]})")

    # ── Method 2: ebtables – block at Ethernet bridge layer by MAC ────────────
    if mac_u:
        for args in [
            ["ebtables", "-I", "FORWARD", "-s", mac_u, "-j", "DROP"],
            ["ebtables", "-I", "FORWARD", "-d", mac_u, "-j", "DROP"],
        ]:
            ok, _ = _run(args)
            if ok:
                ok_any = True
                msgs.append(f"ebtables MAC rule added ({mac_u})")
                break

    # ── Method 3: arptables – poison ARP so the device can't communicate ──────
    if mac_u:
        ok, _ = _run(["arptables", "-I", "OUTPUT", "--dst-ip", ip,
                       "--src-mac", mac_u, "-j", "DROP"])
        if ok:
            ok_any = True
            msgs.append(f"arptables rule added")

    # ── Method 4: ARP poison via scapy (deauth the device off the LAN) ────────
    # Tell the victim that the gateway's IP maps to a bogus locally-
    # administered MAC. Because real ARP caches expire, keep re-poisoning in
    # the background for as long as the device stays blocked.
    if SCAPY_OK and IS_ROOT and mac_u:
        try:
            from scapy.all import ARP, Ether, sendp
            gw = monitor.gateway
            poison_pkt = (
                Ether(dst=mac_u) /
                ARP(op=2, pdst=ip, hwdst=mac_u,
                    psrc=gw,
                    hwsrc=POISON_MAC)
            )
            # Send 5 times to ensure it lands
            sendp(poison_pkt, count=5, inter=0.1, verbose=False)
            ok_any = True
            msgs.append("ARP poison sent (scapy deauth)")

            def _repoison():
                """Refresh the poison every 10 s until the device is unblocked."""
                while ip in blocked_devices:
                    time.sleep(10)
                    if ip not in blocked_devices:
                        break
                    try:
                        sendp(poison_pkt, count=2, inter=0.1, verbose=False)
                    except Exception:
                        break

            threading.Thread(target=_repoison, daemon=True,
                             name=f"poison-{ip}").start()
            msgs.append("Periodic re-poison active while blocked")
        except Exception as e:
            msgs.append(f"ARP poison failed: {e}")

    # ── Method 5: tc (traffic control) – bandwidth limit to 0 ────────────────
    # Find which interface the IP is reachable on
    try:
        result = subprocess.run(["ip", "route", "get", ip],
                                 capture_output=True, text=True, timeout=3)
        iface_m = re.search(r"dev\s+(\S+)", result.stdout)
        iface   = iface_m.group(1) if iface_m else None
        if iface:
            # Add qdisc only once per interface, then filter to DROP
            if iface not in _tc_qdisc_created:
                ok_q, _ = _run(["tc", "qdisc", "add", "dev", iface, "root",
                                "handle", "1:", "prio"])
                if ok_q:
                    _tc_qdisc_created.add(iface)
            ok2, _ = _run([
                "tc", "filter", "add", "dev", iface, "parent", "1:",
                "protocol", "ip", "u32", "match", "ip", "dst", ip,
                "flowid", "1:3", "action", "drop"
            ])
            if ok2:
                ok_any = True
                _tc_filter_count[iface] = _tc_filter_count.get(iface, 0) + 1
                msgs.append(f"tc filter added on {iface}")
    except Exception:
        pass

    if not msgs:
        msgs.append("No root/tools available – flag set (UI only)")
    return ok_any, msgs


def _unblock_device(ip: str, mac: str) -> List[str]:
    """Remove all block rules for this device."""
    msgs   = []
    mac_u  = mac.upper() if mac and mac != "N/A" else ""

    # iptables cleanup
    for table, chain in [("FORWARD","s"), ("FORWARD","d"), ("INPUT","s")]:
        flag = "-s" if chain == "s" else "-d"
        for _ in range(3):   # try up to 3 times in case rules were added multiple times
            ok, _ = _run(["iptables", "-D", table, flag, ip, "-j", "DROP"])
            if not ok:
                break
    msgs.append("iptables rules removed")

    # ebtables cleanup
    if mac_u:
        for _ in range(2):
            _run(["ebtables", "-D", "FORWARD", "-s", mac_u, "-j", "DROP"])
            _run(["ebtables", "-D", "FORWARD", "-d", mac_u, "-j", "DROP"])
        msgs.append("ebtables MAC rules removed")

    # arptables cleanup
    if mac_u:
        _run(["arptables", "-D", "OUTPUT", "--dst-ip", ip,
              "--src-mac", mac_u, "-j", "DROP"])

    # Restore ARP via scapy – tell the victim the REAL gateway MAC.
    # (Announcing our own interface MAC here would route the victim's
    # gateway traffic through this host — a MITM position, not a restore.)
    if SCAPY_OK and IS_ROOT and mac_u:
        try:
            from scapy.all import ARP, Ether, sendp
            gw     = monitor.gateway
            gw_mac = _get_gateway_mac()
            if gw_mac:
                restore_pkt = (
                    Ether(dst=mac_u) /
                    ARP(op=2, pdst=ip, hwdst=mac_u,
                        psrc=gw, hwsrc=gw_mac)
                )
                sendp(restore_pkt, count=5, inter=0.1, verbose=False)
                msgs.append("ARP table restored (real gateway MAC)")
            else:
                msgs.append("ARP restore skipped – gateway MAC unknown")
        except Exception as e:
            msgs.append(f"ARP restore note: {e}")

    # tc cleanup
    try:
        result = subprocess.run(["ip", "route", "get", ip],
                                 capture_output=True, text=True, timeout=3)
        iface_m = re.search(r"dev\s+(\S+)", result.stdout)
        iface   = iface_m.group(1) if iface_m else None
        if iface and _tc_filter_count.get(iface, 0) > 0:
            ok, _ = _run(["tc", "filter", "del", "dev", iface, "parent", "1:",
                          "protocol", "ip", "u32", "match", "ip", "dst", ip,
                          "action", "drop"])
            if ok:
                _tc_filter_count[iface] -= 1
                # Remove our qdisc when the last filter is gone
                if _tc_filter_count[iface] <= 0 and iface in _tc_qdisc_created:
                    _run(["tc", "qdisc", "del", "dev", iface, "root"])
                    _tc_qdisc_created.discard(iface)
    except Exception:
        pass

    return msgs


@app.route("/api/block/<ip>", methods=["POST"])
@require_auth
def api_block(ip):
    with _lock:
        d = dict(devices[ip]) if ip in devices else None
    if not d: return jsonify({"error": "unknown IP"}), 404
    if d.get("is_gateway"):
        return jsonify({"error": "Cannot block the gateway"}), 400
    if ip in blocked_devices:
        return jsonify({"ok": True, "message": f"{ip} is already blocked",
                        "root": IS_ROOT})

    # Never claim a block that was not actually applied – that used to leave a
    # permanently "blocked" device in the UI on non-root runs.
    if not IS_ROOT:
        return jsonify({"ok": False, "root": False,
                        "error": "Not running as root – blocking needs sudo/root."}), 403

    mac = d.get("mac", "N/A")
    ok, msgs = _block_device(ip, mac)
    detail = "; ".join(msgs[:3])
    if not ok:
        add_alert(ip, "Block Failed", f"Could not block {ip}: {detail}", "MEDIUM")
        return jsonify({"ok": False, "root": IS_ROOT, "error": detail,
                        "methods": detail}), 500

    blocked_devices[ip] = mac
    with _lock:
        if ip in devices:
            devices[ip]["blocked"] = True
            devices[ip]["status"]  = "blocked"
        entry = dict(devices.get(ip, {}))

    add_alert(ip, "Device Blocked",
              f"{d.get('vendor', ip)} ({d.get('device_type', '?')}) at {ip} — {detail}",
              "HIGH")
    socketio.emit("device_update", entry)
    return jsonify({
        "ok":      True,
        "message": f"{ip} blocked (rules applied)",
        "methods": detail,
        "root":    IS_ROOT,
    })


@app.route("/api/unblock/<ip>", methods=["POST"])
@require_auth
def api_unblock(ip):
    with _lock:
        mac = blocked_devices.get(ip) or devices.get(ip, {}).get("mac", "N/A")
        dev_blocked = bool(devices.get(ip, {}).get("blocked"))
    if ip not in blocked_devices and not dev_blocked:
        return jsonify({"ok": False, "error": f"{ip} is not blocked"}), 409
    # Mirrors api_block: never report an unblock that removed nothing.
    if not IS_ROOT:
        return jsonify({"ok": False, "root": False,
                        "error": "Not running as root – blocking rules need sudo/root."}), 403

    msgs = _unblock_device(ip, mac)
    detail = "; ".join(msgs[:3])

    blocked_devices.pop(ip, None)
    with _lock:
        if ip in devices:
            devices[ip]["blocked"] = False
            devices[ip]["status"]  = "online"
            missed_scans[ip]       = 0
        entry = dict(devices.get(ip, {}))

    add_alert(ip, "Device Unblocked",
              f"{entry.get('vendor') or ip} at {ip} — block rules removed", "INFO")
    socketio.emit("device_update", entry)
    return jsonify({
        "ok":      True,
        "message": f"{ip} unblocked",
        "methods": detail,
        "root":    IS_ROOT,
    })

# ─────────────────────────────────────────────────────────────────────────────
#  INTERNET SPEED & LATENCY TEST
# ─────────────────────────────────────────────────────────────────────────────
#
# A real measurement has to move tens of megabytes, which takes 10-25 s, so it
# never runs inside the HTTP request: POST starts a worker thread and the page
# polls GET /api/speedtest for the current phase, progress and live numbers.
# (The old version ran the whole test inside the request, so the browser sat on
# a single fetch with no progress and no timeout - "taking forever / not
# working".)
#
# Every number reported here is measured:
#   latency  TCP handshake RTT to anycast resolvers.  DNS is resolved once,
#            before the timed section: a cold lookup added ~300 ms to every
#            sample and made the "ping" meaningless.  Median of the samples.
#   jitter   mean absolute difference between consecutive RTT samples - the
#            packet-delay variation VoIP gear reports, not the stdev of a mix
#            of different hosts.
#   download parallel TLS streams from speed.cloudflare.com, which exists for
#            this purpose.  One stream is bounded by the TCP receive window:
#            measured on this link at 3.2 Mbps for 1 stream vs 9.8 Mbps for 4
#            streams and 6.5 Mbps for a single 10 MB file, so a single stream
#            reports a number that is simply wrong.  Bytes/time is taken over a
#            window that starts 0.6 s into the round, so TCP slow start and
#            socket-buffer absorption do not inflate it.
#   upload   parallel POSTs to the same host, timed from the first body byte
#            until the server answers, so connect + TLS are excluded and the
#            bytes are actually acknowledged before they are counted.
#
# speedtest-cli is still used first when the user installed it (it measures
# against a real speedtest.net node); it runs as a subprocess with a hard
# timeout so a hung server cannot wedge the worker.
# ─────────────────────────────────────────────────────────────────────────────

SPEEDTEST_STALL_SECS = 90   # a run with no progress for this long is dead
SPEEDTEST_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
_CF_HOST     = "speed.cloudflare.com"
_CF_DOWN     = "https://speed.cloudflare.com/__down?bytes={n}&measId={mid}"
_CF_UP_PATH  = "/__up"
# Plain mirrors used only when Cloudflare is unreachable.
_DL_FALLBACKS = (
    ("https://proof.ovh.net/files/10Mb.dat", 6_000_000),
    ("https://download.thinkbroadband.com/10MB.zip", 6_000_000),
)

_speed_lock  = threading.Lock()
_speed_state = {
    "running":       False,
    "phase":         "idle",
    "progress":      0.0,
    "download_mbps": 0.0,
    "upload_mbps":   0.0,
    "latency_ms":    0.0,
    "jitter_ms":     0.0,
    "result":        None,
    "error":         "",
    "started":       0.0,
    "finished":      0.0,
    "last_update":   0.0,
}


def _spd_set(**kw) -> None:
    """Update the shared progress/result state (worker thread -> HTTP poller)."""
    with _speed_lock:
        _speed_state["last_update"] = time.time()
        _speed_state.update(kw)


def _spd_snapshot() -> dict:
    with _speed_lock:
        snap = dict(_speed_state)
        snap["result"] = dict(snap["result"]) if snap["result"] else None
    return snap


def _latency_probe(hosts=(("1.1.1.1", 443), ("8.8.8.8", 443)), samples: int = 7,
                   budget: float = 6.0):
    """
    Median TCP handshake RTT (ms) and jitter (mean |delta| between consecutive
    samples), plus the host that answered.  Returns (0.0, 0.0, "") when no
    resolver accepted a connection.  Bounded by `budget` seconds overall so an
    unreachable host cannot stall the run.
    """
    best = None
    started = time.monotonic()
    for host, port in hosts:
        if time.monotonic() - started > budget:
            break
        try:
            ip = socket.gethostbyname(host)      # untimed: DNS is not latency
        except Exception:
            continue
        rtts: list = []
        for _ in range(samples):
            if time.monotonic() - started > budget:
                break
            try:
                t0 = time.perf_counter()
                sock = socket.create_connection((ip, port), timeout=2)
                rtts.append((time.perf_counter() - t0) * 1000.0)
                sock.close()
            except Exception:
                pass
            time.sleep(0.04)
        if len(rtts) >= 4:
            med = statistics.median(rtts)
            if best is None or med < best[0]:
                best = (med, rtts, host)
        if best and best[0] < 40:                # already a nearby anycast node
            break
    if best is None:
        return 0.0, 0.0, "", 0
    med, rtts, host = best
    deltas = [abs(b - a) for a, b in zip(rtts, rtts[1:])]
    jit = statistics.fmean(deltas) if deltas else 0.0
    return round(med, 1), round(jit, 1), host, len(rtts)


def _download_stream(url: str, max_bytes: int, deadline: float,
                     counter: list, clock_lock) -> int:
    """GET url and read up to max_bytes (or until deadline).  Returns bytes."""
    import urllib.request as _ur
    got, resp = 0, None
    try:
        resp = _ur.urlopen(_ur.Request(url, headers={"User-Agent": SPEEDTEST_UA}),
                           timeout=max(3.0, deadline - time.monotonic()))
        while got < max_bytes:
            if time.monotonic() >= deadline:
                break
            chunk = resp.read(65536)
            if not chunk:
                break
            got += len(chunk)
            with clock_lock:
                counter[0] += len(chunk)
    except Exception:
        pass
    finally:
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass
    return got


def _download_round(bytes_per_stream: int, streams: int, max_secs: float,
                    progress_lo: float = 15.0, progress_hi: float = 55.0):
    """
    Run `streams` parallel downloads of `bytes_per_stream` each.
    Returns (bytes_transferred, Mbps) where Mbps is measured over a window that
    starts after the TCP warm-up, so buffer absorption cannot inflate it.
    """
    counter, clock_lock = [0], threading.Lock()
    deadline = time.monotonic() + max_secs
    threads = []
    for _ in range(streams):
        url = _CF_DOWN.format(n=bytes_per_stream, mid=secrets.token_hex(6))
        th = threading.Thread(target=_download_stream,
                              args=(url, bytes_per_stream, deadline, counter, clock_lock),
                              daemon=True)
        th.start()
        threads.append(th)

    time.sleep(min(0.6, max_secs * 0.3))         # let slow start settle
    with clock_lock:
        base_bytes, base_t = counter[0], time.monotonic()
    while any(th.is_alive() for th in threads):
        time.sleep(0.15)
        elapsed = time.monotonic() - base_t
        with clock_lock:
            live = counter[0]
        if elapsed > 0.25:
            _spd_set(download_mbps=round((live - base_bytes) * 8 / elapsed / 1e6, 2),
                     progress=round(progress_lo + (progress_hi - progress_lo)
                                    * min(1.0, elapsed / max_secs), 1))
        if time.monotonic() > deadline + 2:
            break
    for th in threads:
        th.join(timeout=2)

    end_t = time.monotonic()
    with clock_lock:
        total = counter[0]
    window = end_t - base_t
    moved  = total - base_bytes
    mbps   = (moved * 8 / window / 1e6) if window > 0.05 and moved > 0 else 0.0
    return total, mbps


def _download_probe():
    """
    Cloudflare first (4 parallel streams, second round sized from the first);
    plain mirrors if Cloudflare cannot be reached.
    Returns (mbps, bytes, source).
    """
    total, mbps = _download_round(512_000, 4, 5.0, 15.0, 30.0)
    if mbps > 0:
        # size the second round from the first so it lasts about 4 s
        per = int(mbps * 1e6 / 8 * 4.0 / 4)
        per = max(512_000, min(8_000_000, per))
        total, second = _download_round(per, 4, 8.0, 30.0, 55.0)
        if second > 0:
            mbps = second
        return round(mbps, 2), total, "speed.cloudflare.com (4 parallel streams)"

    for url, max_bytes in _DL_FALLBACKS:
        import urllib.request as _ur
        t0, got, resp = time.monotonic(), 0, None
        try:
            resp = _ur.urlopen(_ur.Request(url, headers={"User-Agent": SPEEDTEST_UA}),
                               timeout=6)
            while got < max_bytes:
                chunk = resp.read(65536)
                if not chunk:
                    break
                got += len(chunk)
                if time.monotonic() - t0 > 6:
                    break
        except Exception:
            pass
        finally:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass
        dt = time.monotonic() - t0
        if got and dt > 0.1:
            host = url.split("/")[2]
            return round(got * 8 / dt / 1e6, 2), got, f"{host} (single stream)"
    return 0.0, 0, ""


def _upload_stream(host: str, path: str, payload_bytes: int, deadline: float,
                   counter: list, clock_lock) -> int:
    """POST payload_bytes of zeros; returns bytes the server actually took."""
    ctx = ssl.create_default_context()
    sock = ssock = None
    try:
        sock  = socket.create_connection((host, 443), timeout=6)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        head = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                f"User-Agent: {SPEEDTEST_UA}\r\n"
                "Content-Type: application/octet-stream\r\n"
                f"Content-Length: {payload_bytes}\r\nConnection: close\r\n\r\n")
        ssock.sendall(head.encode())
        blob, sent = b"\0" * 65536, 0
        while sent < payload_bytes and time.monotonic() < deadline:
            n = min(len(blob), payload_bytes - sent)
            ssock.sendall(blob[:n])
            sent += n
            with clock_lock:
                counter[0] += n
        # Wait for the status line: until the server answers, part of the body
        # may still sit in the local socket buffer, which would over-report.
        try:
            ssock.settimeout(max(2.0, deadline - time.monotonic() + 3))
            ssock.recv(256)
        except Exception:
            pass
        return sent
    except Exception:
        return 0
    finally:
        for s in (ssock, sock):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass


def _upload_round(bytes_per_stream: int, streams: int, max_secs: float,
                  progress_lo: float = 58.0, progress_hi: float = 95.0):
    """Parallel uploads; returns (bytes_sent, Mbps over the whole round)."""
    counter, clock_lock = [0], threading.Lock()
    deadline = time.monotonic() + max_secs
    t_start  = time.monotonic()
    threads = []
    for _ in range(streams):
        th = threading.Thread(target=_upload_stream,
                              args=(_CF_HOST, _CF_UP_PATH, bytes_per_stream,
                                    deadline, counter, clock_lock),
                              daemon=True)
        th.start()
        threads.append(th)

    while any(th.is_alive() for th in threads):
        time.sleep(0.2)
        elapsed = time.monotonic() - t_start
        if elapsed > 0.4:
            with clock_lock:
                live = counter[0]
            _spd_set(upload_mbps=round(live * 8 / elapsed / 1e6, 2),
                     progress=round(progress_lo + (progress_hi - progress_lo)
                                    * min(1.0, elapsed / max_secs), 1))
        if time.monotonic() > deadline + 3:
            break
    for th in threads:
        th.join(timeout=2)

    elapsed = time.monotonic() - t_start
    with clock_lock:
        total = counter[0]
    return total, (total * 8 / elapsed / 1e6 if elapsed > 0.1 and total else 0.0)


def _upload_probe():
    """Cloudflare /__up, then httpbin as a fallback.  Returns (mbps, bytes, src)."""
    total, mbps = _upload_round(512_000, 3, 8.0)
    if mbps > 50:
        total, second = _upload_round(4_000_000, 3, 10.0)
        if second > 0:
            mbps = second
    if mbps > 0:
        return round(mbps, 2), total, "speed.cloudflare.com (3 parallel streams)"

    counter, clock_lock = [0], threading.Lock()
    deadline = time.monotonic() + 10
    t0 = time.monotonic()
    sent = _upload_stream("httpbin.org", "/post", 512_000, deadline, counter, clock_lock)
    dt = time.monotonic() - t0
    if sent and dt > 0.1:
        return round(sent * 8 / dt / 1e6, 2), sent, "httpbin.org (single stream)"
    return 0.0, 0, ""


def _speedtest_cli_json(timeout: float):
    """
    Parse speedtest-cli output when the user installed it.  Runs as a
    subprocess so a hung speedtest.net node cannot wedge the worker.
    """
    cmd = None
    if shutil.which("speedtest-cli"):
        cmd = ["speedtest-cli", "--json", "--secure", "--timeout", "15"]
    else:
        try:
            import importlib.util as _ilu
            if _ilu.find_spec("speedtest") is not None:
                cmd = [sys.executable, "-m", "speedtest", "--json", "--secure",
                       "--timeout", "15"]
        except Exception:
            cmd = None
    if cmd is None:
        return None
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout)
    except Exception:
        pass
    return None


def _speed_worker() -> None:
    """Run the whole test and publish the result; never raises."""
    result = {
        "download_mbps": 0.0,
        "upload_mbps":   0.0,
        "latency_ms":    0.0,
        "jitter_ms":     0.0,
        "server":        "",
        "isp":           "",
        "status":        "HTTP probe",
        "method":        "",
        "bytes_down":    0,
        "bytes_up":      0,
    }
    try:
        # ── Latency + jitter (fast, always local) ─────────────────────────
        _spd_set(phase="latency", progress=4.0)
        lat, jit, hop, nsamples = _latency_probe()
        result["latency_ms"] = lat
        result["jitter_ms"]  = jit
        result["method"]     = (f"TCP RTT -> {hop}: median of {nsamples} connect "
                                f"times, jitter = mean |delta| between consecutive"
                                if hop else "TCP RTT")
        _spd_set(latency_ms=lat, jitter_ms=jit, progress=12.0)

        # ── speedtest.net, only when speedtest-cli is installed ───────────
        _spd_set(phase="speedtest-cli", progress=14.0)
        cli = _speedtest_cli_json(timeout=40)
        if cli:
            srv = cli.get("server") or {}
            result["download_mbps"] = round((cli.get("download") or 0) / 1e6, 2)
            result["upload_mbps"]   = round((cli.get("upload")   or 0) / 1e6, 2)
            if not result["latency_ms"] and cli.get("ping"):
                result["latency_ms"] = round(cli["ping"], 1)
            result["server"] = f"{srv.get('name','')}, {srv.get('country','')}".strip(", ")
            result["isp"]    = (cli.get("client") or {}).get("isp", "")
            result["status"] = "speedtest-cli"
            _spd_set(download_mbps=result["download_mbps"],
                     upload_mbps=result["upload_mbps"], progress=100.0)
        else:
            _spd_set(phase="download", progress=15.0)
            dl, dbytes, dsrc = _download_probe()
            result["download_mbps"] = dl
            result["bytes_down"]    = dbytes
            _spd_set(download_mbps=dl, progress=56.0)

            _spd_set(phase="upload", progress=58.0)
            up, ubytes, usrc = _upload_probe()
            result["upload_mbps"] = up
            result["bytes_up"]    = ubytes
            _spd_set(upload_mbps=up, progress=97.0)

            hosts = {s.split(" ")[0] for s in (dsrc, usrc) if s}
            result["server"] = (f"{hosts.pop()} (4 download / 3 upload streams)"
                                if len(hosts) == 1
                                else " / ".join(s for s in (dsrc, usrc) if s))
            result["method"] = (f"{result['method']}; "
                                f"download {dbytes/1e6:.1f} MB, "
                                f"upload {ubytes/1e6:.1f} MB" if dbytes or ubytes
                                else result["method"])
            result["status"] = "HTTP probe"

        if not (result["download_mbps"] or result["upload_mbps"] or result["latency_ms"]):
            result["status"] = "error"
            result["error"]  = ("No measurement succeeded - offline, or every "
                                "test endpoint was unreachable.")
            _spd_set(running=False, phase="error", progress=0.0,
                     error=result["error"], finished=time.time(), result=None)
            return

        _spd_set(running=False, phase="done", progress=100.0,
                 finished=time.time(), result=result, error="")
    except Exception as exc:                      # never leave the UI spinning
        _spd_set(running=False, phase="error", progress=0.0,
                 error=str(exc) or exc.__class__.__name__,
                 finished=time.time(), result=None)


@app.route("/api/speedtest", methods=["GET", "POST"])
@require_auth
def api_speedtest():
    """
    GET  -> current state: {running, phase, progress, live values, result, error}
    POST -> start a measurement (returns 202 + state; force=1 bypasses cache)
    """
    if request.method == "GET":
        return jsonify(_spd_snapshot())

    force = request.args.get("force") == "1"
    cached_out = None
    with _speed_lock:
        stale = (_speed_state["running"]
                 and time.time() - _speed_state.get("last_update", 0) > SPEEDTEST_STALL_SECS)
        if stale:
            # A worker died without clearing the flag - do not wedge the panel.
            _speed_state.update(running=False, phase="error",
                                error="previous run stalled")
        if _speed_state["running"]:
            already = True
        else:
            already = False
            cached, cached_time = _speed_state["result"], _speed_state["finished"]
            if cached and not force and time.time() - cached_time < SPEEDTEST_CACHE_SECS:
                cached_out = dict(cached)
                cached_out["cached"] = True
            else:
                _speed_state.update(running=True, phase="starting", progress=0.0,
                                    download_mbps=0.0, upload_mbps=0.0,
                                    latency_ms=0.0, jitter_ms=0.0, error="",
                                    started=time.time(), last_update=time.time())

    if already:
        return jsonify(_spd_snapshot()), 202          # a run is already going
    if cached_out is not None:
        return jsonify(cached_out)

    threading.Thread(target=_speed_worker, name="speedtest", daemon=True).start()
    return jsonify(_spd_snapshot()), 202



@app.route("/api/activities/<path:ip>")
def api_activities_ip(ip):
    """Return processed activity data for a single device."""
    return jsonify(get_device_activities(ip))

@app.route("/api/activities/summary")
def api_activities_summary():
    """Return activity summary for all devices (for the device grid)."""
    return jsonify(get_all_activities_summary())


# Only allow plausible hostnames/domains (prevents path tricks & URL injection)
_FAVICON_HOST_RE = re.compile(r"^[a-zA-Z0-9._-]{1,253}$")

@app.route("/favicon/<path:host>")
def api_site_favicon(host):
    """Proxy a site's favicon server-side so the browser avoids CORS issues.

    Returns the fetched image bytes with permissive CORS headers; 404 if it
    cannot be retrieved (the frontend then falls back to the globe icon).
    """
    host = (host or "").strip().strip("/")
    if not SITE_ICONS_ENABLED or not _FAVICON_HOST_RE.match(host):
        return ("", 404)
    fetched = _fetch_site_favicon(host)
    if fetched is None:
        return ("", 404)
    data, ctype = fetched
    resp = Response(data, status=200)
    resp.headers["Content-Type"] = ctype
    resp.headers["Cache-Control"] = "public, max-age=86400"
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


def _fetch_site_favicon(host: str):
    """Fetch a host's favicon via Google's s2 service.

    Returns (bytes, content_type) or None. Disabled by default because it
    discloses every hostname observed in LAN traffic to a third party – enable
    with NETRON_SITE_ICONS=1 if that trade-off is acceptable.
    """
    if not SITE_ICONS_ENABLED or not REQUESTS_OK or not _FAVICON_HOST_RE.match(host):
        return None
    try:
        from urllib.parse import quote
        url = f"https://www.google.com/s2/favicons?domain={quote(host, safe='.-')}&sz=64"
        r = _http.get(url, timeout=4, headers={"User-Agent": f"Netron/{VERSION}"})
        if r.status_code == 200 and r.content:
            return r.content, (r.headers.get("Content-Type") or "image/png")
    except Exception:
        pass
    return None

@app.route("/api/rescan/<ip>", methods=["POST"])
@require_auth
def api_rescan(ip):
    with _lock:
        d = dict(devices[ip]) if ip in devices else None
    if not d: return jsonify({"error":"unknown IP"}),404
    threading.Thread(
        target=monitor._deep_scan_guarded,
        args=(ip, d.get("mac","N/A"), d.get("vendor",""),
              d.get("device_type",""), d.get("brand","")),
        daemon=True,
    ).start()
    return jsonify({"ok":True,"message":f"Rescan queued for {ip}"})


@app.route("/api/topology")
def api_topology():
    with _lock:
        gw_ip = monitor.gateway
        node_list = []
        seen_ips = set()
        # Reflect all known devices in the graph – including ones that have
        # disconnected (shown as offline) so the operator can see the device
        # (and its reconnect when it comes back). Caching is kept but driven by
        # accurate real packet data. The monitoring host itself is excluded.
        local_ips = set()
        try:
            local_ips = get_local_ips()
        except Exception:
            pass
        for ip, d in devices.items():
            if ip in local_ips:
                continue   # the monitoring host itself is not a network device
            seen_ips.add(ip)
            node_list.append({
                "ip": ip, "hostname": d.get("hostname",""),
                "vendor": d.get("vendor","Unknown"),
                "device_type": d.get("device_type","Unknown"),
                "os": d.get("os","Unknown"),
                "status": d.get("status","offline"),
                "is_gateway": d.get("is_gateway", ip == gw_ip),
                "vuln_count": d.get("vuln_count",0),
                "bytes_in":   d.get("bytes_in",0),
                "bytes_out":  d.get("bytes_out",0),
                "mac": d.get("mac",""),
                "last_seen": d.get("last_seen",""),
            })
        # Always include gateway node even if not yet scanned
        if gw_ip and gw_ip not in seen_ips:
            node_list.append({
                "ip": gw_ip, "hostname": "gateway", "vendor": "Router",
                "device_type": "Router/AP", "os": "Router/Embedded Linux",
                "status": "online", "is_gateway": True,
                "vuln_count": 0, "bytes_in": 0, "bytes_out": 0, "mac": "",
            })
        nodes = node_list
        # Build edges – only between known LAN devices
        known_ips = {n["ip"] for n in node_list}
        edge_map = {}
        for ip, log in packet_log.items():
            for pkt in list(log)[:80]:
                src, dst = pkt.get("src",""), pkt.get("dst","")
                # Skip if either endpoint is not a known local device
                if not src or not dst: continue
                if src not in known_ips and dst not in known_ips: continue
                # Use gateway as surrogate for external endpoints
                gw = monitor.gateway
                src2 = src if src in known_ips else gw
                dst2 = dst if dst in known_ips else gw
                if src2 == dst2: continue
                key = tuple(sorted([src2, dst2]))
                if key not in edge_map:
                    edge_map[key] = {"a":key[0],"b":key[1],"count":0,
                                     "bytes":0,"proto":pkt.get("proto","OTHER")}
                edge_map[key]["count"] += 1
                edge_map[key]["bytes"] += pkt.get("len",0)
        return jsonify({"nodes":node_list, "edges":list(edge_map.values()),
                        "gateway":monitor.gateway})

@app.route("/api/traffic/<ip>")
def api_traffic(ip):
    with _lock: return jsonify(list(traffic_data.get(ip,[])))

@app.route("/api/packets/<ip>")
def api_packets(ip):
    with _lock: return jsonify(list(packet_log.get(ip,[])))

@app.route("/api/packets")
def api_packets_all():
    """Every captured frame (bounded ring buffer), newest last.

    Filters: ?proto=TCP|UDP|ICMP|ARP|OTHER, ?src=, ?dst=, ?port=, ?limit=.
    """
    proto = (request.args.get("proto") or "").upper()
    src   = (request.args.get("src") or "").strip()
    dst   = (request.args.get("dst") or "").strip()
    port  = request.args.get("port", "").strip()
    try:
        limit = max(1, min(2000, int(request.args.get("limit", "400"))))
    except ValueError:
        limit = 400
    try:
        since = int(request.args.get("since", "0"))
    except ValueError:
        since = 0
    with _lock:
        rows = list(pkt_feed)
    def keep(r):
        if proto and r.get("proto", "") != proto:
            return False
        if src and r.get("src", "") != src:
            return False
        if dst and r.get("dst", "") != dst:
            return False
        if port:
            try:
                p = int(port)
            except ValueError:
                return True
            if p not in (r.get("sport"), r.get("dport")):
                return False
        return True
    # pkt_feed is newest-first; return the requested window oldest-first so the
    # client can append it in capture order.
    out: List[dict] = []
    for r in rows:
        if since and int(r.get("seq") or 0) <= since:
            break
        if keep(r):
            out.append(r)
            if len(out) >= limit:
                break
    out.reverse()
    return jsonify({"packets": out, "captured": len(rows),
                    "mode": DETECT.status()["capture"]["mode"]})

@app.route("/api/voip")
def api_voip():
    """VoIP packets actually captured, grouped by protocol.

    Counts and rows come from the same bounded capture buffer the packet table
    shows, so a protocol appears here only if a packet carrying it was seen.
    Optional filters: ?ip= (either endpoint), ?limit= (newest rows returned).
    """
    ip = (request.args.get("ip") or "").strip()
    try:
        limit = max(1, min(200, int(request.args.get("limit", "40"))))
    except ValueError:
        limit = 40
    counts: Dict[str, int] = {}
    recent: List[dict] = []
    total = 0
    with _lock:
        rows = list(pkt_feed)
    for r in rows:
        v = r.get("voip") or ""
        if not v:
            continue
        if ip and ip not in (r.get("src"), r.get("dst")):
            continue
        total += 1
        counts[v] = counts.get(v, 0) + 1
        if len(recent) < limit:
            recent.append(r)
    recent.reverse()                      # oldest-first, like /api/packets
    return jsonify({"counts": counts, "total": total, "recent": recent,
                    "mode": DETECT.status()["capture"]["mode"],
                    "payload_available": bool(SCAPY_OK and IS_ROOT)})

@app.route("/api/ports")
def api_ports_all():
    """Open ports for every device, with the service/version the scan found."""
    rows = []
    with _lock:
        for ip, d in devices.items():
            for p, info in (d.get("open_ports") or {}).items():
                if not isinstance(info, dict) or info.get("state") != "open":
                    continue
                try:
                    num = int(p)
                except (TypeError, ValueError):
                    continue
                rows.append({"ip": ip, "hostname": d.get("hostname", ""),
                             "vendor": d.get("vendor", ""),
                             "device_type": d.get("device_type", ""),
                             "status": d.get("status", "offline"),
                             "port": num, "protocol": info.get("protocol", "tcp"),
                             "service": service_label(num, info.get("service", "")),
                             "version": info.get("version", "") or "",
                             "risky": num in ADMIN_PORTS or num in DB_PORTS})
    rows.sort(key=lambda r: (r["port"], r["ip"]))
    return jsonify({"ports": rows, "count": len(rows),
                    "devices": len({r["ip"] for r in rows})})

@app.route("/api/vulnerabilities")
def api_vulns_all():
    """All findings for all devices.  These come from the port/service table in
    assess_vulns(), not from an exploit check -- severity is the exposure the
    port implies, and nothing here is reported for a closed port."""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    rows, counts = [], {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    with _lock:
        # A host is "scanned" once it has been assessed, including hosts that
        # turned out to have no open ports -- counting only hosts with ports
        # would understate coverage.
        scanned = sum(1 for d in devices.values() if d.get("vuln_scanned"))
        total   = len(devices)
        for ip, d in devices.items():
            for v in (d.get("vulnerabilities") or []):
                sev = str(v.get("severity") or "LOW").upper()
                counts[sev] = counts.get(sev, 0) + 1
                rows.append({"ip": ip, "hostname": d.get("hostname", ""),
                             "vendor": d.get("vendor", ""),
                             "device_type": d.get("device_type", ""),
                             "status": d.get("status", "offline"),
                             "port": v.get("port", 0),
                             "service": v.get("service", ""),
                             "version": v.get("version", ""),
                             "severity": sev,
                             "description": v.get("description", "")})
    rows.sort(key=lambda r: (order.get(r["severity"], 9), r["ip"], r["port"]))
    return jsonify({"vulnerabilities": rows, "count": len(rows),
                    "by_severity": counts, "devices_scanned": scanned,
                    "devices_total": total})

@app.route("/api/bandwidth")
def api_bandwidth():
    """Per-device recent throughput against the learned baseline, plus the
    largest live flows.  All numbers are measured bytes; nothing is modelled."""
    base = DETECT.bandwidth_baselines()
    now  = time.time()
    rows = []
    with _lock:
        for ip, d in devices.items():
            samples = [s for s in traffic_data.get(ip, []) if isinstance(s, dict)][-60:]
            out_60 = sum(int(s.get("out") or 0) for s in samples)
            in_60  = sum(int(s.get("in") or 0) for s in samples)
            b = base.get(ip) or {}
            bl = int(b.get("baseline_out") or 0)
            ratio = (out_60 / bl) if bl > 0 else 0.0
            rows.append({"ip": ip, "hostname": d.get("hostname", ""),
                         "vendor": d.get("vendor", ""),
                         "role": DETECT._role(ip),
                         "status": d.get("status", "offline"),
                         "out_60": out_60, "in_60": in_60,
                         "baseline_out": bl, "ratio": round(ratio, 2),
                         "outlier": bool(bl and out_60 >= DET_BW_MIN_BYTES
                                         and ratio >= DET_BW_FACTOR),
                         "samples": int(b.get("samples") or 0)})
    rows.sort(key=lambda r: r["out_60"], reverse=True)
    return jsonify({"devices": rows, "flows": DETECT.top_flows(20),
                    "window": 60, "generated": _ts()})

@app.route("/api/detections")
def api_detections():
    """Detection coverage: which rules are running, which need telemetry this
    process cannot see, and the counters for each."""
    return jsonify(DETECT.status())

@socketio.on("connect")
def on_connect():
    with _lock:
        devlist = list(devices.values())
        # Ensure gateway device is always in the list (even if scan not done yet)
        gw_ip = monitor.gateway
        gw_ips = {d.get("ip") for d in devlist}
        if gw_ip and gw_ip not in gw_ips:
            devlist.append({
                "ip": gw_ip, "mac": "N/A", "hostname": "gateway",
                "vendor": "Router", "brand": "Router",
                "device_type": "Router/AP", "os": "Router/Embedded Linux",
                "os_accuracy": "", "ttl": 0,
                "open_ports": {}, "vulnerabilities": [], "vuln_count": 0,
                "status": "online", "is_gateway": True,
                "first_seen": _ts(), "last_seen": _ts(),
                "bytes_in": 0, "bytes_out": 0,
            })
        detections = DETECT.status()
        emit("initial_state", {
            "devices": devlist,
            "alerts":  list(alerts)[:50],
            "detections": detections,
            "flows": DETECT.top_flows(20),
            "stats":   {
                **net_stats,
                "device_count": len(devices),
                "gateway": monitor.gateway,
                "network": monitor.network,
            },
        })


# ─────────────────────────────────────────────────────────────────────────────
#  DASHBOARD HTML
# ─────────────────────────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Netron – Network Dashboard</title>
<link rel="icon" type="image/png" href="/assets/netron.png">
<link rel="apple-touch-icon" href="/assets/netron.png">
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#080b10;--bg2:#0d1117;--bg3:#13192a;--border:#1a2535;
  --accent:#00e5ff;--accent2:#7c4dff;
  --green:#00e676;--yellow:#ffd740;--orange:#ff6d00;--red:#ff1744;
  --text:#dde6f0;--muted:#3d5068;
  --crit:#ff2d55;--high:#ff6b35;--med:#ffd60a;--low:#30d158;--info:#636366;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:13px;overflow-x:hidden}
.mono{font-family:'JetBrains Mono',monospace}

/* HEADER */
header{display:flex;align-items:center;justify-content:space-between;padding:0 20px;height:52px;
  background:var(--bg2);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100}
.logo{display:flex;align-items:center;gap:9px;font-family:'JetBrains Mono',monospace;font-weight:700;font-size:17px;color:var(--accent)}
.logo-img{width:26px;height:26px;object-fit:contain;display:block;flex:0 0 auto}
.hdr-meta{display:flex;align-items:center;gap:16px;font-size:11px;color:var(--muted)}
.live-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}

/* LAYOUT */
.app{display:grid;grid-template-columns:260px 1fr;height:calc(100vh - 52px)}
.sidebar{background:var(--bg2);border-right:1px solid var(--border);overflow-y:auto;padding:12px 0}
.main{overflow-y:auto}

/* SIDEBAR */
.sb-title{font-size:9px;font-weight:700;letter-spacing:.18em;color:var(--muted);text-transform:uppercase;padding:0 14px 6px}
.stat-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px;padding:0 10px;margin-bottom:16px}
.stat-card{background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:9px 11px}
.stat-val{font-family:'JetBrains Mono',monospace;font-size:19px;font-weight:700;color:var(--accent)}
.stat-lbl{font-size:9px;color:var(--muted);margin-top:1px}
.nav-item{display:flex;align-items:center;gap:9px;padding:8px 14px;cursor:pointer;color:var(--muted);
  font-size:12px;border-left:3px solid transparent;transition:all .15s}
.nav-item:hover{color:var(--text);background:var(--bg3)}
.nav-item.active{color:var(--accent);border-left-color:var(--accent);background:rgba(0,229,255,.05)}
.nav-icon{font-size:15px;width:18px;text-align:center}
.badge{margin-left:auto;background:var(--red);color:#fff;border-radius:10px;font-size:9px;padding:1px 5px;font-weight:700}

/* PANELS */
.panel{display:none;padding:18px}
.panel.active{display:block}
.sec-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.sec-title{font-size:15px;font-weight:600}

/* OVERVIEW CARDS */
.ov-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin-bottom:18px}
.ov-card{background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:14px;text-align:center}
.ov-val{font-family:'JetBrains Mono',monospace;font-size:26px;font-weight:700}
.ov-lbl{font-size:10px;color:var(--muted);margin-top:3px}

/* TABLE */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;
  color:var(--muted);padding:7px 10px;border-bottom:1px solid var(--border);
  position:sticky;top:0;background:var(--bg2);z-index:1}
td{padding:9px 10px;border-bottom:1px solid rgba(26,37,53,.6);vertical-align:middle}
tr:hover td{background:var(--bg3);cursor:pointer}
.ip{font-family:'JetBrains Mono',monospace;color:var(--accent);font-size:12px}
.mac-addr{font-family:'JetBrains Mono',monospace;color:var(--muted);font-size:10px}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:5px}
.dot-on{background:var(--green);box-shadow:0 0 4px var(--green)}
.dot-off{background:var(--muted)}

/* BADGES */
.badge-sev{display:inline-block;padding:2px 7px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:.04em}
.sev-CRITICAL{background:rgba(255,45,85,.12);color:var(--crit);border:1px solid var(--crit)}
.sev-HIGH{background:rgba(255,107,53,.12);color:var(--high);border:1px solid var(--high)}
.sev-MEDIUM{background:rgba(255,214,10,.12);color:var(--med);border:1px solid var(--med)}
.sev-LOW{background:rgba(48,209,88,.12);color:var(--low);border:1px solid var(--low)}
.sev-INFO{background:rgba(99,99,102,.12);color:var(--info);border:1px solid var(--info)}

/* MODAL */
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.82);z-index:1000;overflow-y:auto}
.overlay.open{display:flex;align-items:flex-start;justify-content:center;padding:36px 16px}
.modal{background:var(--bg2);border:1px solid var(--border);border-radius:12px;width:100%;max-width:880px;overflow:hidden}
.modal-hdr{display:flex;align-items:center;justify-content:space-between;padding:18px 22px;border-bottom:1px solid var(--border)}
.modal-title{font-size:17px;font-weight:600}
.modal-body{padding:22px}
.close-btn{width:28px;height:28px;background:var(--bg3);border:1px solid var(--border);border-radius:5px;
  cursor:pointer;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:16px}
.close-btn:hover{color:var(--text)}
.detail-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;margin-bottom:18px}
.detail-card{background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:10px 13px}
.detail-key{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em}
.detail-val{font-family:'JetBrains Mono',monospace;font-size:12px;margin-top:3px;word-break:break-all}

/* CHART CARDS */
.chart-card{background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:14px;margin-bottom:14px}
.chart-lbl{font-size:10px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:10px}
.chart-card canvas{max-height:200px}

/* PORT CARDS */
.port-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:7px;margin-bottom:14px}
.port-card{background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:9px 12px;display:flex;align-items:center;gap:9px}
.port-num{font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:700;color:var(--accent2);min-width:46px}
.port-svc{font-weight:600;font-size:11px}
.port-ver{font-size:10px;color:var(--muted)}

/* ALERTS */
.alert-list{display:flex;flex-direction:column;gap:7px}
.alert-card{background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:12px 14px;
  display:flex;align-items:flex-start;gap:10px;transition:opacity .3s}
.alert-card.acked{opacity:.38}
.alert-bar{width:4px;border-radius:2px;align-self:stretch;min-height:38px}
.alert-title{font-weight:600;font-size:13px}
.alert-detail{font-size:11px;color:var(--muted);margin-top:2px}
.alert-meta{font-size:10px;color:var(--muted);margin-top:4px}
.ack-btn{background:none;border:1px solid var(--border);color:var(--muted);border-radius:5px;
  padding:2px 9px;cursor:pointer;font-size:10px;white-space:nowrap;font-family:inherit}
.ack-btn:hover{border-color:var(--green);color:var(--green)}

/* PACKET STREAM */
.pkt-stream{background:var(--bg3);border:1px solid var(--border);border-radius:9px;
  height:340px;overflow-y:auto;padding:6px 8px;font-family:'JetBrains Mono',monospace;font-size:11px}
.pkt{display:flex;gap:10px;padding:2px 5px;border-radius:3px;line-height:1.5}
.pkt:hover{background:var(--bg2)}
.pkt-ts{color:var(--muted);min-width:68px}
.pkt-proto{min-width:46px;font-weight:700}
.pkt-TCP{color:#64b5f6}.pkt-UDP{color:#81c784}.pkt-ICMP{color:#ffb74d}
.pkt-ICMPv6{color:#4dd0e1}.pkt-ARP{color:#9e9e9e}.pkt-IPv6{color:#b0a8e0}
/* VoIP protocols shown in the Protocol column (class = label without punctuation) */
.pkt-SIP{color:#ffd740}.pkt-SIPTLS{color:#ffd740}.pkt-RTP{color:#ff9e40}
.pkt-RTCP{color:#ffb74d}.pkt-H323{color:#ffcc80}.pkt-H323RAS{color:#ffcc80}
.pkt-MGCP{color:#ffab91}.pkt-SCCP{color:#ff8a65}.pkt-STUN{color:#4dd0e1}.pkt-IAX2{color:#ce93d8}
.pkt-RECV{color:#ce93d8}.pkt-SEND{color:#00e676}.pkt-OTHER{color:var(--muted)}
.pkt-src{color:var(--accent)}.pkt-dst{color:#ce93d8}
.pkt-info{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}

/* WIRESHARK-STYLE PACKET TABLE */
.ws-wrap{background:var(--bg3);border:1px solid var(--border);border-radius:9px;
  height:420px;overflow:auto;font-family:'JetBrains Mono',monospace;font-size:11px}
.ws-table{width:100%;border-collapse:collapse}
.ws-table thead th{position:sticky;top:0;z-index:2;background:var(--bg2);color:var(--muted);
  text-align:left;font-weight:600;font-size:10px;letter-spacing:.04em;padding:5px 8px;
  border-bottom:1px solid var(--border);white-space:nowrap}
.ws-table tbody td{padding:2px 8px;white-space:nowrap;border-bottom:1px solid rgba(26,37,53,.5)}
.ws-table tbody tr:hover{background:var(--bg2)}
.ws-no{color:var(--muted)}
.ws-time{color:var(--muted)}
.ws-src{color:var(--accent)}
.ws-dst{color:#ce93d8}
.ws-len{color:var(--muted);text-align:right}
.ws-info{color:#8fa3b8;max-width:520px;overflow:hidden;text-overflow:ellipsis}
.ws-table td.ws-info{white-space:nowrap}
.filter-chip{font-size:10px;padding:3px 9px;border-radius:11px;border:1px solid var(--border);
  background:var(--bg3);color:var(--muted);cursor:pointer;font-family:inherit}
.filter-chip.on{border-color:var(--accent);color:var(--accent);background:rgba(0,229,255,.08)}
.meta-chip{font-size:9px;padding:1px 6px;border-radius:4px;background:var(--bg2);
  border:1px solid var(--border);color:var(--muted);white-space:nowrap}
.meta-chip.atk{border-color:rgba(124,77,255,.45);color:#b39ddb}
.det-row{display:flex;gap:8px;align-items:center;padding:3px 0;font-size:10px;
  border-bottom:1px solid rgba(26,37,53,.6)}
.det-on{color:var(--green)}.det-off{color:var(--orange)}

/* OS BADGE */
.os-badge{display:inline-flex;align-items:center;gap:4px;font-size:10px;padding:2px 7px;border-radius:4px;
  background:rgba(124,77,255,.1);border:1px solid rgba(124,77,255,.3);color:#b39ddb}

/* BUTTONS */
.btn{padding:6px 13px;border-radius:6px;border:1px solid var(--border);background:var(--bg3);color:var(--text);
  cursor:pointer;font-size:11px;font-family:inherit;transition:all .15s;display:inline-flex;align-items:center;gap:5px}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn-prim{background:var(--accent2);border-color:var(--accent2);color:#fff}
.btn-prim:hover{background:#9c72ff;border-color:#9c72ff;color:#fff}
.search{background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:6px;
  padding:6px 11px;font-size:11px;font-family:'JetBrains Mono',monospace;outline:none;width:210px}
.search:focus{border-color:var(--accent)}

/* TOAST */
#toasts{position:fixed;bottom:16px;right:16px;z-index:9999;display:flex;flex-direction:column-reverse;gap:6px}
.toast{background:var(--bg2);border:1px solid var(--border);border-radius:9px;padding:10px 14px;
  min-width:270px;max-width:340px;display:flex;align-items:flex-start;gap:9px;
  animation:slIn .25s ease;box-shadow:0 4px 18px rgba(0,0,0,.45);transition:opacity .35s,transform .35s}
@keyframes slIn{from{transform:translateX(110%);opacity:0}to{transform:none;opacity:1}}
.toast-bar{width:4px;border-radius:2px;min-height:34px}


/* ACTIVITY POPUP CONTROLS (moved out of <body> – <style> belongs in <head>) */
.act-tb-btn{display:flex;flex-direction:column;align-items:center;padding:4px 10px;
  border-radius:4px;cursor:pointer;color:#ccc;min-width:44px}
.act-tb-btn:hover{background:rgba(0,229,255,.1)}
.act-tb-btn:active{background:rgba(0,229,255,.2)}
#act-proto-list::-webkit-scrollbar,#act-canvas::-webkit-scrollbar{width:6px}
#act-proto-list::-webkit-scrollbar-track{background:transparent}
#act-proto-list::-webkit-scrollbar-thumb{background:#333;border-radius:3px}
/* Indeterminate progress bar – the server cannot stream real progress,
   so the bar must not pretend to know a percentage. */
#spd-progress.indeterminate{width:35%!important;transition:none;animation:spdIndet 1.1s linear infinite}
@keyframes spdIndet{0%{margin-left:-35%}100%{margin-left:100%}}

/* TOPOLOGY */
#topo-canvas{background:var(--bg);image-rendering:crisp-edges;display:block}
#topo-wrap{user-select:none}
#topo-trace::-webkit-scrollbar{width:3px}
#topo-trace::-webkit-scrollbar-thumb{background:var(--border)}
.trace-row{display:flex;gap:6px;padding:3px 0;border-bottom:1px solid rgba(26,37,53,.5);line-height:1.5}
.trace-row:last-child{border-bottom:none}
.tr-proto{min-width:36px;font-weight:700}
.tr-TCP{color:#64b5f6}.tr-UDP{color:#81c784}.tr-ICMP{color:#ffb74d}
.tr-RECV{color:#ce93d8}.tr-SEND{color:#00e676}.tr-OTHER{color:var(--muted)}
/* TOOLBAR BUTTON */
.tbtn{padding:4px 10px;border-radius:5px;border:1px solid var(--border);
  background:var(--bg3);color:var(--text);cursor:pointer;font-size:10px;
  font-family:inherit;transition:all .15s;white-space:nowrap}
.tbtn:hover{border-color:var(--accent);color:var(--accent)}
.tbtn.active{background:var(--accent2);border-color:var(--accent2);color:#fff}

/* SCROLLBAR */
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}
</style>
</head>
<body>

<header>
  <div class="logo">
    <img class="logo-img" src="/assets/netron.png" alt="Netron logo"
         width="26" height="26">
    Netron
  </div>
  <div class="hdr-meta">
    <span id="hdr-net" class="mono">—</span>
    <span id="hdr-gw"  class="mono"></span>
    <div class="live-dot"></div>
    <span id="hdr-time" class="mono"></span>
  </div>
</header>

<div class="app">
<nav class="sidebar">
  <div style="margin-bottom:14px">
    <div class="sb-title">Network</div>
    <div class="stat-grid">
      <div class="stat-card"><div class="stat-val" id="s-dev">0</div><div class="stat-lbl">Devices</div></div>
      <div class="stat-card"><div class="stat-val" id="s-on">0</div><div class="stat-lbl">Online</div></div>
      <div class="stat-card"><div class="stat-val" id="s-al">0</div><div class="stat-lbl">Alerts</div></div>
      <div class="stat-card"><div class="stat-val" id="s-pps">0</div><div class="stat-lbl">Pkt/s</div></div>
    </div>
  </div>
  <div class="sb-title">Views</div>
  <div class="nav-item active" data-panel="overview"   onclick="nav(this,'overview')"><span class="nav-icon">🌐</span>Overview</div>
  <div class="nav-item"        data-panel="devices"    onclick="nav(this,'devices')"><span class="nav-icon">💻</span>Devices</div>
  <div class="nav-item"        data-panel="traffic"    onclick="nav(this,'traffic')"><span class="nav-icon">📡</span>Live Traffic</div>
  <div class="nav-item"        data-panel="alerts"     onclick="nav(this,'alerts')">
    <span class="nav-icon">🚨</span>Alerts<span class="badge" id="al-badge" style="display:none">0</span>
  </div>
  <div class="nav-item"        data-panel="vulns"      onclick="nav(this,'vulns')"><span class="nav-icon">🔓</span>Vulnerabilities</div>
  <div class="nav-item"        data-panel="ports"      onclick="nav(this,'ports')"><span class="nav-icon">🔌</span>Open Ports</div>
  <div class="nav-item"        data-panel="graphs"     onclick="nav(this,'graphs')"><span class="nav-icon">📈</span>Bandwidth</div>
  <div class="nav-item"        data-panel="activities" onclick="nav(this,'activities')"><span class="nav-icon">📊</span>Activities</div>

  <div style="margin-top:16px">
    <div class="sb-title">System</div>
    <div id="sys-stats" style="padding:0 12px;font-size:10px;color:var(--muted);line-height:1.9"></div>
  </div>
</nav>

<main class="main">

<!-- OVERVIEW -->
<div class="panel active" id="panel-overview">

  <!-- ── STAT CARDS ── -->
  <div class="ov-grid">
    <div class="ov-card"><div class="ov-val" style="color:var(--accent)"  id="ov-dev">0</div><div class="ov-lbl">Devices</div></div>
    <div class="ov-card"><div class="ov-val" style="color:var(--green)"   id="ov-on">0</div><div class="ov-lbl">Online</div></div>
    <div class="ov-card"><div class="ov-val" style="color:var(--red)"     id="ov-al">0</div><div class="ov-lbl">Alerts</div></div>
    <div class="ov-card"><div class="ov-val" style="color:var(--orange)"  id="ov-vu">0</div><div class="ov-lbl">Vulnerabilities</div></div>
    <div class="ov-card"><div class="ov-val" style="color:var(--yellow)"  id="ov-pt">0</div><div class="ov-lbl">Open Ports</div></div>
    <div class="ov-card"><div class="ov-val" style="color:var(--accent2)" id="ov-sc">0</div><div class="ov-lbl">Scans</div></div>
  </div>

  <!-- ── INTERNET SPEED & LATENCY ── -->
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;
       padding:14px 18px;margin-bottom:16px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
      <div style="display:flex;align-items:center;gap:12px">
        <span style="font-size:13px;font-weight:600">🌐 Internet Speed &amp; Latency</span>
        <span id="spd-engine" style="font-size:9px;padding:2px 7px;border-radius:4px;
          background:var(--bg3);border:1px solid var(--border);color:var(--muted)">not tested</span>
        <span id="spd-server" style="font-size:10px;color:var(--muted)"></span>
        <span id="spd-isp" style="font-size:10px;color:var(--muted)"></span>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <span id="spd-ts" style="font-size:10px;color:var(--muted)"></span>
        <button class="tbtn btn-prim" onclick="runSpeedTest()" id="speed-btn"
                style="padding:5px 14px;font-size:11px">▶ Run Test</button>
      </div>
    </div>

    <!-- 5 metric columns -->
    <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px">

      <!-- Download -->
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 14px">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
          <span style="font-size:16px">⬇</span>
          <span style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em">Download</span>
        </div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:26px;font-weight:700;
             color:var(--accent);line-height:1" id="spd-down">—</div>
        <div style="font-size:10px;color:var(--muted);margin-top:3px">Mbps</div>
        <div style="margin-top:8px;height:5px;background:rgba(0,229,255,.1);border-radius:3px;overflow:hidden">
          <div id="spd-down-bar" style="height:100%;width:0%;background:var(--accent);
               border-radius:3px;transition:width 1s ease"></div>
        </div>
      </div>

      <!-- Upload -->
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 14px">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
          <span style="font-size:16px">⬆</span>
          <span style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em">Upload</span>
        </div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:26px;font-weight:700;
             color:#7c4dff;line-height:1" id="spd-up">—</div>
        <div style="font-size:10px;color:var(--muted);margin-top:3px">Mbps</div>
        <div style="margin-top:8px;height:5px;background:rgba(124,77,255,.1);border-radius:3px;overflow:hidden">
          <div id="spd-up-bar" style="height:100%;width:0%;background:#7c4dff;
               border-radius:3px;transition:width 1s ease"></div>
        </div>
      </div>

      <!-- Ping / Latency -->
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 14px">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
          <span style="font-size:16px">📡</span>
          <span style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em">Ping</span>
        </div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:26px;font-weight:700;
             color:var(--green);line-height:1" id="spd-lat">—</div>
        <div style="font-size:10px;color:var(--muted);margin-top:3px">ms</div>
        <div style="margin-top:8px;height:5px;background:rgba(0,230,118,.1);border-radius:3px;overflow:hidden">
          <div id="spd-lat-bar" style="height:100%;width:0%;background:var(--green);
               border-radius:3px;transition:width 1s ease"></div>
        </div>
      </div>

      <!-- Jitter -->
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 14px">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
          <span style="font-size:16px">〰</span>
          <span style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em">Jitter</span>
        </div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:26px;font-weight:700;
             color:var(--yellow);line-height:1" id="spd-jit">—</div>
        <div style="font-size:10px;color:var(--muted);margin-top:3px">ms</div>
        <div style="margin-top:8px;height:5px;background:rgba(255,215,64,.1);border-radius:3px;overflow:hidden">
          <div id="spd-jit-bar" style="height:100%;width:0%;background:var(--yellow);
               border-radius:3px;transition:width 1s ease"></div>
        </div>
      </div>

      <!-- Rating -->
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:12px 14px;
           display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center">
        <div style="font-size:32px;margin-bottom:4px" id="spd-emoji">⏸</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:700;
             color:var(--muted)" id="spd-status">Not tested</div>
        <div style="font-size:9px;color:var(--muted);margin-top:4px" id="spd-rating-bar">
          <div style="display:flex;gap:3px;justify-content:center" id="spd-bars">
            <span style="width:5px;height:16px;background:var(--border);border-radius:2px;display:inline-block"></span>
            <span style="width:5px;height:20px;background:var(--border);border-radius:2px;display:inline-block"></span>
            <span style="width:5px;height:24px;background:var(--border);border-radius:2px;display:inline-block"></span>
            <span style="width:5px;height:28px;background:var(--border);border-radius:2px;display:inline-block"></span>
            <span style="width:5px;height:32px;background:var(--border);border-radius:2px;display:inline-block"></span>
          </div>
        </div>
      </div>

    </div>

    <!-- Progress bar shown while testing -->
    <div id="spd-progress-wrap" style="display:none;margin-top:12px">
      <div style="height:3px;background:var(--bg3);border-radius:2px;overflow:hidden">
        <div id="spd-progress" style="height:100%;width:0%;background:linear-gradient(90deg,var(--accent),#7c4dff);
             border-radius:2px;transition:width .4s ease"></div>
      </div>
      <div id="spd-phase" style="font-size:10px;color:var(--muted);margin-top:5px;text-align:center">Initialising…</div>
    </div>
  </div>

  <!-- ── NETWORK TOPOLOGY GRAPH ── -->
  <div id="topo-wrap" style="background:var(--bg2);border:1px solid var(--border);
       border-radius:12px;position:relative;overflow:hidden;margin:20px 0">

    <!-- Toolbar -->
    <div id="topo-toolbar" style="display:flex;align-items:center;justify-content:space-between;
         padding:8px 14px;border-bottom:1px solid var(--border)">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <span style="font-size:12px;font-weight:700;color:var(--accent)">🕸 Network Map</span>
        <span id="topo-node-count" style="font-size:10px;color:var(--muted)">0 nodes</span>
        <span id="topo-pps" style="font-size:10px;color:var(--green);
          background:rgba(0,230,118,.07);border:1px solid rgba(0,230,118,.2);
          padding:1px 7px;border-radius:4px;font-family:'JetBrains Mono',monospace">0 pkt/s</span>
        <span style="color:var(--border);font-size:10px">│</span>
        <span style="font-size:9px;color:var(--muted)">
          <span style="color:#00e5ff">●</span> GW &nbsp;
          <span style="color:#00e676">●</span> Online &nbsp;
          <span style="color:#ff6b35">●</span> Vuln &nbsp;
          <span style="color:#3d5068">●</span> Off
        </span>
        <span style="color:var(--border);font-size:10px">│</span>
        <span style="font-size:9px">
          <span style="color:#64b5f6">─</span> TCP &nbsp;
          <span style="color:#81c784">─</span> UDP &nbsp;
          <span style="color:#ffb74d">─</span> ICMP
        </span>
        <span style="color:var(--border);font-size:10px">│</span>
        <span style="font-size:11px" title="Router/GW">🔀</span>
        <span style="font-size:11px" title="Mobile">📱</span>
        <span style="font-size:11px" title="Tablet">📋</span>
        <span style="font-size:11px" title="Laptop">💻</span>
        <span style="font-size:11px" title="Desktop">🖥</span>
        <span style="font-size:11px" title="TV">📺</span>
        <span style="font-size:11px" title="Camera">📷</span>
        <span style="font-size:11px" title="Printer">🖨</span>
        <span style="font-size:11px" title="Console">🎮</span>
        <span style="font-size:11px" title="IoT">🔌</span>
        <span style="font-size:11px" title="Server">🖧</span>
      </div>
      <div style="display:flex;align-items:center;gap:5px">
        <span style="font-size:9px;color:var(--muted);margin-right:4px">Scroll=zoom · Drag=pan · Dbl-click=trace</span>
        <button class="tbtn" id="topo-pause-btn" onclick="topoTogglePause()">⏸ Pause</button>
        <button class="tbtn" onclick="topoFit()">⊡ Fit</button>
        <button class="tbtn" onclick="topoReset()">⟳ Reset</button>
        <button class="tbtn" onclick="topoZoomIn()">＋</button>
        <button class="tbtn" onclick="topoZoomOut()">－</button>
      </div>
    </div>

    <!-- Canvas – JS sets exact height -->
    <canvas id="topo-canvas" style="width:100%;display:block;cursor:grab"></canvas>

    <!-- Packet trace slide-in panel -->
    <div id="topo-trace" style="position:absolute;top:43px;right:0;width:280px;
         height:calc(100% - 43px);background:rgba(8,11,16,.95);
         border-left:1px solid var(--border);overflow-y:auto;padding:12px;
         font-family:'JetBrains Mono',monospace;font-size:10px;
         transition:transform .25s ease;transform:translateX(100%);z-index:4">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
        <span style="font-weight:700;color:var(--accent);font-size:11px" id="trace-title">Packet Trace</span>
        <button onclick="closeTrace()" style="background:none;border:1px solid var(--border);
                color:var(--muted);cursor:pointer;font-size:11px;border-radius:4px;padding:1px 7px">✕</button>
      </div>
      <div id="trace-info" style="color:var(--muted);margin-bottom:8px;font-size:9px;line-height:1.5"></div>
      <div id="trace-list"></div>
    </div>

    <!-- Tooltip -->
    <div id="topo-tip" style="position:absolute;pointer-events:none;display:none;
         background:var(--bg3);border:1px solid var(--border);border-radius:9px;
         padding:11px 15px;font-size:11px;min-width:220px;max-width:300px;
         z-index:20;box-shadow:0 6px 28px rgba(0,0,0,.7)"></div>
  </div>

  <!-- ── ORIGINAL BOTTOM: charts + recent alerts (restored) ── -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px">
    <div class="chart-card"><div class="chart-lbl">Device Types</div><canvas id="ch-types"></canvas></div>
    <div class="chart-card"><div class="chart-lbl">Alert Severity</div><canvas id="ch-sev"></canvas></div>
  </div>
  <div class="sec-hdr" style="margin-top:0"><div class="sec-title" style="font-size:13px">Recent Alerts</div></div>
  <div class="alert-list" id="ov-alerts"></div>

</div>

<!-- DEVICES -->
<div class="panel" id="panel-devices">
  <div class="sec-hdr"><div class="sec-title">Connected Devices</div>
    <input class="search" id="dev-search" placeholder="Filter…" oninput="filterDevs()"></div>
  <div class="tbl-wrap">
    <table><thead><tr>
      <th>Status</th><th>IP</th><th>MAC</th><th>Hostname</th>
      <th>Type</th><th>Vendor</th><th>OS</th>
      <th>Ports</th><th>Vulns</th><th>TTL</th><th>Last Seen</th><th>Action</th>
    </tr></thead><tbody id="dev-tbody"></tbody></table>
  </div>
</div>

<!-- LIVE TRAFFIC -->
<div class="panel" id="panel-traffic">
  <div class="sec-hdr">
    <div class="sec-title">Live Packet Capture</div>
    <div style="display:flex;gap:7px;align-items:center">
      <span id="cap-badge" style="font-size:10px;padding:3px 9px;border-radius:4px;
        background:var(--bg3);border:1px solid var(--border);color:var(--muted)">Detecting…</span>
      <span id="pkt-ctr" class="mono" style="font-size:10px;color:var(--muted)">0 pkts</span>
      <button class="btn" onclick="clearPkts()">🗑 Clear</button>
      <button id="pause-btn" class="btn" onclick="togglePause()">⏸ Pause</button>
    </div>
  </div>
  <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:9px">
    <span style="color:var(--muted);font-size:10px">Protocol:</span>
    <button class="filter-chip on" data-proto="" onclick="setPktFilter(this,'')">All</button>
    <button class="filter-chip" data-proto="TCP" onclick="setPktFilter(this,'TCP')">TCP</button>
    <button class="filter-chip" data-proto="UDP" onclick="setPktFilter(this,'UDP')">UDP</button>
    <button class="filter-chip" data-proto="ICMP" onclick="setPktFilter(this,'ICMP')">ICMP</button>
    <button class="filter-chip" data-proto="ICMPv6" onclick="setPktFilter(this,'ICMPv6')">ICMPv6</button>
    <button class="filter-chip" data-proto="ARP" onclick="setPktFilter(this,'ARP')">ARP</button>
    <button class="filter-chip" data-proto="OTHER" onclick="setPktFilter(this,'OTHER')">Other</button>
    <input class="search" id="pkt-search" placeholder="Filter address / info…"
           oninput="renderPktRows()" style="max-width:230px">
    <span style="margin-left:auto;font-size:10px;color:var(--muted)" id="cap-note"></span>
  </div>
  <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:9px">
    <span style="color:var(--muted);font-size:10px">VoIP:</span>
    <button class="filter-chip on" data-voip="" onclick="setVoipFilter(this,'')">All</button>
    <button class="filter-chip" data-voip="SIP" onclick="setVoipFilter(this,'SIP')">SIP</button>
    <button class="filter-chip" data-voip="RTP" onclick="setVoipFilter(this,'RTP')">RTP</button>
    <button class="filter-chip" data-voip="RTCP" onclick="setVoipFilter(this,'RTCP')">RTCP</button>
    <button class="filter-chip" data-voip="H.323" onclick="setVoipFilter(this,'H.323')">H.323</button>
    <button class="filter-chip" data-voip="MGCP" onclick="setVoipFilter(this,'MGCP')">MGCP</button>
    <button class="filter-chip" data-voip="SCCP" onclick="setVoipFilter(this,'SCCP')">SCCP</button>
    <button class="filter-chip" data-voip="STUN" onclick="setVoipFilter(this,'STUN')">STUN</button>
    <button class="filter-chip" data-voip="IAX2" onclick="setVoipFilter(this,'IAX2')">IAX2</button>
    <span id="voip-summary" class="mono" style="margin-left:auto;font-size:10px;color:var(--muted)">
      VoIP: watching…</span>
  </div>
  <div class="ws-wrap">
    <table class="ws-table">
      <thead><tr>
        <th style="width:62px">No.</th><th style="width:88px">Time</th>
        <th style="width:150px">Source</th><th style="width:150px">Destination</th>
        <th style="width:74px">Protocol</th><th style="width:64px">Length</th><th>Info</th>
      </tr></thead>
      <tbody id="pkt-rows"></tbody>
    </table>
    <div id="pkt-ph" style="color:var(--muted);padding:18px;text-align:center">⏳ Waiting for traffic…</div>
  </div>
</div>

<!-- ALERTS -->
<div class="panel" id="panel-alerts">
  <div class="sec-hdr"><div class="sec-title">Security Alerts</div>
    <div style="display:flex;gap:7px;align-items:center;flex-wrap:wrap">
      <select id="alert-sev" class="search" onchange="renderAlerts()" style="width:130px">
        <option value="">All severities</option>
        <option value="CRITICAL">CRITICAL</option><option value="HIGH">HIGH</option>
        <option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option>
        <option value="INFO">INFO</option>
      </select>
      <input class="search" id="alert-search" placeholder="Filter host / rule / ATT&CK…"
             oninput="renderAlerts()" style="max-width:220px">
      <label style="font-size:10px;color:var(--muted);display:flex;align-items:center;gap:4px">
        <input type="checkbox" id="alert-unacked" onchange="renderAlerts()"> unacked only</label>
      <button class="btn" onclick="ackAll()">✓ Acknowledge All</button>
    </div></div>
  <div class="alert-list" id="alert-list"></div>
  <div style="margin-top:18px;border:1px solid var(--border);border-radius:8px;background:var(--bg3)">
    <div class="sec-hdr" style="margin:0;padding:8px 10px;cursor:pointer" onclick="toggleDetCoverage()">
      <div class="sec-title" style="font-size:12px;display:flex;align-items:center;gap:6px">
        <span id="det-caret" style="display:inline-block;transition:transform .15s;color:var(--muted)">▸</span>
        Detection coverage</div>
      <span style="font-size:10px;color:var(--muted)" id="det-note"></span>
    </div>
    <div id="det-coverage" style="display:none;padding:0 10px 10px"></div>
  </div>
</div>

<!-- VULNERABILITIES -->
<div class="panel" id="panel-vulns">
  <div class="sec-hdr"><div class="sec-title">Detected Vulnerabilities</div>
    <span style="font-size:10px;color:var(--muted)" id="vuln-stats"></span></div>
  <div id="vuln-list"></div>
</div>

<!-- OPEN PORTS -->
<div class="panel" id="panel-ports">
  <div class="sec-hdr"><div class="sec-title">Open Ports</div>
    <div style="display:flex;gap:8px;align-items:center">
      <span style="font-size:10px;color:var(--muted)" id="port-stats"></span>
      <input class="search" id="port-search" placeholder="Filter port/service/host…" oninput="filterPorts()">
    </div></div>
  <div id="ports-content"></div>
</div>

<!-- BANDWIDTH GRAPHS -->
<div class="panel" id="panel-graphs">
  <div class="sec-hdr"><div class="sec-title">Real-Time Bandwidth</div>
    <span style="font-size:10px;color:var(--muted)" id="bw-note"></span></div>
  <div id="bw-summary"></div>
  <div id="graphs-content"></div>
</div>

<!-- ACTIVITIES -->
<div class="panel" id="panel-activities">

  <!-- Toolbar -->
  <div class="sec-hdr">
    <div class="sec-title">📊 Activities — Real-Time Device Traffic</div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" onclick="actRefreshAll()">↻ Refresh All</button>
    </div>
  </div>

  <!-- Device selector grid -->
  <div id="act-device-grid" style="display:flex;flex-wrap:wrap;gap:7px;margin-bottom:16px"></div>

  <!-- Main results area -->
  <div id="act-results">
    <div style="color:var(--muted);text-align:center;padding:40px;font-size:13px">
      Click a device above to view real-time activity details.<br>
      <span style="font-size:11px;margin-top:6px;display:block">
        Shows: sites visited · endpoints · connections · request graph
      </span>
    </div>
  </div>

</div>

<!-- ACTIVITY POPUP MODAL — EtherApe-style dark UI -->
<div id="act-overlay" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;
     background:rgba(0,0,0,.7);z-index:10000;overflow:hidden;
     align-items:center;justify-content:center">
  <div id="act-popup" style="width:95vw;height:92vh;background:#1a1d23;border:1px solid #333;
       border-radius:6px;display:flex;flex-direction:column;overflow:hidden;font-family:'Segoe UI',sans-serif;
       box-shadow:0 8px 32px rgba(0,0,0,.6)">

      <!-- Title bar -->
      <div id="act-titlebar" style="display:flex;align-items:center;justify-content:center;
           background:#1e2128;padding:6px 12px;border-bottom:1px solid #333;position:relative;
           -webkit-user-select:none;user-select:none">
        <div style="font-size:12px;font-weight:600;color:#e0e0e0;text-align:center" id="act-popup-title">
          Device Activity</div>
        <div onclick="actClosePopup()" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);
             width:24px;height:24px;display:flex;align-items:center;justify-content:center;
             border-radius:4px;cursor:pointer;color:#ff4444;font-size:14px;font-weight:700;
             background:rgba(255,68,68,.1);border:1px solid rgba(255,68,68,.3)"
             onmouseover="this.style.background='rgba(255,68,68,.25)'"
             onmouseout="this.style.background='rgba(255,68,68,.1)'">✕</div>
      </div>

      <!-- Toolbar -->
      <div style="display:flex;align-items:center;gap:2px;background:#1e2128;
           padding:4px 8px;border-bottom:1px solid #333">
        <div class="act-tb-btn" onclick="actToolbarAction('start')" title="Start capture">
          <div style="font-size:14px">▶</div><div style="font-size:8px;color:#aaa">Start</div></div>
        <div class="act-tb-btn" onclick="actToolbarAction('next')" title="Next packet">
          <div style="font-size:14px">⏭</div><div style="font-size:8px;color:#aaa">Next</div></div>
        <div class="act-tb-btn" onclick="actToolbarAction('pause')" title="Pause">
          <div style="font-size:14px">⏸</div><div style="font-size:8px;color:#aaa">Pause</div></div>
        <div class="act-tb-btn" onclick="actToolbarAction('stop')" title="Stop">
          <div style="font-size:14px">⏹</div><div style="font-size:8px;color:#aaa">Stop</div></div>
        <div style="width:1px;height:24px;background:#444;margin:0 4px"></div>
        <div class="act-tb-btn" onclick="actToolbarAction('nodes')" title="Nodes">
          <div style="font-size:14px">◉</div><div style="font-size:8px;color:#aaa">Nodes</div></div>
        <div style="flex:1"></div>
        <div style="font-size:10px;color:#888;font-family:'JetBrains Mono',monospace" id="act-popup-sub"></div>
      </div>

      <!-- Main area: sidebar + canvas -->
      <div style="display:flex;flex:1;min-height:0;overflow:hidden">
        <!-- Left sidebar: Protocols -->
        <div style="width:160px;min-width:160px;background:#181b21;border-right:1px solid #333;
             display:flex;flex-direction:column;overflow:hidden;flex-shrink:0">
          <div style="padding:6px 8px;font-size:10px;font-weight:700;color:#aaa;
               border-bottom:1px solid #333;text-transform:uppercase;letter-spacing:.5px">
            Protocols</div>
          <div id="act-proto-list" style="flex:1;overflow-y:auto;padding:4px 0"></div>
        </div>

        <!-- Main canvas -->
        <div style="flex:1;position:relative;background:#0a0c10;overflow:hidden;min-width:0">
          <canvas id="act-canvas" style="position:absolute;top:0;left:0;width:100%;height:100%;max-height:none;cursor:grab;z-index:1"></canvas>
          <!-- Node tooltip -->
          <div id="act-tip" style="position:absolute;pointer-events:none;display:none;
               background:var(--bg3);border:1px solid var(--border);border-radius:9px;
               padding:11px 15px;font-size:11px;min-width:220px;max-width:300px;
               z-index:20;box-shadow:0 6px 28px rgba(0,0,0,.7)"></div>
          <!-- Zoom controls -->
          <div style="position:absolute;bottom:12px;right:12px;display:flex;flex-direction:column;gap:4px;z-index:10">
            <div onclick="actZoomIn()" style="width:30px;height:30px;display:flex;align-items:center;justify-content:center;
                 background:rgba(20,22,28,.9);border:1px solid #444;border-radius:4px;cursor:pointer;
                 color:#ccc;font-size:16px;font-weight:700" title="Zoom In"
                 onmouseover="this.style.borderColor='var(--accent)';this.style.color='#fff'"
                 onmouseout="this.style.borderColor='#444';this.style.color='#ccc'">+</div>
            <div onclick="actZoomReset()" style="width:30px;height:30px;display:flex;align-items:center;justify-content:center;
                 background:rgba(20,22,28,.9);border:1px solid #444;border-radius:4px;cursor:pointer;
                 color:#ccc;font-size:10px;font-weight:600" title="Reset Zoom"
                 onmouseover="this.style.borderColor='var(--accent)';this.style.color='#fff'"
                 onmouseout="this.style.borderColor='#444';this.style.color='#ccc'">⊙</div>
            <div onclick="actZoomOut()" style="width:30px;height:30px;display:flex;align-items:center;justify-content:center;
                 background:rgba(20,22,28,.9);border:1px solid #444;border-radius:4px;cursor:pointer;
                 color:#ccc;font-size:16px;font-weight:700" title="Zoom Out"
                 onmouseover="this.style.borderColor='var(--accent)';this.style.color='#fff'"
                 onmouseout="this.style.borderColor='#444';this.style.color='#ccc'">−</div>
          </div>
          <!-- Zoom level indicator -->
          <div id="act-zoom-label" style="position:absolute;bottom:12px;left:12px;
               background:rgba(20,22,28,.85);border:1px solid #333;border-radius:4px;
               padding:3px 8px;font-size:10px;color:#888;font-family:'JetBrains Mono',monospace;z-index:10">
            100%
          </div>
          <!-- Overlay info -->
          <div id="act-canvas-info" style="position:absolute;top:8px;right:8px;
               background:rgba(20,22,28,.85);border:1px solid #333;border-radius:4px;
               padding:8px 10px;font-size:10px;color:#aaa;display:none;min-width:140px">
          </div>
          <!-- Live packet flash -->
          <div id="act-pkt-flash" style="position:absolute;top:8px;left:8px;
               background:rgba(0,229,255,.15);border:1px solid rgba(0,229,255,.3);border-radius:4px;
               padding:4px 10px;font-size:11px;color:var(--accent);font-family:'JetBrains Mono',monospace;
               display:none;z-index:10;transition:opacity .3s">
          </div>
        </div>

        <!-- Right column: overview-style traffic graph + VoIP capture -->
        <div style="width:310px;min-width:310px;background:#181b21;border-left:1px solid #333;
             display:flex;flex-direction:column;gap:8px;overflow-y:auto;padding:8px;flex-shrink:0">
          <div style="background:#14171c;border:1px solid #333;border-radius:6px;padding:8px">
            <div style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">
              Bandwidth – last 60s</div>
            <canvas id="act-bw" height="90"></canvas>
          </div>
          <div style="background:#14171c;border:1px solid #333;border-radius:6px;padding:8px">
            <div style="font-size:10px;color:#aaa;text-transform:uppercase;letter-spacing:.5px;
                 display:flex;justify-content:space-between;margin-bottom:6px">
              <span>VoIP capture</span>
              <span id="act-voip-total" class="mono" style="color:#ffd740">0 pkts</span></div>
            <div id="act-voip-counts" class="mono" style="font-size:10px;color:#8a9;
                 margin-bottom:6px;line-height:1.5">none captured yet</div>
            <div id="act-voip-list" class="mono" style="font-size:9px;color:#9aa;
                 max-height:170px;overflow-y:auto;line-height:1.5"></div>
          </div>
        </div>
      </div>

      <!-- Status bar -->
      <div style="background:#1e2128;border-top:1px solid #333;padding:3px 10px;
           font-size:10px;color:#888;display:flex;align-items:center;gap:12px">
        <span id="act-status-text">Ready</span>
        <span style="flex:1"></span>
        <span id="act-status-conn" style="color:#666"></span>
      </div>
    </div>
</div>



</main>
</div>

<!-- DEVICE MODAL -->
<div class="overlay" id="modal-overlay">
  <div class="modal">
    <div class="modal-hdr">
      <div>
        <div class="modal-title" id="modal-title">Device</div>
        <div style="font-size:11px;color:var(--muted);margin-top:2px" id="modal-sub"></div>
      </div>
      <div style="display:flex;gap:7px;align-items:center">
        <button class="btn btn-prim" onclick="rescan()">↺ Rescan</button>
        <div class="close-btn" onclick="closeModal()">✕</div>
      </div>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>

<div id="toasts"></div>

<script>
const socket = io();
const S = { devices:{}, alerts:[], stats:{}, ports:null, vulns:null, bw:null,
            detections:null, flows:[] };
let curModal = null, paused = false, pktTotal = 0, capMode = null;
const PKT = { rows:[], filter:"", voip:"", topSeq:0 };
const CACHE = { ports:0, vulns:0, bw:0, det:0 };
let modalChart = null;
let chTypes = null, chSev = null;
const devCharts = {};

// CSRF token (embedded server-side) – required on mutating API calls
const NS_AUTH = "{{ auth_token }}";
async function authFetch(url, opts = {}) {
  opts.headers = Object.assign({}, opts.headers || {}, { "X-NS-Auth": NS_AUTH });
  const r = await fetch(url, opts);
  if (r.status === 403) {
    toast({severity:"HIGH", title:"Not authorized",
           detail:"Server rejected the request token"});
    throw new Error("unauthorized");
  }
  return r;
}

// HTML-escape user/device-controlled strings before injecting into innerHTML
function esc(s){
  return String(s ?? "").replace(/[&<>"']/g, c =>
    ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

// ── Socket events ─────────────────────────────────────────────────────────
const _pendingDeviceUpdates = [];
socket.on("initial_state", d => {
  d.devices.forEach(v => S.devices[v.ip] = v);
  S.alerts = d.alerts || [];
  Object.assign(S.stats, d.stats || {});
  if (d.detections) { S.detections = d.detections; updateCapBadge(); }
  if (Array.isArray(d.flows)) S.flows = d.flows;
  renderAll();
  if (_topoInited) TOPO.onInitialState(d);
  else _pendingInitial = d;  // store for when topo inits
});
socket.on("alert_update", u => {
  const a = S.alerts.find(x => x.id === u.id);
  if (!a) return;
  a.count = u.count; a.last_ts = u.last_ts;
  const node = document.getElementById("al-" + u.id);
  if (node) {
    const card = node.querySelector(".alert-title") && node;
    if (active("alerts")) renderAlerts(); else if (card) { /* count refreshed on next paint */ }
  }
  if (active("overview")) renderOvAlerts();
});
let _pendingInitial = null;
socket.on("device_update", d => {
  S.devices[d.ip] = d;
  if (_topoInited) TOPO.onDeviceUpdate(d);
  else _pendingDeviceUpdates.push(d);  // queue until init
  if (active("devices")) renderDevices();
  if (active("overview")) renderOverview();
  if (active("graphs")) renderGraphs();
  if (active("ports")) renderPorts();
  if (active("vulns")) renderVulns();
  if (active("activities")) actRefreshDeviceGrid();
});
socket.on("new_alert", a => {
  S.alerts.unshift(a);
  S.stats.alert_count = (S.stats.alert_count||0)+1;
  badge(); toast(a);
  if (active("alerts"))   renderAlerts();
  if (active("overview")) renderOvAlerts();
  updateCounters();
});
socket.on("live_packet", p => {
  if (!paused) ingestPacket(p);
  // Activities overlay buffers packets for its own graph
  if (ACT_STATE.currentIP && !ACT_STATE.paused &&
      (p.src === ACT_STATE.currentIP || p.dst === ACT_STATE.currentIP)) {
    ACT_STATE._pktBuf.push(p);
    if (ACT_STATE._pktBuf.length > 500) ACT_STATE._pktBuf.splice(0, 100);
  }
});
socket.on("topo_packet", p => { if (_topoInited) TOPO.onTopoPacket(p); });
socket.on("traffic_update", d => {
  updateDevCharts(d);
});
socket.on("stats_update", s => {
  Object.assign(S.stats, s || {});
  updateCounters();
});
socket.on("device_removed", d => {
  if (!d || !d.ip) return;
  delete S.devices[d.ip];
  if (typeof TOPO !== "undefined" && TOPO.removeNode) TOPO.removeNode(d.ip);
  if (active("devices")) renderDevices();
  updateCounters();
});



// Detect private/LAN IP addresses (RFC1918 + link-local + loopback)
function isLanIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(isNaN)) return false;
  return (
    p[0] === 10 ||
    p[0] === 127 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254)  // link-local
  );
}

// ═══════════════════════════════════════════════════════════════════════════
//  NETWORK TOPOLOGY GRAPH  v2 – pure Canvas2D, rich SVG-path device icons
// ═══════════════════════════════════════════════════════════════════════════
const TOPO = (() => {

  // ── State ─────────────────────────────────────────────────────────────────
  let canvas, ctx, raf;
  let nodes  = {};   // ip → node object
  let edges  = {};   // "a|b" → edge object
  let pkts   = [];   // flying packet dots
  let selIP  = null;
  let traceIP = null;
  let paused = false;
  let gateway = null;
  let pktRateCtr = 0, pktRateTs = Date.now();
  // Camera
  let camX = 0, camY = 0, camZ = 1;
  let dragCam = null, dragNode = null, dragOff = {x:0,y:0};
  let mouseDownAt = null;

  // ── Colour constants ───────────────────────────────────────────────────────
  const C = {
    bg:       '#080b10',
    grid:     'rgba(26,37,53,0.45)',
    accent:   '#00e5ff',
    green:    '#00e676',
    orange:   '#ff6b35',
    red:      '#ff2d55',
    muted:    '#3d5068',
    text:     '#dde6f0',
    dimtext:  '#5a7090',
    gateway:  '#00e5ff',
  };
  const PROTO_COL = {
    TCP:'#64b5f6', UDP:'#81c784', ICMP:'#ffb74d', ICMPv6:'#4dd0e1',
    ARP:'#9e9e9e', IPv6:'#b0a8e0',
    RECV:'#ce93d8', SEND:'#00e676', OTHER:'#7c8fa8'
  };
  const PROTO_EDGE = {
    TCP:'rgba(100,181,246,', UDP:'rgba(129,200,132,',
    ICMP:'rgba(255,183,77,', ICMPv6:'rgba(77,208,225,',
    ARP:'rgba(158,158,158,', IPv6:'rgba(176,168,224,',
    RECV:'rgba(206,147,216,',
    SEND:'rgba(0,230,118,',  OTHER:'rgba(124,143,168,'
  };

  // ── Device type → category for icon selection ──────────────────────────────
  function category(dtype, isGW) {
    if (isGW) return 'router';
    const d = (dtype||'').toLowerCase();
    // \bap\b – "ap" must be a standalone word, so "laptop" doesn't match
    if (d.includes('router') || d.includes('gateway') || /\bap\b/.test(d) || d.includes('access point') || d.includes('switch')) return 'router';
    if (d.includes('iphone') || d.includes('mobile phone') || d.includes('android') || d === 'mobile') return 'phone';
    if (d.includes('ipad') || d.includes('tablet')) return 'tablet';
    if (d.includes('macbook')) return 'laptop';
    if (d.includes('laptop')) return 'laptop';
    if (d.includes('mac') && !d.includes('macbook')) return 'desktop';
    if (d.includes('pc') || d.includes('desktop') || d.includes('workstation')) return 'desktop';
    if (d.includes('server') || d.includes('nas')) return 'server';
    if (d.includes('smart tv') || d.includes('television')) return 'tv';
    if (d.includes('chromecast') || d.includes('firetv') || d.includes('streaming')) return 'tv';
    if (d.includes('printer')) return 'printer';
    if (d.includes('camera') || d.includes('ipcam') || d.includes('ip cam')) return 'camera';
    if (d.includes('playstation') || d.includes('xbox') || d.includes('nintendo') || d.includes('console') || d.includes('gaming')) return 'console';
    if (d.includes('virtual') || d.includes('vm')) return 'vm';
    if (d.includes('iot') || d.includes('sbc') || d.includes('raspberry') || d.includes('embedded')) return 'iot';
    if (d.includes('speaker') || d.includes('echo') || d.includes('home')) return 'speaker';
    if (d.includes('watch') || d.includes('wearable')) return 'watch';
    return 'unknown';
  }

  // ── Draw device icon (canvas path-based SVG-style icons) ──────────────────
  // Each icon is drawn centred on (0,0), scaled to fit radius r
  function drawIcon(cat, r, col, ctx2) {
    const s = r * 0.72; // scale factor
    ctx2.strokeStyle = col;
    ctx2.fillStyle   = col;
    ctx2.lineWidth   = Math.max(1, r * 0.1);
    ctx2.lineCap     = 'round';
    ctx2.lineJoin    = 'round';

    if (cat === 'router') {
      // Wifi/router icon: box + 3 arc waves
      const bw = s*1.0, bh = s*0.55;
      ctx2.strokeRect(-bw/2, s*0.1, bw, bh);
      // Antenna nub
      ctx2.beginPath(); ctx2.moveTo(-s*0.15, s*0.1); ctx2.lineTo(-s*0.15, -s*0.3);
      ctx2.moveTo(s*0.15, s*0.1);  ctx2.lineTo(s*0.15, -s*0.3); ctx2.stroke();
      // Wifi arcs above
      for (let i=0; i<3; i++) {
        const ar = s*(0.28+i*0.22);
        ctx2.beginPath();
        ctx2.arc(0, -s*0.55, ar, Math.PI*1.15, Math.PI*1.85);
        ctx2.globalAlpha = 0.55 + i*0.15;
        ctx2.stroke();
      }
      ctx2.globalAlpha = 1;
      // LED dot
      ctx2.beginPath(); ctx2.arc(s*0.32, s*0.38, s*0.08, 0, Math.PI*2);
      ctx2.fill();
      return;
    }

    if (cat === 'phone') {
      // Rounded phone outline
      const pw = s*0.65, ph = s*1.1, cr = s*0.13;
      roundRect(ctx2, -pw/2, -ph/2, pw, ph, cr, false, true);
      // Home button circle
      ctx2.beginPath(); ctx2.arc(0, ph/2 - s*0.14, s*0.09, 0, Math.PI*2); ctx2.stroke();
      // Speaker slit
      ctx2.beginPath(); ctx2.moveTo(-s*0.15, -ph/2+s*0.12); ctx2.lineTo(s*0.15, -ph/2+s*0.12); ctx2.stroke();
      return;
    }

    if (cat === 'tablet') {
      const tw = s*0.95, th = s*1.15, cr = s*0.1;
      roundRect(ctx2, -tw/2, -th/2, tw, th, cr, false, true);
      // Home button
      ctx2.beginPath(); ctx2.arc(0, th/2-s*0.12, s*0.08, 0, Math.PI*2); ctx2.stroke();
      // Camera dot
      ctx2.beginPath(); ctx2.arc(0, -th/2+s*0.12, s*0.06, 0, Math.PI*2); ctx2.fill();
      return;
    }

    if (cat === 'laptop') {
      // Screen + keyboard
      const sw = s*1.1, sh = s*0.72, cr = s*0.07;
      roundRect(ctx2, -sw/2, -sh-s*0.05, sw, sh, cr, false, true);
      // Hinge base
      ctx2.beginPath(); ctx2.moveTo(-sw*0.6, -s*0.05);
      ctx2.lineTo(sw*0.6, -s*0.05); ctx2.lineTo(sw*0.7, s*0.28);
      ctx2.lineTo(-sw*0.7, s*0.28); ctx2.closePath(); ctx2.stroke();
      // Camera dot on screen
      ctx2.beginPath(); ctx2.arc(0, -sh-s*0.05+s*0.08, s*0.05, 0, Math.PI*2); ctx2.fill();
      return;
    }

    if (cat === 'desktop') {
      // Monitor
      const mw = s*1.15, mh = s*0.85, cr = s*0.07;
      roundRect(ctx2, -mw/2, -mh-s*0.05, mw, mh, cr, false, true);
      // Stand neck
      ctx2.beginPath(); ctx2.moveTo(-s*0.05,-s*0.05); ctx2.lineTo(-s*0.05,s*0.22);
      ctx2.moveTo(s*0.05,-s*0.05); ctx2.lineTo(s*0.05,s*0.22); ctx2.stroke();
      // Stand base
      ctx2.beginPath(); ctx2.moveTo(-s*0.38,s*0.22); ctx2.lineTo(s*0.38,s*0.22); ctx2.stroke();
      return;
    }

    if (cat === 'server') {
      // Stack of 3 server units
      const uw = s*1.1, uh = s*0.28, gap = s*0.06;
      for (let i=0; i<3; i++) {
        const y = -uh*1.5 - gap + i*(uh+gap);
        ctx2.strokeRect(-uw/2, y, uw, uh);
        // LED
        ctx2.beginPath(); ctx2.arc(uw/2-s*0.1, y+uh/2, s*0.05, 0, Math.PI*2); ctx2.fill();
        // Drive slot
        ctx2.strokeRect(-uw/2+s*0.1, y+uh/2-s*0.04, s*0.28, s*0.08);
      }
      return;
    }

    if (cat === 'tv') {
      // Wide TV screen
      const tw = s*1.25, th = s*0.78, cr = s*0.06;
      roundRect(ctx2, -tw/2, -th/2-s*0.1, tw, th, cr, false, true);
      // Stand
      ctx2.beginPath(); ctx2.moveTo(-s*0.22,th/2-s*0.1); ctx2.lineTo(-s*0.32,s*0.55);
      ctx2.lineTo(s*0.32,s*0.55); ctx2.lineTo(s*0.22,th/2-s*0.1); ctx2.stroke();
      // Screen glare line
      ctx2.beginPath(); ctx2.globalAlpha=0.3;
      ctx2.moveTo(-tw/2+s*0.15,-th/2-s*0.1+s*0.12); ctx2.lineTo(-tw/2+s*0.15+s*0.2,-th/2-s*0.1+s*0.12);
      ctx2.stroke(); ctx2.globalAlpha=1;
      return;
    }

    if (cat === 'printer') {
      // Printer body + paper
      ctx2.strokeRect(-s*0.55,-s*0.15,s*1.1,s*0.6);
      // Paper out top
      ctx2.strokeRect(-s*0.28,-s*0.55,s*0.56,s*0.42);
      // Paper in bottom
      ctx2.strokeRect(-s*0.18,s*0.42,s*0.36,s*0.18);
      // Button
      ctx2.beginPath(); ctx2.arc(s*0.35,s*0.15,s*0.06,0,Math.PI*2); ctx2.fill();
      return;
    }

    if (cat === 'camera') {
      // Camera body
      roundRect(ctx2, -s*0.6,-s*0.35,s*1.2,s*0.7,s*0.1,false,true);
      // Lens ring outer
      ctx2.beginPath(); ctx2.arc(0,0,s*0.28,0,Math.PI*2); ctx2.stroke();
      // Lens ring inner
      ctx2.beginPath(); ctx2.arc(0,0,s*0.15,0,Math.PI*2); ctx2.fill();
      // Flash
      ctx2.fillRect(s*0.45,-s*0.32,s*0.1,s*0.14);
      return;
    }

    if (cat === 'console') {
      // Game controller shape
      ctx2.beginPath();
      ctx2.moveTo(-s*0.55,s*0.1); ctx2.quadraticCurveTo(-s*0.7,-s*0.3,-s*0.4,-s*0.5);
      ctx2.lineTo(-s*0.1,-s*0.5); ctx2.lineTo(0,-s*0.3); ctx2.lineTo(s*0.1,-s*0.5);
      ctx2.lineTo(s*0.4,-s*0.5); ctx2.quadraticCurveTo(s*0.7,-s*0.3,s*0.55,s*0.1);
      ctx2.quadraticCurveTo(s*0.3,s*0.55,0,s*0.5);
      ctx2.quadraticCurveTo(-s*0.3,s*0.55,-s*0.55,s*0.1); ctx2.closePath(); ctx2.stroke();
      // Buttons
      ctx2.beginPath(); ctx2.arc(s*0.32,-s*0.12,s*0.07,0,Math.PI*2); ctx2.fill();
      ctx2.beginPath(); ctx2.arc(s*0.47,s*0.05,s*0.07,0,Math.PI*2); ctx2.fill();
      // D-pad cross
      ctx2.fillRect(-s*0.48,-s*0.05,s*0.26,s*0.1);
      ctx2.fillRect(-s*0.38,-s*0.15,s*0.08,s*0.3);
      return;
    }

    if (cat === 'vm') {
      // Cloud shape
      ctx2.beginPath();
      ctx2.arc(-s*0.28,-s*0.1,s*0.32,Math.PI,Math.PI*2);
      ctx2.arc( s*0.28,-s*0.1,s*0.32,Math.PI,Math.PI*2);
      ctx2.arc( s*0.12, s*0.08,s*0.22,0,Math.PI);
      ctx2.arc(-s*0.12, s*0.08,s*0.22,0,Math.PI);
      ctx2.closePath(); ctx2.stroke();
      // Gear/cog inside
      ctx2.beginPath(); ctx2.arc(0,-s*0.08,s*0.16,0,Math.PI*2); ctx2.stroke();
      return;
    }

    if (cat === 'iot') {
      // Circuit-board square with dots
      ctx2.strokeRect(-s*0.5,-s*0.5,s,s);
      // Pins
      const pins = [[-s*0.5,-s*0.2],[s*0.5,-s*0.2],[s*0.5,s*0.2],[-s*0.5,s*0.2]];
      pins.forEach(([px,py]) => {
        ctx2.beginPath(); ctx2.moveTo(px,py); ctx2.lineTo(px+(px<0?-s*0.18:s*0.18),py); ctx2.stroke();
      });
      // Chip dot
      ctx2.beginPath(); ctx2.arc(0,0,s*0.14,0,Math.PI*2); ctx2.fill();
      return;
    }

    if (cat === 'speaker') {
      // Speaker grille oval
      ctx2.beginPath(); ctx2.ellipse(0,0,s*0.45,s*0.6,0,0,Math.PI*2); ctx2.stroke();
      // Three dots for speaker grille
      [-s*0.2,0,s*0.2].forEach(dy => {
        ctx2.beginPath(); ctx2.arc(0,dy,s*0.07,0,Math.PI*2); ctx2.fill();
      });
      return;
    }

    if (cat === 'watch') {
      // Watch face
      ctx2.beginPath(); ctx2.arc(0,0,s*0.45,0,Math.PI*2); ctx2.stroke();
      // Band top/bottom
      ctx2.strokeRect(-s*0.2,-s*0.7,s*0.4,s*0.28);
      ctx2.strokeRect(-s*0.2,s*0.42,s*0.4,s*0.28);
      // Hands
      ctx2.beginPath(); ctx2.moveTo(0,0); ctx2.lineTo(0,-s*0.28); ctx2.stroke();
      ctx2.beginPath(); ctx2.moveTo(0,0); ctx2.lineTo(s*0.2,s*0.1); ctx2.stroke();
      return;
    }

    if (cat === 'internet') {
      // Globe: circle with longitude + latitude arcs
      ctx2.beginPath(); ctx2.arc(0,0,s*0.55,0,Math.PI*2); ctx2.stroke();
      // Longitude ellipse
      ctx2.beginPath(); ctx2.ellipse(0,0,s*0.28,s*0.55,0,0,Math.PI*2); ctx2.stroke();
      // Horizontal latitude line (equator)
      ctx2.beginPath(); ctx2.moveTo(-s*0.55,0); ctx2.lineTo(s*0.55,0); ctx2.stroke();
      // Upper latitude arc
      ctx2.beginPath(); ctx2.ellipse(0,-s*0.14,s*0.42,s*0.41,0,Math.PI,Math.PI*2); ctx2.stroke();
      // Lower latitude arc
      ctx2.beginPath(); ctx2.ellipse(0,s*0.14,s*0.42,s*0.41,0,0,Math.PI); ctx2.stroke();
      return;
    }

    if (cat === 'network') {
      // Network connectivity icon: 3 dots connected by lines
      const dot = s*0.16;
      const pts = [[-s*0.5,-s*0.38],[s*0.45,-s*0.5],[s*0.2,s*0.48]];
      // Connecting lines
      ctx2.beginPath();
      ctx2.moveTo(pts[0][0],pts[0][1]);
      ctx2.lineTo(pts[1][0],pts[1][1]);
      ctx2.lineTo(pts[2][0],pts[2][1]);
      ctx2.closePath();
      ctx2.globalAlpha = 0.6;
      ctx2.stroke();
      ctx2.globalAlpha = 1;
      // Nodes
      pts.forEach(([px,py]) => {
        ctx2.beginPath(); ctx2.arc(px,py,dot,0,Math.PI*2); ctx2.fill();
      });
      return;
    }

    // unknown – question mark circle
    ctx2.beginPath(); ctx2.arc(0,0,s*0.55,0,Math.PI*2); ctx2.stroke();
    ctx2.font = `bold ${Math.round(s*0.8)}px sans-serif`;
    ctx2.textAlign='center'; ctx2.textBaseline='middle';
    ctx2.fillStyle=col; ctx2.fillText('?',0,s*0.05);
  }

  function roundRect(c, x, y, w, h, r, fill, stroke) {
    c.beginPath();
    c.moveTo(x+r, y);
    c.lineTo(x+w-r, y); c.arcTo(x+w,y,x+w,y+r,r);
    c.lineTo(x+w,y+h-r); c.arcTo(x+w,y+h,x+w-r,y+h,r);
    c.lineTo(x+r,y+h); c.arcTo(x,y+h,x,y+h-r,r);
    c.lineTo(x,y+r); c.arcTo(x,y,x+r,y,r);
    c.closePath();
    if (fill) c.fill();
    if (stroke) c.stroke();
  }

  // ── Node colour by status ──────────────────────────────────────────────────
  function nodeCol(n) {
    if (n.is_gateway) return C.gateway;
    if (n.status === 'offline') return C.muted;
    if ((n.vuln_count||0) >= 3) return C.red;
    if ((n.vuln_count||0) >  0) return C.orange;
    return C.green;
  }

  // ── Init ──────────────────────────────────────────────────────────────────
  function init() {
    canvas = document.getElementById('topo-canvas');
    ctx    = canvas.getContext('2d');
    resize();
    window.addEventListener('resize', resize);
    canvas.addEventListener('mousedown',  onMD);
    canvas.addEventListener('mousemove',  onMM);
    canvas.addEventListener('mouseup',    onMU);
    canvas.addEventListener('mouseleave', onML);
    canvas.addEventListener('wheel',      onWheel, {passive:false});
    canvas.addEventListener('click',      onClick);
    canvas.addEventListener('dblclick',   onDbl);
    fetch('/api/topology').then(r=>r.json()).then(applyTopo);
    raf = requestAnimationFrame(loop);
    // Periodic refresh of topology from server
    // Refresh topology: quickly at start, then every 10s
    let _topoRefreshCount = 0;
    function _scheduledTopoRefresh() {
      fetch('/api/topology').then(r=>r.json()).then(applyTopo).catch(()=>{});
      _topoRefreshCount++;
      const delay = _topoRefreshCount < 6 ? 3000 : 10000;
      setTimeout(_scheduledTopoRefresh, delay);
    }
    setTimeout(_scheduledTopoRefresh, 2000);
  }

  function resize() {
    const wrap    = document.getElementById('topo-wrap');
    const toolbar = document.getElementById('topo-toolbar');
    const dpr     = window.devicePixelRatio || 1;
    const w       = wrap.clientWidth || (window.innerWidth - 260);
    // Fit the topo panel (toolbar + canvas) within the left sidebar height,
    // leaving a line of spacing at the top and bottom.
    const tbH   = (toolbar && toolbar.offsetHeight) || 44;
    const sidebarH = window.innerHeight - 52 - 2; // header ~52px + 2px border
    const space = 40; // combined top+bottom margin (20px each) + border 2px
    const h     = Math.max(480, (sidebarH - tbH) - space);
    canvas.style.width  = w + 'px';
    canvas.style.height = h + 'px';
    canvas.width  = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function W() { return parseFloat(canvas.style.width)  || canvas.width; }
  function H() { return parseFloat(canvas.style.height) || canvas.height; }

  // ── Topology data ─────────────────────────────────────────────────────────
  function applyTopo(data) {
    gateway = data.gateway;
    const cx = W()/2, cy = H()/2;
    // Only show devices the server actually scanned. Never show external IPs.
    // data.nodes comes from /api/topology which only includes known devices.
    const lanNodes = (data.nodes||[]).filter(d =>
      (isLanIp(d.ip) || d.is_gateway || d.ip === gateway)
    );
    // Remove nodes that are no longer in the scanned device list
    const incomingIPs = new Set(lanNodes.map(d => d.ip));
    Object.keys(nodes).forEach(ip => {
      if (ip !== gateway && !incomingIPs.has(ip)) {
        // Only remove if also not in edges (keep gateways safe)
        delete nodes[ip];
      }
    });
    // Drop edges that now reference a node that no longer exists, otherwise
    // stale edges accumulate forever across devices churn.
    Object.keys(edges).forEach(k => {
      if (!nodes[edges[k].a] || !nodes[edges[k].b]) delete edges[k];
    });

    lanNodes.forEach(d => {
      if (!nodes[d.ip]) {
        const angle = Math.random()*Math.PI*2;
        const dist  = d.is_gateway ? 0 : 110 + Math.random()*220;
        nodes[d.ip] = {
          x: cx + Math.cos(angle)*dist,
          y: cy + Math.sin(angle)*dist,
          vx:0, vy:0,
          pinned: d.is_gateway,
          phase: Math.random()*Math.PI*2,
          activity: 0,
        };
      }
      Object.assign(nodes[d.ip], d);
      nodes[d.ip].r = d.is_gateway ? 30 : 22;
    });

    (data.edges||[]).forEach(e => {
      const k = e.a+'|'+e.b;
      if (!edges[k]) edges[k] = {a:e.a, b:e.b, activity:0, count:0, bytes:0, recentBytes:0};
      // Cap count so restored topology edges don't re-inflate line thickness
      const ec = Math.min(e.count||0, 50);
      Object.assign(edges[k], {
        proto:        e.proto||'OTHER',
        count:        ec,
        bytes:        e.bytes||0,
        recentBytes:  0           // reset decay counter on topology refresh
      });
    });

    // Auto-connect every device to gateway if no edge exists yet.
    // Always use the normalised key (lexicographic order) to avoid duplicates.
    if (gateway && nodes[gateway]) {
      Object.keys(nodes).forEach(ip => {
        if (ip === gateway) return;
        const pair = [ip, gateway].sort();
        const kn   = pair[0]+'|'+pair[1];
        // Also remove any un-normalised reverse key left from older code
        const krev = pair[1]+'|'+pair[0];
        if (edges[krev] && krev !== kn) {
          edges[kn] = edges[krev];
          delete edges[krev];
        }
        if (!edges[kn]) {
          edges[kn] = {a:pair[0], b:pair[1], proto:'OTHER',
                       count:0, bytes:0, recentBytes:0, activity:0};
        }
      });
    }

    updStats();
  }

  function updStats() {
    const nc = Object.keys(nodes).length;
    const ec = Object.keys(edges).length;
    const el = document.getElementById('topo-node-count');
    if (el) el.textContent = nc+' nodes · '+ec+' edges';
  }

  // ── Physics ───────────────────────────────────────────────────────────────
  const KR=5500, KA=0.035, KC=0.004, KD=0.80, IDEAL=175;

  function physics(dt) {
    const ips = Object.keys(nodes);
    if (ips.length < 2) return;
    const cx=W()/2, cy=H()/2;

    for (let i=0;i<ips.length;i++) for (let j=i+1;j<ips.length;j++) {
      const a=nodes[ips[i]], b=nodes[ips[j]];
      const dx=b.x-a.x, dy=b.y-a.y, d2=dx*dx+dy*dy+1, d=Math.sqrt(d2);
      const f=KR/d2, fx=f*dx/d, fy=f*dy/d;
      if(!a.pinned){a.vx-=fx; a.vy-=fy;}
      if(!b.pinned){b.vx+=fx; b.vy+=fy;}
    }

    Object.values(edges).forEach(e => {
      const a=nodes[e.a], b=nodes[e.b];
      if(!a||!b) return;
      const dx=b.x-a.x, dy=b.y-a.y, d=Math.sqrt(dx*dx+dy*dy)||1;
      const f=KA*(d-IDEAL), fx=f*dx/d, fy=f*dy/d;
      if(!a.pinned){a.vx+=fx; a.vy+=fy;}
      if(!b.pinned){b.vx-=fx; b.vy-=fy;}
    });

    ips.forEach(ip => {
      const n=nodes[ip];
      if(n.pinned) return;
      n.vx+=(cx-n.x)*KC; n.vy+=(cy-n.y)*KC;
      n.vx*=KD; n.vy*=KD;
      n.x+=n.vx*dt; n.y+=n.vy*dt;
      // Boundary bounce
      const m=40;
      if(n.x<m){n.x=m;n.vx*=-0.3;}
      if(n.y<m){n.y=m;n.vy*=-0.3;}
      if(n.x>W()-m){n.x=W()-m;n.vx*=-0.3;}
      if(n.y>H()-m){n.y=H()-m;n.vy*=-0.3;}
    });
  }

  // ── Packet spawn ──────────────────────────────────────────────────────────
  function spawnPkt(src, dst, proto, bytes, key) {
    const a=nodes[src], b=nodes[dst];
    if (!a||!b) return;
    const sz  = Math.max(3, Math.min(7, 3 + Math.log2((bytes||64)/64) * 1.2));
    const ek  = key || [src,dst].sort().join('|');
    pkts.push({ax:a.x, ay:a.y, bx:b.x, by:b.y, t:0, proto, sz, key:ek});
    // Node activity pulse — capped so it never accumulates on busy links
    if(a) a.activity = Math.min(0.8, (a.activity||0) + 0.35);
    if(b) b.activity = Math.min(0.8, (b.activity||0) + 0.25);
  }

  // ── Draw frame ────────────────────────────────────────────────────────────
  function draw(now) {
    const dpr = window.devicePixelRatio || 1;
    // Reset to DPR-scaled identity (set in resize) then clear
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W(), H());

    // Dark background
    ctx.fillStyle = C.bg;
    ctx.fillRect(0, 0, W(), H());

    // Grid (in logical/screen coords, before camera transform)
    ctx.strokeStyle = C.grid;
    ctx.lineWidth   = 0.5;
    const gs = 50 * camZ;
    const ox = ((camX % gs) + gs) % gs;
    const oy = ((camY % gs) + gs) % gs;
    for (let x = ox - gs; x < W() + gs; x += gs) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H()); ctx.stroke();
    }
    for (let y = oy - gs; y < H() + gs; y += gs) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W(), y); ctx.stroke();
    }

    // Apply camera transform for world-space drawing
    ctx.save();
    ctx.translate(camX, camY);
    ctx.scale(camZ, camZ);

    const t = now/1000;

    // ── Edges ──────────────────────────────────────────────────────────────
    Object.values(edges).forEach(e => {
      const a = nodes[e.a], b = nodes[e.b];
      if (!a || !b) return;

      const act  = e.activity || 0;
      const base = PROTO_EDGE[e.proto] || PROTO_EDGE.OTHER;

      // LINE WIDTH is fixed at 2.0px (slightly thicker for readability).
      // Alpha pulses briefly when a packet travels, then returns to idle.
      const idleAlpha   = 0.30;
      const activeAlpha = Math.min(0.82, idleAlpha + act * 0.52);

      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.strokeStyle = base + activeAlpha + ')';
      ctx.lineWidth   = 2.0;                       // FIXED — never grows with traffic
      ctx.setLineDash(act > 0.10 ? [] : [5, 6]);   // solid on active, dashed at rest
      ctx.stroke();
      ctx.setLineDash([]);

      // Brief traffic-bytes label (only shown during an active burst)
      if (act > 0.55 && (e.recentBytes || 0) > 512) {
        const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
        ctx.fillStyle    = base + '0.82)';
        ctx.font         = '8px JetBrains Mono,monospace';
        ctx.textAlign    = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(fmtB(e.recentBytes), mx, my - 9);
      }

      // Decay: activity fades to 0 in ~24 frames (0.4 s at 60 fps)
      e.activity    = Math.max(0, act - 0.042);
      // recentBytes decays separately so the label disappears fast
      e.recentBytes = Math.max(0, (e.recentBytes || 0) * 0.88);
    });

    // ── Flying packets ─────────────────────────────────────────────────────
    pkts.forEach(p => {
      const x = p.ax+(p.bx-p.ax)*p.t;
      const y = p.ay+(p.by-p.ay)*p.t;
      const col = PROTO_COL[p.proto]||PROTO_COL.OTHER;
      ctx.beginPath(); ctx.arc(x,y,p.sz,0,Math.PI*2);
      ctx.fillStyle   = col;
      ctx.shadowBlur  = p.sz*2.5;
      ctx.shadowColor = col;
      ctx.fill();
    });
    ctx.shadowBlur = 0;

    // ── Nodes ──────────────────────────────────────────────────────────────
    Object.values(nodes).forEach(n => {
      const col  = nodeCol(n);
      const r    = n.r || 22;
      const act  = n.activity||0;
      const pulse= 1+0.08*Math.sin(t*2.2+n.phase);
      const rr   = r*(act>0.5?1.18:1)*pulse;

      // Outer glow
      if (n.status !== 'offline' || n.is_gateway) {
        try {
          const gr = ctx.createRadialGradient(n.x, n.y, rr*0.3, n.x, n.y, rr*2.6);
          const glowA = n.is_gateway ? 0.45 : (act > 0.3 ? 0.38 : 0.20);
          // Safe hex→rgba: always works regardless of colour format
          gr.addColorStop(0, hexToRgba(col, glowA));
          gr.addColorStop(1, 'rgba(0,0,0,0)');
          ctx.beginPath(); ctx.arc(n.x, n.y, rr*2.6, 0, Math.PI*2);
          ctx.fillStyle = gr; ctx.fill();
        } catch(e) {}
      }

      // Activity ping ring
      if(act>0.15) {
        ctx.beginPath(); ctx.arc(n.x,n.y,rr+act*16,0,Math.PI*2);
        ctx.strokeStyle=col; ctx.lineWidth=0.8; ctx.globalAlpha=act*0.45; ctx.stroke();
        ctx.globalAlpha=1;
      }

      // Node background circle
      ctx.beginPath(); ctx.arc(n.x,n.y,rr,0,Math.PI*2);
      ctx.fillStyle='rgba(10,14,20,0.93)'; ctx.fill();

      // Node border
      ctx.strokeStyle=col;
      ctx.lineWidth  = (n.ip===selIP) ? 3 : 1.8;
      ctx.stroke();

      // Selection dashed ring
      if(n.ip===selIP) {
        ctx.beginPath(); ctx.arc(n.x,n.y,rr+8,0,Math.PI*2);
        ctx.strokeStyle=C.accent; ctx.lineWidth=1.5; ctx.setLineDash([5,4]);
        ctx.stroke(); ctx.setLineDash([]);
      }

      // Device icon drawn inside node
      ctx.save();
      ctx.translate(n.x, n.y);
      const cat = category(n.device_type, n.is_gateway);
      drawIcon(cat, rr*0.72, col, ctx);
      ctx.restore();

      // IP label below node
      const fontSize = Math.max(8, Math.min(11, rr*0.42));
      ctx.font      = `bold ${fontSize}px JetBrains Mono,monospace`;
      ctx.fillStyle = col;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(n.ip, n.x, n.y+rr+5);

      // Hostname (shorter)
      if(n.hostname) {
        const hn = n.hostname.split('.')[0].substring(0,16);
        ctx.font      = `${Math.max(7,fontSize-2)}px Inter,sans-serif`;
        ctx.fillStyle = C.dimtext;
        ctx.fillText(hn, n.x, n.y+rr+5+fontSize+2);
      }

      // Vendor badge (small pill under IP)
      if(n.vendor && n.vendor!=='Unknown' && camZ>0.65) {
        const vnd = n.vendor.substring(0,10);
        const vw  = ctx.measureText(vnd).width+8;
        ctx.fillStyle='rgba(20,30,50,0.85)';
        ctx.strokeStyle='rgba(100,150,200,0.25)';
        ctx.lineWidth=0.6;
        const vy = n.y+rr+5+fontSize*2+5;
        roundRect(ctx, n.x-vw/2, vy, vw, fontSize+2, 3, true, true);
        ctx.font=`${Math.max(7,fontSize-2)}px Inter,sans-serif`;
        ctx.fillStyle='rgba(160,190,220,0.7)';
        ctx.fillText(vnd, n.x, vy+1);
      }

      // Vuln count badge (top-right corner)
      if((n.vuln_count||0)>0) {
        const bx=n.x+rr*0.72, by=n.y-rr*0.72, br=9;
        ctx.beginPath(); ctx.arc(bx,by,br,0,Math.PI*2);
        ctx.fillStyle=n.vuln_count>2?C.red:C.orange; ctx.fill();
        ctx.font='bold 8px Inter,sans-serif';
        ctx.fillStyle='#fff'; ctx.textAlign='center'; ctx.textBaseline='middle';
        ctx.fillText(n.vuln_count, bx, by);
      }

      // MAC label (shown only when zoomed in)
      if(camZ>1.4 && n.mac && n.mac!=='N/A') {
        const vy2 = n.y+rr+5+fontSize*2+fontSize+10;
        ctx.font=`7px JetBrains Mono,monospace`;
        ctx.fillStyle='rgba(100,130,160,0.55)';
        ctx.textAlign='center'; ctx.textBaseline='top';
        ctx.fillText(n.mac, n.x, vy2);
      }

      n.activity = Math.max(0, act - 0.028);
    });

    ctx.restore(); // end camera transform
  }

  // Helper: safe hex colour to rgba string
  function hexToRgba(hex, alpha) {
    hex = hex.replace('#','');
    if (hex.length === 3) hex = hex[0]+hex[0]+hex[1]+hex[1]+hex[2]+hex[2];
    const r = parseInt(hex.substring(0,2),16);
    const g = parseInt(hex.substring(2,4),16);
    const b = parseInt(hex.substring(4,6),16);
    return `rgba(${r},${g},${b},${alpha})`;
  }

  // ── Main loop ─────────────────────────────────────────────────────────────
  let lastT=0;
  function loop(now) {
    raf = requestAnimationFrame(loop);
    if(!paused) {
      const dt = Math.min(32, now-lastT)/16;
      lastT = now;
      physics(dt);
      pkts.forEach(p => p.t += 0.035);
      pkts = pkts.filter(p => p.t<1);
    }
    draw(now);
    // pkt/s
    if(now-pktRateTs>1000) {
      const el=document.getElementById('topo-pps');
      if(el) el.textContent=pktRateCtr+' pkt/s';
      pktRateCtr=0; pktRateTs=now;
    }
  }

  // ── Interaction ───────────────────────────────────────────────────────────
  function sw(x,y){return{x:(x-camX)/camZ, y:(y-camY)/camZ};}
  function hit(wx,wy){
    let best=null, bd=1e9;
    for(const [ip,n] of Object.entries(nodes)){
      const dx=n.x-wx,dy=n.y-wy,d=dx*dx+dy*dy;
      const rr=((n.r||22)+10)**2;
      if(d<rr&&d<bd){bd=d;best=ip;}
    }
    return best;
  }

  function onMD(e){
    const r=canvas.getBoundingClientRect();
    const sx=e.clientX-r.left, sy=e.clientY-r.top;
    const wp=sw(sx,sy);
    const h=hit(wp.x,wp.y);
    mouseDownAt={x:e.clientX,y:e.clientY};
    if(h){
      dragNode=h;
      dragOff={x:nodes[h].x-wp.x, y:nodes[h].y-wp.y};
      canvas.style.cursor='grabbing';
    } else {
      dragCam={sx:e.clientX,sy:e.clientY,cx:camX,cy:camY};
      canvas.style.cursor='grabbing';
    }
  }

  function onMM(e){
    const r=canvas.getBoundingClientRect();
    const sx=e.clientX-r.left, sy=e.clientY-r.top;
    const wp=sw(sx,sy);
    if(dragNode){
      nodes[dragNode].x=wp.x+dragOff.x;
      nodes[dragNode].y=wp.y+dragOff.y;
      nodes[dragNode].vx=0; nodes[dragNode].vy=0;
    } else if(dragCam){
      camX=dragCam.cx+(e.clientX-dragCam.sx);
      camY=dragCam.cy+(e.clientY-dragCam.sy);
    } else {
      const h=hit(wp.x,wp.y);
      canvas.style.cursor=h?'pointer':'grab';
      showTip(h, sx, sy);
    }
  }

  function onMU(e){ dragNode=null; dragCam=null; canvas.style.cursor='grab'; }
  function onML(e){ dragNode=null; dragCam=null; hideTip(); }

  function onWheel(e){
    e.preventDefault();
    const f=e.deltaY<0?1.12:0.89;
    const r=canvas.getBoundingClientRect();
    const mx=e.clientX-r.left, my=e.clientY-r.top;
    camX=mx+(camX-mx)*f; camY=my+(camY-my)*f;
    camZ=Math.max(0.18,Math.min(4,camZ*f));
  }

  function onClick(e){
    if(mouseDownAt){
      const dx=e.clientX-mouseDownAt.x, dy=e.clientY-mouseDownAt.y;
      if(dx*dx+dy*dy>25) return;
    }
    const r=canvas.getBoundingClientRect();
    const wp=sw(e.clientX-r.left,e.clientY-r.top);
    const h=hit(wp.x,wp.y);
    selIP=h||null;
    if(!h) closeTrace();
  }

  function onDbl(e){
    const r=canvas.getBoundingClientRect();
    const wp=sw(e.clientX-r.left,e.clientY-r.top);
    const h=hit(wp.x,wp.y);
    if(h) openTrace(h);
  }

  // ── Tooltip ───────────────────────────────────────────────────────────────
  let _tipNode=null, _tipSig=null;
  function showTip(ip, sx, sy){
    const tip=document.getElementById('topo-tip');
    if(!ip){hideTip();return;}
    const n=nodes[ip]; if(!n) return;
    // The tooltip lives in #topo-wrap, but sx/sy are canvas-relative – offset by
    // the toolbar height instead of the old hard-coded +52px guess.
    const wrap=document.getElementById('topo-wrap');
    const cv=document.getElementById('topo-canvas');
    const off=(wrap&&cv)?Math.max(0,cv.getBoundingClientRect().top-wrap.getBoundingClientRect().top):0;
    const place=()=>{ tip.style.left=(sx+16)+'px'; tip.style.top=(sy+off+12)+'px'; };
    const sig=[n.ip,n.hostname,n.vendor,n.mac,n.os,n.status,n.vuln_count,n.bytes_in,n.bytes_out].join('|');
    if(ip===_tipNode && sig===_tipSig){ place(); return; }
    _tipNode=ip; _tipSig=sig;
    const col=nodeCol(n);
    const cat=category(n.device_type,n.is_gateway);
    const catLabel={'router':'Router/AP','phone':'Mobile Phone','tablet':'Tablet',
      'laptop':'Laptop','desktop':'Desktop PC','server':'Server','tv':'Smart TV',
      'printer':'Printer','camera':'IP Camera','console':'Game Console',
      'vm':'Virtual Machine','iot':'IoT Device','speaker':'Smart Speaker',
      'watch':'Wearable','unknown':'Unknown'}[cat]||cat;
    tip.style.display='block';
    place();
    tip.innerHTML=`
      <div style="display:flex;align-items:center;gap:7px;margin-bottom:8px;border-bottom:1px solid var(--border);padding-bottom:7px">
        <div style="width:10px;height:10px;border-radius:50%;background:${col};box-shadow:0 0 6px ${col}"></div>
        <span style="font-weight:700;color:${col};font-size:12px">${esc(n.ip)}</span>
        ${n.is_gateway?'<span style="font-size:9px;color:var(--accent);border:1px solid var(--accent);border-radius:3px;padding:1px 4px">GATEWAY</span>':''}
      </div>
      <div style="display:grid;grid-template-columns:90px 1fr;gap:3px 8px;font-size:10px;line-height:1.6">
        <span style="color:var(--muted)">Type</span><span style="font-weight:600">${catLabel}</span>
        <span style="color:var(--muted)">Hostname</span><span>${esc(n.hostname||'–')}</span>
        <span style="color:var(--muted)">Vendor</span><span>${esc(n.vendor||'Unknown')}</span>
        <span style="color:var(--muted)">MAC</span><span style="font-family:'JetBrains Mono',monospace">${esc(n.mac||'–')}</span>
        <span style="color:var(--muted)">OS</span><span>${esc((n.os||'Unknown').substring(0,26))}</span>
        <span style="color:var(--muted)">Status</span><span style="color:${n.status==='online'?'#00e676':'#3d5068'}">${esc(n.status)}</span>
        <span style="color:var(--muted)">Vulns</span><span style="color:${(n.vuln_count||0)>0?'#ff2d55':'#00e676'};font-weight:700">${n.vuln_count||0}</span>
        <span style="color:var(--muted)">↓ Traffic</span><span>${fmtB(n.bytes_in||0)}</span>
        <span style="color:var(--muted)">↑ Traffic</span><span>${fmtB(n.bytes_out||0)}</span>
      </div>
      <div style="margin-top:7px;font-size:9px;color:var(--muted);border-top:1px solid var(--border);padding-top:6px">
        Click = select  ·  Double-click = packet trace  ·  Drag = move
      </div>`;
  }
  function hideTip(){
    _tipNode=null;
    const t=document.getElementById('topo-tip');
    if(t) t.style.display='none';
  }

  // ── Packet trace panel ─────────────────────────────────────────────────────
  function openTrace(ip){
    traceIP=ip; selIP=ip;
    const n=nodes[ip];
    document.getElementById('trace-title').textContent=ip;
    document.getElementById('trace-info').textContent=
      [n&&n.hostname, n&&n.vendor, n&&n.os].filter(Boolean).join(' · ').substring(0,60);
    document.getElementById('topo-trace').style.transform='translateX(0)';
    refreshTrace();
  }
  function closeTrace(){
    traceIP=null;
    const t=document.getElementById('topo-trace');
    if(t) t.style.transform='translateX(100%)';
  }
  let _traceTimer=null;
  function refreshTrace(){
    if(!traceIP) return;
    fetch('/api/packets/'+traceIP).then(r=>r.json()).then(pkts2=>{
      const el=document.getElementById('trace-list');
      if(!el) return;
      el.innerHTML=pkts2.slice(0,80).map(p=>`
        <div class="trace-row">
          <span class="tr-proto tr-${p.proto}">${p.proto}</span>
          <span style="color:var(--muted);min-width:56px">${p.ts}</span>
          <span style="color:var(--accent)">${p.src}</span>
          <span style="color:var(--muted)">→</span>
          <span style="color:#ce93d8">${p.dst}</span>
          <span style="color:var(--muted);margin-left:auto">${fmtB(p.len||0)}</span>
        </div>`).join('')||'<div style="color:var(--muted);padding:8px;font-size:10px">No packets yet.</div>';
    }).catch(()=>{});
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  function onTopoPacket(p){
    pktRateCtr++;
    // STRICT: only animate packets between nodes that the scanner already knows.
    // Never create phantom nodes from packet traffic – the graph shows only
    // devices that have been discovered by the network scan.
    const srcKnown = !!nodes[p.src];
    const dstKnown = !!nodes[p.dst];
    // If neither endpoint is a known device, ignore completely
    if (!srcKnown && !dstKnown) { updStats(); return; }
    // Remap unknown endpoint to gateway for edge accounting
    const eSrc = srcKnown ? p.src : (gateway || p.src);
    const eDst = dstKnown ? p.dst : (gateway || p.dst);
    if (eSrc === eDst) { updStats(); return; }
    // ── Normalised edge upsert — sorted key prevents duplicate a|b + b|a ───────
    const epair = [eSrc, eDst].sort();
    const ekn   = epair[0]+'|'+epair[1];
    if (!edges[ekn]) {
      edges[ekn] = {a:epair[0], b:epair[1], proto:p.proto,
                    count:0, bytes:0, recentBytes:0, activity:0};
    }
    const e = edges[ekn];

    // Accumulate bytes for tooltip; count only for stats (not width/alpha)
    e.count       = Math.min((e.count||0) + 1, 999);
    e.bytes       = (e.bytes||0) + (p.len||0);
    e.recentBytes = (e.recentBytes||0) + (p.len||0);
    e.proto       = p.proto;

    // Activity boost: rate-limited so a busy link (device↔router carries ALL
    // traffic) cannot keep activity pinned at 1.0.
    // Only boost when activity has decayed below 0.35 — produces a visible
    // flash rather than a permanently lit/thick line.
    if ((e.activity||0) < 0.35) e.activity = 0.80;

    // ── Flying dot — one dot per edge at a time ─────────────────────────────
    // On busy links every packet would spawn a dot otherwise, making the line
    // look like a thick glowing bar. Skip if a dot for this edge is in flight.
    if (!pkts.some(pt => pt.key === ekn)) {
      const src_ = srcKnown ? p.src : eSrc;
      const dst_ = dstKnown ? p.dst : eDst;
      spawnPkt(src_, dst_, p.proto, p.len||64, ekn);
    }
    // Live refresh of trace panel
    if(traceIP&&(p.src===traceIP||p.dst===traceIP)){
      clearTimeout(_traceTimer);
      _traceTimer=setTimeout(refreshTrace, 600);
    }
    updStats();
  }

  function onDeviceUpdate(d){
    if (!d || !d.ip) return;
    if (!nodes[d.ip]) {
      // New node – place it around gateway or canvas centre
      const gn  = gateway ? nodes[gateway] : null;
      const cx  = gn ? gn.x : W()/2;
      const cy  = gn ? gn.y : H()/2;
      const ang = Math.random() * Math.PI * 2;
      const dst = d.is_gateway ? 0 : 120 + Math.random()*180;
      nodes[d.ip] = {
        x: cx + Math.cos(ang)*dst, y: cy + Math.sin(ang)*dst,
        vx:0, vy:0, pinned: d.is_gateway||false,
        phase: Math.random()*Math.PI*2, activity:0,
      };
      // Add edge to gateway — use normalised key
      if (!d.is_gateway && gateway && nodes[gateway]) {
        const pair = [d.ip, gateway].sort();
        const ekn  = pair[0]+'|'+pair[1];
        if (!edges[ekn]) {
          edges[ekn] = {a:pair[0], b:pair[1], proto:'OTHER',
                        count:0, bytes:0, recentBytes:0, activity:0};
        }
      }
    }
    Object.assign(nodes[d.ip], d);
    nodes[d.ip].r = d.is_gateway ? 30 : 22;
    if (d.is_gateway && !gateway) {
      gateway = d.ip;
      nodes[d.ip].pinned = true;
      nodes[d.ip].x = W()/2;
      nodes[d.ip].y = H()/2;
    }
    updStats();
  }

  function onInitialState(data){
    // Immediately seed nodes from the device list in initial_state
    // so the graph shows devices even before the topology API fetch completes.
    // Both online and offline (disconnected) devices are seeded — offline ones
    // render dimmed/gray, and reconnect flips them back to online. The
    // /api/topology fetch (which excludes the monitoring host) finalizes the state.
    if (data && data.devices && data.devices.length > 0) {
      const synth = {
        gateway: data.stats ? data.stats.gateway : gateway,
        nodes: data.devices.map(d => ({
          ip:          d.ip,
          hostname:    d.hostname || '',
          vendor:      d.vendor || 'Unknown',
          device_type: d.device_type || 'Unknown',
          os:          d.os || 'Unknown',
          status:      d.status || 'offline',
          is_gateway:  d.is_gateway || false,
          vuln_count:  d.vuln_count || 0,
          bytes_in:    d.bytes_in || 0,
          bytes_out:   d.bytes_out || 0,
          mac:         d.mac || '',
        })),
        edges: []
      };
      if (!synth.gateway && data.stats) synth.gateway = data.stats.gateway;
      applyTopo(synth);
    }
    // Also fetch full topology (edges + confirmed data)
    fetch('/api/topology').then(r=>r.json()).then(applyTopo).catch(()=>{});
  }

  function togglePause(){
    paused=!paused;
    const b=document.getElementById('topo-pause-btn');
    if(b) b.textContent=paused?'▶ Resume':'⏸ Pause';
  }
  function reset(){
    camX=0;camY=0;camZ=1;
    const cx=W()/2,cy=H()/2;
    Object.values(nodes).forEach(n=>{
      if(n.pinned){n.x=cx;n.y=cy;return;}
      const a=Math.random()*Math.PI*2,d=110+Math.random()*200;
      n.x=cx+Math.cos(a)*d; n.y=cy+Math.sin(a)*d; n.vx=0;n.vy=0;
    });
  }
  function zoomIn() {camZ=Math.min(4,camZ*1.2);}
  function zoomOut(){camZ=Math.max(0.18,camZ*0.83);}

  function fit() {
    const ns = Object.values(nodes);
    if (!ns.length) return;
    const xs = ns.map(n=>n.x), ys = ns.map(n=>n.y);
    const minX=Math.min(...xs), maxX=Math.max(...xs);
    const minY=Math.min(...ys), maxY=Math.max(...ys);
    const pw=W(), ph=H();
    const pad=80;
    const scaleX=(pw-pad*2)/Math.max(1,maxX-minX);
    const scaleY=(ph-pad*2)/Math.max(1,maxY-minY);
    camZ=Math.max(0.18,Math.min(3,Math.min(scaleX,scaleY)));
    camX=pw/2-((minX+maxX)/2)*camZ;
    camY=ph/2-((minY+maxY)/2)*camZ;
  }

  function fmtB(b){
    if(b<1024)return b+'B';
    if(b<1048576)return(b/1024).toFixed(1)+'KB';
    return(b/1048576).toFixed(1)+'MB';
  }

  function removeNode(ip){
    if(!ip || ip === gateway) return;
    delete nodes[ip];
    Object.keys(edges).forEach(k => {
      if(edges[k].a === ip || edges[k].b === ip) delete edges[k];
    });
    updStats();
  }

  return {init,onTopoPacket,onDeviceUpdate,onInitialState,removeNode,
          togglePause,reset,zoomIn,zoomOut,fit,closeTrace,
          category,drawIcon,roundRect,hexToRgba,nodeCol,fmtB};
})();

function topoTogglePause(){TOPO.togglePause();}
function topoReset()      {TOPO.reset();}
function topoZoomIn()     {TOPO.zoomIn();}
function topoZoomOut()    {TOPO.zoomOut();}
function topoFit()        {TOPO.fit();}
function closeTrace()     {TOPO.closeTrace();}

let _topoInited=false;
function ensureTopoInit(){
  if(!_topoInited){
    _topoInited=true;
    setTimeout(()=>{
      TOPO.init();
      // Flush any device data that arrived before the graph was ready
      setTimeout(()=>{
        if(_pendingInitial) { TOPO.onInitialState(_pendingInitial); _pendingInitial=null; }
        _pendingDeviceUpdates.forEach(d=>TOPO.onDeviceUpdate(d));
        _pendingDeviceUpdates.length=0;
      }, 150);
    }, 50);
  }
}

// ── Render ────────────────────────────────────────────────────────────────
function renderAll() {
  renderOverview(); renderDevices(); renderAlerts();
  renderVulns(); renderPorts(); renderGraphs(); updateCounters();
  loadDetections(); renderPktRows();
}

function updateCounters() {
  const devs = Object.values(S.devices);
  const online = devs.filter(d=>d.status==="online").length;
  const vulns  = devs.reduce((s,d)=>s+(d.vuln_count||0),0);
  const ports  = devs.reduce((s,d)=>s+Object.keys(d.open_ports||{}).length,0);
  ["s-dev","ov-dev"].forEach(i=>el(i,devs.length));
  ["s-on","ov-on"].forEach(i=>el(i,online));
  el("s-pps", S.stats.pps || 0);
  ["s-al","ov-al"].forEach(i=>el(i,S.stats.alert_count||0));
  el("ov-vu",vulns); el("ov-pt",ports); el("ov-sc",S.stats.scan_count||0);
  el("hdr-net",S.stats.network||""); el("hdr-gw","GW: "+(S.stats.gateway||""));
  badge();
  // Sys stats
  document.getElementById("sys-stats").innerHTML =
    `Network: <span style="color:var(--accent)">${S.stats.network||"–"}</span><br>
     Gateway: <span style="color:var(--accent2)">${S.stats.gateway||"–"}</span><br>
     Scans: <span style="color:var(--yellow)">${S.stats.scan_count||0}</span><br>
     Pkt/s: <span style="color:var(--green)">${S.stats.pps||0}</span>`;
}

function renderOverview() { updateCounters(); renderOvCharts(); renderOvAlerts(); }

function renderOvCharts() {
  const devs = Object.values(S.devices);
  const tc={}, sc={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  devs.forEach(d=>{const t=d.device_type||"Unknown";tc[t]=(tc[t]||0)+1;});
  S.alerts.forEach(a=>{if(sc[a.severity]!==undefined)sc[a.severity]++;});
  const pal=["#00e5ff","#7c4dff","#00e676","#ffd740","#ff6d00","#ff1744","#69f0ae","#ea80fc"];
  const tl=Object.keys(tc), td=tl.map(k=>tc[k]);
  if(chTypes){chTypes.data.labels=tl;chTypes.data.datasets[0].data=td;chTypes.update();}
  else chTypes=mkChart("ch-types","doughnut",tl,td,pal);
  const sl=Object.keys(sc), sd=Object.values(sc);
  const sp=["#ff2d55","#ff6b35","#ffd60a","#30d158","#636366"];
  if(chSev){chSev.data.datasets[0].data=sd;chSev.update();}
  else chSev=mkBarChart("ch-sev",sl,sd,sp);
}

function mkChart(id,type,labels,data,colors){
  return new Chart(document.getElementById(id),{
    type,data:{labels,datasets:[{data,backgroundColor:colors,borderWidth:0}]},
    options:{plugins:{legend:{labels:{color:"#8899aa",font:{size:10}}}}}
  });
}
function mkBarChart(id,labels,data,colors){
  return new Chart(document.getElementById(id),{
    type:"bar",
    data:{labels,datasets:[{data,backgroundColor:colors,borderWidth:0,borderRadius:3}]},
    options:{plugins:{legend:{display:false}},
      scales:{x:{ticks:{color:"#4a6080"},grid:{color:"#1a2535"}},
              y:{ticks:{color:"#4a6080"},grid:{color:"#1a2535"}}}}
  });
}

function renderOvAlerts(){
  document.getElementById("ov-alerts").innerHTML=
    S.alerts.slice(0,5).map(alertHtml).join("")||"<div style='color:var(--muted);padding:12px'>No alerts.</div>";
}

// Helper: is a string "empty" / "unknown"
function _isBlank(s){ return !s || s.toLowerCase()==="unknown" || s.trim()===""; }

function renderDevices() {
  const q=(document.getElementById("dev-search").value||"").toLowerCase();
  const rows=Object.values(S.devices)
    .filter(d=>!q||JSON.stringify(d).toLowerCase().includes(q))
    .sort((a,b)=>(a.ip||"").localeCompare(b.ip||"",undefined,{numeric:true}));

  document.getElementById("dev-tbody").innerHTML=rows.map(d=>{
    // ── Vendor: show IP when unknown/empty or already an IP ───────────────────
    const vendorRaw  = d.brand || d.vendor || "";
    const vendorIsIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(vendorRaw.trim());
    const vendorDisp = (!_isBlank(vendorRaw) && !vendorIsIP)
      ? `<span title="${esc(vendorRaw)}">${esc(vendorRaw.substring(0,18))}</span>`
      : `<span class="mono" style="color:var(--accent);font-size:10px">${d.ip}</span>`;

    // ── Device type: show IP when unknown/empty, no icon for IP ───────────────
    const typeRaw   = d.device_type || "";
    const typeIsIP  = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(typeRaw.trim());
    const typeBlank = _isBlank(typeRaw) || typeIsIP;
    const typeIcon  = typeBlank ? "" : dtIcon(typeRaw);
    const typeLabel = typeBlank ? d.ip : typeRaw;
    const typeDisp  = typeBlank
      ? `<span class="mono" style="color:var(--accent);font-size:10px">${d.ip}</span>`
      : `${typeIcon?typeIcon+" ":""}${esc(typeRaw)}`;

    // ── OS: resolve to exact fallback text, never show Apple icon for unknowns ──
    const osResolved = resolveOsDisplay(d.os, d.ttl);
    const osText     = osResolved.text;
    const osIcon_    = osResolved.icon;  // "" for any mixed/unknown OS
    const osAcc      = d.os_accuracy ? d.os_accuracy.replace("ARP (fast scan pending)","detecting…") : "";

    // ── Status + blocked styling ────────────────────────────────────────────
    const isBlocked  = !!(d.blocked || d.status === "blocked");
    const isOnline   = !isBlocked && d.status === "online";
    const statusDot  = isBlocked ? "dot-off" : isOnline ? "dot-on" : "dot-off";
    const statusText = isBlocked
      ? '<span style="color:var(--red);font-weight:600;font-size:10px">🚫 blocked</span>'
      : `<span style="color:${isOnline?"var(--green)":"var(--muted)"}">${esc(d.status)||"offline"}</span>`;

    return `<tr onclick="openModal('${d.ip}')"
        style="${isBlocked?"opacity:.65;background:rgba(255,45,85,.04)":""}">
      <td style="white-space:nowrap"><span class="dot ${statusDot}"></span>${statusText}</td>
      <td class="ip" style="white-space:nowrap">${d.ip}</td>
      <td class="mac-addr">${esc(d.mac)||"–"}</td>
      <td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${esc(d.hostname||"")}">${esc(d.hostname)||"–"}</td>
      <td style="white-space:nowrap">${typeDisp}</td>
      <td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${vendorDisp}</td>
      <td>
        <span class="os-badge" title="${esc(osText)}">${osIcon_?osIcon_+" ":""}${esc(osText)}</span>
        ${osAcc?`<span style="font-size:9px;color:var(--muted);display:block;margin-top:1px">${esc(osAcc)}</span>`:""}
      </td>
      <td style="text-align:center">${Object.keys(d.open_ports||{}).length}</td>
      <td style="text-align:center">${(d.vuln_count||0)>0
          ?`<span style="color:var(--red);font-weight:700">${d.vuln_count}</span>`:"0"}</td>
      <td class="mono" style="font-size:10px;color:var(--muted);white-space:nowrap">${d.ttl||"–"}</td>
      <td style="font-size:10px;color:var(--muted);white-space:nowrap">${esc((d.last_seen||"").substring(11))||""}</td>
      <td onclick="event.stopPropagation()" style="white-space:nowrap">
        ${isBlocked
          ? `<button class="tbtn" style="color:var(--green);border-color:var(--green);
               font-size:9px;padding:2px 8px;min-width:70px"
               onclick="blockDevice('${d.ip}',event)" title="Reconnect">✓ Unblock</button>`
          : `<button class="tbtn" style="color:var(--red);border-color:var(--red);
               font-size:9px;padding:2px 8px;min-width:70px"
               onclick="blockDevice('${d.ip}',event)" title="Disconnect from network">🚫 Block</button>`}
      </td>
    </tr>`;
  }).join("");
}
function filterDevs(){renderDevices();}

function alertHtml(a){
  const c=sev2col(a.severity);
  const chips=_enrichChips(a);
  const count=(a.count||1)>1?`<span class="meta-chip" style="color:var(--yellow);border-color:var(--yellow)">×${a.count}</span>`:"";
  const inc=a.incident?`<span class="meta-chip">incident ${esc(a.incident)}${a.correlated?" · correlated":""}</span>`:"";
  return `<div class="alert-card ${a.ack?'acked':''}" id="al-${esc(a.id)}">
    <div class="alert-bar" style="background:${c}"></div>
    <div style="flex:1;min-width:0">
      <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap">
        <span class="badge-sev sev-${esc(a.severity)}">${esc(a.severity)}</span>
        <span class="alert-title">${esc(a.title)}</span>${count}${inc}
      </div>
      <div class="alert-detail">${esc(a.detail)}</div>
      <div style="display:flex;gap:5px;flex-wrap:wrap;margin-top:5px">${chips}</div>
      ${a.attack?`<div class="alert-meta"><span class="meta-chip atk">${esc(a.attack)}</span></div>`:""}
      ${a.action?`<div class="alert-meta">▸ ${esc(a.action)}</div>`:""}
      <div class="alert-meta"><span class="ip">${esc(a.ip)}</span> · ${esc(a.last_ts||a.ts)}</div>
    </div>
    ${!a.ack?`<button class="ack-btn" onclick="ack('${esc(a.id)}',event)">✓ ACK</button>`
            :`<span style="font-size:9px;color:var(--muted)">ACKed</span>`}
  </div>`;
}

function _enrichChips(a){
  const e=a.enrich||{}, out=[];
  if(e.hostname) out.push(`<span class="meta-chip">${esc(e.hostname)}</span>`);
  if(e.role)     out.push(`<span class="meta-chip">role: ${esc(e.role)}</span>`);
  if(e.crit)     out.push(`<span class="meta-chip" style="color:${sev2col(e.crit)};border-color:${sev2col(e.crit)}">crit: ${esc(e.crit)}</span>`);
  if(e.vlan && e.vlan!=="unknown") out.push(`<span class="meta-chip">VLAN ${esc(e.vlan)}</span>`);
  if(e.vendor)   out.push(`<span class="meta-chip">${esc(e.vendor)}</span>`);
  if(e.geo)      out.push(`<span class="meta-chip">${esc(e.geo)}</span>`);
  if(e.ti)       out.push(`<span class="meta-chip" style="color:var(--red);border-color:var(--red)">${esc(e.ti)}</span>`);
  if(e.owner)    out.push(`<span class="meta-chip">owner: ${esc(e.owner)}</span>`);
  return out.join(" ");
}

function renderAlerts(){
  const sev   = (document.getElementById("alert-sev")||{}).value || "";
  const q     = (document.getElementById("alert-search")||{}).value || "";
  const ql    = q.toLowerCase();
  const unack = !!(document.getElementById("alert-unacked")||{}).checked;
  const rows  = S.alerts.filter(a=>{
    if(sev && a.severity!==sev) return false;
    if(unack && a.ack) return false;
    if(!ql) return true;
    return JSON.stringify([a.ip,a.title,a.detail,a.attack,a.action,a.rule,a.incident])
      .toLowerCase().includes(ql);
  });
  document.getElementById("alert-list").innerHTML=
    rows.map(alertHtml).join("")||"<div style='color:var(--muted);padding:16px'>No alerts match.</div>";
  renderDetectionCoverage();
}

// Detection coverage starts collapsed; the header is the toggle.
function toggleDetCoverage(){
  const box=document.getElementById("det-coverage");
  if(!box) return;
  const open=box.style.display!=="block";
  box.style.display=open?"block":"none";
  const c=document.getElementById("det-caret");
  if(c) c.style.transform=open?"rotate(90deg)":"";
}

function loadDetections(force){
  const now=Date.now();
  if(!force && S.detections && now-CACHE.det<15000) return;
  CACHE.det=now;
  fetch("/api/detections").then(r=>r.ok?r.json():Promise.reject(r.status))
    .then(d=>{S.detections=d; updateCapBadge(); renderDetectionCoverage();})
    .catch(()=>{});
}

function renderDetectionCoverage(){
  const box=document.getElementById("det-coverage");
  if(!box) return;
  const d=S.detections;
  if(!d){ box.innerHTML="<div style='color:var(--muted);font-size:11px'>Loading detection status…</div>"; return; }
  const cap=d.capture||{}, al=d.authlog||{};
  const head=`<div style="display:flex;gap:14px;flex-wrap:wrap;font-size:10px;margin-bottom:8px">
    <span class="meta-chip" style="color:${cap.network_wide?'var(--green)':'var(--orange)'};border-color:currentColor">
      ${cap.network_wide?'capture: scapy (network-wide)':'capture: psutil (this host only)'}</span>
    <span class="meta-chip" style="color:${al.active?'var(--green)':'var(--orange)'};border-color:currentColor">
      auth log: ${esc(al.active?al.path:al.reason||'inactive')}</span>
    <span class="meta-chip">tor exits: ${esc((d.tor||{}).status||'?')}</span>
    <span class="meta-chip">TI list: ${esc((d.ti||{}).status||'?')}</span>
    <span class="meta-chip">geolocation: ${(d.geo||{}).enabled?'on':'off'}</span>
    <span class="meta-chip">new-domain: ${esc((d.rdap||{}).status||'?')}</span>
  </div>`;
  const active=(d.rules||[]).filter(r=>r.active), inactive=(d.rules||[]).filter(r=>!r.active);
  const line=r=>`<div class="det-row">
      <span class="${r.active?'det-on':'det-off'}">${r.active?'●':'○'}</span>
      <span style="flex:1;color:var(--text)">${esc(r.title)}</span>
      <span class="meta-chip atk" style="font-size:8px">${esc(r.attack.split(' ')[0])}</span>
      <span style="font-size:9px;color:var(--muted);min-width:70px;text-align:right">${r.hits?r.hits+' hits':'0 hits'}</span>
      <span style="font-size:9px;color:${r.active?'var(--muted)':'var(--orange)'};max-width:340px;overflow:hidden;text-overflow:ellipsis" title="${esc(r.reason||'')}">${esc(r.reason||'')}</span>
    </div>`;
  el("det-note", `${active.length} active / ${(d.rules||[]).length} rules · ${inactive.length} need telemetry this process cannot read`);
  box.innerHTML=head+
    `<div style="font-size:10px;color:var(--muted);margin:6px 0 2px">Active (${active.length})</div>`+
    active.map(line).join("")+
    (inactive.length?`<div style="font-size:10px;color:var(--muted);margin:8px 0 2px">Inactive (${inactive.length}) — not counted as coverage</div>`+inactive.map(line).join(""):"");
}

function _vulnRows(){
  if(S.vulns && Array.isArray(S.vulns.vulnerabilities)) return S.vulns.vulnerabilities;
  const rows=[];
  Object.values(S.devices).forEach(d=>(d.vulnerabilities||[]).forEach(v=>rows.push({ip:d.ip,...v})));
  return rows;
}

function renderVulns(){
  paintVulns();
  const now=Date.now();
  if(now-CACHE.vulns < 4000) return;
  CACHE.vulns=now;
  fetch("/api/vulnerabilities").then(r=>r.ok?r.json():Promise.reject(r.status))
    .then(d=>{S.vulns=d; paintVulns();})
    .catch(()=>{});
}

function paintVulns(){
  const rows=_vulnRows().slice()
    .sort((a,b)=>({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[a.severity]||9)-
                 ({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[b.severity]||9));
  const counts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  rows.forEach(v=>{if(counts[v.severity]!==undefined)counts[v.severity]++;});
  const scanned=(S.vulns&&S.vulns.devices_scanned)||Object.values(S.devices).filter(d=>d.vuln_scanned).length;
  const total=(S.vulns&&S.vulns.devices_total)||Object.keys(S.devices).length;
  el("vuln-stats", `${rows.length} finding(s) on ${new Set(rows.map(r=>r.ip)).size} device(s)`+
     ` · ${scanned}/${total} device(s) scanned · `+
     Object.keys(counts).filter(k=>counts[k]).map(k=>`${k} ${counts[k]}`).join(" · "));
  document.getElementById("vuln-list").innerHTML=rows.length?rows.map(v=>`
    <div class="alert-card" style="margin-bottom:7px">
      <div class="alert-bar" style="background:${sev2col(v.severity)}"></div>
      <div style="flex:1;min-width:0">
        <div style="display:flex;gap:7px;align-items:center;flex-wrap:wrap">
          <span class="badge-sev sev-${esc(v.severity)}">${esc(v.severity)}</span>
          <strong>${esc(v.service)}</strong>
          ${v.port?`<span class="mono" style="color:var(--accent2);font-size:11px">:${v.port}</span>`:""}
          ${v.hostname?`<span class="meta-chip">${esc(v.hostname)}</span>`:""}
          ${v.device_type?`<span class="meta-chip">${esc(v.device_type)}</span>`:""}
          ${v.status && v.status!=="online"?`<span class="meta-chip" style="color:var(--muted)">${esc(v.status)}</span>`:""}
          <span class="ip" style="font-size:11px;margin-left:auto">${esc(v.ip)}</span>
        </div>
        <div class="alert-detail">${esc(v.description)}</div>
        ${v.version?`<div style="font-size:10px;color:var(--muted);margin-top:2px">ver: ${esc(v.version)}</div>`:""}
      </div>
    </div>`).join("")
    :"<div style='color:var(--muted);padding:16px'>No vulnerabilities detected yet.</div>";
}

// ── Open ports (all devices) ──────────────────────────────────────────────
function _portRows(){
  if(S.ports && Array.isArray(S.ports.ports)) return S.ports.ports;
  const rows=[];
  Object.values(S.devices).forEach(d=>{
    Object.entries(d.open_ports||{}).forEach(([p,i])=>{
      if(i.state!=="open") return;
      rows.push({ip:d.ip, hostname:d.hostname||"", vendor:d.vendor||"",
                 device_type:d.device_type||"", status:d.status||"",
                 port:parseInt(p,10), protocol:i.protocol||"tcp",
                 service:i.service||"", version:i.version||"",
                 risky: !!VPMAP[parseInt(p,10)]});
    });
  });
  return rows;
}

function renderPorts(){
  paintPorts();
  const now=Date.now();
  if(now-CACHE.ports < 4000) return;
  CACHE.ports=now;
  fetch("/api/ports").then(r=>r.ok?r.json():Promise.reject(r.status))
    .then(d=>{S.ports=d; paintPorts();})
    .catch(()=>{});
}

function paintPorts(){
  const q=((document.getElementById("port-search")||{}).value||"").toLowerCase();
  const byIp={};
  _portRows().forEach(r=>{(byIp[r.ip]=byIp[r.ip]||{...r,ports:[]}).ports.push(r);});
  const ips=Object.keys(byIp).sort((a,b)=>a.localeCompare(b,undefined,{numeric:true}));
  let shown=0, html="";
  ips.forEach(ip=>{
    const g=byIp[ip];
    const pts=g.ports.filter(r=>!q||
      String(r.port).includes(q) ||
      (r.service||"").toLowerCase().includes(q) ||
      (r.version||"").toLowerCase().includes(q) ||
      ip.includes(q) || (g.hostname||"").toLowerCase().includes(q));
    if(!pts.length) return;
    shown+=pts.length;
    const dev=S.devices[ip]||{};
    html+=`<div style="margin-bottom:18px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
        <span class="ip">${esc(ip)}</span>
        ${g.hostname?`<span class="meta-chip">${esc(g.hostname)}</span>`:""}
        <span style="color:var(--muted);font-size:10px">${esc(g.vendor||"unknown vendor")} – ${esc(g.device_type||"unknown type")}</span>
        <span class="meta-chip">${pts.length} open</span>
        <span class="os-badge" style="margin-left:auto">${(()=>{const r=resolveOsDisplay(dev.os,dev.ttl);return (r.icon?r.icon+" ":"")+r.text;})()}</span>
      </div>
      <div class="port-grid">
        ${pts.sort((a,b)=>a.port-b.port).map(r=>{
          const vp=VPMAP[r.port];
          const s=vp?vp[1]:"LOW";
          return `<div class="port-card">
            <div class="port-num">${r.port}</div>
            <div style="min-width:0">
              <div class="port-svc">${esc(r.service||"unknown")}
                <span class="badge-sev sev-${s}" style="font-size:8px">${s}</span>
                <span class="meta-chip" style="font-size:8px">${esc(r.protocol||"")}</span></div>
              <div class="port-ver">${esc(r.version||"version not identified")}</div></div></div>`;
        }).join("")}
      </div></div>`;
  });
  const total=_portRows().length;
  el("port-stats", `${shown}/${total} port entries · ${new Set(_portRows().map(r=>r.ip)).size} device(s)`);
  document.getElementById("ports-content").innerHTML=html||
    (total?"<div style='color:var(--muted);padding:16px'>No ports match the filter.</div>"
          :"<div style='color:var(--muted);padding:16px'>Scanning…</div>");
}
function filterPorts(){renderPorts();}

// ── Bandwidth ─────────────────────────────────────────────────────────────
function renderGraphs(){
  paintGraphs();
  const now=Date.now();
  if(now-CACHE.bw < 4000) return;
  CACHE.bw=now;
  fetch("/api/bandwidth").then(r=>r.ok?r.json():Promise.reject(r.status))
    .then(d=>{S.bw=d; S.flows=d.flows||[]; paintBwSummary();})
    .catch(()=>{});
}

function paintBwSummary(){
  const box=document.getElementById("bw-summary");
  if(!box) return;
  const d=S.bw;
  if(!d){ box.innerHTML="<div style='color:var(--muted);font-size:11px'>Measuring…</div>"; return; }
  const devs=(d.devices||[]).filter(x=>x.out_60||x.in_60);
  const flows=d.flows||[];
  const totOut=devs.reduce((s,x)=>s+(x.out_60||0),0);
  const totIn =devs.reduce((s,x)=>s+(x.in_60||0),0);
  const outliers=(d.devices||[]).filter(x=>x.outlier);
  el("bw-note", `window ${d.window||60}s · ${devs.length} device(s) with traffic · baselines need a few minutes of samples`);
  const stat=(lbl,val,col)=>`<div class="chart-card" style="margin:0">
      <div class="chart-lbl">${lbl}</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:20px;font-weight:700;color:${col}">${val}</div></div>`;
  let html=`<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px">
    ${stat("Outbound / 60s", fmt(totOut), "#7c4dff")}
    ${stat("Inbound / 60s",  fmt(totIn),  "var(--accent)")}
    ${stat("Above baseline", outliers.length, outliers.length?"var(--red)":"var(--green)")}
    ${stat("Largest upload", flows.length?fmt(Math.max(...flows.map(f=>f.bytes_out||0))):"–", "var(--yellow)")}
  </div>`;
  if(outliers.length){
    html+=`<div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">
      Above learned baseline</div>`+outliers.map(o=>`
      <div class="alert-card" style="margin-bottom:7px">
        <div class="alert-bar" style="background:var(--high)"></div>
        <div style="flex:1;min-width:0">
          <div style="display:flex;gap:7px;align-items:center;flex-wrap:wrap">
            <span class="badge-sev sev-HIGH">OUTLIER</span>
            <span class="ip">${esc(o.ip)}</span>
            ${o.hostname?`<span class="meta-chip">${esc(o.hostname)}</span>`:""}
            <span class="meta-chip">role: ${esc(o.role)}</span>
            <span style="font-size:11px;margin-left:auto;color:var(--high)">
              ${fmt(o.out_60)} / 60s · ${o.ratio}× baseline</span>
          </div>
          <div class="alert-detail">learned baseline ${fmt(o.baseline_out)} / 60s
            (${o.samples} sample(s)) ${o.vendor?"· "+esc(o.vendor):""}</div>
        </div></div>`).join("");
  }
  if(flows.length){
    html+=`<div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin:14px 0 6px">
      Largest live flows</div>
      <div class="ws-wrap" style="height:auto;max-height:320px">
      <table class="ws-table"><thead><tr>
        <th>Source</th><th>Destination</th><th>Proto</th><th style="text-align:right">Out</th>
        <th style="text-align:right">In</th><th style="text-align:right">Pkts</th><th>Session</th></tr></thead><tbody>`+
      flows.map(f=>`<tr>
        <td class="ws-src">${esc(f.src)}</td>
        <td class="ws-dst">${esc(f.dst)}:${f.dport}${f.domain?` <span class="meta-chip">${esc(f.domain)}</span>`:""}</td>
        <td class="pkt-${esc(f.proto)}">${esc(f.proto)}</td>
        <td class="ws-len">${fmt(f.bytes_out||0)}</td>
        <td class="ws-len">${fmt(f.bytes_in||0)}</td>
        <td class="ws-len">${f.packets||0}</td>
        <td class="ws-time">${f.first&&f.last?Math.max(0,Math.round(f.last-f.first))+"s":"–"}</td>
      </tr>`).join("")+`</tbody></table></div>`;
  } else {
    html+=`<div style='color:var(--muted);font-size:11px;padding:10px'>No flows recorded yet.</div>`;
  }
  box.innerHTML=html;
}

function paintGraphs(){
  const c=document.getElementById("graphs-content");
  if(!c) return;
  Object.values(S.devices).filter(d=>d.status==="online").forEach(d=>{
    const cid="bwc-"+d.ip.replace(/\./g,"-");
    if(!document.getElementById(cid)){
      const wrap=document.createElement("div");
      wrap.className="chart-card";
      wrap.dataset.ip=d.ip;
      wrap.innerHTML=`<div class="chart-lbl">${d.ip} – ${esc(d.vendor||d.device_type||"Device")}
        <span class="os-badge" style="margin-left:8px;font-size:9px">${(()=>{const r=resolveOsDisplay(d.os,d.ttl);return (r.icon?r.icon+" ":"")+r.text.substring(0,20);})()}</span></div>
        <canvas id="${cid}" height="70"></canvas>`;
      c.appendChild(wrap);
    }
  });
  // Drop cards (and their Chart instances) for devices that are no longer online
  c.querySelectorAll(".chart-card").forEach(w=>{
    const ip=w.dataset.ip;
    const dev=S.devices[ip];
    if(!dev || dev.status!=="online"){
      if(devCharts[ip]){ devCharts[ip].destroy(); delete devCharts[ip]; }
      w.remove();
    }
  });
}
function updateDevCharts(upd){
  Object.entries(upd.data||{}).forEach(([ip,bw])=>{
    const cid="bwc-"+ip.replace(/\./g,"-");
    const canvas=document.getElementById(cid);
    if(!canvas) return;
    if(!devCharts[ip]){
      devCharts[ip]=new Chart(canvas,{
        type:"line",
        data:{labels:[],datasets:[
          {label:"In",  data:[],borderColor:"#00e5ff",backgroundColor:"rgba(0,229,255,.07)",tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
          {label:"Out", data:[],borderColor:"#7c4dff",backgroundColor:"rgba(124,77,255,.07)",tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
        ]},
        options:{animation:false,
          plugins:{legend:{labels:{color:"#8899aa",font:{size:9}}}},
          scales:{x:{ticks:{color:"#3d5068",maxTicksLimit:6},grid:{color:"#1a2535"}},
                  y:{ticks:{color:"#3d5068"},grid:{color:"#1a2535"}}}}
      });
    }
    const ch=devCharts[ip];
    ch.data.labels.push(upd.ts);
    ch.data.datasets[0].data.push(bw.in);
    ch.data.datasets[1].data.push(bw.out);
    if(ch.data.labels.length>60){ch.data.labels.shift();ch.data.datasets.forEach(ds=>ds.data.shift());}
    ch.update("none");
  });
  // The activities popup graphs the same series for the device it has open.
  if (typeof ACT_STATE !== "undefined" && actBwChart && ACT_STATE.currentIP) {
    const bw = (upd.data||{})[ACT_STATE.currentIP];
    if (bw) {
      actBwChart.data.labels.push(upd.ts);
      actBwChart.data.datasets[0].data.push(bw.in);
      actBwChart.data.datasets[1].data.push(bw.out);
      if (actBwChart.data.labels.length > 60) {
        actBwChart.data.labels.shift();
        actBwChart.data.datasets.forEach(ds => ds.data.shift());
      }
      actBwChart.update("none");
    }
  }
}

// ── Packet table (Wireshark-style) ────────────────────────────────────────
function updateCapBadge(){
  const b=document.getElementById("cap-badge"), note=document.getElementById("cap-note");
  if(!b) return;
  const cap=S.detections && S.detections.capture;
  if(cap){
    if(cap.network_wide){
      b.textContent="🔴 Network-wide capture (root)";b.style.color="var(--green)";
      if(note) note.textContent="every TCP / UDP / ICMP / ARP frame on the interface";
    } else {
      b.textContent="🟡 This host only — run as root for network-wide";
      b.style.color="var(--yellow)";
      if(note) note.textContent=cap.reason||"";
    }
    return;
  }
  if(capMode==="scapy"){
    b.textContent="🔴 Full capture (root)";b.style.color="var(--green)";
  } else {
    b.textContent="🟡 This host only (run as root for full capture)";b.style.color="var(--yellow)";
  }
}

function _pktMatch(p){
  if(PKT.filter && p.proto!==PKT.filter) return false;
  // VoIP filter: "SIP" also selects "SIP/TLS" and "H.323" selects "H.323 RAS".
  if(PKT.voip && !String(p.voip||"").startsWith(PKT.voip)) return false;
  const q=((document.getElementById("pkt-search")||{}).value||"").toLowerCase();
  if(!q) return true;
  return (p.src||"").toLowerCase().includes(q) ||
         (p.dst||"").toLowerCase().includes(q) ||
         (p.info||"").toLowerCase().includes(q) ||
         String(p.len||"").includes(q);
}

function _pktHtml(p){
  const t=(p.ts||"").length>=19 ? p.ts.substring(11) : (p.ts||"");
  return `<tr>
    <td class="ws-no">${p.seq||""}</td>
    <td class="ws-time">${esc(t)}</td>
    <td class="ws-src">${esc(p.src||"")}</td>
    <td class="ws-dst">${esc(p.dst||"")}</td>
    <td class="pkt-${esc(String(p.voip||p.proto||"OTHER").replace(/[^A-Za-z0-9]/g,""))}" style="font-weight:700"
        title="${p.voip?esc(p.voip+" over "+(p.proto||"")):esc(p.proto||"")}">${esc(p.voip||p.proto||"")}</td>
    <td class="ws-len">${p.len||0}</td>
    <td class="ws-info" title="${esc(p.info||"")}">${esc(p.info||"")}</td>
  </tr>`;
}

function ingestPacket(p){
  if(p && p.seq){
    if(p.seq <= PKT.topSeq) return;      // socket event already seen in a poll
    PKT.topSeq = p.seq;
  }
  pktTotal++;
  PKT.rows.push(p);
  if(PKT.rows.length>2000) PKT.rows.shift();
  if(!paused && _pktMatch(p)){
    const body=document.getElementById("pkt-rows");
    if(body){
      const ph=document.getElementById("pkt-ph");
      if(ph) ph.remove();
      body.insertAdjacentHTML("afterbegin", _pktHtml(p));
      while(body.children.length>800) body.removeChild(body.lastChild);
    }
  }
  el("pkt-ctr", pktTotal.toLocaleString()+" pkts");
  if(pktTotal%50===1) updateCapBadge();
}

function renderPktRows(){
  const body=document.getElementById("pkt-rows");
  if(!body) return;
  const rows=PKT.rows.filter(_pktMatch).slice(-800).reverse();
  body.innerHTML=rows.map(_pktHtml).join("");
  if(!rows.length){
    body.innerHTML=`<tr><td colspan="7" style="color:var(--muted);padding:18px;text-align:center">
      ${PKT.rows.length?"No packets match the filter.":"Waiting for traffic…"}</td></tr>`;
  }
}

function setVoipFilter(btn,voip){
  PKT.voip=voip||"";
  document.querySelectorAll(".filter-chip[data-voip]").forEach(b=>b.classList.remove("on"));
  if(btn) btn.classList.add("on");
  renderPktRows();
}

function pollVoip(){
  if(!active("traffic")) return;
  fetch("/api/voip?limit=1").then(r=>r.ok?r.json():Promise.reject(r.status)).then(d=>{
    const e=document.getElementById("voip-summary");
    if(!e) return;
    const parts=Object.entries(d.counts||{});
    // Nothing is listed until a VoIP packet has actually been captured; the
    // capture mode is named so an empty list is never mistaken for "no VoIP".
    e.textContent = parts.length
      ? "VoIP " + d.total + " pkts: " + parts.map(([k,v])=>k+" "+v).join(" · ")
      : (d.payload_available
          ? "VoIP: none captured yet"
          : "VoIP: none captured yet (RTP needs payload — run as root)");
  }).catch(()=>{});
}
setInterval(pollVoip, 5000);

function setPktFilter(btn,proto){
  PKT.filter=proto;
  document.querySelectorAll(".filter-chip[data-proto]").forEach(b=>b.classList.remove("on"));
  if(btn) btn.classList.add("on");
  renderPktRows();
}

function pollPackets(){
  if(paused || !active("traffic")) return;
  fetch(`/api/packets?limit=600&since=${PKT.topSeq}`)
    .then(r=>r.ok?r.json():Promise.reject(r.status))
    .then(d=>{(d.packets||[]).forEach(ingestPacket);})
    .catch(()=>{});
}
setInterval(pollPackets, 3000);

function clearPkts(){
  PKT.rows=[];
  const body=document.getElementById("pkt-rows");
  if(body) body.innerHTML=`<tr><td colspan="7" style="color:var(--muted);padding:18px;text-align:center">
    Cleared — waiting…</td></tr>`;
  pktTotal=0; el("pkt-ctr","0 pkts");
}
function togglePause(){
  paused=!paused;
  document.getElementById("pause-btn").textContent=paused?"▶ Resume":"⏸ Pause";
  if(!paused) renderPktRows();
}

// ── Modal ─────────────────────────────────────────────────────────────────
function openModal(ip){
  curModal=ip;
  const d=S.devices[ip];
  if(!d) return;
  document.getElementById("modal-overlay").classList.add("open");
  document.getElementById("modal-title").textContent=`${dtIcon(d.device_type)} ${d.ip}`;
  document.getElementById("modal-sub").textContent=`${d.brand||d.vendor||"Unknown"} · ${d.device_type||"Unknown"} · ${d.os||"Unknown OS"}`;
  const ports=Object.entries(d.open_ports||{}).filter(([_,i])=>i.state==="open");
  const vulns=d.vulnerabilities||[];
  document.getElementById("modal-body").innerHTML=`
    <div class="detail-grid">
      ${kv("IP",d.ip)} ${kv("MAC",esc(d.mac||"N/A"))} ${kv("Hostname",esc(d.hostname||"N/A"))}
      ${kv("Vendor",esc(d.vendor||"Unknown"))} ${kv("Brand",esc(d.brand||"Unknown"))} ${kv("Type",esc(d.device_type||"Unknown"))}
      ${kv("OS",(()=>{const r=resolveOsDisplay(d.os,d.ttl);return (r.icon?r.icon+" ":"")+r.text;})())}
      ${kv("OS Accuracy",esc(d.os_accuracy||"N/A"))} ${kv("TTL",d.ttl||"N/A")}
      ${kv("Status",esc(d.status||"offline"))} ${kv("First Seen",esc(d.first_seen||"N/A"))} ${kv("Last Seen",esc(d.last_seen||"N/A"))}
      ${kv("Traffic In",fmt(d.bytes_in||0))} ${kv("Traffic Out",fmt(d.bytes_out||0))}
    </div>
    <div class="chart-card"><div class="chart-lbl">Bandwidth – last 60s</div>
      <canvas id="modal-bw" height="70"></canvas></div>
    <div style="margin-bottom:14px">
      <div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:7px">
        Open Ports (${ports.length})</div>
      <div class="port-grid">
        ${ports.map(([p,i])=>`<div class="port-card">
          <div class="port-num">${p}</div>
          <div><div class="port-svc">${esc(i.service||"unknown")}</div>
          <div class="port-ver">${esc(i.version||"")}</div></div></div>`).join("")
          ||"<span style='color:var(--muted);font-size:11px'>No open ports</span>"}
      </div>
    </div>
    <div>
      <div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:7px">
        Vulnerabilities (${vulns.length})</div>
      ${vulns.map(v=>`<div class="alert-card" style="margin-bottom:7px">
        <div class="alert-bar" style="background:${sev2col(v.severity)}"></div>
        <div><div style="display:flex;gap:6px;align-items:center">
          <span class="badge-sev sev-${esc(v.severity)}">${esc(v.severity)}</span>
          <strong>${esc(v.service)}</strong>
          ${v.port?`<span class="mono" style="color:var(--accent2);font-size:11px">:${v.port}</span>`:""}
        </div>
        <div class="alert-detail">${esc(v.description)}</div></div></div>`).join("")
        ||"<span style='color:var(--low);font-size:11px'>✓ No vulnerabilities</span>"}
    </div>`;
  fetch(`/api/traffic/${ip}`).then(r=>r.json()).then(td=>{
    try{
      // Chart.js throws "Canvas is already in use" if the previous instance is
      // not destroyed before re-creating one on the same canvas.
      if (modalChart) { modalChart.destroy(); modalChart = null; }
      modalChart = new Chart(document.getElementById("modal-bw"),{
        type:"line",
        data:{labels:td.map(t=>t.ts),datasets:[
          {label:"In",  data:td.map(t=>t.in),  borderColor:"#00e5ff",backgroundColor:"rgba(0,229,255,.08)",tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
          {label:"Out", data:td.map(t=>t.out), borderColor:"#7c4dff",backgroundColor:"rgba(124,77,255,.08)",tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
        ]},
        options:{animation:false,
          plugins:{legend:{labels:{color:"#8899aa"}}},
          scales:{x:{ticks:{color:"#3d5068",maxTicksLimit:8},grid:{color:"#1a2535"}},
                  y:{ticks:{color:"#3d5068"},grid:{color:"#1a2535"}}}}
      });
    }catch(e){}
  });
}
function closeModal(){
  document.getElementById("modal-overlay").classList.remove("open");
  curModal=null;
  if(modalChart){modalChart.destroy();modalChart=null;}
}
function rescan(){
  if(!curModal) return;
  authFetch(`/api/rescan/${curModal}`, {method:"POST"}).then(r=>r.json())
    .then(d=>toast({title:"Rescan Queued",detail:d.message||"",severity:"INFO"}))
    .catch(err=>toast({title:"Rescan Failed",detail:String(err&&err.message||err),severity:"HIGH"}));
}
document.getElementById("modal-overlay").addEventListener("click",function(e){if(e.target===this)closeModal();});

// ── Alerts ────────────────────────────────────────────────────────────────
function ack(id,e){
  e.stopPropagation();
  authFetch(`/api/alerts/ack/${id}`,{method:"POST"}).then(()=>{
    const a=S.alerts.find(x=>x.id===id);if(a)a.ack=true;
    renderAlerts();renderOvAlerts();badge();
  });
}
function ackAll(){
  S.alerts.filter(a=>!a.ack).forEach(a=>{authFetch(`/api/alerts/ack/${a.id}`,{method:"POST"});a.ack=true;});
  renderAlerts();badge();
}
function badge(){
  const n=S.alerts.filter(a=>!a.ack).length;
  const b=document.getElementById("al-badge");
  b.style.display=n>0?"":"none";b.textContent=n;
  el("s-al",S.stats.alert_count||0);
}

// ── Toast ─────────────────────────────────────────────────────────────────
function toast(a){
  const c=document.getElementById("toasts");
  const d=document.createElement("div");d.className="toast";
  d.innerHTML=`<div class="toast-bar" style="background:${sev2col(a.severity||'INFO')}"></div>
    <div><div style="font-weight:600;font-size:12px">${esc(a.title||"")}</div>
    <div style="font-size:10px;color:var(--muted);margin-top:2px">${esc((a.detail||"").substring(0,80))}</div></div>`;
  c.appendChild(d);
  setTimeout(()=>{d.style.opacity="0";d.style.transform="translateX(110%)";setTimeout(()=>d.remove(),400);},5000);
}

// ── Navigation ────────────────────────────────────────────────────────────
function nav(el,name){
  document.querySelectorAll(".panel").forEach(p=>p.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n=>n.classList.remove("active"));
  document.getElementById("panel-"+name).classList.add("active");
  el.classList.add("active");
  if(name==="overview"){ensureTopoInit();}
  if(name==="graphs"){renderGraphs();}
  if(name==="ports"){renderPorts();}
  if(name==="vulns"){renderVulns();}
  if(name==="traffic"){pollPackets(); pollVoip(); updateCapBadge();}
  if(name==="alerts"){renderAlerts(); loadDetections(true);}
  if(name==="activities"){actInit();}
}

// ── INTERNET SPEED TEST ──────────────────────────────────────────────────────
// The measurement runs in a background thread on the server (it has to move
// tens of MB, 10–25 s), so the page starts it and then polls for the phase,
// the progress and the live numbers instead of blocking on one request.
let _spdPoll = null;
let _spdPollFails = 0;

const SPD_PHASES = {
  starting:        "⏳ Starting…",
  latency:         "📡 Measuring latency & jitter…",
  "speedtest-cli": "🌐 speedtest-cli: measuring download & upload…",
  download:        "⬇ Measuring download speed…",
  upload:          "⬆ Measuring upload speed…",
  done:            "✓ Complete",
  error:           "❌ Failed",
};

function updateSpeedProgress(st) {
  const pwrap = document.getElementById("spd-progress-wrap");
  const pbar  = document.getElementById("spd-progress");
  const phase = document.getElementById("spd-phase");
  if (pwrap) pwrap.style.display = "block";
  if (pbar) {
    pbar.classList.remove("indeterminate");
    pbar.style.width = Math.min(100, Math.max(0, st.progress || 0)) + "%";
  }
  if (phase) phase.textContent = SPD_PHASES[st.phase] || "⏳ Testing…";
  // live values as they are measured (muted until the run finishes)
  const live = { "spd-down": st.download_mbps, "spd-up": st.upload_mbps,
                 "spd-lat": st.latency_ms, "spd-jit": st.jitter_ms };
  for (const [id, v] of Object.entries(live)) {
    if (!v) continue;
    const e = document.getElementById(id);
    if (e) { e.textContent = Number(v).toFixed(1); e.style.color = "var(--muted)"; }
  }
}

function speedTestFailed(err) {
  clearTimeout(_spdPoll); _spdPoll = null;
  const pbar  = document.getElementById("spd-progress");
  const pwrap = document.getElementById("spd-progress-wrap");
  const btn   = document.getElementById("speed-btn");
  if (pbar)  { pbar.classList.remove("indeterminate"); pbar.style.width = "0%"; }
  if (pwrap) pwrap.style.display = "block";
  el("spd-phase", "❌ " + (err && err.message ? err.message : "test failed"));
  if (btn) { btn.disabled = false; btn.textContent = "▶ Run Test"; }
  el("spd-status", "Error");
  el("spd-emoji",  "❌");
  const statusEl = document.getElementById("spd-status");
  if (statusEl) statusEl.style.color = "var(--red)";
  const engineEl = document.getElementById("spd-engine");
  if (engineEl) { engineEl.textContent = "failed"; engineEl.style.color = "var(--red)"; }
  console.error("Speed test error:", err);
}

function pollSpeedState() {
  clearTimeout(_spdPoll);
  authFetch("/api/speedtest").then(r => r.json()).then(st => {
    _spdPollFails = 0;
    updateSpeedProgress(st);
    if (st.running) {
      const now = Date.now() / 1000;
      if (st.last_update && now - st.last_update > 70) {
        speedTestFailed(new Error("the measurement stalled"));
        return;
      }
      _spdPoll = setTimeout(pollSpeedState, 500); return;
    }
    if (st.error) { speedTestFailed(new Error(st.error)); return; }
    const d = st.result || {};
    if (!d.status || d.status === "error" ||
        (!(d.download_mbps) && !(d.upload_mbps) && !(d.latency_ms))) {
      speedTestFailed(new Error("no measurement succeeded"));
      return;
    }
    renderSpeedResult(d);
  }).catch(() => {
    // a single dropped poll must not abort a running measurement
    if (++_spdPollFails > 20) { speedTestFailed(new Error("lost contact with the server")); return; }
    _spdPoll = setTimeout(pollSpeedState, 1000);
  });
}

function renderSpeedResult(d) {
  clearTimeout(_spdPoll); _spdPoll = null;
  const pbar  = document.getElementById("spd-progress");
  const pwrap = document.getElementById("spd-progress-wrap");
  const btn   = document.getElementById("speed-btn");
  if (pbar)  { pbar.classList.remove("indeterminate"); pbar.style.width = "100%"; }
  el("spd-phase", "✓ Complete");
  setTimeout(() => { if (pwrap) pwrap.style.display = "none"; }, 1200);
  if (btn) { btn.disabled = false; btn.textContent = "↺ Run Again"; }

  const dl  = d.download_mbps || 0;
  const up  = d.upload_mbps   || 0;
  const lat = d.latency_ms    || 0;
  const jit = d.jitter_ms     || 0;

  // ── Download ──
  const dlCol = dl > 50 ? "var(--green)" : dl > 10 ? "var(--accent)" : "var(--orange)";
  el("spd-down", dl.toFixed(1));
  document.getElementById("spd-down").style.color = dlCol;
  document.getElementById("spd-down-bar").style.width = Math.min(100, (dl / 100) * 100) + "%";

  // ── Upload ──
  const upCol = up > 20 ? "var(--green)" : up > 5 ? "#7c4dff" : "var(--orange)";
  el("spd-up", up.toFixed(1));
  document.getElementById("spd-up").style.color = upCol;
  document.getElementById("spd-up-bar").style.width = Math.min(100, (up / 50) * 100) + "%";

  // ── Ping ──
  const latCol = lat < 30 ? "var(--green)" : lat < 80 ? "var(--yellow)" : "var(--red)";
  el("spd-lat", lat.toFixed(1));
  document.getElementById("spd-lat").style.color = latCol;
  // Ping bar: lower = better (invert: 200ms = 0 bar, 0ms = full bar)
  document.getElementById("spd-lat-bar").style.width = Math.min(100, Math.max(0, 100 - (lat / 200) * 100)) + "%";

  // ── Jitter ──
  const jitCol = jit < 10 ? "var(--green)" : jit < 30 ? "var(--yellow)" : "var(--red)";
  el("spd-jit", jit.toFixed(1));
  document.getElementById("spd-jit").style.color = jitCol;
  document.getElementById("spd-jit-bar").style.width = Math.min(100, Math.max(0, 100 - (jit / 50) * 100)) + "%";

  // ── Quality rating ──
  let quality, emoji, bars, qCol;
  if (dl > 50 && up > 20 && lat < 30) {
    quality = "Excellent"; emoji = "🚀"; bars = 5; qCol = "var(--green)";
  } else if (dl > 20 && up > 5 && lat < 60) {
    quality = "Good";      emoji = "✅"; bars = 4; qCol = "var(--green)";
  } else if (dl > 5 && lat < 120) {
    quality = "Fair";      emoji = "⚡"; bars = 3; qCol = "var(--yellow)";
  } else if (dl > 1) {
    quality = "Slow";      emoji = "🐢"; bars = 2; qCol = "var(--orange)";
  } else {
    quality = "Poor";      emoji = "❌"; bars = 1; qCol = "var(--red)";
  }
  el("spd-status", quality);
  el("spd-emoji",  emoji);
  const statusEl2 = document.getElementById("spd-status");
  if (statusEl2) statusEl2.style.color = qCol;

  // Signal strength bars
  const barsEl = document.getElementById("spd-bars");
  if (barsEl) {
    const heights = [16, 20, 24, 28, 32];
    barsEl.innerHTML = heights.map((h,i) =>
      `<span style="width:5px;height:${h}px;border-radius:2px;display:inline-block;
       background:${i < bars ? qCol : "var(--border)"}"></span>`
    ).join("");
  }

  // Engine badge — which method produced these numbers
  const isCli = (d.status||"").includes("speedtest-cli");
  const isProbe = isCli || (d.status||"").includes("HTTP probe");
  const engine = isCli ? "speedtest-cli ✓" :
                 isProbe ? "HTTP probe ✓" : d.status || "unknown";
  const engineEl = document.getElementById("spd-engine");
  if (engineEl) {
    engineEl.textContent = engine;
    const eCol = isCli ? "var(--green)" : isProbe ? "var(--accent)" : "var(--yellow)";
    engineEl.style.color = eCol;
    engineEl.style.borderColor = isCli ? "rgba(0,230,118,.3)" :
                                 isProbe ? "rgba(0,229,255,.3)" : "rgba(255,215,64,.3)";
    if (d.method) engineEl.title = d.method;
  }
  if (d.server) el("spd-server", "📍 " + d.server);
  if (d.isp)    el("spd-isp",    "🌐 " + d.isp);
  el("spd-ts", new Date().toLocaleTimeString());
}

function runSpeedTest() {
  const btn = document.getElementById("speed-btn");
  if (btn.disabled) return;  // already running
  btn.disabled = true;
  btn.textContent = "⏳ Testing…";

  // Reset UI
  ["spd-down","spd-up","spd-lat","spd-jit"].forEach(id => {
    const e = document.getElementById(id);
    if (e) { e.textContent = "—"; e.style.color = "var(--muted)"; }
  });
  ["spd-down-bar","spd-up-bar","spd-lat-bar","spd-jit-bar"].forEach(id => {
    const e = document.getElementById(id);
    if (e) e.style.width = "0%";
  });
  el("spd-status","Testing…"); el("spd-emoji","⏳");
  el("spd-server",""); el("spd-isp",""); el("spd-ts","");
  const statusEl = document.getElementById("spd-status");
  if (statusEl) statusEl.style.color = "var(--yellow)";

  const pwrap = document.getElementById("spd-progress-wrap");
  const pbar  = document.getElementById("spd-progress");
  if (pwrap) pwrap.style.display = "block";
  if (pbar)  { pbar.classList.remove("indeterminate"); pbar.style.width = "0%"; }
  el("spd-phase", SPD_PHASES.starting);

  // POST starts the worker thread and returns immediately (202 + state).
  _spdPollFails = 0;
  authFetch("/api/speedtest?force=1", {method:"POST"})
    .then(async r => {
      const d = await r.json().catch(() => ({}));
      if (!r.ok && r.status !== 202) throw new Error(d.error || ("HTTP " + r.status));
      if (d.error) throw new Error(d.error);
      return d;
    })
    .then(st => {
      updateSpeedProgress(st);
      pollSpeedState();
    })
    .catch(err => speedTestFailed(err));
}

// ── BLOCK / UNBLOCK DEVICE ───────────────────────────────────────────────────
function blockDevice(ip, e){
  e.stopPropagation();
  const d = S.devices[ip];
  const isBlocked = d && d.blocked;
  const url = isBlocked ? `/api/unblock/${ip}` : `/api/block/${ip}`;
  authFetch(url, {method:"POST"}).then(async r=>{
    const res = await r.json().catch(()=>({}));
    if(!r.ok || res.ok === false){
      toast({title: isBlocked?"Unblock Failed":"Block Failed",
             detail: res.error || res.message || ("HTTP "+r.status), severity:"HIGH"});
      return;          // never flip local state on a failed block
    }
    toast({title: isBlocked?"Device Unblocked":"Device Blocked",
           detail: res.message||"", severity: isBlocked?"INFO":"HIGH"});
    if(S.devices[ip]) S.devices[ip].blocked = !isBlocked;
    if(active("devices")) renderDevices();
  }).catch(err=>toast({title:"Request Failed",detail:String(err&&err.message||err),severity:"HIGH"}));
}
function active(name){return document.getElementById("panel-"+name)?.classList.contains("active");}

// ── Utils ─────────────────────────────────────────────────────────────────
function el(id,v){const e=document.getElementById(id);if(e)e.textContent=v;}
function kv(k,v){return `<div class="detail-card"><div class="detail-key">${k}</div><div class="detail-val">${v}</div></div>`;}
function fmt(b){
  b=b||0;
  if(b<1024)return b+"B";if(b<1048576)return(b/1024).toFixed(1)+"KB";
  if(b<1073741824)return(b/1048576).toFixed(1)+"MB";return(b/1073741824).toFixed(2)+"GB";
}
function sev2col(s){return{CRITICAL:"#ff2d55",HIGH:"#ff6b35",MEDIUM:"#ffd60a",LOW:"#30d158",INFO:"#636366"}[s]||"#636366";}
function dtIcon(t){
  const map={
    "Mobile/Tablet":"📱","iPhone":"📱","iPad":"📋","iPhone/iPad":"📱",
    "Mobile Phone":"📱","Android Tablet":"📋","Tablet":"📋",
    "Laptop":"💻","MacBook (Laptop)":"💻","PC/Laptop":"💻","Linux PC":"🖥","Windows PC":"🖥",
    "PC":"🖥","Desktop":"🖥","Mac":"🖥","Mac Desktop":"🖥",
    "Router/Switch":"🔀","Router/AP":"🔀","Router":"🔀","Router / Switch":"🔀",
    "IoT Device":"🔌","IoT/SBC":"🔌","IoT / SBC":"🔌",
    "Smart TV":"📺","Smart Device":"🏠","Virtual Machine":"☁","Printer":"🖨",
    "PlayStation":"🎮","Xbox":"🎮","Nintendo Switch":"🎮","Gaming Console":"🎮",
    "Wearable":"⌚","Smart Speaker":"🔊","Network Switch":"🔗",
    "Windows Server":"🖧","Server":"🖧","IP Camera":"📷","Streaming Device":"📡",
    "Windows PC (RDP)":"🖥","NAS / Server":"🖧","Apple Device":"🍎",
    "Chromecast":"📡","Echo":"🔊","FireTV":"📺","Google Home":"🏠",
    "Pixel Phone":"📱","Smart Home":"🏠",
  };
  if (!t || t.toLowerCase()==="unknown") return "";
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(t.trim())) return "";
  return map[t] || "💡";
}

function osIcon(os){
  const o = (os||"").toLowerCase().trim();
  if (!o || o==="unknown") return "";
  if (o.includes("linux / android")||o.includes("android / ios")||
      o.includes("ios / macos")||o.includes("linux / android / ios")||
      o.includes("windows / android")||o.includes("ios / network")) return "";
  if (o.includes("windows server")) return "🖧";
  if (o.includes("windows"))        return "🪟";
  if ((o==="macos"||o==="mac os"||o.startsWith("macos ")||o.startsWith("mac os "))
      &&!o.includes("android")&&!o.includes("linux")&&!o.includes("ios")) return "🍎";
  if (o.includes("ios")&&!o.includes("android")&&!o.includes("linux")&&
      !o.includes("macos")&&!o.includes("ios / macos")) return "📱";
  if (o.includes("ipados")) return "📱";
  if (o.includes("android")&&!o.includes("linux")&&!o.includes("ios")) return "🤖";
  if (o.includes("linux"))   return "🐧";
  if (o.includes("router")||o.includes("network os")) return "🔀";
  if (o.includes("smart tv")||o.includes("tizen"))    return "📺";
  if (o.includes("playstation")||o.includes("xbox")||o.includes("nintendo")) return "🎮";
  if (o.includes("embedded")||o.includes("iot")||o.includes("printer")) return "🔌";
  return "";
}

function resolveOsDisplay(os, ttl){
  const FALLBACK = "Linux / Android / iOS / macOS";
  const o  = (os||"").trim();
  const ol = o.toLowerCase();
  if (!o||ol==="unknown"||ol==="?") return {text:FALLBACK,icon:""};
  if (ol.includes("linux / android")||ol.includes("windows / android")||
      ol.includes("ios / network")||ol.includes("linux / android / ios")||
      ol.includes("android / ios")||ol.includes("linux / android / macos")||
      ol.includes("ios / macos")||ol.includes("macos / ios"))
    return {text:FALLBACK,icon:""};
  const t = parseInt(ttl)||0;
  if (t>0&&t<=64&&(ol==="unknown"||!o)) return {text:FALLBACK,icon:""};
  const icon = osIcon(o);
  return {text:o, icon};
}

// Vulnerable ports map (for badge colours in ports panel)
const VPMAP={21:["FTP","MEDIUM"],22:["SSH","LOW"],23:["Telnet","HIGH"],25:["SMTP","MEDIUM"],
  80:["HTTP","MEDIUM"],135:["RPC","HIGH"],139:["NetBIOS","HIGH"],443:["HTTPS","LOW"],
  445:["SMB","CRITICAL"],1433:["MSSQL","HIGH"],3306:["MySQL","HIGH"],3389:["RDP","HIGH"],
  5432:["PostgreSQL","HIGH"],5900:["VNC","HIGH"],6379:["Redis","CRITICAL"],
  8080:["HTTP-Alt","MEDIUM"],9200:["Elasticsearch","CRITICAL"],27017:["MongoDB","CRITICAL"]};

// Init topology graph on load (overview is default active)
window.addEventListener('load', () => setTimeout(ensureTopoInit, 200));




// ═══════════════════════════════════════════════════════════════════════════
//  ACTIVITIES  –  EtherApe-style real-time network graph per device
// ═══════════════════════════════════════════════════════════════════════════

const ACT_STATE = {
  currentIP: null,
  data: null,
  animFrame: null,
  nodes: [],
  edges: [],
  paused: false,
  protoFilter: null,
  _pktBuf: [],
  zoom: 1,
  panX: 0,
  panY: 0,
  _dragging: false,
  selectedIP: null,
  _dragNode: null,       // {id, ox, oy} for independent node dragging
  _dragStartX: 0,
  _dragStartY: 0,
  _panStartX: 0,
  _panStartY: 0,
  voip: { counts:{}, total:0, recent:[] },
};

// Protocol colors (user-specified)
const ACT_PROTO_COLORS = {
  HTTPS:          '#ff4444',
  DOMAIN:         '#4488ff',
  'UDP-UNKNOWN':  '#00e676',
  ICMP:           '#00e5ff',
  HTTP:           '#ff4444',
  POSTGRESQL:     '#ffab40',
  LOGIN:          '#e040fb',
  EXEC:           '#ffffff',
  LDAP:           '#ff6b35',
  SNMP:           '#ff6b9d',
  'MS-SQL-S':     '#90a4ae',
  SHELL:          '#40c4ff',
  REDIS:          '#90a4ae',
  POP3:           '#00e676',
  FTP:            '#ffab40',
  TELNET:         '#e040fb',
  'TCP-UNKNOWN':  '#ffffff',
  'MICROSOFT-DS': '#ff6b35',
  SMB:            '#ff80ab',
  'HTTP-ALT':     '#90a4ae',
  'MS-WBT-SERVER':'#4488ff',
  MYSQL:          '#90a4ae',
  SSH:            '#00e676',
  TCP:            '#00e5ff',
  UDP:            '#7c4dff',
  DNS:            '#ff6b35',
  ICMPv6:         '#4dd0e1',
  ARP:            '#9e9e9e',
  IPv6:           '#b0a8e0',
  OTHER:          '#90a4ae',
};

function _actColor(proto) {
  const p = (proto||'').toUpperCase();
  if (ACT_PROTO_COLORS[p]) return ACT_PROTO_COLORS[p];
  return ACT_PROTO_COLORS.OTHER;
}

// ── Device grid ──────────────────────────────────────────────────────────
function actRefreshDeviceGrid() {
  const grid = document.getElementById('act-device-grid');
  if (!grid) return;
  const devs = Object.values(S.devices)
    .filter(d => d.status !== 'offline')
    .sort((a,b)=>(a.ip||'').localeCompare(b.ip||'',undefined,{numeric:true}));

  grid.innerHTML = devs.map(d => {
    const sel = ACT_STATE.currentIP === d.ip;
    const vendor = (d.brand||d.vendor||'').toLowerCase();
    const isIP   = /^\d+\.\d+\.\d+\.\d+$/.test(vendor);
    const label  = isIP ? d.ip : (d.brand||d.vendor||d.ip);
    const bi = d.bytes_in||0, bo = d.bytes_out||0;
    return `<div onclick="actSelectDevice('${d.ip}')"
      style="cursor:pointer;padding:8px 12px;border-radius:8px;
             background:${sel?'rgba(0,229,255,.07)':'var(--bg3)'};
             border:1px solid ${sel?'var(--accent)':'var(--border)'};
             min-width:120px;transition:all .15s"
      onmouseover="this.style.borderColor='var(--accent)'"
      onmouseout="this.style.borderColor='${sel?'var(--accent)':'var(--border)'}'"
      id="act-chip-${d.ip.replace(/\./g,'-')}">
      <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--accent)">${d.ip}</div>
      <div style="font-size:9px;color:var(--muted);margin-top:1px;overflow:hidden;text-overflow:ellipsis;
                  white-space:nowrap;max-width:110px" title="${esc(label)}">${esc(label.substring(0,14))}</div>
      <div style="margin-top:5px;font-size:9px;color:var(--muted)">↑${_fmtAct(bo)} ↓${_fmtAct(bi)}</div>
    </div>`;
  }).join('');
}

function _fmtAct(b) {
  if (b > 1048576) return (b/1048576).toFixed(1)+'MB';
  if (b > 1024) return (b/1024).toFixed(1)+'KB';
  return b+'B';
}

// ── Select device ────────────────────────────────────────────────────────
function actSelectDevice(ip) {
  ACT_STATE.currentIP = ip;
  actRefreshDeviceGrid();
  actLoadPopup(ip);
}

// ── Load popup ───────────────────────────────────────────────────────────
function actLoadPopup(ip) {
  const overlay = document.getElementById('act-overlay');
  const title   = document.getElementById('act-popup-title');
  const sub     = document.getElementById('act-popup-sub');

  const dev = S.devices[ip] || {};
  title.textContent = ip;
  sub.textContent   = `${dev.hostname||''} ${dev.vendor&&dev.vendor!==ip?'· '+dev.vendor:''}`;
  overlay.style.display = 'flex';

  // Reset state
  ACT_STATE.data = null;
  ACT_STATE.paused = false;
  ACT_STATE.protoFilter = null;
  ACT_STATE._pktBuf = [];
  ACT_STATE.zoom = 1;
  ACT_STATE.panX = 0;
  ACT_STATE.panY = 0;
  ACT_STATE.selectedIP = null;
  _actHoverNode = null;
  _actHideTip();
  _actCanvasReady = false;
  _actSetStatus('Capturing traffic...');
  _actUpdateZoomLabel();
  _actBindCanvasEvents();

  // Overview-style traffic graph + VoIP capture for this device
  ACT_STATE.voip = { counts:{}, total:0, recent:[] };
  _actRenderVoip();
  _actInitBwChart(ip);
  _actSeedVoip(ip);

  fetch(`/api/activities/${ip}`).then(r=>r.json()).then(data => {
    ACT_STATE.data = data;
    _actBuildGraph(data);
    _actRenderProtoSidebar(data);
    _actDrawCanvas();
    _actSetStatus(`Live — ${data.summary?.total_requests||0} packets · ${data.summary?.unique_destinations||0} hosts`);
    document.getElementById('act-status-conn').textContent =
      `${data.connections?.length||0} flows`;
    _actStartLoop();
  }).catch(e => {
    _actSetStatus('Error: ' + e);
  });
}

// ── Overview-style bandwidth graph for this device ────────────────────────
// Same Chart.js line chart the dashboard's overview charts are built with, and
// the same datasets/colours/options as the per-device bandwidth graphs, fed by
// /api/traffic (history) and traffic_update (live).
let actBwChart = null;
function _actInitBwChart(ip) {
  const cv = document.getElementById('act-bw');
  if (!cv) return;
  if (actBwChart) { actBwChart.destroy(); actBwChart = null; }
  actBwChart = new Chart(cv, {
    type:"line",
    data:{labels:[],datasets:[
      {label:"In",  data:[],borderColor:"#00e5ff",backgroundColor:"rgba(0,229,255,.07)",tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
      {label:"Out", data:[],borderColor:"#7c4dff",backgroundColor:"rgba(124,77,255,.07)",tension:.4,fill:true,pointRadius:0,borderWidth:1.5},
    ]},
    options:{animation:false,
      plugins:{legend:{labels:{color:"#8899aa",font:{size:9}}}},
      scales:{x:{ticks:{color:"#3d5068",maxTicksLimit:6},grid:{color:"#1a2535"}},
              y:{ticks:{color:"#3d5068"},grid:{color:"#1a2535"}}}}
  });
  fetch(`/api/traffic/${ip}`).then(r=>r.json()).then(td=>{
    if (!actBwChart) return;
    // Last 60 samples, matching the window the live feed keeps.
    const win = td.slice(-60);
    actBwChart.data.labels = win.map(t=>t.ts);
    actBwChart.data.datasets[0].data = win.map(t=>t.in);
    actBwChart.data.datasets[1].data = win.map(t=>t.out);
    actBwChart.update("none");
  }).catch(()=>{});
}

// ── VoIP capture for this device ──────────────────────────────────────────
function _actVoipPkt(p) {
  const v = ACT_STATE.voip;
  if (!v || !p.voip) return;
  v.counts[p.voip] = (v.counts[p.voip]||0) + 1;
  v.total++;
  v.recent.push(p);
  if (v.recent.length > 40) v.recent.shift();
  _actRenderVoip();
}
function _actSeedVoip(ip) {
  fetch(`/api/voip?ip=${encodeURIComponent(ip)}&limit=40`).then(r=>r.ok?r.json():Promise.reject(r.status))
    .then(d=>{
      if (!ACT_STATE.voip || ACT_STATE.currentIP !== ip) return;
      // History is seeded first; live packets keep incrementing the same counters.
      ACT_STATE.voip.counts = Object.assign({}, d.counts||{}, {});
      ACT_STATE.voip.total  = d.total||0;
      ACT_STATE.voip.recent = (d.recent||[]).slice(-40);
      ACT_STATE.voip.payload_available = d.payload_available;
      _actRenderVoip();
    }).catch(()=>{});
}
function _actRenderVoip() {
  const v = ACT_STATE.voip;
  const tot = document.getElementById('act-voip-total');
  const box = document.getElementById('act-voip-counts');
  const lst = document.getElementById('act-voip-list');
  if (!v || !tot || !box || !lst) return;
  tot.textContent = v.total + ' pkts';
  const parts = Object.entries(v.counts||{}).sort((a,b)=>b[1]-a[1]);
  box.innerHTML = parts.length
    ? parts.map(([k,n])=>`<div style="display:flex;justify-content:space-between">
        <span style="color:#ffd740">${esc(k)}</span><span>${n}</span></div>`).join('')
    : '<span style="color:#666">none captured yet</span>';
  lst.innerHTML = (v.recent||[]).slice(-10).reverse().map(p=>{
    const t = (p.ts||'').length>=19 ? p.ts.substring(11,19) : (p.ts||'');
    return `<div style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
      <span style="color:#666">${esc(t)}</span>
      <span style="color:#ffd740">${esc(p.voip||'')}</span>
      ${esc((p.src||'').split('.').pop())}→${esc((p.dst||'').split('.').pop())}
      <span style="color:#666">${p.sport||''}→${p.dport||''}</span></div>`;
  }).join('');
}

// ── Close popup ──────────────────────────────────────────────────────────
function actClosePopup() {
  document.getElementById('act-overlay').style.display = 'none';
  if (actBwChart) { actBwChart.destroy(); actBwChart = null; }
  ACT_STATE.voip = { counts:{}, total:0, recent:[] };
  _actStopLoop();
  ACT_STATE.currentIP = null;
  ACT_STATE.data = null;
  ACT_STATE._pktBuf = [];
  ACT_STATE.selectedIP = null;
  _actHoverNode = null;
  _actHideTip();
  _actCanvasReady = false;
}

// ── Refresh all ──────────────────────────────────────────────────────────
function actRefreshAll() {
  actRefreshDeviceGrid();
  if (ACT_STATE.currentIP) actLoadPopup(ACT_STATE.currentIP);
}

// ── Animation loop ───────────────────────────────────────────────────────
let _actLoopRunning = false;
function _actStartLoop() {
  if (_actLoopRunning) return;
  _actLoopRunning = true;
  (function tick() {
    if (!_actLoopRunning) return;
    if (!ACT_STATE.paused && ACT_STATE._pktBuf.length) _actFlushPackets();
    _actDrawCanvas();
    ACT_STATE.animFrame = requestAnimationFrame(tick);
  })();
}
function _actStopLoop() {
  _actLoopRunning = false;
  if (ACT_STATE.animFrame) { cancelAnimationFrame(ACT_STATE.animFrame); ACT_STATE.animFrame = null; }
}

// ── Flush incoming packet buffer into graph ──────────────────────────────
function _actFlushPackets() {
  const buf = ACT_STATE._pktBuf;
  if (!buf.length) return;
  const batch = buf.splice(0, 50);
  batch.forEach(pkt => _actIngestPacket(pkt));
  if (ACT_STATE.data) {
    _actRenderProtoSidebar(ACT_STATE.data);
    _actUpdateCanvasInfo();
  }
  if (ACT_STATE.data) {
    const sum = ACT_STATE.data.summary || {};
    _actSetStatus(`Live — ${sum.total_requests||0} packets · ${sum.unique_destinations||0} hosts`);
  }
}

// ── Ingest a single live packet into the graph ───────────────────────────
function _actIngestPacket(pkt) {
  const ip = ACT_STATE.currentIP;
  if (!ip) return;
  if (pkt.src !== ip && pkt.dst !== ip) return;
  const proto = (pkt.proto||'OTHER').toUpperCase();
  // VoIP is counted whether or not a graph protocol filter is active: the VoIP
  // panel reports captured packets, not the filtered view.
  _actVoipPkt(pkt);
  if (ACT_STATE.protoFilter && proto !== ACT_STATE.protoFilter) return;

  const data = ACT_STATE.data;
  if (!data) return;

  // Update summary
  if (!data.summary) data.summary = {};
  data.summary.total_requests = (data.summary.total_requests||0) + 1;
  data.summary.total_bytes = (data.summary.total_bytes||0) + (pkt.len||0);

  // Track destination
  const remote = pkt.src === ip ? pkt.dst : pkt.src;
  if (!data._seenDests) data._seenDests = new Set();
  if (!data._seenDests.has(remote)) {
    data._seenDests.add(remote);
    data.summary.unique_destinations = (data.summary.unique_destinations||0) + 1;
  }

  // Add to connections
  if (!data.connections) data.connections = [];
  let conn = data.connections.find(c =>
    ((c.src===pkt.src&&c.dst===pkt.dst)||(c.src===pkt.dst&&c.dst===pkt.src)) && c.proto===proto);
  if (conn) {
    conn.count = (conn.count||0) + 1;
    conn.len = (conn.len||0) + (pkt.len||0);
    conn.last_ts = pkt.ts;
  } else {
    data.connections.push({
      src: pkt.src, dst: pkt.dst, proto: proto,
      count: 1, len: pkt.len||0,
      sport: pkt.sport, dport: pkt.dport,
      info: pkt.info||'', last_ts: pkt.ts,
    });
  }

  // Add to sites
  if (!data.sites_visited) data.sites_visited = [];
  let site = data.sites_visited.find(s => s.ip === remote);
  if (!site) {
    site = { ip: remote, domain: remote, count: 1, last_seen: pkt.ts };
    data.sites_visited.push(site);
  } else {
    site.count = (site.count||0) + 1;
  }

  // Ensure node exists
  let node = ACT_STATE.nodes.find(n => n.id === remote);
  if (!node) {
    const angle = Math.random() * Math.PI * 2;
    const radius = 0.22 + Math.random() * 0.12;
    const label = _actIsDomain(site.domain) ? site.domain : remote;
    node = {
      id: remote, label,
      x: 0.5 + Math.cos(angle) * radius,
      y: 0.5 + Math.sin(angle) * radius,
      size: 5, color: _actColor(proto), isLocal: false, traffic: 0,
      activity: 0, _phase: Math.random()*Math.PI*2,
      host: _actIsDomain(site.domain) ? site.domain : null,
    };
    ACT_STATE.nodes.push(node);
  }
  node.traffic += (pkt.len||0);
  node.color = _actColor(proto);
  node.activity = Math.min(0.9, (node.activity||0) + 0.35);
  if (!node.host && _actIsDomain(site.domain)) {
    node.host = site.domain;
    node.label = site.domain;
  }

  // Ensure edge exists (per protocol)
  const key = [pkt.src, pkt.dst].sort().join('→') + '|' + proto;
  let edge = ACT_STATE.edges.find(e => e._key === key);
  if (!edge) {
    edge = { src: pkt.src, dst: pkt.dst, proto: proto, count: 0, bytes: 0,
             color: _actColor(proto), _key: key, _pulse: 1 };
    ACT_STATE.edges.push(edge);
  }
  edge.count++;
  edge.bytes += (pkt.len||0);
  edge._pulse = 1;

  // Resize nodes by traffic (larger than before for readability)
  const maxTraffic = Math.max(1, ...ACT_STATE.nodes.map(n => n.traffic));
  ACT_STATE.nodes.forEach(n => {
    if (!n.isLocal) n.size = Math.max(7, Math.min(26, 7 + (n.traffic / maxTraffic) * 19));
    else n.size = 26;
  });

  // Flash packet indicator
  _actFlashPacket(pkt);
}

// ── Flash live packet indicator ──────────────────────────────────────────
function _actFlashPacket(pkt) {
  const el = document.getElementById('act-pkt-flash');
  if (!el) return;
  const proto = (pkt.proto||'?').toUpperCase();
  el.textContent = `${proto} ${pkt.len||0}B ${pkt.src} → ${pkt.dst}`;
  el.style.display = 'block';
  el.style.opacity = '1';
  clearTimeout(el._hideTimer);
  el._hideTimer = setTimeout(() => { el.style.opacity='0'; setTimeout(()=>el.style.display='none',300); }, 1500);
}

// ── Zoom controls ────────────────────────────────────────────────────────
function actZoomIn() {
  ACT_STATE.zoom = Math.min(8, ACT_STATE.zoom * 1.3);
  _actUpdateZoomLabel();
  _actDrawCanvas();
}
function actZoomOut() {
  ACT_STATE.zoom = Math.max(0.2, ACT_STATE.zoom / 1.3);
  _actUpdateZoomLabel();
  _actDrawCanvas();
}
function actZoomReset() {
  ACT_STATE.zoom = 1;
  ACT_STATE.panX = 0;
  ACT_STATE.panY = 0;
  _actUpdateZoomLabel();
  _actDrawCanvas();
}
function _actUpdateZoomLabel() {
  const el = document.getElementById('act-zoom-label');
  if (el) el.textContent = Math.round(ACT_STATE.zoom * 100) + '%';
}

// ── Canvas interaction (pan + wheel zoom) ────────────────────────────────
let _actCanvasBound = false;
function _actBindCanvasEvents() {
  if (_actCanvasBound) return;
  _actCanvasBound = true;
  const canvas = document.getElementById('act-canvas');
  if (!canvas) return;

  canvas.addEventListener('mousedown', e => {
    const r = canvas.getBoundingClientRect();
    const sx = e.clientX - r.left, sy = e.clientY - r.top;
    const id = _actHitNode(sx, sy);
    if (id) {
      // Begin independent node drag
      const node = ACT_STATE.nodes.find(n => n.id === id);
      const p = _actScreenToNode(sx, sy);
      node.forced = true;
      ACT_STATE._dragNode = { id, ox: p.x - node.x, oy: p.y - node.y };
      ACT_STATE._dragging = true;
      ACT_STATE.selectedIP = id;
      canvas.style.cursor = 'grabbing';
    } else {
      // Begin camera pan
      ACT_STATE._dragNode = null;
      ACT_STATE._dragging = true;
      ACT_STATE._dragStartX = e.clientX;
      ACT_STATE._dragStartY = e.clientY;
      ACT_STATE._panStartX = ACT_STATE.panX;
      ACT_STATE._panStartY = ACT_STATE.panY;
      canvas.style.cursor = 'grabbing';
    }
  });
  window.addEventListener('mousemove', e => {
    if (!ACT_STATE._dragging) return;
    const r = canvas.getBoundingClientRect();
    const sx = e.clientX - r.left, sy = e.clientY - r.top;
    if (ACT_STATE._dragNode) {
      // Move the dragged node independently (world coords normalized to 0..1)
      const node = ACT_STATE.nodes.find(n => n.id === ACT_STATE._dragNode.id);
      if (node) {
        const p = _actScreenToNode(sx, sy);
        node.x = Math.max(0.05, Math.min(0.95, p.x - ACT_STATE._dragNode.ox));
        node.y = Math.max(0.05, Math.min(0.95, p.y - ACT_STATE._dragNode.oy));
      }
    } else {
      ACT_STATE.panX = ACT_STATE._panStartX + (e.clientX - ACT_STATE._dragStartX) / ACT_STATE.zoom;
      ACT_STATE.panY = ACT_STATE._panStartY + (e.clientY - ACT_STATE._dragStartY) / ACT_STATE.zoom;
    }
  });
  window.addEventListener('mouseup', () => {
    if (ACT_STATE._dragNode) {
      const node = ACT_STATE.nodes.find(n => n.id === ACT_STATE._dragNode.id);
      if (node) node.forced = false;
    }
    ACT_STATE._dragging = false;
    ACT_STATE._dragNode = null;
    canvas.style.cursor = 'grab';
  });

  canvas.addEventListener('wheel', e => {
    e.preventDefault();
    ACT_STATE.zoom = Math.max(0.2, Math.min(8, ACT_STATE.zoom * (e.deltaY > 0 ? 0.9 : 1.1)));
    _actUpdateZoomLabel();
    _actDrawCanvas();
  }, { passive: false });

  // Touch pinch
  let _lastPinchDist = 0;
  canvas.addEventListener('touchstart', e => {
    if (e.touches.length === 2) {
      _lastPinchDist = Math.hypot(e.touches[0].clientX-e.touches[1].clientX, e.touches[0].clientY-e.touches[1].clientY);
    } else if (e.touches.length === 1) {
      ACT_STATE._dragging = true;
      ACT_STATE._dragStartX = e.touches[0].clientX;
      ACT_STATE._dragStartY = e.touches[0].clientY;
      ACT_STATE._panStartX = ACT_STATE.panX;
      ACT_STATE._panStartY = ACT_STATE.panY;
    }
  }, { passive: true });
  canvas.addEventListener('touchmove', e => {
    if (e.touches.length === 2) {
      const dist = Math.hypot(e.touches[0].clientX-e.touches[1].clientX, e.touches[0].clientY-e.touches[1].clientY);
      if (_lastPinchDist > 0) ACT_STATE.zoom = Math.max(0.2, Math.min(8, ACT_STATE.zoom * (dist/_lastPinchDist)));
      _lastPinchDist = dist;
      _actUpdateZoomLabel();
    } else if (e.touches.length === 1 && ACT_STATE._dragging) {
      ACT_STATE.panX = ACT_STATE._panStartX + (e.touches[0].clientX-ACT_STATE._dragStartX)/ACT_STATE.zoom;
      ACT_STATE.panY = ACT_STATE._panStartY + (e.touches[0].clientY-ACT_STATE._dragStartY)/ACT_STATE.zoom;
    }
  }, { passive: true });
  canvas.addEventListener('touchend', () => { ACT_STATE._dragging = false; _lastPinchDist = 0; }, { passive: true });

  // Click to select a node
  canvas.addEventListener('click', e => {
    if (ACT_STATE._dragging) return;
    const r = canvas.getBoundingClientRect();
    const sx = e.clientX - r.left, sy = e.clientY - r.top;
    const id = _actHitNode(sx, sy);
    ACT_STATE.selectedIP = id || null;
    if (!id) _actHideTip();
    else _actShowTip(id, sx, sy, true);
  });

  // Hover tooltip
  canvas.addEventListener('mousemove', _actOnHoverMove);
  canvas.addEventListener('mouseleave', () => { _actHoverNode = null; _actHideTip(); });
  canvas.addEventListener('mousedown', () => { _actHoverNode = null; _actHideTip(); });
}

// ── Node helpers (enrichment, hit-testing, tooltip) ──────────────────────
let _actHoverNode = null;

function _actNodeDev(id) {
  return S.devices[id] || null;
}

// True if host is a real domain name (not a bare IP address)
function _actIsDomain(host) {
  if (!host || typeof host !== 'string') return false;
  const h = host.toLowerCase();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return false;   // IPv4
  if (h.includes(':')) return false;                     // IPv6 / port
  return h.indexOf('.') > -1;                            // has at least one dot and not an IP
}

// ── Site favicon loading with cache ──────────────────────────────────────
const _actFavCache = {};   // host -> Image (or null while loading / on failure)
function _actFavIcon(host) {
  if (!host) return null;
  if (host in _actFavCache) return _actFavCache[host] || null;
  // Same-origin proxy through the app -> no CORS issues, works offline too
  const img = new Image();
  img.crossOrigin = 'anonymous';
  _actFavCache[host] = null;   // mark as "loading"
  img.onload = () => { _actFavCache[host] = img; };
  img.onerror = () => { _actFavCache[host] = null; };
  try { img.src = '/favicon/' + encodeURIComponent(host); } catch(e) {}
  return null;
}

// Classify an activity node: 'local' (the tracked device), 'network' (LAN), or 'internet' (external)
function _actNodeKind(n) {
  if (!n) return 'internet';
  if (n.isLocal || (ACT_STATE.data && n.id === ACT_STATE.data.ip)) return 'local';
  if (isLanIp(n.id)) return 'network';
  // Non-IP labels (domain names) are external → internet
  return 'internet';
}

// Choose the icon category for a node.
// Known LAN devices (in S.devices) get their real device-type icon (PC, Mobile Phone, etc.)
// so the gateway popup shows connected devices by type, not a generic icon.
// True internet destinations get a globe (or favicon), unknown LAN peers get a network icon.
function _actNodeIconCat(n, dev, kind) {
  if (dev && dev.device_type) {
    return (TOPO && TOPO.category) ? TOPO.category(dev.device_type, !!dev.is_gateway) : 'unknown';
  }
  if (kind === 'internet') return 'internet';
  if (kind === 'network') return 'network';
  if (n && n.isLocal && dev) {
    return (TOPO && TOPO.category) ? TOPO.category(dev.device_type || '', !!dev.is_gateway) : 'unknown';
  }
  return 'unknown';
}

// Convert a screen position to world node coords (nx, ny in [0,1]-ish)
function _actScreenToNode(sx, sy) {
  const canvas = document.getElementById('act-canvas');
  const container = canvas.parentElement;
  const W = container.clientWidth, H = container.clientHeight;
  const z = ACT_STATE.zoom, px = ACT_STATE.panX, py = ACT_STATE.panY;
  const wx = (sx - (W/2 + px*z)) / z + W/2;
  const wy = (sy - (H/2 + py*z)) / z + H/2;
  return { x: wx / W, y: wy / H };
}

// Hit-test: find the node under a screen point
function _actHitNode(sx, sy) {
  const p = _actScreenToNode(sx, sy);
  const nodes = ACT_STATE.nodes;
  let best = null, bd = 1e9;
  for (const n of nodes) {
    const dx = n.x - p.x, dy = n.y - p.y;
    const d = dx*dx + dy*dy;
    const rr = (n.size + 10) * (n.size + 10);
    if (d < rr && d < bd) { bd = d; best = n.id; }
  }
  return best;
}

function _actOnHoverMove(e) {
  const canvas = document.getElementById('act-canvas');
  if (!canvas) return;
  if (ACT_STATE._dragging) { _actHoverNode = null; _actHideTip(); return; }
  const r = canvas.getBoundingClientRect();
  const sx = e.clientX - r.left, sy = e.clientY - r.top;
  const id = _actHitNode(sx, sy);
  canvas.style.cursor = id ? 'pointer' : 'grab';
  if (id !== _actHoverNode) {
    _actHoverNode = id;
    canvas.style.cursor = id ? 'pointer' : 'grab';
    if (id) _actShowTip(id, sx, sy, false);
    else _actHideTip();
  }
}

let _actTipNode = null;
function _actShowTip(id, sx, sy, stay) {
  // Every device-controlled field below is escaped: values come from reverse
  // DNS, HTTP banners and vendor APIs and must never reach innerHTML raw.
  const tip = document.getElementById('act-tip');
  if (!tip) return;
  const dev = _actNodeDev(id);
  const n = (ACT_STATE.nodes||[]).find(x => x.id === id);
  const col = (dev && dev.is_gateway) ? '#00e5ff' : (n ? n.color : '#00e5ff');
  const catLabelTrans = {
    router:'Router/AP', phone:'Mobile Phone', tablet:'Tablet',
    laptop:'Laptop', desktop:'Desktop PC', server:'Server', tv:'Smart TV',
    printer:'Printer', camera:'IP Camera', console:'Game Console',
    vm:'Virtual Machine', iot:'IoT Device', speaker:'Smart Speaker',
    watch:'Wearable', internet:'Internet (External)', network:'Network Device',
    unknown:'Unknown'
  };
  const kind = _actNodeKind(n);
  let cat = _actNodeIconCat(n, dev, kind);
  const catLabel = catLabelTrans[cat] || cat;
  _actTipNode = id;
  tip.style.display = 'block';
  tip.style.left = (sx + 16) + 'px';
  tip.style.top = (sy + 16) + 'px';
  const title = (kind === 'internet' && n && n.host) ? n.host : id;
  tip.innerHTML = `
    <div style="display:flex;align-items:center;gap:7px;margin-bottom:8px;border-bottom:1px solid var(--border);padding-bottom:7px">
      <div style="width:10px;height:10px;border-radius:50%;background:${col};box-shadow:0 0 6px ${col}"></div>
      <span style="font-weight:700;color:${col};font-size:12px;font-family:'JetBrains Mono',monospace">${esc(title)}</span>
      ${(dev && dev.is_gateway)?'<span style="font-size:9px;color:var(--accent);border:1px solid var(--accent);border-radius:3px;padding:1px 4px">GATEWAY</span>':''}
    </div>
    <div style="display:grid;grid-template-columns:90px 1fr;gap:3px 8px;font-size:10px;line-height:1.6">
      <span style="color:var(--muted)">Type</span><span style="font-weight:600">${esc(catLabel)}</span>
      <span style="color:var(--muted)">Address</span><span style="font-family:'JetBrains Mono',monospace">${esc(id)}</span>
      <span style="color:var(--muted)">Domain</span><span>${esc((kind==='internet' && n && n.host) || (dev && dev.hostname) || '–')}</span>
      <span style="color:var(--muted)">Vendor</span><span>${esc((dev && dev.vendor) || 'Unknown')}</span>
      <span style="color:var(--muted)">MAC</span><span style="font-family:'JetBrains Mono',monospace">${esc((dev && dev.mac) || '–')}</span>
      <span style="color:var(--muted)">OS</span><span>${esc(((dev && dev.os)||'Unknown').substring(0,26))}</span>
      <span style="color:var(--muted)">Status</span><span style="color:${(dev&&dev.status)==='online'?'#00e676':'#3d5068'}">${esc((dev && dev.status) || '–')}</span>
      <span style="color:var(--muted)">Vulns</span><span style="color:${(dev&&(dev.vuln_count||0))>0?'#ff2d55':'#00e676'};font-weight:700">${dev && dev.vuln_count || 0}</span>
      <span style="color:var(--muted)">↓ Traffic</span><span>${TOPO && TOPO.fmtB ? TOPO.fmtB(dev && dev.bytes_in || 0) : (dev ? dev.bytes_in||0 : 0)}</span>
      <span style="color:var(--muted)">↑ Traffic</span><span>${TOPO && TOPO.fmtB ? TOPO.fmtB(dev && dev.bytes_out || 0) : (dev ? dev.bytes_out||0 : 0)}</span>
    </div>
    <div style="margin-top:7px;font-size:9px;color:var(--muted);border-top:1px solid var(--border);padding-top:6px">
      Click = pin info  ·  Drag node = move  ·  Drag space = pan  ·  Scroll = zoom
    </div>`;
}
function _actHideTip() {
  _actTipNode = null;
  const t = document.getElementById('act-tip');
  if (t) t.style.display = 'none';
}

// ── Build graph from initial data ────────────────────────────────────────
function _actBuildGraph(data) {
  const ip = data.ip;
  const conns = data.connections || [];
  const sites = data.sites_visited || [];
  const nodeMap = {};
  nodeMap[ip] = { id: ip, label: ip, x: 0.5, y: 0.5, size: 18, color: '#00e5ff', isLocal: true, traffic: 0, activity: 0, _phase: Math.random()*Math.PI*2 };

  sites.forEach((s, i) => {
    if (s.ip === ip) return;
    // DNS-only entries have no resolved IP (the packet log cannot see the
    // answer) – key them by domain so they never collide on an empty string.
    const sid = s.ip || (s.domain ? 'dns:' + s.domain : '');
    if (!sid) return;
    const angle = (i / Math.max(1, sites.length)) * Math.PI * 2;
    const radius = 0.28 + Math.random() * 0.08;
    const host = _actIsDomain(s.domain) ? s.domain : null;
    nodeMap[sid] = {
      id: sid, label: s.domain || s.ip, host,
      x: 0.5 + Math.cos(angle) * radius, y: 0.5 + Math.sin(angle) * radius,
      size: Math.max(5, Math.min(14, 4 + Math.sqrt(s.count) * 2)),
      color: _actColor(s.proto || 'OTHER'), isLocal: false, traffic: s.count,
      activity: 0, _phase: Math.random()*Math.PI*2,
    };
  });

  const edgeMap = {};
  conns.forEach(c => {
    const src = c.src === ip ? ip : c.src;
    const dst = c.dst === ip ? ip : c.dst;
    if (src === dst) return;
    if (!nodeMap[src]) nodeMap[src] = { id: src, label: src, x: Math.random(), y: Math.random(), size: 5, color: _actColor(c.proto), isLocal: false, traffic: 0, activity: 0, _phase: Math.random()*Math.PI*2 };
    if (!nodeMap[dst]) nodeMap[dst] = { id: dst, label: dst, x: Math.random(), y: Math.random(), size: 5, color: _actColor(c.proto), isLocal: false, traffic: 0, activity: 0, _phase: Math.random()*Math.PI*2 };
    nodeMap[src].traffic += (c.len||0);
    nodeMap[dst].traffic += (c.len||0);
    const key = [src, dst].sort().join('→') + '|' + (c.proto||'OTHER').toUpperCase();
    if (!edgeMap[key]) edgeMap[key] = { src, dst, proto: (c.proto||'OTHER').toUpperCase(), count: 0, bytes: 0, color: _actColor(c.proto), _key: key };
    edgeMap[key].count++;
    edgeMap[key].bytes += (c.len||0);
  });

  ACT_STATE.nodes = Object.values(nodeMap);
  ACT_STATE.edges = Object.values(edgeMap);

  const maxTraffic = Math.max(1, ...ACT_STATE.nodes.map(n => n.traffic));
  ACT_STATE.nodes.forEach(n => {
    if (n.isLocal) n.size = 26;
    else n.size = Math.max(7, Math.min(26, 7 + (n.traffic / maxTraffic) * 19));
  });
  data._seenDests = new Set(sites.map(s => s.ip));
}

// ── Render protocol sidebar ──────────────────────────────────────────────
function _actRenderProtoSidebar(data) {
  const el = document.getElementById('act-proto-list');
  if (!el) return;
  const conns = data.connections || [];
  const protoCounts = {}, protoBytes = {};
  conns.forEach(c => {
    const p = c.proto || 'OTHER';
    protoCounts[p] = (protoCounts[p]||0) + (c.count||1);
    protoBytes[p] = (protoBytes[p]||0) + (c.len||0);
  });

  const sorted = Object.entries(protoCounts).sort((a,b)=>b[1]-a[1]);
  const filter = ACT_STATE.protoFilter;

  let html = `<div onclick="actFilterProto(null)" style="display:flex;align-items:center;gap:8px;padding:5px 8px;cursor:pointer;border-radius:3px;transition:background .15s;
    background:${!filter?'rgba(0,229,255,.12)':'transparent'};border:1px solid ${!filter?'var(--accent)':'transparent'};margin-bottom:4px"
    onmouseover="this.style.background='rgba(0,255,255,.08)'" onmouseout="this.style.background='${!filter?'rgba(0,229,255,.12)':'transparent'}'">
    <div style="font-size:10px;font-weight:700;color:${!filter?'var(--accent)':'#aaa'};flex:1">ALL</div>
  </div>`;

  html += sorted.map(([proto, count]) => {
    const col = _actColor(proto);
    const bytes = protoBytes[proto]||0;
    const isActive = filter === proto;
    return `<div data-proto="${esc(proto)}" onclick="actFilterProto(this.dataset.proto)" style="display:flex;align-items:center;gap:8px;padding:5px 8px;cursor:pointer;border-radius:3px;transition:background .15s;
      background:${isActive?'rgba(0,229,255,.12)':'transparent'};border:1px solid ${isActive?col+'44':'transparent'}"
      onmouseover="this.style.background='rgba(255,255,255,.05)'" onmouseout="this.style.background='${isActive?'rgba(0,229,255,.12)':'transparent'}'">
      <div style="width:10px;height:10px;border-radius:50%;background:${col};box-shadow:0 0 6px ${col}55;flex-shrink:0"></div>
      <div style="flex:1;min-width:0">
        <div style="font-size:11px;color:${col};font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${proto}</div>
        <div style="font-size:9px;color:#555">${_fmtAct(bytes)}</div>
      </div>
      <div style="font-size:10px;color:#666;font-family:'JetBrains Mono',monospace;min-width:24px;text-align:right">${count}</div>
    </div>`;
  }).join('');

  el.innerHTML = html;
}

function actFilterProto(proto) {
  ACT_STATE.protoFilter = proto;
  if (ACT_STATE.data) _actRenderProtoSidebar(ACT_STATE.data);
  _actSetStatus(proto ? `Filtered: ${proto}` : 'Live — all protocols');
}

// ── Canvas drawing ───────────────────────────────────────────────────────
let _actCanvasReady = false;
function _actDrawCanvas() {
  const canvas = document.getElementById('act-canvas');
  if (!canvas) return;
  const container = canvas.parentElement;
  const W = container.clientWidth;
  const H = container.clientHeight;
  // Size the backing store to the device pixel ratio once, not on every
  // animation frame (that reallocated and cleared the canvas 60×/s).
  const dpr = window.devicePixelRatio || 1;
  const bw = Math.round(W * dpr), bh = Math.round(H * dpr);
  if (canvas.width !== bw || canvas.height !== bh) {
    canvas.width = bw;
    canvas.height = bh;
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  _actCanvasReady = true;

  const zoom = ACT_STATE.zoom;
  const panX = ACT_STATE.panX;
  const panY = ACT_STATE.panY;

  ctx.fillStyle = '#0a0c10';
  ctx.fillRect(0, 0, W, H);

  // Grid (scales with zoom)
  ctx.save();
  ctx.translate(W/2 + panX*zoom, H/2 + panY*zoom);
  ctx.scale(zoom, zoom);
  ctx.translate(-W/2, -H/2);

  ctx.strokeStyle = 'rgba(255,255,255,.03)';
  ctx.lineWidth = 0.5 / zoom;
  for (let x = 0; x < W/zoom + Math.abs(panX)*2; x += 40) { ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,H/zoom+Math.abs(panY)*2); ctx.stroke(); }
  for (let y = 0; y < H/zoom + Math.abs(panY)*2; y += 40) { ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W/zoom+Math.abs(panX)*2,y); ctx.stroke(); }

  const filter = ACT_STATE.protoFilter;
  const nodes = ACT_STATE.nodes;
  const edges = ACT_STATE.edges;

  // Filter to only edges matching the protocol filter
  const visEdges = filter ? edges.filter(e => e.proto === filter) : edges;

  // Only show nodes that have at least one visible edge (or the local device)
  const visNodeIds = new Set();
  visNodeIds.add(ACT_STATE.currentIP);
  visEdges.forEach(e => { visNodeIds.add(e.src); visNodeIds.add(e.dst); });
  const visNodes = filter ? nodes.filter(n => visNodeIds.has(n.id)) : nodes;

  // Animation time (seconds) drives idle drift + breathing glow
  const now = performance.now() / 1000;

  // Compute each node's rendered position: base + idle drift (nodes being dragged stay put)
  const pos = {};
  visNodes.forEach(n => {
    const ph = n._phase || (n._phase = Math.random() * Math.PI * 2);
    const d = n.forced ? 0 : 0.02;   // 0 when user is dragging this node
    pos[n.id] = {
      x: n.x + Math.sin(now * 0.7 + ph) * d,
      y: n.y + Math.cos(now * 0.6 + ph * 1.3) * d,
    };
    if (n.activity) n.activity = Math.max(0, n.activity - 0.02);
  });

  // Edges
  visEdges.forEach(e => {
    const srcN = visNodes.find(n => n.id === e.src);
    const dstN = visNodes.find(n => n.id === e.dst);
    if (!srcN || !dstN) return;
    const x1=pos[srcN.id].x*W, y1=pos[srcN.id].y*H, x2=pos[dstN.id].x*W, y2=pos[dstN.id].y*H;
    const thickness = Math.max(0.8, Math.min(5, Math.sqrt(e.count) * 0.6));
    const pulse = e._pulse || 0;
    const lineW = pulse > 0 ? thickness + pulse*2 : thickness;

    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.strokeStyle = e.color + (pulse > 0 ? 'cc' : '88');
    ctx.lineWidth = lineW;
    ctx.stroke();

    // Animated packet dot
    if (pulse > 0.3) {
      const t = (Date.now() % 800) / 800;
      const px = x1 + (x2-x1)*t, py = y1 + (y2-y1)*t;
      ctx.beginPath();
      ctx.arc(px, py, 3, 0, Math.PI*2);
      ctx.fillStyle = e.color;
      ctx.fill();
    }

    if (e._pulse > 0) e._pulse = Math.max(0, e._pulse - 0.03);
  });

  // Nodes
  visNodes.forEach(n => {
    const x = pos[n.id].x*W, y = pos[n.id].y*H, r = n.size;
    const activity = n.activity || 0;
    const breath = 0.5 + 0.5 * Math.sin(now * 2 + (n._phase || 0));
    const glowR = r * (1.9 + 0.6 * breath + activity * 2.6);
    const dev = _actNodeDev(n.id);
    const col = (dev && dev.is_gateway) ? '#00e5ff' : n.color;
    const kind = _actNodeKind(n);

    // Outer glow (breathing + activity-driven, mirrors overview topology graph)
    const glowAlpha255 = Math.round(Math.max(0, Math.min(1, 0.28 + 0.22 * breath + activity * 0.5)) * 255);
    const glowHex = glowAlpha255.toString(16).padStart(2, '0');
    const grad = ctx.createRadialGradient(x, y, r*0.4, x, y, glowR);
    grad.addColorStop(0, col + glowHex);
    grad.addColorStop(1, 'transparent');
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.arc(x, y, glowR, 0, Math.PI*2);
    ctx.fill();

    // Node background circle (subtle scale pulse on activity)
    ctx.beginPath();
    ctx.arc(x, y, r * (1 + activity * 0.15), 0, Math.PI*2);
    ctx.fillStyle = 'rgba(10,14,20,0.93)';
    ctx.fill();

    // Node border (highlight if hovered, selected, or gateway)
    const hl = (n.id === _actHoverNode) || (n.id === ACT_STATE.selectedIP);
    ctx.strokeStyle = hl ? '#fff' : col;
    ctx.lineWidth = (n.id === ACT_STATE.selectedIP) ? 3 : (hl ? 2.5 : 1.5);
    ctx.stroke();

    // Selected dashed ring
    if (n.id === ACT_STATE.selectedIP) {
      ctx.beginPath(); ctx.arc(x, y, r+8, 0, Math.PI*2);
      ctx.strokeStyle = '#00e5ff'; ctx.lineWidth = 1.5; ctx.setLineDash([5,4]);
      ctx.stroke(); ctx.setLineDash([]);
    }

    // Icon inside node
    ctx.save();
    ctx.translate(x, y);
    const isLocal = (kind === 'local');
    const isKnownDev = !!(dev && dev.device_type);
    if (isLocal || isKnownDev) {
      // Local device + known LAN peers keep their real device-type icon
      let cat = _actNodeIconCat(n, dev, kind);
      if (TOPO && TOPO.drawIcon) TOPO.drawIcon(cat, r*0.8, col, ctx);
      // Overlay favicon on top of the device icon for known LAN devices that are internet sites
      const fav = (kind === 'internet' && n.host) ? _actFavIcon(n.host) : null;
      if (fav) {
        const fs = r*0.5, fr = r*0.54;
        ctx.beginPath(); ctx.arc(0,0,fr,0,Math.PI*2); ctx.clip();
        ctx.drawImage(fav, -fs/2, -fs/2, fs, fs);
        ctx.strokeStyle = 'rgba(255,255,255,.85)'; ctx.lineWidth = Math.max(1, r*0.06);
        ctx.beginPath(); ctx.arc(0,0,fr,0,Math.PI*2); ctx.stroke();
      }
    } else {
      // Remote site / unknown peer -> bold server icon, favicon overlaid on top
      if (TOPO && TOPO.drawIcon) {
        ctx.lineWidth = Math.max(2.5, r*0.16);   // thicker stroke for a bold icon
        TOPO.drawIcon('server', r*0.86, col, ctx);
        ctx.lineWidth = Math.max(2.5, r*0.16);
      }
      const fav = (kind === 'internet' && n.host) ? _actFavIcon(n.host) : null;
      if (fav) {
        const fs = r*0.58, fr = r*0.55;
        ctx.beginPath(); ctx.arc(0,0,fr,0,Math.PI*2); ctx.clip();
        ctx.drawImage(fav, -fs/2, -fs/2, fs, fs);
        ctx.strokeStyle = 'rgba(255,255,255,.9)'; ctx.lineWidth = Math.max(1.5, r*0.09);
        ctx.beginPath(); ctx.arc(0,0,fr,0,Math.PI*2); ctx.stroke();
      }
    }
    ctx.restore();

    // Label below node: domain name for sites, else IP; local device keeps IP
    const fontSize = Math.max(8, Math.min(11, r * 0.40));
    const label = n.host || n.label || n.id;
    ctx.font = `bold ${n.isLocal?fontSize+1:fontSize}px "JetBrains Mono", monospace`;
    ctx.fillStyle = col;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText(label, x, y + r + 6);
  });

  // Title
  if (ACT_STATE.data) {
    ctx.fillStyle = 'rgba(255,255,255,.15)';
    ctx.font = 'bold 14px "Segoe UI", sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(`Network Graph — ${ACT_STATE.data.ip}`, W/2, 20);
  }

  ctx.restore();
  _actUpdateCanvasInfo();
}

function _actUpdateCanvasInfo() {
  const el = document.getElementById('act-canvas-info');
  if (!el || !ACT_STATE.data) return;
  const sum = ACT_STATE.data.summary || {};
  const filter = ACT_STATE.protoFilter;
  const fEdges = filter ? ACT_STATE.edges.filter(e=>e.proto===filter) : ACT_STATE.edges;
  const fPkts = fEdges.reduce((s,e)=>s+(e.count||0),0);
  const fBytes = fEdges.reduce((s,e)=>s+(e.bytes||0),0);
  const fHosts = new Set(); fEdges.forEach(e=>{fHosts.add(e.src);fHosts.add(e.dst)});
  el.style.display = 'block';
  el.innerHTML = `
    <div style="margin-bottom:4px;font-weight:600;color:#fff">${esc(ACT_STATE.data.ip)}</div>
    ${filter?`<div style="margin-bottom:4px;color:var(--accent);font-size:9px">Filtered: ${esc(filter)}</div>`:''}
    <div>Packets: <span style="color:#00e5ff">${fPkts}</span></div>
    <div>Bytes: <span style="color:#00e676">${_fmtAct(fBytes)}</span></div>
    <div>Hosts: <span style="color:#ff6b35">${fHosts.size}</span></div>
    <div>Edges: <span style="color:#7c4dff">${fEdges.length}</span></div>
    <div style="margin-top:4px;color:#666">Zoom: ${Math.round(ACT_STATE.zoom*100)}%</div>
  `;
}

// ── Toolbar actions ──────────────────────────────────────────────────────
function actToolbarAction(action) {
  if (action === 'pause') {
    ACT_STATE.paused = !ACT_STATE.paused;
    _actSetStatus(ACT_STATE.paused ? 'Paused' : 'Live');
  } else if (action === 'stop') {
    ACT_STATE.paused = true;
    _actSetStatus('Stopped');
  } else if (action === 'start') {
    ACT_STATE.paused = false;
    ACT_STATE._pktBuf = [];
    _actSetStatus('Live');
    if (ACT_STATE.currentIP) actLoadPopup(ACT_STATE.currentIP);
  } else if (action === 'next') {
    if (ACT_STATE.currentIP) actLoadPopup(ACT_STATE.currentIP);
  } else if (action === 'nodes') {
    const info = document.getElementById('act-canvas-info');
    if (info) info.style.display = info.style.display === 'none' ? 'block' : 'none';
  }
}

function _actSetStatus(txt) {
  const el = document.getElementById('act-status-text');
  if (el) el.textContent = txt;
}

// ── Init on nav ──────────────────────────────────────────────────────────
function actInit() {
  actRefreshDeviceGrid();
}

// Clock
setInterval(()=>{const e=document.getElementById("hdr-time");if(e)e.textContent=new Date().toLocaleTimeString();},1000);

</script>
</body>
</html>"""

# ─────────────────────────────────────────────────────────────────────────────
#  STATIC ASSETS  (logo + favicon)
# ─────────────────────────────────────────────────────────────────────────────
ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")

@app.route("/assets/<path:filename>")
def asset_file(filename):
    """Serve files from ./assets (the dashboard logo/favicon lives there)."""
    return send_from_directory(ASSETS_DIR, filename, max_age=86400)

@app.route("/favicon.ico")
def favicon_ico():
    """Browsers request /favicon.ico by default – answer with the PNG logo."""
    return send_from_directory(ASSETS_DIR, "netron.png",
                               mimetype="image/png", max_age=86400)

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML, auth_token=AUTH_TOKEN)


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
def print_banner():
    mode = "ROOT – all features on" if IS_ROOT else "NO ROOT – limited mode"
    cap  = ("Scapy deep-capture" if (SCAPY_OK and IS_ROOT)
            else "psutil poll (install scapy + run as root for deep capture)")
    print(f"""
╔{'═'*50}╗
║{'Netron - Network Security':^50}║
╚{'═'*50}╝
  Gateway  : {monitor.gateway}
  Network  : {monitor.network}
  Mode     : {mode}
  Capture  : {cap}
  Bind     : {APP_HOST}:{APP_PORT}
  Dashboard: http://{'localhost' if APP_HOST in ('0.0.0.0', '127.0.0.1') else APP_HOST}:{APP_PORT}
""")

if __name__ == "__main__":
    if not IS_ROOT:
        print("\n[!] Not root - packet capture uses psutil, OS detect uses heuristics.")
        print("    For full features: sudo python3 netron.py\n")
    monitor.start()
    print_banner()
    print("  Press Ctrl+C to stop.\n")
    try:
        socketio.run(app, host=APP_HOST, port=APP_PORT,
                     debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
        monitor.capture.stop()
