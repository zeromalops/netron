<div align="center">

<pre>
███╗   ██╗███████╗████████╗██████╗  ██████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   ██████╔╝██║   ██║██╔██╗ ██║
██║╚██╗██║██╔════╝   ██║   ██╔══██╗██║   ██║██║╚██╗██║
██║ ╚████║███████╗   ██║   ██║  ██║╚██████╔╝██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
</pre>



**Real-time network monitoring, vulnerability detection & traffic analysis dashboard**

</div>

---

## 📸 Dashboard

![Netron Dashboard](dashboard.png)

---

## ✨ Features

- 🌐 **Live Network Map** — Interactive node graph with TCP/UDP/ICMP/ICMPv6/ARP traffic visualization
- 📡 **Device Discovery** — Auto-detects all devices on the local subnet with OS fingerprinting
- ⚡ **Internet Speed & Latency** — HTTP probe for real-time download, upload, ping & jitter
- 🚨 **Alert Engine** — Severity-ranked alerts with live badge counters
- 🔒 **Vulnerability Scanner** — Open-port and service analysis with per-port risk notes
- 📊 **Bandwidth Monitor** — Per-device packet rate tracking
- 🖥️ **Multi-view Sidebar** — Overview, Devices, Live Traffic, Alerts, Vulnerabilities, Open Ports

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/maulezero/netron.git
```

### 2. Navigate into the Project

```bash
cd netron
```

### 3. Create and Activate a Virtual Environment

No virtual environment is included in the repo — create one first.

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

**macOS / Linux:**
```bash
python3 netron.py
```

**Windows:**
```bash
python netron.py
```

Then open your browser and navigate to:

```
http://localhost:5000
```

---

## 🗂️ Project Structure

```
netron/
├── netron.py       # Main application entry point
├── requirements.txt     # Python dependencies
├── dashboard.png        # UI screenshot
└── README.md
```

---

## ⚙️ Requirements

- Python 3.8 or higher
- A virtual environment (`venv`) — create one as shown above
- Network interface with access to the local subnet
- Root / Administrator privileges recommended for full packet capture
  (root + Scapy: IPv4/IPv6/ARP with TCP, UDP, ICMP, ICMPv6 and other
  Internet protocols; without root, psutil mode reports TCP/UDP only)

### Configuration

| Environment variable | Default   | Purpose                      |
|----------------------|-----------|------------------------------|
| `NETRON_HOST`   | `0.0.0.0` | Address the dashboard binds  |
| `NETRON_PORT`   | `5000`    | Port the dashboard binds     |

### ⚠️ Security Note

Netron is a **local network tool**. The dashboard has no login — anyone
who can reach the host on the configured port can view everything and use the
block/unblock/rescan actions. State-changing API calls are protected against
cross-site requests with a per-run CSRF token, but that is not authentication.
Keep it on a trusted network, and prefer binding via
`NETRON_HOST=127.0.0.1` when you don't need remote access.

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

---

## 📄 License

MIT © [github.com/maulezero](https://github.com/maulezero)

---

<div align="center">
<sub>Built with 🖤 for network defenders and red teamers</sub>
</div>