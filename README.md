# IP Sentinel AI — Threat Intelligence, WAF Forensics & Origin Discovery

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.13-blue.svg)
![GUI Framework](https://img.shields.io/badge/GUI-PySide6%20%2F%20Qt-green.svg)
![License](https://img.shields.io/badge/license-MIT-purple.svg)
![Tests](https://img.shields.io/badge/tests-89%20passed-brightgreen.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-lightgrey.svg)
![Self-Test](https://img.shields.io/badge/self--test-10%2F10%20passed-success.svg)

**A professional, standalone Windows cybersecurity desktop application for incident response, WAF log analysis, threat intelligence correlation, and CDN origin IP discovery.**

*Developed By: **Vivek Nigam***

</div>

---

## ⚠️ Legal & Ethical Disclaimer

> **IMPORTANT**: **IP Sentinel AI** is developed strictly for **defensive security auditing, authorized penetration testing, and educational research**.  
> Users are strictly required to ensure they have proper authorization before executing active scans against any target. The author (**Vivek Nigam**) assumes no responsibility or liability for unauthorized or malicious use of this software.

---

## 🌟 Key Capabilities & Architecture

### 1. 🛡️ WAF Behavioral & Attack Analysis Engine
* **Multi-Format Log Ingestion**: High-throughput parser for AWS WAF, Cloudflare, ModSecurity, and Akamai log files in CSV, JSON, and NDJSON formats.
* **Telemetry & Rate Analytics**: Computes request volumes, observation windows, burstiness ratios, peak requests/sec, and rate anomaly flags.
* **User-Agent & Endpoint Profiling**: Analyzes UA diversity, missing UA percentages, and flags probing across sensitive endpoints (`CONFIG_DISCOVERY`, `ADMIN_ENUMERATION`, `CMS_SCAN`, `WEB_SCANNER`, `CREDENTIAL_ENDPOINT`).
* **Automated Attack Classification**: Classifies attacks into `NORMAL_CLIENT`, `AUTOMATED_BOT`, `MALICIOUS_BOT`, `WEB_SCANNER`, `HTTP_FLOOD`, `CREDENTIAL_ATTACK`, or `SUSPICIOUS_AUTOMATION` with confidence ratings and supporting evidence.
* **9-Dimensional Behavioral Fingerprint**: Visual radar and status metrics across traffic patterns.

### 2. 🌐 Origin IP & CDN Bypass Engine
* **CDN IP Range Identification**: Automatically validates resolved IPs against official CIDR ranges for **Cloudflare**, **AWS CloudFront**, **Fastly**, and **Akamai**.
* **Direct Subdomain Enumeration**: Probes unproxied and administrative subdomains (`direct`, `origin`, `backend`, `cpanel`, `dev`, `vpn`, etc.).
* **Certificate Transparency Search**: Queries `crt.sh` historical logs to uncover unmasked staging and backend domains.
* **Favicon MurmurHash3 Fingerprinting**: Computes MMH3 hash of target favicons for Shodan-style asset correlation.
* **Email Header Parser**: Extracts real mail server and MTA origin IPs from RFC 5322 `Received: from` headers.

### 3. 🕰️ Historical Passive DNS Origin Finder
* **Multi-Source Aggregation**: Leverages public passive DNS archives (**AlienVault OTX** and **HackerTarget Hostsearch**).
* **Pre-CDN Adoption Discovery**: Traces DNS record timelines (`first_seen`, `last_seen`) to reveal origin IPs used before adopting CDN edge proxies.
* **Automated Candidate Filtering**: Flags historical IPs that fall outside CDN ranges as high-confidence origin server candidates.

### 4. 🔌 Port & Service Banner Grabber
* **Multi-Threaded Concurrent Scanner**: Fast 8-worker thread pool probing standard ports (`21, 22, 80, 443, 3306, 3389, 8080, 8443`) in ~1.5 seconds.
* **Protocol Banner Extraction**:
  * **FTP (21)**: RFC 959 server greeting banner.
  * **SSH (22)**: RFC 4253 protocol identification string.
  * **HTTP / HTTPS (80, 443, 8080, 8443)**: Server header and TLS cipher negotiation.
  * **MySQL (3306)**: Native Initial Handshake Packet parsing to extract exact version strings without external drivers.
  * **RDP (3389)**: Windows Remote Desktop endpoint verification.

### 5. 🔐 SSL/TLS Certificate & Expiry Inspector
* **Full Certificate Inspection**: Examines Common Name (CN), Subject Alternative Names (SANs), Issuer, Validity Window, Serial Number, and SHA-256 Fingerprint.
* **Health & Expiration Status**: Live status badges for 🟢 `VALID`, 🟡 `EXPIRING_SOON`, and 🔴 `EXPIRED`.

### 6. 📄 Forensic HTML & PDF Report Generation
* Generates audit-ready forensic reports powered by Jinja2 and ReportLab Platypus, incorporating threat summaries, network evidence, WAF behavioral telemetry, and disclaimers.

---

## ⚡ Download & Run (Standalone EXE — No Python Required)

For end users and security analysts who just want to use the application without installing Python or dependencies:

1. Go to the [Releases](https://github.com/vivekn1980/IP-Sentinel-AI/releases) page on GitHub.
2. Download the precompiled binary: **`IP-Sentinel-AI.exe`** (~54 MB).
3. **Double-click `IP-Sentinel-AI.exe`** to start using the tool immediately.

> [!NOTE]
> **Zero Installation Required**: The single executable contains the embedded Python runtime, PySide6 GUI framework, and all libraries. It runs directly on any 64-bit Windows 10, Windows 11, or Windows Server system without needing administrator privileges.

> [!TIP]
> **Windows SmartScreen Prompt**:  
> Since open-source binaries do not have a paid enterprise code-signing certificate, Windows Defender SmartScreen may display:  
> *"Windows protected your PC (Unknown Publisher)"*  
> Simply click **More info** → **Run anyway**.

### Standalone EXE Command-Line Flags
You can also launch `IP-Sentinel-AI.exe` directly from PowerShell / CMD with flags:
```powershell
# Run the 10-check diagnostic self-test
.\IP-Sentinel-AI.exe --self-test

# Launch with verbose debug console output
.\IP-Sentinel-AI.exe --debug

# Verify binary version
.\IP-Sentinel-AI.exe --version
```

---

## 🛠️ Developer Setup (Running from Source)

If you wish to modify the code or contribute to the project:

### Prerequisites
* **Windows 10 / 11 (64-bit)**
* **Python 3.13+**
* **Git**

### Installation

```powershell
# 1. Clone the repository
git clone https://github.com/vivekn1980/IP-Sentinel-AI.git
cd IP-Sentinel-AI

# 2. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
```

### Running the Application

```powershell
# Set PYTHONPATH to the src directory
$env:PYTHONPATH="src"

# Launch the Desktop GUI
python -m ip_sentinel.main
```

### CLI Utilities

```powershell
# Show version information
python -m ip_sentinel.main --version

# Run diagnostic self-test (10 engine checks)
python -m ip_sentinel.main --self-test

# Headless initialization check
python -m ip_sentinel.main --headless-test
```

---

## 🧪 Automated Testing

The project includes an automated test suite covering all services, parsers, and UI components:

```powershell
# Run the complete test suite
pytest
```

**Results**: `89 passed in ~40s`

---

## 📦 Building Standalone Executable (EXE)

To compile the standalone portable binary (`dist/IP-Sentinel-AI.exe`):

```powershell
python build.py
```

The build script will:
1. Clean previous build artifacts.
2. Run automated unit tests.
3. Bundle Python and PySide6 into a single portable `.exe` (~54 MB) requiring zero runtime dependencies.

---

## 📁 Repository Structure

```
IP-Sentinel-AI/
├── src/
│   └── ip_sentinel/
│       ├── core/           # Async workers, signals, config, logging
│       ├── models/         # Data classes for threat, WAF, and origin models
│       ├── providers/      # RDAP, GeoIP, AbuseIPDB, VirusTotal providers
│       ├── reports/        # HTML and PDF forensic report generators
│       ├── services/       # Investigation, WAF analysis, origin discovery services
│       └── ui/             # PySide6 main window, navigation, and views
├── resources/
│   ├── fixtures/           # Sample WAF logs (CSV, JSON, NDJSON)
│   ├── styles/             # Dark theme Qt stylesheet (QSS)
│   └── templates/          # Jinja2 forensic report template
├── tests/                  # 89 automated pytest unit and UI tests
├── build.py                # Automated build and packaging pipeline
├── pyinstaller.spec        # PyInstaller specification file
├── requirements.txt        # Pinned Python package dependencies
├── LICENSE                 # MIT License
├── README.md               # Project documentation
└── SECURITY.md             # Security policy and responsible disclosure
```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

Developed By: **Vivek Nigam**
