# Self-Healing Cybersecurity System (SHCS)

A Windows-based autonomous cybersecurity agent that continuously monitors system activity, detects threats in real time using both rule-based logic and **ML-based anomaly detection**, and automatically responds to neutralise them without human intervention.

---

## Architecture

```
+---------------------------+
|        Dashboard          |  <-- CustomTkinter GUI (dashboard/app.py)
|  Start / Stop Agent       |      ML Status indicator
|  ML Status Indicator      |      Threat counter badge
|  Threat Counter Badge     |      Notification toggle
|  Notification Toggle      |
+------------+--------------+
             |
             v
+---------------------------+
|          Agent            |  <-- agent.py (main loop)
+---------------------------+
      |      |      |      |      |         |
      v      v      v      v      v         v
  System  Process Network Event  Traffic  Threat
  Monitor Monitor Monitor Log    Monitor  Intel
                               Monitor
      \      |      /      /      |         |
       \     v     /      /       |         |
        +---------------+         |         |
        |  Rule Engine  | <-------+         |
        | + ML Anomaly  | <-----------------+
        +-------+-------+
                |
                v
        +---------------+
        |  Self-Heal    |  <-- response/self_heal.py
        | (Terminate /  |
        |   Block /     |
        |   Re-enable)  |
        +---------------+
                |
                v
        +---------------+
        |   Notifier    |  <-- utils/notifier.py (toast notifications)
        +---------------+
```

---

## Features

- **Real-time CPU & Memory monitoring** — alerts when usage exceeds configurable thresholds
- **Malicious process detection** — identifies blacklisted processes (e.g. cryptominers) and high-CPU processes
- **Suspicious network connection detection** — flags unexpected outbound connections to unknown IPs
- **Brute-force login detection** — reads the Windows Security event log for failed login events (ID 4625)
- **ML-based anomaly detection** — Isolation Forest model trained on system/network metrics; raises `ML_ANOMALY` threats after a learning period
- **Network traffic monitoring** — tracks bandwidth per second and total connections via `psutil`
- **Threat intelligence** — local database of known malicious ports, Tor exit node prefixes, and suspicious ports
- **New rule-based threat types**:
  - `PORT_SCAN` — multiple connections from same IP to different ports
  - `DATA_EXFILTRATION` — outbound bandwidth exceeds threshold
  - `SUSPICIOUS_PORT` — connection on known malicious port
  - `FIREWALL_DISABLED` — Windows Firewall is off (auto re-enabled)
- **Automatic self-healing responses**:
  - Terminates malicious processes (`taskkill`)
  - Blocks suspicious / scanning IPs via Windows Firewall (`netsh`)
  - Logs warnings for high CPU/memory and brute-force attacks
  - Re-enables Windows Firewall when disabled
  - Resets DNS to 8.8.8.8 / 1.1.1.1 on DNS tampering
- **Windows toast notifications** — desktop alerts for MEDIUM/HIGH/CRITICAL threats via `plyer`
- **System tray icon** — optional tray icon with Open Dashboard / Quit menu via `pystray`
- **Live dashboard** — CustomTkinter GUI shows agent status, ML mode indicator, threat counter, and scrollable live log output
- **Configurable thresholds** — all detection limits are read from `config.json`
- **Structured logging** — timestamped entries written to `C:\ProgramData\SHCS\shcs.log`
- **Windows startup via Task Scheduler** — more reliable than registry; runs at highest privilege

---

## Project Structure

```
Self-Healing-Cybersecurity-System/
├── agent.py                  # Main agent loop
├── main.py                   # Entry point (single-instance lock)
├── autostart.py              # Registers agent with Windows Task Scheduler
├── config.json               # Configurable thresholds and settings
├── requirements.txt
├── .gitignore
├── model/                    # Persisted ML model (anomaly_model.pkl)
├── dashboard/
│   ├── app.py                # CustomTkinter GUI dashboard
│   ├── agent_control.py      # Start/stop agent process
│   ├── log_reader.py         # Read recent log entries
│   ├── theme.py              # Colour and font definitions
│   └── tray_icon.py          # System tray icon (pystray)
├── detection/
│   ├── rule_engine.py        # Rule-based threat detection
│   └── ml_anomaly.py         # ML anomaly detection (Isolation Forest)
├── monitor/
│   ├── system_monitor.py     # CPU, memory, disk metrics
│   ├── process_monitor.py    # Suspicious process detection
│   ├── network_monitor.py    # Suspicious connection detection
│   ├── eventlog_monitor.py   # Windows Security event log (failed logins)
│   ├── traffic_monitor.py    # Network bandwidth tracking
│   └── threat_intel.py       # Local threat intelligence (ports, Tor nodes)
├── response/
│   └── self_heal.py          # Automated remediation actions
├── utils/
│   ├── logger.py             # Timestamped file logger
│   └── notifier.py           # Windows toast notifications
└── tests/
    ├── test_rule_engine.py   # Unit tests for rule engine
    ├── test_self_heal.py     # Unit tests for self-heal module
    ├── test_ml_anomaly.py    # Unit tests for ML anomaly detector
    ├── test_traffic_monitor.py # Unit tests for traffic monitor
    └── test_threat_intel.py  # Unit tests for threat intelligence
```

---

## Installation

### Prerequisites

- Windows 10/11
- Python 3.10+
- Administrator privileges (required for firewall rules and Security event log)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/UNKNOWN69x0/Self-Healing-Cybersecurity-System.git
cd Self-Healing-Cybersecurity-System

# 2. Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Run the agent directly

```bash
python main.py --agent
```

### Run the dashboard

```bash
cd dashboard
python app.py
```

The dashboard provides Start/Stop buttons to control the agent process, an ML status indicator showing whether the detector is in learning or active mode, a threat counter badge, a notifications toggle button, and a live scrolling log viewer that refreshes every 3 seconds.

### Add agent to Windows startup (optional)

```bash
python autostart.py
```

Registers a Task Scheduler task (`SHCS Agent`) that runs the agent at highest privilege on user logon.

---

## Configuration

Edit `config.json` in the project root to customise detection thresholds:

```json
{
    "thresholds": {
        "cpu_percent": 90,
        "memory_percent": 95,
        "failed_login_limit": 5,
        "bandwidth_alert_mbps": 10,
        "port_scan_threshold": 5
    },
    "ml": {
        "enabled": true,
        "min_training_samples": 20,
        "retrain_interval": 50,
        "contamination": 0.1
    },
    "notifications": {
        "enabled": true,
        "min_severity": "MEDIUM"
    },
    "process_blacklist": ["xmrig", "miner", "hacktool", "coinhive", "cryptonight"],
    "suspicious_ports": [4444, 5555, 6666, 1337, 31337, 8443, 9001],
    "trusted_ip_prefixes": ["13.", "15.", "20.", "40.", "52.", "142.250.", "142.251.", "104.16.", "104.17.", "104.18."],
    "safe_ips": ["127.0.0.1", "::1"],
    "monitoring_interval_seconds": 5,
    "log_directory": "C:\\ProgramData\\SHCS"
}
```

| Key | Description |
|---|---|
| `thresholds.cpu_percent` | CPU % above which a HIGH_CPU threat is raised |
| `thresholds.memory_percent` | Memory % above which a HIGH_MEMORY threat is raised |
| `thresholds.failed_login_limit` | Failed login count above which BRUTE_FORCE is raised |
| `thresholds.bandwidth_alert_mbps` | Outbound MB/s above which DATA_EXFILTRATION is raised |
| `thresholds.port_scan_threshold` | Distinct ports from one IP above which PORT_SCAN is raised |
| `ml.enabled` | Enable/disable ML anomaly detection |
| `ml.min_training_samples` | Cycles before ML model starts predicting |
| `ml.retrain_interval` | Cycles between model retraining |
| `ml.contamination` | Expected fraction of anomalies (Isolation Forest parameter) |
| `notifications.enabled` | Enable/disable desktop toast notifications |
| `notifications.min_severity` | Minimum severity level to trigger a notification |
| `process_blacklist` | Process name substrings flagged as MALICIOUS_PROCESS |
| `suspicious_ports` | Ports flagged as SUSPICIOUS_PORT threats |
| `trusted_ip_prefixes` | IP prefixes considered safe (not flagged) |
| `safe_ips` | Exact IPs never flagged (loopback etc.) |
| `monitoring_interval_seconds` | Seconds between each monitoring cycle |
| `log_directory` | Directory where `shcs.log` is written |

---

## Testing

```bash
python -m pytest tests/ -v
```

Or run individual test modules:

```bash
python -m pytest tests/test_rule_engine.py -v
python -m pytest tests/test_self_heal.py -v
python -m pytest tests/test_ml_anomaly.py -v
python -m pytest tests/test_traffic_monitor.py -v
python -m pytest tests/test_threat_intel.py -v
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.10+ |
| System monitoring | psutil |
| GUI | CustomTkinter |
| Windows integration | pywin32 (win32evtlog) |
| Firewall control | netsh (Windows built-in) |
| Process termination | taskkill (Windows built-in) |
| Startup registration | schtasks (Windows Task Scheduler) |
| ML anomaly detection | scikit-learn (Isolation Forest) |
| Model persistence | joblib |
| Numerical features | numpy |
| Desktop notifications | plyer |
| System tray icon | pystray + Pillow |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Architecture

```
+---------------------------+
|        Dashboard          |  <-- CustomTkinter GUI (dashboard/app.py)
|  Start / Stop Agent       |
|  Live Log Viewer          |
+------------+--------------+
             |
             v
+---------------------------+
|          Agent            |  <-- agent.py (main loop)
+---------------------------+
      |         |       |      |
      v         v       v      v
  System    Process  Network  EventLog
  Monitor   Monitor  Monitor  Monitor
      \         |       /      /
       \        v      /      /
        +---------------+
        |  Rule Engine  |  <-- detection/rule_engine.py
        +-------+-------+
                |
                v
        +---------------+
        |  Self-Heal    |  <-- response/self_heal.py
        | (Terminate /  |
        |   Block)      |
        +---------------+
```

---

## Features

- **Real-time CPU & Memory monitoring** — alerts when usage exceeds configurable thresholds
- **Malicious process detection** — identifies blacklisted processes (e.g. cryptominers) and high-CPU processes
- **Suspicious network connection detection** — flags unexpected outbound connections to unknown IPs
- **Brute-force login detection** — reads the Windows Security event log for failed login events (ID 4625)
- **Automatic self-healing responses**:
  - Terminates malicious processes (`taskkill`)
  - Blocks suspicious IPs via Windows Firewall (`netsh`)
  - Logs warnings for high CPU/memory and brute-force attacks
- **Live dashboard** — CustomTkinter GUI shows agent status and scrollable live log output
- **Configurable thresholds** — all detection limits are read from `config.json`
- **Structured logging** — timestamped entries written to `C:\ProgramData\SHCS\shcs.log`

---

## Project Structure

```
Self-Healing-Cybersecurity-System/
├── agent.py                  # Main agent loop
├── main.py                   # Entry point (single-instance lock)
├── autostart.py              # Adds agent to Windows startup registry
├── config.json               # Configurable thresholds and settings
├── requirements.txt
├── .gitignore
├── dashboard/
│   ├── app.py                # CustomTkinter GUI dashboard
│   ├── agent_control.py      # Start/stop agent process
│   ├── log_reader.py         # Read recent log entries
│   └── theme.py              # Colour and font definitions
├── detection/
│   └── rule_engine.py        # Threat detection logic
├── monitor/
│   ├── system_monitor.py     # CPU, memory, disk metrics
│   ├── process_monitor.py    # Suspicious process detection
│   ├── network_monitor.py    # Suspicious connection detection
│   └── eventlog_monitor.py   # Windows Security event log (failed logins)
├── response/
│   └── self_heal.py          # Automated remediation actions
├── utils/
│   └── logger.py             # Timestamped file logger
└── tests/
    ├── test_rule_engine.py   # Unit tests for rule engine
    └── test_self_heal.py     # Unit tests for self-heal module
```

---

## Installation

### Prerequisites

- Windows 10/11
- Python 3.10+
- Administrator privileges (required for firewall rules and Security event log)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/UNKNOWN69x0/Self-Healing-Cybersecurity-System.git
cd Self-Healing-Cybersecurity-System

# 2. Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Run the agent directly

```bash
python main.py --agent
```

### Run the dashboard

```bash
cd dashboard
python app.py
```

The dashboard provides Start/Stop buttons to control the agent process and a live scrolling log viewer that refreshes every 3 seconds.

### Add agent to Windows startup (optional)

```bash
python autostart.py
```

---

## Configuration

Edit `config.json` in the project root to customise detection thresholds:

```json
{
    "thresholds": {
        "cpu_percent": 90,
        "memory_percent": 95,
        "failed_login_limit": 5
    },
    "process_blacklist": ["xmrig", "miner", "hacktool"],
    "trusted_ip_prefixes": ["13.", "15.", "20.", "40.", "52.", "142.250.", "142.251.", "104.16.", "104.17.", "104.18."],
    "safe_ips": ["127.0.0.1", "::1"],
    "monitoring_interval_seconds": 5,
    "log_directory": "C:\\ProgramData\\SHCS"
}
```

| Key | Description |
|---|---|
| `thresholds.cpu_percent` | CPU % above which a HIGH_CPU threat is raised |
| `thresholds.memory_percent` | Memory % above which a HIGH_MEMORY threat is raised |
| `thresholds.failed_login_limit` | Failed login count above which BRUTE_FORCE is raised |
| `process_blacklist` | Process name substrings flagged as MALICIOUS_PROCESS |
| `trusted_ip_prefixes` | IP prefixes considered safe (not flagged) |
| `safe_ips` | Exact IPs never flagged (loopback etc.) |
| `monitoring_interval_seconds` | Seconds between each monitoring cycle |
| `log_directory` | Directory where `shcs.log` is written |

---

## Testing

```bash
python -m pytest tests/ -v
```

Or run individual test modules:

```bash
python -m pytest tests/test_rule_engine.py -v
python -m pytest tests/test_self_heal.py -v
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.10+ |
| System monitoring | psutil |
| GUI | CustomTkinter |
| Windows integration | pywin32 (win32evtlog, winreg) |
| Firewall control | netsh (Windows built-in) |
| Process termination | taskkill (Windows built-in) |

---

## License

MIT License — see [LICENSE](LICENSE) for details.