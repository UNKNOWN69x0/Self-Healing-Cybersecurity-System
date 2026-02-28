# Self-Healing Cybersecurity System (SHCS)

A Windows-based autonomous cybersecurity agent that continuously monitors system activity, detects threats in real time, and automatically responds to neutralise them without human intervention.

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