# Network Traffic Watchdog

A lightweight Windows background application that monitors active network connections in real time and alerts you when suspicious activity is detected — malware ports, unusual processes making connections, cryptocurrency mining, Tor usage, C2 beaconing, and more.

> **Platform:** Windows 10 / 11
> **Python:** 3.10+
> **No cloud, no telemetry** — everything runs locally.

---

## Features

- **System tray icon** — green/orange/red shield reflects current threat level at a glance
- **Windows balloon notifications** — instant alerts without interrupting your work
- **Persistent SQLite log** — every connection and alert is stored for later review
- **Alerts UI** — dark-themed window with full alert history, statistics, and live connection view
- **HTML report** — self-refreshing report you can open in any browser
- **Pause/resume** — temporarily disable monitoring from the tray menu
- **Single-instance guard** — won't spawn duplicates on accidental double-launch
- **Admin elevation** — requests UAC on start so all system connections are visible

---

## Use Cases

### "Something weird is connecting to the internet — what is it?"

You notice unusual network activity (high CPU, slow connection, antivirus warning) but don't know which process is responsible. Open the **Live** tab to see every active connection with its owning process, destination IP, country, and whether the watchdog considers it suspicious — all updating every 5 seconds.

### "I think I might have malware"

The watchdog checks for a long list of known-bad patterns every 5 seconds. If malware is running, you will likely see one or more of:
- A **critical process alert** if the malware uses a Windows LOLBin (`mshta.exe`, `certutil.exe`, `regsvr32.exe`, …) to phone home
- A **malware port alert** if it connects to classic RAT/backdoor ports (4444, 31337, 12345, …)
- A **suspicious exe path alert** if the malware lives in `%TEMP%`, `\Downloads\`, or `\Desktop\`
- A **beaconing alert** if the malware checks in with its C2 server at regular intervals

Alerts appear as Windows balloon notifications and are logged to `logs/alerts.log` so you have a permanent record.

### "Has my PC been cryptojacked?"

If a process is secretly mining cryptocurrency on your hardware, it will connect to a mining pool — the watchdog flags known mining ports (3333, 3334, 14444, 14433, …) and raises a **mining pool** alert the first time the connection is seen.

### "I want to know when any program talks to Russia / China / Iran / North Korea"

Enable `GEOIP_ENABLED = True` in `config.py` (on by default) and configure `HIGH_RISK_COUNTRIES`. The watchdog resolves the country for every new remote IP via [ip-api.com](https://ip-api.com) (free, no API key) and raises a **high risk country** alert whenever a new connection to a flagged country is established. The **Dashboard** tab shows top destination countries for a quick geographic overview.

### "I want ongoing peace of mind, not just a one-off scan"

The watchdog runs continuously in the background, launching on login via Task Scheduler (set up with `setup.bat`). A shield icon in the system tray tells you at a glance whether everything is clean (green), suspicious (orange), or critical (red). You never need to think about it unless something trips a rule.

### "Something triggered a false positive"

Add the process name to `SAFE_PROCESS_NAMES` in `config.py` to exempt it from the suspicious-path check, or remove a port from `WARNING_PORTS` / `CRITICAL_PORTS` if you use it legitimately. All thresholds are plain Python — no GUI config editor needed, just edit the file and restart.

---

## Detection Rules

Each scan (every 5 seconds) runs the following checks against all active connections:

| Rule | Severity | Description |
|---|---|---|
| **Known malware ports** | Critical | Connections to ports associated with RATs and backdoors (4444 Metasploit, 31337 Back Orifice, 12345 NetBus, 27374 Sub7, IRC botnets, …) |
| **Critical LOLBin processes** | Critical | `mshta.exe`, `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe`, `installutil.exe`, `regasm.exe`, `cmstp.exe` and other Living-off-the-Land binaries opening outbound connections |
| **Suspicious processes** | High | `cmd.exe`, `powershell.exe`, `wscript.exe`, `rundll32.exe`, `wmic.exe` and similar shells/interpreters initiating network connections |
| **Suspicious executable path** | High | Processes running from `%TEMP%`, `\Downloads\`, `\Desktop\`, `\Users\Public\`, or the Recycle Bin |
| **Tor connections** | High | Traffic to known Tor ports (9050, 9001, 9030, 9051, 9150) |
| **Cryptocurrency mining** | High | Connections to common mining pool ports (3333, 3334, 14444, 14433, …) |
| **C2 Beaconing** | High | A process connecting to the same IP at statistically regular intervals (std-dev < 3 s) — hallmark of malware command-and-control |
| **Connection flood / port scan** | High | A single process reaching 30+ unique remote IPs within 60 seconds |
| **Unusual ports** | Medium | Connections to SOCKS/HTTP proxies, alternate HTTPS ports, VNC, UPnP, and other atypical destinations |

All rules are tunable in [`config.py`](config.py). Popular Electron apps (Spotify, Discord, Slack, VS Code, …) are whitelisted from the path check to reduce false positives.

---

## Requirements

| Package | Version | Purpose |
|---|---|---|
| [psutil](https://github.com/giampaolo/psutil) | ≥ 5.9 | Network connections & process info |
| [pywin32](https://github.com/mhammond/pywin32) | ≥ 300 | Native Win32 system tray (win32gui) |
| [Pillow](https://python-pillow.org/) | ≥ 10.0 | Dynamic tray icon rendering |

```
pip install -r requirements.txt
```

> **Note:** `pywin32` ships pre-installed with many Python distributions on Windows (Anaconda, WinPython, the official installer's bundled tools). If `pip install` works for you, all three packages will be fetched automatically.

---

## Installation

```bat
git clone https://github.com/your-username/network-traffic-watchdog.git
cd network-traffic-watchdog
pip install -r requirements.txt
```

Run the setup wizard (also handles optional autostart):

```bat
setup.bat
```

---

## Usage

### Start (background, no console window)

```bat
start.bat
```

This runs `pythonw main.py` so no console window appears. A shield icon shows up in the system tray.

### Start (with console — useful for debugging)

```bat
python main.py
```

### Tray menu (right-click the shield icon)

| Item | Action |
|---|---|
| **View Alerts** | Opens the dark-themed GUI window |
| **View HTML Report** | Generates and opens `data/report.html` in your browser |
| **Pause / Resume** | Temporarily halt monitoring (icon turns grey) |
| **Quit** | Stop the watchdog and remove the tray icon |

Double-clicking the tray icon also opens the Alerts window.

### Autostart on login

Run `setup.bat` as Administrator and choose **yes** when prompted. It creates a Task Scheduler entry that launches the watchdog at every logon with the highest privileges.

To remove autostart:

```bat
schtasks /delete /tn "NetworkWatchdog" /f
```

---

## Output files

| File | Description |
|---|---|
| `logs/watchdog.log` | Application log (info, errors) |
| `logs/alerts.log` | Plain-text record of every alert with timestamp and description |
| `data/watchdog.db` | SQLite database (connections, alerts, connection events) |
| `data/report.html` | Self-refreshing HTML report (auto-updated on every "View Report" click) |
| `data/watchdog.pid` | Single-instance lock file (deleted on clean exit) |

---

## Project Structure

```
network-traffic-watchdog/
├── main.py          # Entry point — UAC elevation, single-instance guard, wiring
├── monitor.py       # Background thread — polls psutil every 5 s
├── detector.py      # Detection engine — all rules, beaconing, flood detection
├── alerter.py       # Alert dispatcher — balloon tips + log
├── tray.py          # System tray — win32gui, dynamic shield icon, context menu
├── ui.py            # Alerts window — tkinter, dark theme, alerts/stats/live tabs
├── database.py      # SQLite wrapper — thread-safe, WAL mode
├── report.py        # HTML report generator
├── config.py        # All thresholds, port lists, process lists, whitelists
├── requirements.txt
├── setup.bat        # Dependency install + optional autostart
├── start.bat        # Launch without console window
└── start_hidden.bat # Task Scheduler variant
```

---

## Configuration

All detection parameters live in [`config.py`](config.py). Notable settings:

```python
MONITOR_INTERVAL = 5      # Seconds between scans
ALERT_COOLDOWN   = 300    # Seconds before re-alerting on the same issue

CRITICAL_PORTS   = { 4444: "Metasploit", 31337: "Back Orifice", ... }
WARNING_PORTS    = { 1080: "SOCKS proxy", 8443: "HTTPS alternate", ... }

CRITICAL_PROCESSES = { "mshta.exe": "...", "certutil.exe": "...", ... }
WARNING_PROCESSES  = { "powershell.exe": "...", "cmd.exe": "...", ... }

SAFE_PROCESS_NAMES = { "spotify.exe", "discord.exe", "brave.exe", ... }

BEACONING_MIN_CONNECTIONS    = 5    # Minimum samples before beaconing analysis
BEACONING_VARIANCE_THRESHOLD = 3.0  # Max std-dev (s) to flag as beaconing
MAX_UNIQUE_REMOTE_IPS        = 30   # Per-process, per-60s flood threshold
```

To add your own rules, edit the relevant dictionary and restart the watchdog.

### Language

The UI language is set in `config.py`:

```python
LANGUAGE = "cs"   # Czech
# LANGUAGE = "en" # English
```

Available languages: Czech (`cs`), English (`en`). To add a new language, copy
`strings/en.py` to `strings/<code>.py`, translate the strings, and set
`LANGUAGE = "<code>"`. Restart the watchdog to apply the change.

### Notification thresholds

Not every detected issue triggers a tray balloon — that would cause alert fatigue
on a normal Windows system (e.g. PowerShell running Windows Update scripts).
The notification policy is:

| Alert type | Tray balloon | Alerts UI | Log file |
|---|---|---|---|
| Known malware port | ✅ | ✅ | ✅ |
| Critical LOLBin process | ✅ | ✅ | ✅ |
| Suspicious exe path | ✅ | ✅ | ✅ |
| Beaconing / C2 | ✅ | ✅ | ✅ |
| Cryptocurrency mining | ✅ | ✅ | ✅ |
| Tor connection | ✅ | ✅ | ✅ |
| Connection flood | ✅ | ✅ | ✅ |
| Warning process (cmd, powershell…) | ❌ | ✅ | ✅ |
| Unusual port | ❌ | ✅ | ✅ |
| High-risk country | ❌ | ✅ | ✅ |

To promote any silent alert type to a balloon, add its `alert_type` string to
`_NOTIFY_ALERT_TYPES` in [`alerter.py`](alerter.py).

---

## How Beaconing Detection Works

The detector tracks every *new* connection appearance (when a `(pid, remote_ip)` pair is seen for the first time in a scan). It maintains a rolling 1-hour history of these timestamps.

When a process accumulates 5+ appearances to the same IP, it computes the intervals between consecutive appearances. If the standard deviation of those intervals is below 3 seconds **and** the mean interval falls between 5 s and 600 s, the detector raises a `beaconing` alert.

This catches malware that "phones home" at regular intervals (common in RATs, stealers, and C2 implants) while ignoring legitimate long-lived connections (e.g. a browser tab that stays open).

---

## Permissions

The watchdog requests UAC elevation at startup. Administrator rights are needed to read the owning process for every network connection via `psutil.net_connections()`. Without elevation, connections belonging to system services or other users will still be listed but may lack process information.

If you decline elevation, the tool continues running with reduced visibility.

---

## Privacy & Security

- All analysis is performed **locally** — no data ever leaves your machine.
- No hardcoded external URLs. The optional threat-intel hooks (currently unused) are designed to be opt-in.
- The SQLite database stores raw connection metadata. If you want to clear it: `del data\watchdog.db`.

---

## Contributing

Pull requests are welcome. Some areas where help is appreciated:

- **Threat intelligence integration** — AbuseIPDB / VirusTotal lookups (opt-in, API-key based)
- **Tor exit node list** — periodic download of the Tor Project's bulk exit list
- **GeoIP display** — country flags / ASN info in the UI
- **YARA rules** — match process memory or command lines
- **Tray notifications on Windows 11** — migrate from balloon tips to modern toast (WinRT)
- **Unit tests** — especially for `detector.py` edge cases

Please open an issue before working on a large feature so we can discuss the approach first.

---

## License

MIT — see [LICENSE](LICENSE) for details.
