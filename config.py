"""
Network Traffic Watchdog — Configuration
"""
import json
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR  = BASE_DIR / "logs"

DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

DB_PATH         = DATA_DIR / "watchdog.db"
LOG_PATH        = LOG_DIR  / "watchdog.log"
ALERTS_LOG_PATH = LOG_DIR  / "alerts.log"
REPORT_PATH     = DATA_DIR / "report.html"

# ── Language ──────────────────────────────────────────────────────────────────
# Available: "cs" (Czech), "en" (English). Add strings/<lang>.py for more.
LANGUAGE = "cs"

# ── Timing ──────────────────────────────────────────────────────────────────
MONITOR_INTERVAL = 5    # seconds between scans
ALERT_COOLDOWN   = 300  # seconds before re-alerting on the same issue

# ── Severity labels ──────────────────────────────────────────────────────────
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH     = "high"
SEVERITY_MEDIUM   = "medium"
SEVERITY_LOW      = "low"

# ── Known malware / RAT ports (CRITICAL) ────────────────────────────────────
CRITICAL_PORTS: dict[int, str] = {
    4444:  "Metasploit default shell",
    31337: "Back Orifice RAT",
    1337:  "Common hacker port",
    12345: "NetBus RAT",
    12346: "NetBus RAT (alt)",
    27374: "Sub7 RAT",
    1243:  "Sub7 RAT (alt)",
    6666:  "IRC botnet",
    6667:  "IRC botnet",
    6668:  "IRC botnet",
    6669:  "IRC botnet",
    65000: "Stacheldraht DDoS agent",
    9996:  "Agobot",
    5554:  "Sasser worm",
    4899:  "Radmin remote admin",
    7777:  "Common backdoor",
    9999:  "Common backdoor",
    2222:  "Common backdoor",
}

# ── Unusual / suspicious ports (WARNING) ────────────────────────────────────
WARNING_PORTS: dict[int, str] = {
    1080: "SOCKS proxy",
    3128: "Squid proxy",
    8080: "Alternate HTTP / proxy",
    8888: "Alternate HTTP",
    3333: "Possible mining / Metasploit",
    3334: "Mining pool",
    5555: "Android ADB / mining",
    4433: "HTTPS alternate",
    8443: "HTTPS alternate",
    9001: "Tor relay",
    9030: "Tor directory",
    9050: "Tor SOCKS proxy",
    9051: "Tor control port",
    9150: "Tor Browser proxy",
    14444: "Mining pool (XMR)",
    14433: "Mining pool (XMR TLS)",
    5900:  "VNC (unencrypted)",
    5000:  "UPnP / often abused",
}

TOR_PORTS    = {9001, 9030, 9050, 9051, 9150}
MINING_PORTS = {3333, 3334, 3335, 3336, 3337, 3338, 4444, 5555,
                7777, 8333, 9332, 9333, 14444, 14433}

# ── Processes that should NEVER open outbound connections ────────────────────
CRITICAL_PROCESSES: dict[str, str] = {
    "mshta.exe":        "HTML Application Host — executes remote HTA scripts",
    "regsvr32.exe":     "Register Server — LOLBin for fileless malware",
    "certutil.exe":     "Certificate Utility — often abused to download payloads",
    "bitsadmin.exe":    "BITS Admin — abused to download/upload files",
    "installutil.exe":  ".NET Install Utility — LOLBin for bypass",
    "regasm.exe":       "Registry Assembly — LOLBin",
    "regsvcs.exe":      "Registry Services — LOLBin",
    "cmstp.exe":        "MS Connection Manager — LOLBin UAC bypass",
    "ieexec.exe":       "IE Execute — LOLBin",
    "mavinject.exe":    "Code injection utility",
    "xwizard.exe":      "Extensible Wizard — LOLBin",
    "expand.exe":       "Windows expand — LOLBin",
    "extrac32.exe":     "CAB extraction — LOLBin",
    "syncappvpublishingserver.exe": "App-V — LOLBin",
    "pcwrun.exe":       "Program Compatibility Wizard — LOLBin",
}

# ── Processes worth monitoring (WARNING) ─────────────────────────────────────
WARNING_PROCESSES: dict[str, str] = {
    "cmd.exe":             "Command shell — unusual to initiate network connections",
    "powershell.exe":      "PowerShell — frequently abused in attacks",
    "powershell_ise.exe":  "PowerShell ISE",
    "wscript.exe":         "Windows Script Host",
    "cscript.exe":         "Windows Script Host (console)",
    "rundll32.exe":        "Run DLL — frequently abused",
    "msiexec.exe":         "Windows Installer",
    "wmic.exe":            "WMI Command — frequently abused",
    "control.exe":         "Control Panel",
    "msdt.exe":            "MS Support Diagnostic Tool (Follina vector)",
    "rpcping.exe":         "RPC Ping — LOLBin",
    "replace.exe":         "Replace utility — LOLBin",
    "findstr.exe":         "Find String — LOLBin",
    "msdeploy.exe":        "Web Deploy",
    "presentationhost.exe":"XAML Browser Application host",
}

# ── Executable-path patterns that indicate suspicious location ───────────────
# IMPORTANT: keep these specific — general AppData paths cause too many FPs
# (Spotify, Discord, Slack, etc. all legitimately live in AppData)
SUSPICIOUS_PATH_PATTERNS = [
    r"appdata\local\temp",   # True Windows temp folder — high suspicion
    r"\temp\\",              # Standalone \Temp\ directory
    r"\tmp\\",               # /tmp/ equivalent
    r"\users\public\\",      # World-writable — unusual for real apps
    r"\desktop\\",           # Executable on the Desktop
    r"\downloads\\",         # Executable run directly from Downloads
    r"$recycle",             # Recycle Bin
]

# Legitimate processes that are whitelisted from the path check even if they
# match a suspicious pattern (e.g. Electron apps in %LocalAppData%).
SAFE_PROCESS_NAMES = {
    "spotify.exe", "discord.exe", "slack.exe", "zoom.exe",
    "teams.exe", "brave.exe", "chrome.exe", "firefox.exe",
    "msedge.exe", "code.exe", "cursor.exe", "opera.exe",
    "1password.exe", "bitwarden.exe", "nordvpn.exe",
    "whatsapp.exe", "telegram.exe", "signal.exe",
    "update.exe", "squirrel.exe",   # common Electron updater names
}

# ── Windows kernel pseudo-processes ──────────────────────────────────────────
# PID 0 (System Idle) and PID 4 (System) are kernel-level pseudo-processes.
# Connections attributed to them are unowned system traffic — excluding them
# prevents false-positive flood and beaconing alerts.
SYSTEM_PIDS: set = {0, 4}

# ── Geographic threat detection ───────────────────────────────────────────────
# Country codes (ISO 3166-1 alpha-2) to flag as high-risk.
# Edit to match your personal threat model. Note that many CDNs, cloud providers
# and legitimate SaaS companies have infrastructure in these countries too, so
# a medium (not critical) severity is used by default.
GEOIP_ENABLED = True

HIGH_RISK_COUNTRIES: set = {
    "RU",  # Russia
    "CN",  # China
    "KP",  # North Korea
    "IR",  # Iran
    "BY",  # Belarus
    "SY",  # Syria
    "CU",  # Cuba
    "VE",  # Venezuela (state-sponsored actors)
    "MM",  # Myanmar / Burma
}

# ── Beaconing detection ───────────────────────────────────────────────────────
BEACONING_MIN_CONNECTIONS   = 5    # min new connections to same IP before analysis
BEACONING_VARIANCE_THRESHOLD = 3.0  # max std-dev (seconds) to call it beaconing
BEACONING_MIN_INTERVAL      = 5    # seconds — too fast = normal keepalive
BEACONING_MAX_INTERVAL      = 600  # seconds — 10 min max beacon window

# ── Connection flood ─────────────────────────────────────────────────────────
MAX_UNIQUE_REMOTE_IPS = 30  # per process in 60 s → triggers flood/scan warning
