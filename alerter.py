"""
Network Traffic Watchdog — Alert dispatcher

Sends Windows notifications and writes to the alerts log.

Notification strategy (in priority order):
  1. Tray balloon tip via Shell_NotifyIcon (if tray is registered)
  2. PowerShell balloon tip (always available on Windows 10/11)
  3. Log file (always)
"""
import logging
import subprocess
import time
from datetime import datetime
from typing import Optional

import config
from detector import Alert

logger = logging.getLogger("watchdog.alerter")

_ICONS = {
    config.SEVERITY_CRITICAL: "🚨",
    config.SEVERITY_HIGH:     "⚠️",
    config.SEVERITY_MEDIUM:   "⚡",
    config.SEVERITY_LOW:      "ℹ️",
}

# Alert types that produce a tray balloon notification.
# Everything else is still logged to DB and visible in the Alerts UI — just silently.
# Rationale: warning_process (cmd/powershell), suspicious_port, and high_risk_country
# fire far too often on normal Windows systems and cause alert fatigue.
_NOTIFY_ALERT_TYPES: frozenset = frozenset({
    "malware_port",        # CRITICAL — known RAT/backdoor port
    "critical_process",    # CRITICAL — LOLBin with network connection
    "suspicious_exe_path", # HIGH     — executable in Temp/Downloads/Desktop
    "beaconing",           # HIGH     — regular C2 heartbeat pattern
    "mining_pool",         # HIGH     — cryptojacking
    "tor_connection",      # HIGH     — Tor usage
    "connection_flood",    # HIGH     — port scan / flood
})


class Alerter:
    """Manages alert delivery and cooldown tracking."""

    def __init__(self):
        self._cooldowns: dict[tuple, float] = {}
        # Optional reference to SystemTray for balloon tips
        self._tray = None

    def register_tray(self, tray):
        """Call this after the tray is created so alerts can use balloon tips."""
        self._tray = tray

    # ── Public API ────────────────────────────────────────────────────────────

    def is_cooldown(self, alert: Alert) -> bool:
        """True if the same alert was sent within ALERT_COOLDOWN seconds."""
        last = self._cooldowns.get(alert.key(), 0)
        return (time.time() - last) < config.ALERT_COOLDOWN

    def send(self, alert: Alert, db=None):
        """Deliver an alert: update cooldown, log, notify, optionally persist."""
        self._cooldowns[alert.key()] = time.time()
        self._write_log(alert)
        self._notify(alert)

        if db:
            try:
                db.store_alert(alert)
            except Exception as e:
                logger.error("DB store_alert selhalo: %s", e)


        logger.warning("[%s] %s | %s", alert.severity.upper(), alert.title, alert.description)

    # ── Log file ──────────────────────────────────────────────────────────────

    def _write_log(self, alert: Alert):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = (
            f"[{ts}] [{alert.severity.upper()}] [{alert.alert_type}] "
            f"{alert.title} | {alert.description}\n"
        )
        try:
            with open(config.ALERTS_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            logger.error("Zápis alertu do logu selhal: %s", e)

    # ── Notification dispatch ─────────────────────────────────────────────────

    def _notify(self, alert: Alert):
        if alert.alert_type not in _NOTIFY_ALERT_TYPES:
            return

        icon  = _ICONS.get(alert.severity, "")
        title = f"{icon} Network Watchdog — {alert.title}"
        body  = alert.description
        if len(body) > 250:
            body = body[:247] + "…"

        is_crit = alert.severity == config.SEVERITY_CRITICAL

        # Try tray balloon first (instant, no extra process)
        if self._tray:
            try:
                self._tray.show_balloon(title, body, is_critical=is_crit)
                return
            except Exception as e:
                logger.debug("Tray balloon selhal: %s", e)

        # Fallback: PowerShell Windows Forms balloon tip
        self._notify_powershell(title, body)

    def _notify_powershell(self, title: str, body: str):
        """Spawn a hidden PowerShell process that shows a balloon tip."""

        def _esc(s: str) -> str:
            return s.replace('"', '').replace("'", '').replace('`', '').replace('\n', ' ')

        t = _esc(title)[:100]
        b = _esc(body)[:300]

        ps = f"""
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$n = New-Object System.Windows.Forms.NotifyIcon
$n.Icon = [System.Drawing.SystemIcons]::Shield
$n.BalloonTipIcon  = 'Warning'
$n.BalloonTipTitle = "{t}"
$n.BalloonTipText  = "{b}"
$n.Visible = $true
$n.ShowBalloonTip(8000)
Start-Sleep -Milliseconds 9000
$n.Dispose()
"""
        try:
            subprocess.Popen(
                ["powershell", "-WindowStyle", "Hidden", "-Command", ps],
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except Exception as e:
            logger.error("PowerShell notifikace selhala: %s", e)
