"""English (en) strings for Network Traffic Watchdog."""

STRINGS: dict[str, str] = {

    # ── Severity labels ────────────────────────────────────────────────────────
    "sev.critical": "● CRITICAL",
    "sev.high":     "▲ HIGH",
    "sev.medium":   "◆ MEDIUM",
    "sev.low":      "▸ LOW",

    # ── Alert titles ──────────────────────────────────────────────────────────
    "alert.malware_port.title":        "Connection to port {port} — known malware port",
    "alert.suspicious_port.title":     "Connection to unusual port {port}",
    "alert.critical_process.title":    "Suspicious process opened a network connection: {name}",
    "alert.warning_process.title":     "Warning — network connection from: {name}",
    "alert.suspicious_exe_path.title": "Process running from suspicious location: {name}",
    "alert.tor_connection.title":      "Possible Tor connection detected",
    "alert.high_risk_country.title":   "Connection to high-risk country: {flag} {country} ({cc})",
    "alert.mining_pool.title":         "Possible cryptocurrency mining detected",
    "alert.beaconing.title":           "Beaconing / C2 communication detected",
    "alert.connection_flood.title":    "Connection flood / port scan detected",

    # ── Alert descriptions ────────────────────────────────────────────────────
    "alert.malware_port.desc":
        "{name} (PID {pid}) connected to {addr}:{port} — {reason}",
    "alert.suspicious_port.desc":
        "{name} (PID {pid}) connected to {addr}:{port} — {reason}",
    "alert.critical_process.desc":
        "{name} (PID {pid}) connected to {addr}:{port}. Reason: {reason}",
    "alert.warning_process.desc":
        "{name} (PID {pid}) connected to {addr}:{port}. Reason: {reason}",
    "alert.suspicious_exe_path.desc":
        "Executable '{exe}' is located in a suspicious folder"
        " and is communicating with {addr}:{port}.",
    "alert.tor_connection.desc":
        "{name} (PID {pid}) connected to {addr}:{port}"
        " (Tor port — anonymisation network).",
    "alert.high_risk_country.desc":
        "{name} (PID {pid}) is communicating with {addr}:{port}"
        " in {country} ({cc}).",
    "alert.mining_pool.desc":
        "{name} (PID {pid}) connected to {addr}:{port}"
        " (typical mining pool port).",
    "alert.beaconing.desc":
        "{name} (PID {pid}) connects to {addr} at regular intervals"
        " every {mean:.1f} s (±{std:.1f} s, {count} connections)."
        " This behaviour is typical of malware communicating with a C2 server.",
    "alert.connection_flood.desc":
        "{name} (PID {pid}) connected to {count} unique remote IPs within 60 s."
        "\n\nSample IPs: {ips}",
    "alert.flood.more_ips": " … (+{count} more)",

    # ── Alert type explanations (detail pane) ─────────────────────────────────
    "info.malware_port":
        "This port is traditionally associated with trojans, RATs (Remote Access Trojans)"
        " or backdoor software. Legitimate applications almost never use it.",
    "info.suspicious_port":
        "Unusual port — less typical for standard internet traffic."
        " May indicate proxy usage, tunnelling, or an alternative protocol.",
    "info.critical_process":
        "This Windows system tool (LOLBin) should not normally initiate outbound"
        " network connections. Attackers use it because it is Microsoft-signed and"
        " bypasses many security tools.",
    "info.warning_process":
        "A process like cmd.exe or powershell.exe may have a legitimate reason"
        " for network communication (Windows Update scripts, IT automation…),"
        " but it is also the most common attack vector and is worth investigating.",
    "info.suspicious_exe_path":
        "The executable is located in a path attackers typically choose because"
        " it is writable without admin rights (Temp, Downloads, Desktop)."
        " Legitimate applications are usually installed in Program Files.",
    "info.tor_connection":
        "Tor is an anonymisation network. It may have legitimate uses (privacy, journalism),"
        " but it is also widely used by malware to hide C2 communication and exfiltrate data.",
    "info.mining_pool":
        "This port is typical for cryptocurrency mining pools. If you have not"
        " started any mining, this may be cryptojacking — mining on your hardware"
        " by a third party.",
    "info.high_risk_country":
        "Connection to a country with a higher incidence of cyber threats."
        " This is not necessarily malicious — CDN networks, cloud providers and"
        " legitimate SaaS companies have infrastructure worldwide."
        " Pay extra attention when the process is unknown.",
    "info.beaconing":
        "Regular connections to the same IP at constant intervals is the hallmark"
        " behaviour of malware communicating with a C2 (command & control) server."
        " The implant checks in regularly and waits for instructions.",
    "info.connection_flood":
        "A single process connected to a large number of unique IPs in a short time."
        " This may indicate: port scanning, a UDP broadcast storm, a misconfigured"
        " application, or botnet activity. Verify which application this is.",

    # ── Kernel PID explanations ───────────────────────────────────────────────
    "pid_info.0":
        "PID 0 — System Idle Process\n\n"
        "This pseudo-process represents CPU idle time. Network connections attributed"
        " to PID 0 are low-level system or kernel connections whose owner Windows"
        " cannot determine. These are typically network operations performed directly"
        " in the OS kernel (TCP/IP stack, firewall, VPN driver…).\n\n"
        "⚠ This is very likely a false positive.",
    "pid_info.4":
        "PID 4 — System\n\n"
        "The Windows kernel process responsible for low-level network operations:"
        " SMB (file shares), NetBIOS, Windows Update kernel cache, NTFS, and similar."
        " Network activity from PID 4 is usually legitimate.\n\n"
        "If you see unusual destinations (unknown IPs, high-risk countries), it is"
        " worth investigating — otherwise this is normal traffic.",

    # ── Tray ──────────────────────────────────────────────────────────────────
    "tray.starting":           "Network Watchdog — Starting…",
    "tray.status_ok":          "Network Watchdog — Monitoring",
    "tray.status_paused":      "Network Watchdog — Paused",
    "tray.status_alerts":      "Network Watchdog — {count} alert(s) (1 h)",
    "tray.menu_status_ok":     "Network Watchdog — OK",
    "tray.menu_status_alerts": "Network Watchdog — {count} alert(s)",
    "tray.menu_view_alerts":   "View Alerts",
    "tray.menu_view_report":   "View HTML Report",
    "tray.menu_pause":         "Pause Monitoring",
    "tray.menu_resume":        "Resume Monitoring",
    "tray.menu_quit":          "Quit",

    # ── UI — general ──────────────────────────────────────────────────────────
    "ui.window_title":      "Network Watchdog",
    "ui.header_title":      "🛡 Network Watchdog",
    "ui.header_alerts_24h": "24h: {count} alert(s)",
    "ui.header_critical":   "Critical: {count}",
    "ui.header_monitoring": "● MONITORING",
    "ui.header_paused":     "● PAUSED",
    "ui.footer_logs":       "Logs: {path}",
    "ui.footer_open_logs":  "Open log folder",

    # ── UI — tabs ─────────────────────────────────────────────────────────────
    "ui.tab_dashboard": "📊  Dashboard",
    "ui.tab_alerts":    "🔔  Alerts",
    "ui.tab_live":      "📡  Live",

    # ── UI — dashboard ────────────────────────────────────────────────────────
    "ui.dash.stat_total":       "Total alerts (24 h)",
    "ui.dash.stat_critical":    "Critical alerts (24 h)",
    "ui.dash.stat_countries":   "High-risk countries (24 h)",
    "ui.dash.chart_title":      "ALERTS — LAST 12 HOURS",
    "ui.dash.top_processes":    "TOP ALERTED PROCESSES",
    "ui.dash.top_destinations": "TOP REMOTE DESTINATIONS",
    "ui.dash.no_data":          "No data",
    "ui.dash.unknown":          "Unknown",

    # ── UI — alerts tab ───────────────────────────────────────────────────────
    "ui.alerts.filter_all":        "ALL",
    "ui.alerts.col_time":          "Time",
    "ui.alerts.col_severity":      "Severity",
    "ui.alerts.col_type":          "Type",
    "ui.alerts.col_title":         "Alert",
    "ui.alerts.col_process":       "Process",
    "ui.alerts.col_address":       "Address",
    "ui.alerts.col_country":       "Country",
    "ui.alerts.updated_at":        "Updated: {time}",
    "ui.alerts.detail_title":      "Alert detail",
    "ui.alerts.section_detail":    "DETAIL",
    "ui.alerts.field_time":        "Time:",
    "ui.alerts.field_type":        "Type:",
    "ui.alerts.samples_ip":        "Sample IPs:",
    "ui.alerts.section_process":   "PROCESS",
    "ui.alerts.field_name":        "Name:",
    "ui.alerts.field_pid":         "PID:",
    "ui.alerts.field_path":        "Path:",
    "ui.alerts.section_target":    "TARGET",
    "ui.alerts.field_address":     "Address:",
    "ui.alerts.field_country":     "Country:",
    "ui.alerts.country_resolving": "resolving… (up to 15 s)",
    "ui.alerts.high_risk_suffix":  "  ⚠ HIGH-RISK COUNTRY",
    "ui.alerts.section_whatisit":  "WHAT DOES THIS MEAN?",
    "ui.alerts.copy_ip":           "📋 Copy IP",

    # ── main.py messages ──────────────────────────────────────────────────────
    "main.requesting_elevation":
        "Requesting administrator privileges (required to see all connections)…",
    "main.elevation_warning":
        "WARNING: System connections may be hidden without administrator rights.",
    "main.already_running_body":
        "Network Traffic Watchdog is already running.\n\nLook for the icon in the system tray.",

    # ── HTML report ───────────────────────────────────────────────────────────
    "report.no_alerts":     "No alerts in the last 24 hours.",
    "report.no_data":       "No data",
    "report.unknown":       "Unknown",
    "report.generated_at":  "Generated: {time} \u00a0|\u00a0 Auto-refresh every 60 s",
    "report.stat_total":    "Total alerts (24 h)",
    "report.stat_critical": "Critical alerts (24 h)",
    "report.top_processes": "Top alerted processes",
    "report.top_ips":       "Top remote IPs",
    "report.alerts_24h":    "Alerts — last 24 hours",
    "report.col_time":      "Time",
    "report.col_severity":  "Severity",
    "report.col_type":      "Type",
    "report.col_title":     "Alert",
    "report.col_process":   "Process",
    "report.col_address":   "Remote address",

    # ── UI — live tab ─────────────────────────────────────────────────────────
    "ui.live.title":       "Live Network Connections",
    "ui.live.col_pid":     "PID",
    "ui.live.col_process": "Process",
    "ui.live.col_target":  "Target",
    "ui.live.col_port":    "Port",
    "ui.live.col_status":  "Status",
    "ui.live.col_country": "Country",
    "ui.live.col_risk":    "!",
    "ui.live.auto_on":     "⟳ Auto-refresh: ON",
    "ui.live.auto_off":    "⟳ Auto-refresh: OFF",
}
