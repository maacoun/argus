"""Czech (cs) strings for Network Traffic Watchdog."""

STRINGS: dict[str, str] = {

    # ── Severity labels ────────────────────────────────────────────────────────
    "sev.critical": "● KRITICKÉ",
    "sev.high":     "▲ VYSOKÉ",
    "sev.medium":   "◆ STŘEDNÍ",
    "sev.low":      "▸ NÍZKÉ",

    # ── Alert titles ──────────────────────────────────────────────────────────
    "alert.malware_port.title":        "Spojení na port {port} — known malware port",
    "alert.suspicious_port.title":     "Spojení na neobvyklý port {port}",
    "alert.critical_process.title":    "Podezřelý proces otevřel síťové spojení: {name}",
    "alert.warning_process.title":     "Pozor — síťové spojení od: {name}",
    "alert.suspicious_exe_path.title": "Proces spuštěný z podezřelého umístění: {name}",
    "alert.tor_connection.title":      "Možné Tor spojení zjištěno",
    "alert.high_risk_country.title":   "Spojení do rizikové země: {flag} {country} ({cc})",
    "alert.mining_pool.title":         "Možná těžba kryptoměn zjištěna",
    "alert.beaconing.title":           "Detekováno beaconing / C2 komunikace",
    "alert.connection_flood.title":    "Detekován flood spojení / port scan",

    # ── Alert descriptions ────────────────────────────────────────────────────
    "alert.malware_port.desc":
        "{name} (PID {pid}) se připojil na {addr}:{port} — {reason}",
    "alert.suspicious_port.desc":
        "{name} (PID {pid}) se připojil na {addr}:{port} — {reason}",
    "alert.critical_process.desc":
        "{name} (PID {pid}) se připojil na {addr}:{port}. Důvod: {reason}",
    "alert.warning_process.desc":
        "{name} (PID {pid}) se připojil na {addr}:{port}. Důvod: {reason}",
    "alert.suspicious_exe_path.desc":
        "Spustitelný soubor '{exe}' se nachází v podezřelé složce"
        " a komunikuje s {addr}:{port}.",
    "alert.tor_connection.desc":
        "{name} (PID {pid}) se připojil na {addr}:{port}"
        " (Tor port — anonymizační síť).",
    "alert.high_risk_country.desc":
        "{name} (PID {pid}) komunikuje s {addr}:{port} v {country} ({cc}).",
    "alert.mining_pool.desc":
        "{name} (PID {pid}) se připojil na {addr}:{port}"
        " (typický port těžebního poolu).",
    "alert.beaconing.desc":
        "{name} (PID {pid}) se připojuje na {addr} v pravidelných intervalech"
        " každých {mean:.1f} s (±{std:.1f} s, {count} spojení)."
        " Toto chování je typické pro malware komunikující s C2 serverem.",
    "alert.connection_flood.desc":
        "{name} (PID {pid}) se během 60 s připojil na {count} různých IP adres."
        "\n\nVzorky IP: {ips}",
    "alert.flood.more_ips": " … (+{count} dalších)",

    # ── Alert type explanations (detail pane) ─────────────────────────────────
    "info.malware_port":
        "Port je tradičně asociován s trojskými koni, RAT (Remote Access Trojan)"
        " nebo backdoor software. Legitimní aplikace tento port téměř nikdy nepoužívají.",
    "info.suspicious_port":
        "Neobvyklý port — méně typický pro standardní internetový provoz."
        " Může jít o proxy, tunelování nebo alternativní protokol.",
    "info.critical_process":
        "Tento Windows systémový nástroj (LOLBin) by za normálních okolností"
        " neměl navazovat odchozí síťová spojení. Útočníci ho používají,"
        " protože je podepsaný Microsoftem a obchází řadu bezpečnostních nástrojů.",
    "info.warning_process":
        "Proces jako cmd.exe nebo powershell.exe může mít legitimní důvod"
        " pro síťovou komunikaci (Windows Update skripty, automatizace IT…),"
        " ale je také nejčastějším nástrojem útoků a stojí za prověření.",
    "info.suspicious_exe_path":
        "Spustitelný soubor se nachází v umístění, které útočníci typicky"
        " volí, protože je zapisovatelné bez admin práv (Temp, Downloads, Desktop)."
        " Legitimní aplikace se obvykle instalují do Program Files.",
    "info.tor_connection":
        "Tor je anonymizační síť. Může mít legitimní použití (soukromí, novinářství),"
        " ale je také hojně využívána malwarem k skrytí C2 komunikace a exfiltraci dat.",
    "info.mining_pool":
        "Port typický pro těžební pooly kryptoměn. Pokud jste žádnou těžbu"
        " nespustili, může jít o cryptojacking — cizí těžbu na vašem hardwaru.",
    "info.high_risk_country":
        "Spojení do země s vyšším výskytem kybernetických hrozeb."
        " Samo o sobě nemusí být škodlivé — CDN sítě, cloudoví poskytovatelé"
        " a legitimní SaaS mají infrastrukturu po celém světě."
        " Vyšší pozornost je namístě zejména u neznámých procesů.",
    "info.beaconing":
        "Pravidelné spojení ke stejné IP v konstantních intervalech je"
        " typickým chováním malwaru komunikujícího s C2 (command & control) serverem."
        " Implantát se pravidelně hlásí a čeká na instrukce.",
    "info.connection_flood":
        "Jeden proces se za krátkou dobu připojil na velké množství různých"
        " IP adres. Může jít o: port scan, UDP broadcast storm, špatně nakonfigurovanou"
        " aplikaci nebo botnet aktivitu. Ověřte o jakou aplikaci jde.",

    # ── Kernel PID explanations ───────────────────────────────────────────────
    "pid_info.0":
        "PID 0 — System Idle Process\n\n"
        "Tento pseudo-proces reprezentuje nečinnost CPU. Síťová spojení přiřazená"
        " k PID 0 jsou nízkoúrovňová systémová nebo kernel spojení, u nichž Windows"
        " nedokáže určit vlastníka. Obvykle jde o síťové operace prováděné přímo"
        " v jádru OS (TCP/IP stack, firewall, VPN driver…).\n\n"
        "⚠ Toto je velmi pravděpodobně falešný poplach.",
    "pid_info.4":
        "PID 4 — System\n\n"
        "Jádrový proces Windows zodpovědný za nízkoúrovňové síťové operace:"
        " SMB (sdílené složky), NetBIOS, Windows Update kernel cache, NTFS a podobné."
        " Síťová aktivita PID 4 bývá legitimní.\n\n"
        "Pokud vidíte neobvyklé cíle (neznámé IP, rizikové země), stojí za"
        " bližší zkoumání — jinak je to normální provoz.",

    # ── Tray ──────────────────────────────────────────────────────────────────
    "tray.starting":           "Network Watchdog — Spouštím…",
    "tray.status_ok":          "Network Watchdog — Monitoruji",
    "tray.status_paused":      "Network Watchdog — Pozastaveno",
    "tray.status_alerts":      "Network Watchdog — {count} výstrah (1 h)",
    "tray.menu_status_ok":     "Network Watchdog — OK",
    "tray.menu_status_alerts": "Network Watchdog — {count} výstrah",
    "tray.menu_view_alerts":   "Zobrazit výstrahy",
    "tray.menu_view_report":   "Zobrazit HTML report",
    "tray.menu_pause":         "Pozastavit monitoring",
    "tray.menu_resume":        "Pokračovat v monitorování",
    "tray.menu_quit":          "Ukončit",

    # ── UI — general ──────────────────────────────────────────────────────────
    "ui.window_title":      "Network Watchdog",
    "ui.header_title":      "🛡 Network Watchdog",
    "ui.header_alerts_24h": "24h: {count} výstrah",
    "ui.header_critical":   "Kritické: {count}",
    "ui.header_monitoring": "● MONITORUJI",
    "ui.header_paused":     "● POZASTAVENO",
    "ui.footer_logs":       "Logy: {path}",
    "ui.footer_open_logs":  "Otevřít složku s logy",

    # ── UI — tabs ─────────────────────────────────────────────────────────────
    "ui.tab_dashboard": "📊  Dashboard",
    "ui.tab_alerts":    "🔔  Výstrahy",
    "ui.tab_live":      "📡  Živá spojení",

    # ── UI — dashboard ────────────────────────────────────────────────────────
    "ui.dash.stat_total":       "Celkem výstrah (24 h)",
    "ui.dash.stat_critical":    "Kritické výstrahy (24 h)",
    "ui.dash.stat_countries":   "Rizikové země (24 h)",
    "ui.dash.chart_title":      "VÝSTRAHY — POSLEDNÍCH 12 HODIN",
    "ui.dash.top_processes":    "TOP PROCESY S VÝSTRAHAMI",
    "ui.dash.top_destinations": "TOP VZDÁLENÉ DESTINACE",
    "ui.dash.no_data":          "Žádná data",
    "ui.dash.unknown":          "Neznámý",

    # ── UI — alerts tab ───────────────────────────────────────────────────────
    "ui.alerts.filter_all":        "VŠE",
    "ui.alerts.col_time":          "Čas",
    "ui.alerts.col_severity":      "Závažnost",
    "ui.alerts.col_type":          "Typ",
    "ui.alerts.col_title":         "Výstraha",
    "ui.alerts.col_process":       "Proces",
    "ui.alerts.col_address":       "Adresa",
    "ui.alerts.col_country":       "Země",
    "ui.alerts.updated_at":        "Aktualizováno: {time}",
    "ui.alerts.detail_title":      "Detail výstrahy",
    "ui.alerts.section_detail":    "DETAIL",
    "ui.alerts.field_time":        "Čas:",
    "ui.alerts.field_type":        "Typ:",
    "ui.alerts.samples_ip":        "Vzorky IP:",
    "ui.alerts.section_process":   "PROCES",
    "ui.alerts.field_name":        "Název:",
    "ui.alerts.field_pid":         "PID:",
    "ui.alerts.field_path":        "Cesta:",
    "ui.alerts.section_target":    "CÍL",
    "ui.alerts.field_address":     "Adresa:",
    "ui.alerts.field_country":     "Země:",
    "ui.alerts.country_resolving": "zjišťuji… (do 15 s)",
    "ui.alerts.high_risk_suffix":  "  ⚠ RIZIKOVÁ ZEMĚ",
    "ui.alerts.section_whatisit":  "CO TO ZNAMENÁ?",
    "ui.alerts.copy_ip":           "📋 Kopírovat IP",

    # ── main.py messages ──────────────────────────────────────────────────────
    "main.requesting_elevation":
        "Žádám o oprávnění správce (nutné pro sledování všech spojení)…",
    "main.elevation_warning":
        "VAROVÁNÍ: Bez práv správce mohou být skryta systémová spojení.",
    "main.already_running_body":
        "Network Traffic Watchdog již běží.\n\nHledejte ikonu v systémovém trayi.",

    # ── HTML report ───────────────────────────────────────────────────────────
    "report.no_alerts":     "Žádné výstrahy v posledních 24 hodinách.",
    "report.no_data":       "Žádná data",
    "report.unknown":       "Neznámý",
    "report.generated_at":  "Vygenerováno: {time} \u00a0|\u00a0 Automatická aktualizace každých 60 s",
    "report.stat_total":    "Celkem výstrah (24 h)",
    "report.stat_critical": "Kritické výstrahy (24 h)",
    "report.top_processes": "Top procesy s výstrahami",
    "report.top_ips":       "Top vzdálené IP adresy",
    "report.alerts_24h":    "Výstrahy za posledních 24 hodin",
    "report.col_time":      "Čas",
    "report.col_severity":  "Závažnost",
    "report.col_type":      "Typ",
    "report.col_title":     "Název výstrahy",
    "report.col_process":   "Proces",
    "report.col_address":   "Vzdálená adresa",

    # ── UI — live tab ─────────────────────────────────────────────────────────
    "ui.live.title":       "Živá síťová spojení",
    "ui.live.col_pid":     "PID",
    "ui.live.col_process": "Proces",
    "ui.live.col_target":  "Cíl",
    "ui.live.col_port":    "Port",
    "ui.live.col_status":  "Stav",
    "ui.live.col_country": "Země",
    "ui.live.col_risk":    "!",
    "ui.live.auto_on":     "⟳ Auto-refresh: ZAP",
    "ui.live.auto_off":    "⟳ Auto-refresh: VYP",
}
