"""
Network Traffic Watchdog — HTML report generator
"""
from datetime import datetime
import config
from i18n import t


def generate_report(db) -> str:
    """Write an HTML report to DATA_DIR/report.html and return the file path."""
    alerts = db.get_recent_alerts(hours=24)
    stats  = db.get_stats()
    now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Alert table rows ──────────────────────────────────────────────────────
    sev_color = {
        "critical": "#FF4444",
        "high":     "#FF8844",
        "medium":   "#FFCC44",
        "low":      "#66CC66",
    }

    rows_html = ""
    for a in alerts:
        color  = sev_color.get(a["severity"], "#ffffff")
        ts     = a["timestamp"][:16].replace("T", " ")
        remote = (
            f"{a['remote_addr']}:{a['remote_port']}"
            if a["remote_addr"] else "—"
        )
        rows_html += f"""
        <tr>
          <td>{ts}</td>
          <td><span class="badge" style="background:{color}">{a['severity'].upper()}</span></td>
          <td>{a['alert_type']}</td>
          <td>{a['title']}</td>
          <td>{a['process_name'] or '—'}</td>
          <td class="mono">{remote}</td>
        </tr>"""

    if not rows_html:
        rows_html = f"""
        <tr>
          <td colspan="6" style="text-align:center;color:#555;padding:30px">
            {t("report.no_alerts")}
          </td>
        </tr>"""

    # ── Top processes ─────────────────────────────────────────────────────────
    _unknown = t("report.unknown")
    _no_data = f"<li style='color:#555'>{t('report.no_data')}</li>"

    top_proc_html = "".join(
        f'<li><strong>{r["process_name"] or _unknown}</strong>'
        f' &nbsp;<span class="cnt">{r["cnt"]}</span></li>'
        for r in stats["top_processes"]
    ) or _no_data

    top_ip_html = "".join(
        f'<li><code>{r["remote_addr"] or _unknown}</code>'
        f' &nbsp;<span class="cnt">{r["cnt"]}</span></li>'
        for r in stats["top_ips"]
    ) or _no_data

    # ── Full HTML ─────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="{config.LANGUAGE}">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="60">
  <title>Network Watchdog — Report</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body   {{ margin:0; padding:24px; background:#121212; color:#e0e0e0;
             font-family:'Segoe UI',Arial,sans-serif; font-size:14px; }}
    h1     {{ color:#4FC3F7; margin:0 0 4px; font-size:28px; }}
    h2     {{ color:#4FC3F7; border-bottom:1px solid #333; padding-bottom:6px;
             font-size:18px; margin-top:32px; }}
    p.sub  {{ color:#777; margin:0 0 24px; font-size:12px; }}

    .stat-row  {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:24px; }}
    .stat-card {{ background:#1e1e1e; border:1px solid #2a2a2a; border-radius:8px;
                 padding:18px 24px; min-width:160px; flex:1; }}
    .stat-card .lbl {{ color:#888; font-size:11px; text-transform:uppercase;
                      letter-spacing:.08em; }}
    .stat-card .val {{ font-size:42px; font-weight:700; color:#fff; line-height:1; }}
    .stat-card.crit .val {{ color:#FF4444; }}

    .two-col {{ display:flex; gap:32px; flex-wrap:wrap; }}
    .two-col > div {{ flex:1; min-width:220px; }}
    ul {{ padding-left:18px; line-height:2; }}
    li  {{ color:#ccc; }}
    .cnt {{ background:#333; border-radius:4px; padding:1px 8px;
           font-size:12px; color:#FF8800; font-weight:700; }}
    code {{ background:#1e1e1e; color:#64B5F6; padding:2px 6px; border-radius:3px; }}

    table  {{ width:100%; border-collapse:collapse; margin-top:12px; }}
    th     {{ background:#1e1e1e; color:#888; font-size:11px; text-transform:uppercase;
             letter-spacing:.08em; padding:10px 12px; text-align:left; }}
    td     {{ padding:9px 12px; border-bottom:1px solid #1e1e1e;
             vertical-align:top; }}
    tr:hover td {{ background:#1a1a2e; }}

    .badge {{ display:inline-block; border-radius:4px; padding:2px 8px;
             font-size:11px; font-weight:700; color:#000; }}
    .mono  {{ font-family:Consolas,monospace; font-size:12px; }}

    footer {{ text-align:center; color:#444; margin-top:48px; font-size:11px; }}
  </style>
</head>
<body>
  <h1>🛡 Network Watchdog</h1>
  <p class="sub">{t("report.generated_at", time=now)}</p>

  <div class="stat-row">
    <div class="stat-card">
      <div class="lbl">{t("report.stat_total")}</div>
      <div class="val">{stats['total_alerts_24h']}</div>
    </div>
    <div class="stat-card crit">
      <div class="lbl">{t("report.stat_critical")}</div>
      <div class="val">{stats['critical_alerts_24h']}</div>
    </div>
  </div>

  <div class="two-col">
    <div>
      <h2>{t("report.top_processes")}</h2>
      <ul>{top_proc_html}</ul>
    </div>
    <div>
      <h2>{t("report.top_ips")}</h2>
      <ul>{top_ip_html}</ul>
    </div>
  </div>

  <h2>{t("report.alerts_24h")}</h2>
  <table>
    <thead>
      <tr>
        <th>{t("report.col_time")}</th>
        <th>{t("report.col_severity")}</th>
        <th>{t("report.col_type")}</th>
        <th>{t("report.col_title")}</th>
        <th>{t("report.col_process")}</th>
        <th>{t("report.col_address")}</th>
      </tr>
    </thead>
    <tbody>{rows_html}</tbody>
  </table>

  <footer>Network Watchdog &nbsp;|&nbsp; {config.BASE_DIR}</footer>
</body>
</html>"""

    path = config.REPORT_PATH
    path.write_text(html, encoding="utf-8")
    return str(path)
