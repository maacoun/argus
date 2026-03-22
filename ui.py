"""
Network Traffic Watchdog — GUI (tkinter, dark GitHub-style theme)

Tabs:
  1. Dashboard  — stat cards, 12-hour alert timeline, top processes/countries
  2. Alerts     — filterable alert log with detail pane + copy-IP
  3. Live       — auto-refreshing connection table with country flags
"""
import threading
import logging
import webbrowser
from datetime import datetime
from typing import Optional

import tkinter as tk
from tkinter import ttk

import config
from geoip import geoip_cache, flag_emoji
from i18n import t, maybe

# Lazy import to avoid circular dependency at module load time
# (config is imported before detector in some test scenarios)


logger = logging.getLogger("watchdog.ui")

# ── Colour palette (GitHub dark) ──────────────────────────────────────────────
BG      = "#0d1117"
CARD    = "#161b22"
CARD2   = "#21262d"
BG3     = "#1c2128"   # tab hover
BORDER  = "#30363d"
FG      = "#e6edf3"
FG_DIM  = "#7d8590"
FG_MUTE = "#484f58"
ACCENT  = "#58a6ff"
GREEN   = "#3fb950"
YELLOW  = "#e3b341"
ORANGE  = "#d29922"
RED     = "#f85149"
PURPLE  = "#bc8cff"

SEV_COLOR = {
    "critical": RED,
    "high":     ORANGE,
    "medium":   YELLOW,
    "low":      GREEN,
}

SEV_LABEL = {
    "critical": t("sev.critical"),
    "high":     t("sev.high"),
    "medium":   t("sev.medium"),
    "low":      t("sev.low"),
}



# ── Helpers ───────────────────────────────────────────────────────────────────

def _apply_theme():
    s = ttk.Style()
    s.theme_use("clam")

    s.configure("Treeview",
                background=CARD,   foreground=FG,
                fieldbackground=CARD, rowheight=28,
                borderwidth=0,     font=("Segoe UI", 9))
    s.configure("Treeview.Heading",
                background=BG,     foreground=FG_DIM,
                font=("Segoe UI", 9, "bold"), relief="flat")
    s.map("Treeview",
          background=[("selected", ACCENT)],
          foreground=[("selected", "#000000")])

    s.configure("Vertical.TScrollbar",
                background=CARD2,  troughcolor=CARD,
                arrowcolor=FG_DIM, borderwidth=0, width=10)
    s.configure("TSeparator", background=BORDER)


def _label(parent, text, font=("Segoe UI", 10), fg=FG, bg=BG, **kw) -> tk.Label:
    return tk.Label(parent, text=text, font=font, fg=fg, bg=bg, **kw)


def _frame(parent, bg=BG, **kw) -> tk.Frame:
    return tk.Frame(parent, bg=bg, **kw)


def _card(parent, **kw) -> tk.Frame:
    f = tk.Frame(parent, bg=CARD, highlightbackground=BORDER,
                 highlightthickness=1, **kw)
    return f


def _btn(parent, text, cmd, bg=CARD2, fg=FG, font=("Segoe UI", 9)) -> tk.Label:
    """Clickable label that looks like a button."""
    lbl = tk.Label(parent, text=text, font=font, fg=fg, bg=bg,
                   padx=12, pady=4, cursor="hand2")
    lbl.bind("<Button-1>", lambda _e: cmd())
    lbl.bind("<Enter>",    lambda _e: lbl.config(bg=BORDER))
    lbl.bind("<Leave>",    lambda _e: lbl.config(bg=bg))
    return lbl


# ── Chart helpers ─────────────────────────────────────────────────────────────

def _draw_bar_chart(canvas: tk.Canvas, data: list[tuple[str, int]],
                    bar_color_fn=None):
    """
    Draw a vertical bar chart on *canvas*.
    data: [(label, count), ...]   — displayed left to right
    """
    canvas.update_idletasks()
    w = canvas.winfo_width()  or 400
    h = canvas.winfo_height() or 100
    canvas.delete("all")

    if not data:
        canvas.create_text(w // 2, h // 2, text=t("ui.dash.no_data"),
                           fill=FG_MUTE, font=("Segoe UI", 9))
        return

    n       = len(data)
    max_val = max(c for _, c in data) or 1
    pad_x   = 6
    pad_y   = 6
    label_h = 16
    bar_area_h = h - pad_y * 2 - label_h
    bar_w      = (w - pad_x * 2) / n

    for i, (label, count) in enumerate(data):
        x0 = pad_x + i * bar_w + 1
        x1 = pad_x + (i + 1) * bar_w - 1
        bar_h = (count / max_val) * bar_area_h if max_val > 0 else 0
        y0 = pad_y + bar_area_h - bar_h
        y1 = pad_y + bar_area_h

        color = (bar_color_fn(count) if bar_color_fn
                 else (RED if count > 5 else YELLOW if count > 0 else FG_MUTE))
        canvas.create_rectangle(x0, y0, x1, y1, fill=color, outline="")

        if count > 0:
            canvas.create_text((x0 + x1) / 2, max(y0 - 9, pad_y),
                                text=str(count), fill=FG,
                                font=("Segoe UI", 7, "bold"))
        canvas.create_text((x0 + x1) / 2, h - pad_y,
                            text=label, fill=FG_DIM,
                            font=("Segoe UI", 7), anchor="s")


def _draw_h_bars(canvas: tk.Canvas, data: list[tuple[str, int]], color=ACCENT):
    """Draw horizontal proportion bars next to labels on *canvas*."""
    canvas.update_idletasks()
    w = canvas.winfo_width()  or 300
    h = canvas.winfo_height() or 120
    canvas.delete("all")

    if not data:
        return

    n       = len(data)
    row_h   = h / n
    max_val = max(v for _, v in data) or 1
    label_w = 140
    bar_max = w - label_w - 50

    for i, (label, val) in enumerate(data):
        y    = i * row_h
        mid  = y + row_h / 2
        bar_w = (val / max_val) * bar_max

        canvas.create_text(4, mid, text=label[:22], anchor="w",
                           fill=FG, font=("Segoe UI", 9))
        canvas.create_rectangle(label_w, mid - 5,
                                 label_w + bar_w, mid + 5,
                                 fill=color, outline="")
        canvas.create_text(label_w + bar_w + 6, mid,
                            text=str(val), anchor="w",
                            fill=FG_DIM, font=("Segoe UI", 8))


# ── Custom notebook (consistent tab heights + accent underline) ───────────────

class _CustomNotebook(tk.Frame):
    """
    Replaces ttk.Notebook.  All tabs have identical height; the active tab
    is indicated by a 2-px ACCENT underline instead of ttk's "merge with
    content" trick (which always made the selected tab look shorter).
    """

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG, **kw)

        # Tab strip
        self._bar = tk.Frame(self, bg=CARD2)
        self._bar.pack(fill="x", side="top")
        tk.Frame(self._bar, bg=BORDER, height=1).pack(fill="x", side="bottom")

        # Content host — all tab frames are stacked here via place()
        self._host = tk.Frame(self, bg=BG)
        self._host.pack(fill="both", expand=True)

        # (wrapper, label, indicator, content_frame)
        self._tabs: list[tuple] = []
        self._active = -1

    def add(self, text: str) -> tk.Frame:
        """Create a tab labelled *text* and return its content frame."""
        idx = len(self._tabs)

        wrap = tk.Frame(self._bar, bg=CARD2, cursor="hand2")
        wrap.pack(side="left")

        lbl = tk.Label(wrap, text=text,
                       font=("Segoe UI", 10), padx=18, pady=9,
                       bg=CARD2, fg=FG_DIM, cursor="hand2")
        lbl.pack(side="top")

        # Accent underline (hidden when tab is inactive)
        ind = tk.Frame(wrap, bg=CARD2, height=2)
        ind.pack(fill="x", side="bottom")

        content = tk.Frame(self._host, bg=BG)

        def _click(_e=None, i=idx):
            self._select(i)

        def _enter(_e=None, i=idx, w=wrap, l=lbl):
            if i != self._active:
                w.config(bg=BG3)
                l.config(bg=BG3)

        def _leave(_e=None, w=wrap):
            # Only un-hover if the pointer truly left the tab wrapper
            mx, my = w.winfo_pointerxy()
            wx, wy = w.winfo_rootx(), w.winfo_rooty()
            if not (wx <= mx < wx + w.winfo_width() and
                    wy <= my < wy + w.winfo_height()):
                self._restyle()

        for widget in (wrap, lbl):
            widget.bind("<Button-1>", _click)
            widget.bind("<Enter>",    _enter)
            widget.bind("<Leave>",    _leave)

        self._tabs.append((wrap, lbl, ind, content))
        if idx == 0:
            self._select(0)
        return content

    def _select(self, idx: int):
        self._active = idx
        self._restyle()

    def _restyle(self):
        for i, (wrap, lbl, ind, content) in enumerate(self._tabs):
            active = (i == self._active)
            wrap.config(bg=CARD  if active else CARD2)
            lbl .config(bg=CARD  if active else CARD2,
                        fg=FG    if active else FG_DIM)
            ind .config(bg=ACCENT if active else CARD2)
            if active:
                content.place(in_=self._host, x=0, y=0, relwidth=1, relheight=1)
                content.lift()
            else:
                content.place_forget()


# ── Main window ───────────────────────────────────────────────────────────────

class AlertsWindow:
    def __init__(self, db, monitor=None):
        self._db      = db
        self._monitor = monitor

    def show(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    # ── Bootstrap ─────────────────────────────────────────────────────────────

    def _run(self):
        root = tk.Tk()
        root.title(t("ui.window_title"))
        root.geometry("1200x760")
        root.minsize(900, 600)
        root.configure(bg=BG)
        self._root = root

        _apply_theme()
        self._build_header(root)

        nb = _CustomNotebook(root)
        nb.pack(fill="both", expand=True)

        f1 = nb.add(t("ui.tab_dashboard"))
        self._tab_dashboard(f1)

        f2 = nb.add(t("ui.tab_alerts"))
        self._tab_alerts(f2)

        f3 = nb.add(t("ui.tab_live"))
        self._tab_live(f3)

        self._build_footer(root)
        root.mainloop()

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self, root):
        hf = _frame(root, bg=CARD)
        hf.pack(fill="x")
        tk.Frame(hf, bg=BORDER, height=1).pack(fill="x", side="bottom")

        inner = _frame(hf, bg=CARD)
        inner.pack(fill="x", padx=20, pady=10)

        # Left: title
        _label(inner, t("ui.header_title"),
               font=("Segoe UI", 16, "bold"), bg=CARD, fg=FG).pack(side="left")

        # Right: live pill badges
        right = _frame(inner, bg=CARD)
        right.pack(side="right")

        stats = self._db.get_stats()
        self._header_pill(right, t("ui.header_alerts_24h", count=stats['total_alerts_24h']), FG_DIM)
        self._header_pill(right, t("ui.header_critical", count=stats['critical_alerts_24h']),
                          RED if stats["critical_alerts_24h"] else FG_MUTE)
        is_paused    = self._monitor and self._monitor.is_paused
        status_color = YELLOW if is_paused else GREEN
        self._header_pill(right,
                          t("ui.header_paused") if is_paused else t("ui.header_monitoring"),
                          status_color)

    def _header_pill(self, parent, text, color):
        lbl = tk.Label(parent, text=text, font=("Segoe UI", 9, "bold"),
                       fg=color, bg=CARD, padx=10, pady=3)
        lbl.pack(side="left", padx=4)

    # ── Footer ────────────────────────────────────────────────────────────────

    def _build_footer(self, root):
        ff = _frame(root, bg=CARD2)
        ff.pack(fill="x", side="bottom")
        tk.Frame(ff, bg=BORDER, height=1).pack(fill="x", side="top")

        inner = _frame(ff, bg=CARD2)
        inner.pack(fill="x", padx=16, pady=6)

        _label(inner, t("ui.footer_logs", path=config.LOG_DIR),
               font=("Segoe UI", 8), fg=FG_DIM, bg=CARD2).pack(side="left")

        _btn(inner, t("ui.footer_open_logs"),
             lambda: webbrowser.open(str(config.LOG_DIR)),
             bg=CARD, fg=ACCENT).pack(side="right", padx=4)

    # ── Tab 1: Dashboard ──────────────────────────────────────────────────────

    def _tab_dashboard(self, parent):
        stats = self._db.get_stats()

        # ── Top row: stat cards ───────────────────────────────────────────────
        top = _frame(parent)
        top.pack(fill="x", padx=16, pady=(14, 6))

        self._dash_total    = self._stat_card(top, t("ui.dash.stat_total"),
                                              stats["total_alerts_24h"], FG)
        self._dash_critical = self._stat_card(top, t("ui.dash.stat_critical"),
                                              stats["critical_alerts_24h"], RED)
        self._dash_countries= self._stat_card(top, t("ui.dash.stat_countries"),
                                              stats.get("flagged_countries", 0), PURPLE)

        # ── Alert timeline chart ──────────────────────────────────────────────
        chart_card = _card(parent)
        chart_card.pack(fill="x", padx=16, pady=6)

        hdr = _frame(chart_card, bg=CARD)
        hdr.pack(fill="x", padx=14, pady=(10, 4))
        _label(hdr, t("ui.dash.chart_title"),
               font=("Segoe UI", 9, "bold"), fg=FG_DIM, bg=CARD).pack(side="left")

        self._dash_chart = tk.Canvas(chart_card, bg=CARD, height=110,
                                     highlightthickness=0)
        self._dash_chart.pack(fill="x", padx=14, pady=(0, 10))

        self._dash_hourly = list(self._db.get_hourly_alert_counts(hours=12))
        self._dash_chart.after(100, lambda: _draw_bar_chart(self._dash_chart, self._dash_hourly))
        self._dash_chart.bind("<Configure>", lambda _e: _draw_bar_chart(self._dash_chart, self._dash_hourly))

        # ── Bottom row: Top processes + Top destinations ──────────────────────
        bottom = _frame(parent)
        bottom.pack(fill="both", expand=True, padx=16, pady=6)

        # Left: processes
        left_card = _card(bottom)
        left_card.pack(side="left", fill="both", expand=True, padx=(0, 6))

        _label(left_card, t("ui.dash.top_processes"),
               font=("Segoe UI", 9, "bold"), fg=FG_DIM, bg=CARD,
               padx=14, pady=10).pack(anchor="w")

        self._dash_proc_data = [(r["process_name"] or t("ui.dash.unknown"), r["cnt"])
                                for r in stats["top_processes"]]
        self._dash_pc = tk.Canvas(left_card, bg=CARD, height=130, highlightthickness=0)
        self._dash_pc.pack(fill="x", padx=14, pady=(0, 14))
        self._dash_pc.after(120, lambda: _draw_h_bars(self._dash_pc, self._dash_proc_data, ACCENT))
        self._dash_pc.bind("<Configure>", lambda _e: _draw_h_bars(self._dash_pc, self._dash_proc_data, ACCENT))

        # Right: countries + IPs
        right_card = _card(bottom)
        right_card.pack(side="left", fill="both", expand=True, padx=(6, 0))

        _label(right_card, t("ui.dash.top_destinations"),
               font=("Segoe UI", 9, "bold"), fg=FG_DIM, bg=CARD,
               padx=14, pady=10).pack(anchor="w")

        self._dash_dest_data = self._build_dest_data(stats)
        self._dash_dc = tk.Canvas(right_card, bg=CARD, height=130, highlightthickness=0)
        self._dash_dc.pack(fill="x", padx=14, pady=(0, 14))
        self._dash_dc.after(140, lambda: _draw_h_bars(self._dash_dc, self._dash_dest_data, PURPLE))
        self._dash_dc.bind("<Configure>", lambda _e: _draw_h_bars(self._dash_dc, self._dash_dest_data, PURPLE))

    def _build_dest_data(self, stats: dict) -> list:
        country_rows = stats.get("top_countries", [])
        if country_rows:
            return [(f"{flag_emoji(r['country_code'])} {r['country'] or r['country_code']}",
                     r["cnt"]) for r in country_rows]
        return [(r["remote_addr"] or "?", r["cnt"]) for r in stats["top_ips"]]

    def _refresh_dashboard(self):
        """Update all Dashboard widgets in-place from the current DB state."""
        stats = self._db.get_stats()

        self._dash_total.set(str(stats["total_alerts_24h"]))
        self._dash_critical.set(str(stats["critical_alerts_24h"]))
        self._dash_countries.set(str(stats.get("flagged_countries", 0)))

        self._dash_hourly[:] = self._db.get_hourly_alert_counts(hours=12)
        _draw_bar_chart(self._dash_chart, self._dash_hourly)

        self._dash_proc_data[:] = [(r["process_name"] or t("ui.dash.unknown"), r["cnt"])
                                   for r in stats["top_processes"]]
        _draw_h_bars(self._dash_pc, self._dash_proc_data, ACCENT)

        self._dash_dest_data[:] = self._build_dest_data(stats)
        _draw_h_bars(self._dash_dc, self._dash_dest_data, PURPLE)

    def _stat_card(self, parent, label, value, color) -> tk.StringVar:
        var = tk.StringVar(value=str(value))
        card = _card(parent, padx=20, pady=16)
        card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        _label(card, label, font=("Segoe UI", 9), fg=FG_DIM, bg=CARD).pack(anchor="w")
        tk.Label(card, textvariable=var, font=("Segoe UI", 38, "bold"),
                 fg=color, bg=CARD).pack(anchor="w")
        return var

    # ── Tab 2: Alerts ─────────────────────────────────────────────────────────

    def _tab_alerts(self, parent):
        self._alert_sev_filter = tk.StringVar(value="ALL")
        self._all_alerts = self._db.get_recent_alerts(hours=24)
        self._filtered_alerts = self._all_alerts

        # ── Filter pills ──────────────────────────────────────────────────────
        pill_row = _frame(parent, bg=CARD2)
        pill_row.pack(fill="x")
        tk.Frame(pill_row, bg=BORDER, height=1).pack(fill="x", side="bottom")

        self._pills: dict[str, tk.Label] = {}
        for sev in ["ALL", "critical", "high", "medium", "low"]:
            text = t("ui.alerts.filter_all") if sev == "ALL" else SEV_LABEL.get(sev, sev.upper())
            color = SEV_COLOR.get(sev, FG_DIM)
            lbl = tk.Label(pill_row, text=text,
                           font=("Segoe UI", 9, "bold"),
                           fg=color, bg=CARD2, padx=14, pady=8,
                           cursor="hand2")
            lbl.pack(side="left")
            lbl.bind("<Button-1>", lambda _e, s=sev: self._set_sev_filter(s))
            self._pills[sev] = lbl
        self._set_sev_filter("ALL", redraw=False)

        # Clear logs button (right side of pill row)
        clr = tk.Label(pill_row, text=t("ui.alerts.btn_clear"),
                       font=("Segoe UI", 9), fg=FG_MUTE, bg=CARD2,
                       padx=12, pady=8, cursor="hand2")
        clr.pack(side="right")
        clr.bind("<Enter>", lambda _e: clr.config(fg=RED))
        clr.bind("<Leave>", lambda _e: clr.config(fg=FG_MUTE))
        clr.bind("<Button-1>", lambda _e: self._on_clear_logs())

        # Auto-refresh label
        self._refresh_ts_var = tk.StringVar(value="")
        tk.Label(pill_row, textvariable=self._refresh_ts_var,
                 font=("Segoe UI", 8), fg=FG_MUTE, bg=CARD2).pack(side="right", padx=10)

        # ── Split pane ────────────────────────────────────────────────────────
        pane = tk.PanedWindow(parent, orient="horizontal", bg=BG,
                               sashrelief="flat", sashwidth=3)
        pane.pack(fill="both", expand=True)

        # Left: treeview
        left = _frame(pane, bg=BG)
        pane.add(left, minsize=520)

        cols = (t("ui.alerts.col_time"), t("ui.alerts.col_severity"),
                t("ui.alerts.col_type"), t("ui.alerts.col_title"),
                t("ui.alerts.col_process"), t("ui.alerts.col_address"),
                t("ui.alerts.col_country"))
        self._alert_tree = ttk.Treeview(left, columns=cols, show="headings")
        for col, w in zip(cols, [115, 100, 130, 240, 130, 140, 100]):
            self._alert_tree.heading(col, text=col)
            self._alert_tree.column(col, width=w, minwidth=60)

        for sev, clr in SEV_COLOR.items():
            self._alert_tree.tag_configure(sev, foreground=clr)
        self._alert_tree.tag_configure("country", foreground=PURPLE)

        vsb = ttk.Scrollbar(left, orient="vertical",
                             command=self._alert_tree.yview)
        self._alert_tree.configure(yscrollcommand=vsb.set)
        self._alert_tree.pack(side="left", fill="both", expand=True,
                               padx=(10, 0), pady=8)
        vsb.pack(side="right", fill="y", pady=8, padx=(0, 2))

        # Right: detail pane
        right = _frame(pane, bg=CARD)
        pane.add(right, minsize=220)
        tk.Frame(right, bg=BORDER, width=1).pack(side="left", fill="y")

        detail_inner = _frame(right, bg=CARD)
        detail_inner.pack(fill="both", expand=True)

        _label(detail_inner, t("ui.alerts.detail_title"),
               font=("Segoe UI", 11, "bold"), bg=CARD, fg=FG,
               padx=14, pady=12).pack(anchor="w")

        self._detail_text = tk.Text(detail_inner, bg=BG, fg=FG, wrap="word",
                                    font=("Segoe UI", 9), relief="flat",
                                    state="disabled", padx=10, pady=8,
                                    insertbackground=FG)
        self._detail_text.pack(fill="both", expand=True, padx=8)

        # Copy IP button (shown only when an alert with IP is selected)
        self._copy_ip_btn = _btn(detail_inner, t("ui.alerts.copy_ip"),
                                 self._copy_ip, bg=CARD2, fg=ACCENT)
        self._copy_ip_btn.pack(pady=8, padx=14, anchor="w")

        self._selected_ip: Optional[str] = None

        # Populate and bind
        self._populate_alerts()
        self._alert_tree.bind("<<TreeviewSelect>>", self._on_alert_select)

        # Auto-refresh every 30 s
        self._root.after(30_000, self._refresh_alerts)

    def _set_sev_filter(self, sev: str, redraw: bool = True):
        self._alert_sev_filter.set(sev)
        for s, lbl in self._pills.items():
            is_active = s == sev
            lbl.config(bg=CARD if is_active else CARD2,
                       relief="solid" if is_active else "flat")
        if redraw:
            self._populate_alerts()

    def _populate_alerts(self):
        sev = self._alert_sev_filter.get()
        tree = self._alert_tree
        tree.delete(*tree.get_children())

        alerts = self._all_alerts
        if sev != "ALL":
            alerts = [a for a in alerts if a["severity"] == sev]
        self._filtered_alerts = alerts  # cache so _on_alert_select uses same snapshot

        for a in alerts:
            ts     = a["timestamp"][:16].replace("T", " ")
            remote = (f"{a['remote_addr']}:{a['remote_port']}"
                      if a["remote_addr"] else "—")
            sev_lbl = SEV_LABEL.get(a["severity"], a["severity"].upper())

            # Country from GeoIP cache (live lookup)
            country_str = ""
            if a["remote_addr"]:
                country_str = geoip_cache.get_country_display(a["remote_addr"])

            tags = (a["severity"],)
            if geoip_cache.is_high_risk(a["remote_addr"] or ""):
                tags = (a["severity"], "country")

            tree.insert("", "end",
                        values=(ts, sev_lbl, a["alert_type"],
                                a["title"][:52], a["process_name"] or "—",
                                remote, country_str),
                        tags=tags)

        self._refresh_ts_var.set(
            t("ui.alerts.updated_at", time=datetime.now().strftime("%H:%M:%S"))
        )

    def _on_clear_logs(self):
        import tkinter.messagebox as mb
        if mb.askyesno(t("tray.clear_logs_title"), t("tray.clear_logs_confirm"),
                       icon="warning", default="no"):
            self._db.clear_all_data()
            self._all_alerts = []
            self._populate_alerts()
            self._refresh_dashboard()

    def _refresh_alerts(self):
        self._all_alerts = self._db.get_recent_alerts(hours=24)
        self._populate_alerts()
        self._root.after(30_000, self._refresh_alerts)

    def _on_alert_select(self, _event):
        sel = self._alert_tree.selection()
        if not sel:
            return
        idx = self._alert_tree.index(sel[0])
        filtered = getattr(self, "_filtered_alerts", self._all_alerts)
        if idx >= len(filtered):
            return
        a = filtered[idx]

        dt = self._detail_text
        dt.config(state="normal")
        dt.delete("1.0", "end")

        # ── Text helpers ──────────────────────────────────────────────────────
        dt.tag_configure("sev",     foreground=SEV_COLOR.get(a["severity"], FG),
                         font=("Segoe UI", 10, "bold"))
        dt.tag_configure("heading", foreground=FG_DIM,  font=("Segoe UI", 8, "bold"))
        dt.tag_configure("val",     foreground=FG,      font=("Segoe UI", 9))
        dt.tag_configure("dim",     foreground=FG_DIM,  font=("Segoe UI", 8))
        dt.tag_configure("mono",    foreground=ACCENT,  font=("Consolas", 9))
        dt.tag_configure("warn",    foreground=YELLOW,  font=("Segoe UI", 9, "bold"))
        dt.tag_configure("box",     foreground=FG_DIM,  font=("Segoe UI", 8),
                         background=CARD2)

        def h(text):
            dt.insert("end", f"\n{text}\n", ("heading",))

        def v(text, tag="val"):
            dt.insert("end", text + "\n", (tag,))

        def kv(key, val, val_tag="val"):
            dt.insert("end", f"{key}  ", ("dim",))
            dt.insert("end", f"{val}\n", (val_tag,))

        # ── Severity + title ──────────────────────────────────────────────────
        dt.insert("end", SEV_LABEL.get(a["severity"], "") + "\n", ("sev",))
        dt.insert("end", "\n")
        v(a["title"], "val")

        # ── Meta ──────────────────────────────────────────────────────────────
        h(t("ui.alerts.section_detail"))
        kv(t("ui.alerts.field_time"), a["timestamp"][:19].replace("T", " "))
        kv(t("ui.alerts.field_type"), a["alert_type"], "mono")

        # Description — split on \n\n to separate flood IP list
        dt.insert("end", "\n")
        desc_parts = a["description"].split("\n\n", 1)
        for line in desc_parts[0].split("\n"):
            if line.strip():
                v(line)
        if len(desc_parts) > 1:
            dt.insert("end", t("ui.alerts.samples_ip") + "\n", ("dim",))
            raw = desc_parts[1]
            ips = raw.split(":", 1)[1].strip() if ":" in raw else raw
            dt.insert("end", ips + "\n", ("mono",))

        # ── Process info ──────────────────────────────────────────────────────
        pid = a["pid"] if a["pid"] is not None else None

        if a["process_name"] or pid is not None:
            h(t("ui.alerts.section_process"))
            if a["process_name"]:
                kv(t("ui.alerts.field_name"), a["process_name"], "val")
            if pid is not None:
                kv(t("ui.alerts.field_pid"), str(pid), "dim")
            if a.get("process_exe"):
                kv(t("ui.alerts.field_path"), a["process_exe"], "dim")

            # Special explanation for kernel pseudo-processes
            pid_info = maybe(f"pid_info.{pid}")
            if pid_info:
                dt.insert("end", "\n")
                dt.insert("end", pid_info + "\n", ("warn",))

        # ── Remote address + GeoIP ────────────────────────────────────────────
        if a["remote_addr"]:
            h(t("ui.alerts.section_target"))
            kv(t("ui.alerts.field_address"), f"{a['remote_addr']}:{a['remote_port']}", "mono")
            geo = geoip_cache.get(a["remote_addr"])
            if geo:
                flag = geo.get("flag", "")
                risk = t("ui.alerts.high_risk_suffix") if geo["is_high_risk"] else ""
                kv(t("ui.alerts.field_country"), f"{flag} {geo['country']}{risk}",
                   "warn" if geo["is_high_risk"] else "val")
            else:
                kv(t("ui.alerts.field_country"), t("ui.alerts.country_resolving"), "dim")

        # ── What does this mean? ──────────────────────────────────────────────
        explanation = maybe(f"info.{a['alert_type']}")
        if explanation:
            h(t("ui.alerts.section_whatisit"))
            dt.insert("end", explanation + "\n", ("box",))

        dt.config(state="disabled")
        self._selected_ip = a["remote_addr"]

    def _copy_ip(self):
        if self._selected_ip:
            self._root.clipboard_clear()
            self._root.clipboard_append(self._selected_ip)

    # ── Tab 3: Live connections ───────────────────────────────────────────────

    def _tab_live(self, parent):
        # Controls bar
        ctrl = _frame(parent, bg=CARD2)
        ctrl.pack(fill="x")
        tk.Frame(ctrl, bg=BORDER, height=1).pack(fill="x", side="bottom")

        _label(ctrl, t("ui.live.title"),
               font=("Segoe UI", 10, "bold"), bg=CARD2, fg=FG,
               padx=14, pady=8).pack(side="left")

        self._live_auto     = True
        self._live_auto_job = None

        self._auto_btn = tk.Label(
            ctrl, text=t("ui.live.auto_on"), bg=CARD2,
            fg=GREEN, font=("Segoe UI", 9, "bold"), padx=12, pady=8,
            cursor="hand2",
        )
        self._auto_btn.pack(side="right", padx=10)
        self._auto_btn.bind("<Button-1>", lambda _e: self._toggle_live_refresh())

        self._live_ts_var = tk.StringVar(value="")
        tk.Label(ctrl, textvariable=self._live_ts_var,
                 font=("Segoe UI", 8), fg=FG_MUTE, bg=CARD2).pack(side="right", padx=6)

        # Treeview
        cols = (t("ui.live.col_pid"), t("ui.live.col_process"), t("ui.live.col_target"),
                t("ui.live.col_port"), t("ui.live.col_status"), t("ui.live.col_country"),
                t("ui.live.col_risk"))
        self._live_tree = ttk.Treeview(parent, columns=cols, show="headings")
        for col, w in zip(cols, [55, 160, 170, 60, 90, 140, 24]):
            self._live_tree.heading(col, text=col)
            self._live_tree.column(col, width=w, minwidth=40)

        self._live_tree.tag_configure("suspicious",
                                      background="#2a1414", foreground=RED)
        self._live_tree.tag_configure("highRisk",
                                      foreground=PURPLE)
        self._live_tree.tag_configure("normal", foreground=FG)

        vsb = ttk.Scrollbar(parent, orient="vertical",
                             command=self._live_tree.yview)
        self._live_tree.configure(yscrollcommand=vsb.set)
        self._live_tree.pack(side="left", fill="both", expand=True,
                              padx=(10, 0), pady=8)
        vsb.pack(side="right", fill="y", pady=8)

        self._refresh_live()

    def _refresh_live(self):
        tree = self._live_tree
        # Preserve scroll position
        try:
            yview = tree.yview()
        except Exception:
            yview = (0, 1)

        tree.delete(*tree.get_children())

        conns = self._monitor.get_current_connections() if self._monitor else []

        for c in sorted(conns, key=lambda x: x.get("process_name") or ""):
            rip     = c.get("remote_addr", "")
            geo     = geoip_cache.get(rip) if rip else None
            flag    = geo["flag"]    if geo else ""
            country = geo["country"] if geo else ""
            hi_risk = geo.get("is_high_risk", False) if geo else False
            susp    = c.get("is_suspicious", 0)
            risk_dot = "●" if hi_risk else ""

            tags = ("suspicious",) if susp else ("highRisk",) if hi_risk else ("normal",)

            tree.insert("", "end", values=(
                c.get("pid") or "—",
                c.get("process_name") or "—",
                rip or "—",
                c.get("remote_port") or "—",
                (c.get("status") or "—")[:8],
                f"{flag} {country}"[:20] if country else "",
                risk_dot,
            ), tags=tags)

        self._live_ts_var.set(datetime.now().strftime("%H:%M:%S"))

        if self._live_auto:
            self._live_auto_job = self._root.after(5_000, self._refresh_live)

    def _toggle_live_refresh(self):
        self._live_auto = not self._live_auto
        if self._live_auto:
            self._auto_btn.config(text=t("ui.live.auto_on"), fg=GREEN)
            self._refresh_live()
        else:
            self._auto_btn.config(text=t("ui.live.auto_off"), fg=FG_DIM)
            if self._live_auto_job:
                try:
                    self._root.after_cancel(self._live_auto_job)
                except Exception:
                    pass
