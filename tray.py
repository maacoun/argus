"""
Network Traffic Watchdog — System tray (pywin32, no pystray required)

Creates a native Win32 message window, attaches a Shell_NotifyIcon tray entry,
and runs a standard GetMessage pump in the main thread (same pattern pystray uses).
"""
import io
import logging
import os
import tempfile
import threading
import time
import webbrowser
from typing import Optional

import ctypes

import win32api
import win32con
import win32gui
from PIL import Image, ImageDraw

import config
from i18n import t

logger = logging.getLogger("watchdog.tray")

# ── Constants ─────────────────────────────────────────────────────────────────
WM_TRAY       = win32con.WM_USER + 20
WM_REFRESH    = win32con.WM_APP + 2   # posted by the refresh timer thread
TRAY_ID       = 1
REFRESH_SECS  = 10

# Menu command IDs
ID_STATUS       = 900   # read-only label
ID_VIEW_ALERTS  = 1001
ID_VIEW_REPORT  = 1002
ID_CLEAR_LOGS   = 1003
ID_TOGGLE_PAUSE = 1004
ID_QUIT         = 1005


# ── PIL → HICON ───────────────────────────────────────────────────────────────

def _pil_to_hicon(img: Image.Image) -> int:
    """Save a 32×32 RGBA PIL image as a temp .ico and load it as an HICON."""
    img = img.resize((32, 32), Image.LANCZOS).convert("RGBA")
    buf = io.BytesIO()
    img.save(buf, format="ICO", sizes=[(32, 32)])
    buf.seek(0)

    fd, tmp = tempfile.mkstemp(suffix=".ico")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(buf.read())
        hicon = win32gui.LoadImage(
            0, tmp,
            win32con.IMAGE_ICON, 32, 32,
            win32con.LR_LOADFROMFILE,
        )
        return hicon
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _make_icon_image(status: str) -> Image.Image:
    """Draw a 32×32 shield icon whose colour reflects the alert status."""
    size  = 32
    img   = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw  = ImageDraw.Draw(img)

    palette = {
        "ok":       (40,  180, 40,  255),
        "warning":  (255, 160, 0,   255),
        "critical": (220, 40,  40,  255),
        "paused":   (120, 120, 120, 255),
    }
    c  = palette.get(status, palette["ok"])
    m  = 2
    cx = size // 2
    cy = size // 2

    pts = [
        (cx,        m),
        (size - m,  m + (size - 2 * m) // 3),
        (size - m,  m + (size - 2 * m) * 2 // 3),
        (cx,        size - m),
        (m,         m + (size - 2 * m) * 2 // 3),
        (m,         m + (size - 2 * m) // 3),
    ]
    draw.polygon(pts, fill=c)

    w = (255, 255, 255, 255)
    if status in ("critical", "warning"):
        draw.rectangle([cx - 2, cy - 8, cx + 2, cy + 1], fill=w)
        draw.ellipse(  [cx - 2, cy + 4, cx + 2, cy + 8], fill=w)
    elif status == "paused":
        draw.rectangle([cx - 6, cy - 6, cx - 2, cy + 6], fill=w)
        draw.rectangle([cx + 2, cy - 6, cx + 6, cy + 6], fill=w)
    else:
        draw.line([(cx - 8, cy + 1), (cx - 3, cy + 6), (cx + 8, cy - 5)],
                  fill=w, width=3)

    return img


# ── SystemTray ────────────────────────────────────────────────────────────────

class SystemTray:
    def __init__(self, monitor, db):
        self._monitor = monitor
        self._db      = db
        self._hwnd: Optional[int] = None
        self._icons: dict[str, int] = {}
        self._cur_status = "ok"

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self):
        """Register window class, create tray icon, run message pump (blocks)."""
        hinst = win32api.GetModuleHandle(None)

        # Register window class
        wc                = win32gui.WNDCLASS()
        wc.hInstance      = hinst
        wc.lpszClassName  = "NWatchdogClass"
        wc.lpfnWndProc    = self._wnd_proc
        win32gui.RegisterClass(wc)

        # Create an invisible overlapped window (message-only windows don't
        # receive WM_TIMER reliably on all Windows versions)
        self._hwnd = win32gui.CreateWindow(
            "NWatchdogClass", "Network Watchdog",
            0, 0, 0, 0, 0,
            0, 0, hinst, None,
        )

        # Pre-build icons for all states
        for s in ("ok", "warning", "critical", "paused"):
            try:
                self._icons[s] = _pil_to_hicon(_make_icon_image(s))
            except Exception as e:
                logger.error("Nelze vytvořit ikonu '%s': %s", s, e)
                self._icons[s] = win32gui.LoadIcon(0, win32con.IDI_APPLICATION)

        # Add tray icon
        self._notify_icon_add()

        # Start periodic refresh via a daemon thread that posts WM_REFRESH
        self._start_refresh_thread()

        logger.info("Systémový tray spuštěn (hwnd=%s)", self._hwnd)

        # Blocking message pump
        win32gui.PumpMessages()

    # ── Refresh thread ────────────────────────────────────────────────────────

    def _start_refresh_thread(self):
        """Post WM_REFRESH to our window every REFRESH_SECS seconds."""
        self._refresh_running = True

        def _loop():
            while self._refresh_running:
                time.sleep(REFRESH_SECS)
                if self._hwnd and self._refresh_running:
                    try:
                        win32gui.PostMessage(self._hwnd, WM_REFRESH, 0, 0)
                    except Exception:
                        pass

        t = threading.Thread(target=_loop, name="tray-refresh", daemon=True)
        t.start()

    # ── Win32 message handler ─────────────────────────────────────────────────

    def _wnd_proc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_TRAY:
                if lparam == win32con.WM_LBUTTONDBLCLK:
                    threading.Thread(target=self._on_view_alerts, daemon=True).start()
                elif lparam == win32con.WM_RBUTTONUP:
                    self._show_menu(hwnd)

            elif msg == WM_REFRESH:
                self._refresh_icon()

            elif msg == win32con.WM_COMMAND:
                cmd = win32api.LOWORD(wparam)
                if   cmd == ID_VIEW_ALERTS:  threading.Thread(target=self._on_view_alerts,  daemon=True).start()
                elif cmd == ID_VIEW_REPORT:  threading.Thread(target=self._on_view_report,  daemon=True).start()
                elif cmd == ID_CLEAR_LOGS:   threading.Thread(target=self._on_clear_logs,   daemon=True).start()
                elif cmd == ID_TOGGLE_PAUSE: self._on_toggle_pause()
                elif cmd == ID_QUIT:         self._on_quit(hwnd)

            elif msg == win32con.WM_DESTROY:
                self._refresh_running = False
                self._notify_icon_remove()
                win32gui.PostQuitMessage(0)

        except Exception as e:
            logger.error("WndProc chyba: %s", e, exc_info=True)

        return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

    # ── Tray icon management ──────────────────────────────────────────────────

    def _nid(self, flags: int, hicon: int = 0, tip: str = "", info: str = "", info_title: str = "") -> tuple:
        """Build a Shell_NotifyIcon tuple."""
        return (
            self._hwnd,
            TRAY_ID,
            flags,
            WM_TRAY,
            hicon or self._icons.get(self._cur_status, 0),
            tip[:127],
            info[:255],
            5000,
            info_title[:63],
            win32gui.NIIF_INFO,
        )

    def _notify_icon_add(self):
        flags = win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP
        nid   = self._nid(flags, self._icons["ok"], t("tray.starting"))
        win32gui.Shell_NotifyIcon(win32gui.NIM_ADD, nid)

    def _notify_icon_remove(self):
        try:
            win32gui.Shell_NotifyIcon(
                win32gui.NIM_DELETE,
                (self._hwnd, TRAY_ID, 0, 0, 0, "", "", 0, "", 0),
            )
        except Exception:
            pass

    def _refresh_icon(self):
        try:
            count = self._db.get_alert_count(hours=1)
        except Exception:
            count = 0

        if self._monitor.is_paused:
            new_status = "paused"
        elif count == 0:
            new_status = "ok"
        elif count <= 3:
            new_status = "warning"
        else:
            new_status = "critical"

        tip = (
            t("tray.status_paused") if self._monitor.is_paused else
            t("tray.status_alerts", count=count) if count else
            t("tray.status_ok")
        )

        flags = win32gui.NIF_ICON | win32gui.NIF_TIP
        nid   = self._nid(flags, self._icons.get(new_status, 0), tip)

        try:
            win32gui.Shell_NotifyIcon(win32gui.NIM_MODIFY, nid)
        except Exception as e:
            logger.debug("Shell_NotifyIcon NIM_MODIFY: %s", e)

        self._cur_status = new_status

    def show_balloon(self, title: str, message: str, is_critical: bool = False):
        """Show a tray balloon tip (called from alerter thread)."""
        try:
            flags = win32gui.NIF_INFO
            nid = (
                self._hwnd, TRAY_ID, flags,
                WM_TRAY,
                self._icons.get(self._cur_status, 0),
                "",                                        # szTip
                message[:255],                             # szInfo
                8000,                                      # uTimeout
                title[:63],                                # szInfoTitle
                win32gui.NIIF_ERROR if is_critical else win32gui.NIIF_INFO,
            )
            win32gui.Shell_NotifyIcon(win32gui.NIM_MODIFY, nid)
        except Exception as e:
            logger.debug("show_balloon: %s", e)

    # ── Context menu ──────────────────────────────────────────────────────────

    def _show_menu(self, hwnd: int):
        menu = win32gui.CreatePopupMenu()
        try:
            count = self._db.get_alert_count(hours=1)
        except Exception:
            count = 0

        status_str = (t("tray.menu_status_alerts", count=count) if count
                      else t("tray.menu_status_ok"))
        win32gui.AppendMenu(menu, win32con.MF_STRING | win32con.MF_GRAYED, ID_STATUS, status_str)
        win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, "")
        win32gui.AppendMenu(menu, win32con.MF_STRING, ID_VIEW_ALERTS,  t("tray.menu_view_alerts"))
        win32gui.AppendMenu(menu, win32con.MF_STRING, ID_VIEW_REPORT,  t("tray.menu_view_report"))
        win32gui.AppendMenu(menu, win32con.MF_STRING, ID_CLEAR_LOGS,   t("tray.menu_clear_logs"))
        win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, "")

        pause_label = (t("tray.menu_resume") if self._monitor.is_paused
                       else t("tray.menu_pause"))
        win32gui.AppendMenu(menu, win32con.MF_STRING, ID_TOGGLE_PAUSE, pause_label)
        win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, "")
        win32gui.AppendMenu(menu, win32con.MF_STRING, ID_QUIT, t("tray.menu_quit"))

        pos = win32gui.GetCursorPos()
        win32gui.SetForegroundWindow(hwnd)
        win32gui.TrackPopupMenu(
            menu,
            win32con.TPM_LEFTALIGN | win32con.TPM_BOTTOMALIGN,
            pos[0], pos[1], 0, hwnd, None,
        )
        win32gui.PostMessage(hwnd, win32con.WM_NULL, 0, 0)
        win32gui.DestroyMenu(menu)

    # ── Menu actions ──────────────────────────────────────────────────────────

    def _on_view_alerts(self):
        try:
            from ui import AlertsWindow
            AlertsWindow(self._db, monitor=self._monitor).show()
        except Exception as e:
            logger.error("Nelze otevřít okno výstrah: %s", e)

    def _on_view_report(self):
        try:
            from report import generate_report
            path = generate_report(self._db)
            webbrowser.open(f"file:///{path}")
        except Exception as e:
            logger.error("Nelze vygenerovat report: %s", e)

    def _on_toggle_pause(self):
        if self._monitor.is_paused:
            self._monitor.resume()
        else:
            self._monitor.pause()

    def _on_clear_logs(self):
        MB_YESNO          = 0x04
        MB_ICONWARNING    = 0x30
        IDYES             = 6
        result = ctypes.windll.user32.MessageBoxW(
            0,
            t("tray.clear_logs_confirm"),
            t("tray.clear_logs_title"),
            MB_YESNO | MB_ICONWARNING,
        )
        if result == IDYES:
            try:
                self._db.clear_all_data()
            except Exception as e:
                logger.error("clear_all_data selhalo: %s", e)

    def _on_quit(self, hwnd: int):
        self._refresh_running = False
        self._monitor.stop()
        win32gui.DestroyWindow(hwnd)
