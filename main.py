"""
Network Traffic Watchdog — Entry point

Requests admin elevation (needed to see connections from all processes),
sets up logging, then starts the monitor thread and the system tray.

Usage:
    python main.py
    pythonw main.py          # no console window

Run as administrator for full visibility of all network connections.
"""
import os
import sys
import ctypes
import logging
import threading
from pathlib import Path

from i18n import t


# ── Admin elevation ───────────────────────────────────────────────────────────

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _request_elevation():
    """Re-launch the current script with UAC elevation and exit."""
    params = " ".join(f'"{a}"' for a in sys.argv)
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )
    # ret > 32 means success; the new elevated process is now running
    sys.exit(0)


# ── Logging ───────────────────────────────────────────────────────────────────

def _setup_logging():
    from config import LOG_PATH

    fmt = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(str(LOG_PATH), encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def _check_already_running() -> bool:
    """Return True if another instance is already running (via PID file)."""
    from pathlib import Path
    import psutil

    pid_file = Path(__file__).parent / "data" / "watchdog.pid"
    if pid_file.exists():
        try:
            old_pid = int(pid_file.read_text().strip())
            if psutil.pid_exists(old_pid):
                proc = psutil.Process(old_pid)
                # Check that it's actually us (not a recycled PID)
                if "python" in proc.name().lower():
                    return True
        except Exception:
            pass

    pid_file.parent.mkdir(exist_ok=True)
    pid_file.write_text(str(os.getpid()))
    return False


def main():
    # ① Elevation check
    if not _is_admin():
        print(t("main.requesting_elevation"))
        try:
            _request_elevation()
        except SystemExit:
            raise
        except Exception:
            # Could not elevate (e.g., UAC disabled) — continue with limited visibility
            print(t("main.elevation_warning"))

    # ② Single-instance guard
    if _check_already_running():
        ctypes.windll.user32.MessageBoxW(
            0,
            t("main.already_running_body"),
            "Network Traffic Watchdog",
            0x40,  # MB_ICONINFORMATION
        )
        sys.exit(0)

    _setup_logging()
    logger = logging.getLogger("watchdog.main")

    logger.info("=" * 60)
    logger.info("Network Traffic Watchdog spouštím")
    logger.info("Python %s", sys.version)
    logger.info("=" * 60)

    # ② Lazy imports (after logging is configured)
    from database import Database
    from detector import DetectionEngine
    from alerter  import Alerter
    from monitor  import NetworkMonitor
    from tray     import SystemTray

    # ③ Wire components together
    db       = Database()
    alerter  = Alerter()
    detector = DetectionEngine(db=db)
    monitor  = NetworkMonitor(db, alerter, detector)
    tray     = SystemTray(monitor, db)

    # Allow alerter to show balloon tips through the tray icon
    alerter.register_tray(tray)

    # ④ Start monitor in a daemon thread
    mon_thread = threading.Thread(target=monitor.run, name="monitor-thread", daemon=True)
    mon_thread.start()
    logger.info("Monitor vlákno spuštěno")

    # ⑤ Run tray (blocks until the user clicks Quit)
    logger.info("Spouštím systémový tray…")
    tray.run()

    # Cleanup PID file
    try:
        pid_file = Path(__file__).parent / "data" / "watchdog.pid"
        if pid_file.exists():
            pid_file.unlink()
    except Exception:
        pass

    logger.info("Ukončuji…")


if __name__ == "__main__":
    main()
