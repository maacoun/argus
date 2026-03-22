"""
Network Traffic Watchdog — Core monitoring loop

Runs in a daemon thread, polls psutil for network connections, enriches
them with process information, runs the detection engine, and dispatches
alerts.
"""
import time
import logging
import threading
from typing import Optional

import psutil

import config
from detector import DetectionEngine, Alert
from geoip import geoip_cache

logger = logging.getLogger("watchdog.monitor")


class NetworkMonitor:
    """Background network-connection poller and alert dispatcher."""

    def __init__(self, db, alerter, detector: DetectionEngine):
        self._db       = db
        self._alerter  = alerter
        self._detector = detector

        self._running = False
        self._paused  = False
        self._lock    = threading.Lock()

        # Shared state (read by tray / UI without holding the lock is fine
        # because Python assignments are atomic for small objects)
        self._current_connections: list[dict] = []
        self._status      = "starting"
        self._alert_count = 0
        self._scan_count  = 0
        self._last_scan_ts: float = 0.0

        # Periodic cleanup counter (every hour ≈ 720 scans @ 5 s)
        self._cleanup_counter = 0

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def status(self) -> str:
        return self._status

    @property
    def alert_count(self) -> int:
        return self._alert_count

    @property
    def is_paused(self) -> bool:
        return self._paused

    # ── Control ───────────────────────────────────────────────────────────────

    def pause(self):
        self._paused = True
        self._status = "paused"
        logger.info("Monitor paused")

    def resume(self):
        self._paused = False
        self._status = "running"
        logger.info("Monitor resumed")

    def stop(self):
        self._running = False
        logger.info("Monitor stop requested")

    def get_current_connections(self) -> list[dict]:
        with self._lock:
            return list(self._current_connections)

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self):
        self._running = True
        self._status  = "running"
        logger.info("Network monitor started (interval=%ds)", config.MONITOR_INTERVAL)

        while self._running:
            try:
                if self._paused:
                    time.sleep(1)
                    continue

                connections = self._collect_connections()

                with self._lock:
                    self._current_connections = connections

                # Detection
                alerts = self._detector.analyze(connections)

                # Dispatch alerts
                for alert in alerts:
                    if not self._alerter.is_cooldown(alert):
                        self._alerter.send(alert, db=self._db)
                        self._alert_count += 1

                # Persist a sample of connections (every 5th scan → every 25 s)
                if self._scan_count % 5 == 0:
                    flagged = self._flag_suspicious(connections, alerts)
                    try:
                        if flagged:
                            self._db.store_connections(flagged)
                    except Exception as e:
                        logger.error("DB store_connections: %s", e)

                # Hourly cleanup
                self._cleanup_counter += 1
                if self._cleanup_counter >= 720:
                    self._cleanup_counter = 0
                    try:
                        self._db.cleanup_old_data()
                    except Exception as e:
                        logger.error("DB cleanup: %s", e)

                self._scan_count   += 1
                self._last_scan_ts  = time.time()
                self._status        = "running"

            except Exception as e:
                logger.error("Monitor loop error: %s", e, exc_info=True)
                self._status = "error"

            time.sleep(config.MONITOR_INTERVAL)

        self._status = "stopped"
        logger.info("Network monitor stopped")

    # ── Connection collection ─────────────────────────────────────────────────

    def _collect_connections(self) -> list[dict]:
        """Return all active outbound TCP/UDP connections enriched with process info."""
        try:
            raw = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            logger.warning(
                "Přístup odepřen — spusťte aplikaci jako správce, "
                "aby byly viditelné všechny spojení."
            )
            return []
        except Exception as e:
            logger.error("net_connections failed: %s", e)
            return []

        # Build a PID → proc-info cache to avoid repeated Process() calls
        pid_cache: dict[int, dict] = {}
        results: list[dict] = []

        for conn in raw:
            # Skip listening sockets and connections without a remote address
            if not conn.raddr:
                continue
            if conn.status == "LISTEN":
                continue

            pid = conn.pid
            if pid not in pid_cache:
                pid_cache[pid] = self._proc_info(pid)
            info = pid_cache[pid]

            rip = conn.raddr.ip if conn.raddr else None
            geo = geoip_cache.get(rip) if rip else None
            if rip:
                geoip_cache.enqueue(rip)

            results.append({
                "pid":          pid,
                "process_name": info["name"],
                "process_exe":  info["exe"],
                "local_addr":   conn.laddr.ip   if conn.laddr else None,
                "local_port":   conn.laddr.port if conn.laddr else None,
                "remote_addr":  rip,
                "remote_port":  conn.raddr.port if conn.raddr else None,
                "status":       conn.status,
                "is_suspicious": 0,
                "country_code": geo["country_code"] if geo else "",
                "country":      geo["country"]      if geo else "",
                "is_high_risk": geo["is_high_risk"]  if geo else False,
                "flag":         geo["flag"]          if geo else "",
            })

        return results

    @staticmethod
    def _proc_info(pid: Optional[int]) -> dict:
        """Return {"name": ..., "exe": ...} for a PID, handling errors gracefully."""
        if pid is None:
            return {"name": "System", "exe": ""}
        try:
            p = psutil.Process(pid)
            return {"name": p.name(), "exe": p.exe()}
        except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
            return {"name": f"PID-{pid}", "exe": ""}
        except Exception as e:
            logger.debug("proc_info(%d): %s", pid, e)
            return {"name": f"PID-{pid}", "exe": ""}

    @staticmethod
    def _flag_suspicious(connections: list[dict], alerts: list[Alert]) -> list[dict]:
        """Mark connections that are referenced by alerts as suspicious."""
        suspicious_keys: set[tuple] = {
            (a.process_name, a.remote_addr, a.remote_port)
            for a in alerts
            if a.remote_addr
        }
        result = []
        for conn in connections:
            c = dict(conn)
            c["is_suspicious"] = int(
                (c["process_name"], c["remote_addr"], c["remote_port"]) in suspicious_keys
            )
            result.append(c)
        return result
