"""
Network Traffic Watchdog — Detection engine

Runs a set of heuristic rules against every batch of observed connections
and returns a list of Alert objects.
"""
import math
import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

import config
from i18n import t
from geoip import flag_emoji

logger = logging.getLogger("watchdog.detector")


@dataclass
class Alert:
    alert_type:   str
    severity:     str
    title:        str
    description:  str
    pid:          Optional[int] = None
    process_name: Optional[str] = None
    process_exe:  Optional[str] = None
    remote_addr:  Optional[str] = None
    remote_port:  Optional[int] = None
    country_code: Optional[str] = None
    country:      Optional[str] = None

    def key(self) -> tuple:
        """Unique key used for cooldown deduplication."""
        return (self.alert_type, self.process_name, self.remote_addr, self.remote_port)


# IPs that are always safe to ignore in every check
_LOOPBACK_IPS = {"127.0.0.1", "::1", "0.0.0.0", "::"}


class DetectionEngine:
    def __init__(self, db=None):
        self._db = db

        # Track which (pid, laddr, lport, raddr, rport) tuples we saw last scan
        self._prev_keys: set = set()

        # Beaconing: {(pid, remote_addr): [unix timestamps of first appearances]}
        self._appearances: dict[tuple, list[float]] = defaultdict(list)

        # Flood: {pid: set of unique remote IPs seen in the current 60-s window}
        self._flood_ips:    dict[int, set]   = defaultdict(set)
        self._flood_window: dict[int, float] = {}

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def analyze(self, connections: list[dict]) -> list[Alert]:
        """Run all detectors; return deduplicated Alert list."""
        alerts: list[Alert] = []
        now = time.time()

        current_keys: set = set()

        for conn in connections:
            remote = conn.get("remote_addr", "")
            if not remote or remote in _LOOPBACK_IPS:
                continue

            key = (
                conn["pid"],
                conn["local_addr"], conn["local_port"],
                conn["remote_addr"], conn["remote_port"],
            )
            current_keys.add(key)
            is_new = key not in self._prev_keys

            # Per-connection rules
            alerts += self._check_port(conn)
            alerts += self._check_process(conn, is_new)
            alerts += self._check_exe_path(conn)
            alerts += self._check_tor(conn)

            if is_new:
                alerts += self._check_mining(conn)
                alerts += self._check_country(conn)
                self._record_appearance(conn, now)
                self._record_flood(conn, now)

        # Cross-connection rules
        alerts += self._detect_beaconing()
        alerts += self._detect_flood()

        self._prev_keys = current_keys
        self._prune_state(now)

        return self._deduplicate(alerts)

    # ─────────────────────────────────────────────────────────────────────────
    # Per-connection detectors
    # ─────────────────────────────────────────────────────────────────────────

    def _check_port(self, conn: dict) -> list[Alert]:
        port = conn["remote_port"]
        if port is None:
            return []

        if port in config.CRITICAL_PORTS:
            return [Alert(
                alert_type="malware_port",
                severity=config.SEVERITY_CRITICAL,
                title=t("alert.malware_port.title", port=port),
                description=t("alert.malware_port.desc",
                               name=conn["process_name"], pid=conn["pid"],
                               addr=conn["remote_addr"], port=port,
                               reason=config.CRITICAL_PORTS[port]),
                pid=conn["pid"],
                process_name=conn["process_name"],
                process_exe=conn.get("process_exe", ""),
                remote_addr=conn["remote_addr"],
                remote_port=port,
            )]

        if port in config.WARNING_PORTS:
            return [Alert(
                alert_type="suspicious_port",
                severity=config.SEVERITY_MEDIUM,
                title=t("alert.suspicious_port.title", port=port),
                description=t("alert.suspicious_port.desc",
                               name=conn["process_name"], pid=conn["pid"],
                               addr=conn["remote_addr"], port=port,
                               reason=config.WARNING_PORTS[port]),
                pid=conn["pid"],
                process_name=conn["process_name"],
                process_exe=conn.get("process_exe", ""),
                remote_addr=conn["remote_addr"],
                remote_port=port,
            )]

        return []

    def _check_process(self, conn: dict, is_new: bool) -> list[Alert]:
        proc = (conn.get("process_name") or "").lower()

        # CRITICAL processes: alert on every scan — if a LOLBin has a persistent
        # outbound connection we want it to remain visible even after restart.
        if proc in config.CRITICAL_PROCESSES:
            return [Alert(
                alert_type="critical_process",
                severity=config.SEVERITY_CRITICAL,
                title=t("alert.critical_process.title", name=conn["process_name"]),
                description=t("alert.critical_process.desc",
                               name=conn["process_name"], pid=conn["pid"],
                               addr=conn["remote_addr"], port=conn["remote_port"],
                               reason=config.CRITICAL_PROCESSES[proc]),
                pid=conn["pid"],
                process_name=conn["process_name"],
                process_exe=conn.get("process_exe", ""),
                remote_addr=conn["remote_addr"],
                remote_port=conn["remote_port"],
            )]

        # WARNING processes: only on first appearance of the connection.
        # cmd.exe / powershell.exe maintain persistent connections for Windows Update,
        # scripts, etc. — re-alerting every 5 s would flood the DB and alert log.
        if is_new and proc in config.WARNING_PROCESSES:
            return [Alert(
                alert_type="warning_process",
                severity=config.SEVERITY_HIGH,
                title=t("alert.warning_process.title", name=conn["process_name"]),
                description=t("alert.warning_process.desc",
                               name=conn["process_name"], pid=conn["pid"],
                               addr=conn["remote_addr"], port=conn["remote_port"],
                               reason=config.WARNING_PROCESSES[proc]),
                pid=conn["pid"],
                process_name=conn["process_name"],
                process_exe=conn.get("process_exe", ""),
                remote_addr=conn["remote_addr"],
                remote_port=conn["remote_port"],
            )]

        return []

    def _check_exe_path(self, conn: dict) -> list[Alert]:
        exe  = (conn.get("process_exe") or "").lower()
        proc = (conn.get("process_name") or "").lower()
        if not exe:
            return []

        # Skip whitelisted applications (Electron apps, browsers, etc.)
        if proc in config.SAFE_PROCESS_NAMES:
            return []

        for pattern in config.SUSPICIOUS_PATH_PATTERNS:
            if pattern in exe:
                return [Alert(
                    alert_type="suspicious_exe_path",
                    severity=config.SEVERITY_HIGH,
                    title=t("alert.suspicious_exe_path.title", name=conn["process_name"]),
                    description=t("alert.suspicious_exe_path.desc",
                                   exe=conn["process_exe"],
                                   addr=conn["remote_addr"], port=conn["remote_port"]),
                    pid=conn["pid"],
                    process_name=conn["process_name"],
                    process_exe=conn.get("process_exe", ""),
                    remote_addr=conn["remote_addr"],
                    remote_port=conn["remote_port"],
                )]

        return []

    def _check_tor(self, conn: dict) -> list[Alert]:
        if conn["remote_port"] in config.TOR_PORTS:
            return [Alert(
                alert_type="tor_connection",
                severity=config.SEVERITY_HIGH,
                title=t("alert.tor_connection.title"),
                description=t("alert.tor_connection.desc",
                               name=conn["process_name"], pid=conn["pid"],
                               addr=conn["remote_addr"], port=conn["remote_port"]),
                pid=conn["pid"],
                process_name=conn["process_name"],
                process_exe=conn.get("process_exe", ""),
                remote_addr=conn["remote_addr"],
                remote_port=conn["remote_port"],
            )]
        return []

    def _check_country(self, conn: dict) -> list[Alert]:
        """Flag connections to high-risk countries (requires GeoIP cache to be warm)."""
        if not conn.get("is_high_risk"):
            return []
        cc      = conn.get("country_code", "")
        country = conn.get("country", cc)
        flag = flag_emoji(cc)
        return [Alert(
            alert_type="high_risk_country",
            severity=config.SEVERITY_MEDIUM,
            title=t("alert.high_risk_country.title", flag=flag, country=country, cc=cc),
            description=t("alert.high_risk_country.desc",
                           name=conn["process_name"], pid=conn["pid"],
                           addr=conn["remote_addr"], port=conn["remote_port"],
                           country=country, cc=cc),
            pid=conn["pid"],
            process_name=conn["process_name"],
            process_exe=conn.get("process_exe", ""),
            remote_addr=conn["remote_addr"],
            remote_port=conn["remote_port"],
            country_code=cc,
            country=country,
        )]

    def _check_mining(self, conn: dict) -> list[Alert]:
        if conn["remote_port"] in config.MINING_PORTS:
            return [Alert(
                alert_type="mining_pool",
                severity=config.SEVERITY_HIGH,
                title=t("alert.mining_pool.title"),
                description=t("alert.mining_pool.desc",
                               name=conn["process_name"], pid=conn["pid"],
                               addr=conn["remote_addr"], port=conn["remote_port"]),
                pid=conn["pid"],
                process_name=conn["process_name"],
                process_exe=conn.get("process_exe", ""),
                remote_addr=conn["remote_addr"],
                remote_port=conn["remote_port"],
            )]
        return []

    # ─────────────────────────────────────────────────────────────────────────
    # State tracking helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _record_appearance(self, conn: dict, now: float):
        """Record that a new connection to remote_addr was observed now."""
        pid = conn["pid"]
        raddr = conn["remote_addr"]
        if pid is None or not raddr:
            return
        key = (pid, raddr)
        self._appearances[key].append(now)

        # Persist to DB for long-term beaconing analysis
        if self._db:
            try:
                self._db.store_connection_event(
                    pid, conn["process_name"], raddr, conn["remote_port"], now
                )
            except Exception:
                pass

    def _record_flood(self, conn: dict, now: float):
        """Track unique remote IPs per process for flood/scan detection."""
        pid = conn["pid"]
        raddr = conn["remote_addr"]
        # Skip kernel pseudo-processes — their connections are unowned system traffic
        if pid is None or pid in config.SYSTEM_PIDS or not raddr:
            return

        window_start = self._flood_window.get(pid, 0)
        if now - window_start > 60:
            self._flood_ips[pid] = set()
            self._flood_window[pid] = now

        self._flood_ips[pid].add(raddr)

    def _prune_state(self, now: float):
        """Remove stale entries to keep memory bounded."""
        cutoff = now - 3600  # keep last 1 hour
        for key in list(self._appearances.keys()):
            self._appearances[key] = [t for t in self._appearances[key] if t > cutoff]
            if not self._appearances[key]:
                del self._appearances[key]

    # ─────────────────────────────────────────────────────────────────────────
    # Cross-connection detectors
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_beaconing(self) -> list[Alert]:
        """Detect C2 beaconing: connections to same IP at regular intervals."""
        alerts: list[Alert] = []

        for (pid, remote_addr), timestamps in self._appearances.items():
            if pid in config.SYSTEM_PIDS:
                continue
            if len(timestamps) < config.BEACONING_MIN_CONNECTIONS:
                continue

            ts = sorted(timestamps)
            intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]

            if not intervals:
                continue

            mean = sum(intervals) / len(intervals)
            if not (config.BEACONING_MIN_INTERVAL <= mean <= config.BEACONING_MAX_INTERVAL):
                continue

            variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
            std_dev  = math.sqrt(variance)

            if std_dev < config.BEACONING_VARIANCE_THRESHOLD:
                proc_name = self._pid_to_name(pid)
                alerts.append(Alert(
                    alert_type="beaconing",
                    severity=config.SEVERITY_HIGH,
                    title=t("alert.beaconing.title"),
                    description=t("alert.beaconing.desc",
                                   name=proc_name, pid=pid, addr=remote_addr,
                                   mean=mean, std=std_dev, count=len(timestamps)),
                    pid=pid,
                    process_name=proc_name,
                    remote_addr=remote_addr,
                ))

        return alerts

    def _detect_flood(self) -> list[Alert]:
        """Detect connection flooding / port scanning."""
        alerts: list[Alert] = []

        for pid, remote_ips in self._flood_ips.items():
            if pid in config.SYSTEM_PIDS:
                continue
            if len(remote_ips) >= config.MAX_UNIQUE_REMOTE_IPS:
                proc_name = self._pid_to_name(pid)
                proc_exe  = self._pid_to_exe(pid)

                # Include a sample of involved IPs so the user sees context
                sorted_ips = sorted(remote_ips)
                sample     = sorted_ips[:12]
                more       = len(remote_ips) - len(sample)
                ip_list    = ", ".join(sample)
                if more > 0:
                    ip_list += t("alert.flood.more_ips", count=more)

                alerts.append(Alert(
                    alert_type="connection_flood",
                    severity=config.SEVERITY_HIGH,
                    title=t("alert.connection_flood.title"),
                    description=t("alert.connection_flood.desc",
                                   name=proc_name, pid=pid,
                                   count=len(remote_ips), ips=ip_list),
                    pid=pid,
                    process_name=proc_name,
                    process_exe=proc_exe,
                ))

        return alerts

    # ─────────────────────────────────────────────────────────────────────────
    # Utilities
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _pid_to_name(pid: int) -> str:
        try:
            import psutil
            return psutil.Process(pid).name()
        except Exception:
            return f"PID-{pid}"

    @staticmethod
    def _pid_to_exe(pid: int) -> str:
        try:
            import psutil
            return psutil.Process(pid).exe()
        except Exception:
            return ""

    @staticmethod
    def _deduplicate(alerts: list[Alert]) -> list[Alert]:
        seen: set = set()
        unique: list[Alert] = []
        for a in alerts:
            k = a.key()
            if k not in seen:
                seen.add(k)
                unique.append(a)
        return unique
