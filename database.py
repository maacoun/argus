"""
Network Traffic Watchdog — SQLite persistence layer
"""
import sqlite3
import threading
import logging
from datetime import datetime, timedelta

import config

logger = logging.getLogger("watchdog.database")


class Database:
    """Thread-safe SQLite wrapper.

    Each thread gets its own connection via threading.local() so we never
    share a connection across threads (SQLite requirement in check_same_thread=False
    mode is only safe if you *know* calls are serialised — using thread-local
    connections is cleaner and avoids that subtlety entirely).
    """

    def __init__(self):
        self._local = threading.local()
        self._db_path = str(config.DB_PATH)
        self._init_schema()

    # ── Connection management ─────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        """Return (or create) the per-thread SQLite connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return self._local.conn

    def _init_schema(self):
        """Create tables in a fresh connection (called once from __init__)."""
        conn = sqlite3.connect(self._db_path)
        # Migrate existing DBs that pre-date added columns
        for table, col, typedef in [
            ("connections", "country_code", "TEXT"),
            ("connections", "country",      "TEXT"),
            ("alerts",      "pid",          "INTEGER"),
        ]:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}")
                conn.commit()
            except Exception:
                pass  # column already exists
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS connections (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT    NOT NULL,
                pid          INTEGER,
                process_name TEXT,
                process_exe  TEXT,
                local_addr   TEXT,
                local_port   INTEGER,
                remote_addr  TEXT,
                remote_port  INTEGER,
                status        TEXT,
                is_suspicious INTEGER DEFAULT 0,
                country_code  TEXT,
                country       TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT    NOT NULL,
                alert_type   TEXT    NOT NULL,
                severity     TEXT    NOT NULL,
                title        TEXT    NOT NULL,
                description  TEXT    NOT NULL,
                pid          INTEGER,
                process_name TEXT,
                process_exe  TEXT,
                remote_addr  TEXT,
                remote_port  INTEGER,
                acknowledged INTEGER DEFAULT 0
            );

            -- Stores individual connection-appearance events for beaconing analysis
            CREATE TABLE IF NOT EXISTS connection_events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    REAL    NOT NULL,
                pid          INTEGER,
                process_name TEXT,
                remote_addr  TEXT,
                remote_port  INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_ts      ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_conn_events_ts ON connection_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_conn_events_key
                ON connection_events(pid, remote_addr, timestamp);
        """)
        conn.commit()
        conn.close()

    # ── Writes ────────────────────────────────────────────────────────────────

    def store_connections(self, connections: list[dict]):
        now = datetime.now().isoformat()
        rows = [
            (
                now,
                c["pid"], c["process_name"], c["process_exe"],
                c["local_addr"], c["local_port"],
                c["remote_addr"], c["remote_port"],
                c["status"], c["is_suspicious"],
                c.get("country_code"), c.get("country"),
            )
            for c in connections
        ]
        conn = self._conn()
        conn.executemany(
            """INSERT INTO connections
               (timestamp, pid, process_name, process_exe,
                local_addr, local_port, remote_addr, remote_port,
                status, is_suspicious, country_code, country)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        conn.commit()

    def store_alert(self, alert):
        conn = self._conn()
        conn.execute(
            """INSERT INTO alerts
               (timestamp, alert_type, severity, title, description,
                pid, process_name, process_exe, remote_addr, remote_port)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                datetime.now().isoformat(),
                alert.alert_type, alert.severity,
                alert.title, alert.description,
                alert.pid,
                alert.process_name, alert.process_exe,
                alert.remote_addr, alert.remote_port,
            ),
        )
        conn.commit()

    def store_connection_event(self, pid, process_name, remote_addr, remote_port, timestamp: float):
        conn = self._conn()
        conn.execute(
            "INSERT INTO connection_events (timestamp, pid, process_name, remote_addr, remote_port) VALUES (?,?,?,?,?)",
            (timestamp, pid, process_name, remote_addr, remote_port),
        )
        conn.commit()

    # ── Reads ─────────────────────────────────────────────────────────────────

    def get_connection_event_timestamps(self, pid: int, remote_addr: str, since: float) -> list[float]:
        rows = self._conn().execute(
            "SELECT timestamp FROM connection_events WHERE pid=? AND remote_addr=? AND timestamp>? ORDER BY timestamp",
            (pid, remote_addr, since),
        ).fetchall()
        return [r["timestamp"] for r in rows]

    def get_recent_alerts(self, hours: int = 24) -> list:
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        return self._conn().execute(
            "SELECT * FROM alerts WHERE timestamp > ? ORDER BY timestamp DESC",
            (since,),
        ).fetchall()

    def get_alert_count(self, hours: int = 1) -> int:
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        row = self._conn().execute(
            "SELECT COUNT(*) AS cnt FROM alerts WHERE timestamp > ?", (since,)
        ).fetchone()
        return row["cnt"] if row else 0

    def get_stats(self) -> dict:
        since = (datetime.now() - timedelta(hours=24)).isoformat()
        c = self._conn()
        total = c.execute(
            "SELECT COUNT(*) AS cnt FROM alerts WHERE timestamp > ?", (since,)
        ).fetchone()["cnt"]
        critical = c.execute(
            "SELECT COUNT(*) AS cnt FROM alerts WHERE timestamp > ? AND severity='critical'", (since,)
        ).fetchone()["cnt"]
        top_proc = c.execute(
            """SELECT process_name, COUNT(*) AS cnt FROM alerts
               WHERE timestamp > ? GROUP BY process_name ORDER BY cnt DESC LIMIT 5""",
            (since,),
        ).fetchall()
        top_ips = c.execute(
            """SELECT remote_addr, COUNT(*) AS cnt FROM alerts
               WHERE timestamp > ? AND remote_addr IS NOT NULL
               GROUP BY remote_addr ORDER BY cnt DESC LIMIT 5""",
            (since,),
        ).fetchall()
        top_countries = c.execute(
            """SELECT country_code, country, COUNT(*) AS cnt
               FROM connections
               WHERE timestamp > ? AND country_code IS NOT NULL AND country_code != ''
               GROUP BY country_code ORDER BY cnt DESC LIMIT 8""",
            (since,),
        ).fetchall()
        flagged_countries = c.execute(
            """SELECT COUNT(DISTINCT country_code) AS cnt
               FROM connections
               WHERE timestamp > ? AND country_code IN
               (SELECT DISTINCT country_code FROM connections
                WHERE timestamp > ? AND is_suspicious = 1
                  AND country_code IS NOT NULL AND country_code != '')""",
            (since, since),
        ).fetchone()["cnt"]
        return {
            "total_alerts_24h":    total,
            "critical_alerts_24h": critical,
            "flagged_countries":   flagged_countries,
            "top_processes":       top_proc,
            "top_ips":             top_ips,
            "top_countries":       top_countries,
        }

    def get_hourly_alert_counts(self, hours: int = 12) -> list[tuple[str, int]]:
        """Return (hour_label, count) for the last N hours, oldest first."""
        now = datetime.now()
        result = []
        for i in range(hours - 1, -1, -1):
            t_start = (now - timedelta(hours=i + 1)).isoformat()
            t_end   = (now - timedelta(hours=i)).isoformat()
            count = self._conn().execute(
                "SELECT COUNT(*) FROM alerts WHERE timestamp >= ? AND timestamp < ?",
                (t_start, t_end),
            ).fetchone()[0]
            label = (now - timedelta(hours=i)).strftime("%Hh")
            result.append((label, count))
        return result

    # ── Maintenance ───────────────────────────────────────────────────────────

    def clear_all_data(self):
        """Delete every alert, connection, and connection event.
        Also truncates the text alerts log file."""
        conn = self._conn()
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM connections")
        conn.execute("DELETE FROM connection_events")
        conn.commit()           # commit BEFORE vacuum — VACUUM cannot run inside a transaction
        try:
            conn.execute("VACUUM")
        except Exception:
            pass                # VACUUM is optional (just reclaims disk space)
        try:
            open(config.ALERTS_LOG_PATH, "w").close()
        except Exception:
            pass
        logger.info("All log data cleared by user")

    def cleanup_old_data(self, days: int = 7):
        """Delete data older than *days* to keep the DB small."""
        cutoff_iso = (datetime.now() - timedelta(days=days)).isoformat()
        cutoff_ts  = (datetime.now() - timedelta(days=days)).timestamp()
        conn = self._conn()
        conn.execute("DELETE FROM connections       WHERE timestamp < ?", (cutoff_iso,))
        conn.execute("DELETE FROM alerts            WHERE timestamp < ?", (cutoff_iso,))
        conn.execute("DELETE FROM connection_events WHERE timestamp < ?", (cutoff_ts,))
        conn.execute("VACUUM")
        conn.commit()
        logger.info(f"Cleaned up data older than {days} days")
