"""
Network Traffic Watchdog — GeoIP country resolver

Uses ip-api.com free batch API (no key required, up to 100 IPs per request,
45 requests/minute). Resolution is fully async — callers get None on first
query and the cached result on subsequent scans ~15 seconds later.

Import the module-level singleton:
    from geoip import geoip_cache
"""
import ipaddress
import logging
import threading
import time
from typing import Optional

import requests

import config

logger = logging.getLogger("watchdog.geoip")

# ── Private / reserved ranges to skip ────────────────────────────────────────
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("100.64.0.0/10"),   # carrier-grade NAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),        # unique-local IPv6
    ipaddress.ip_network("fe80::/10"),       # link-local IPv6
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True  # invalid → skip


def flag_emoji(country_code: str) -> str:
    """Convert a 2-letter ISO 3166-1 code to a Unicode flag emoji (🇨🇿, 🇷🇺 …)."""
    if not country_code or len(country_code) != 2:
        return ""
    try:
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())
    except Exception:
        return ""


# ── GeoIPCache ────────────────────────────────────────────────────────────────

class GeoIPCache:
    """
    Thread-safe, async GeoIP resolver backed by ip-api.com.

    Usage:
        geoip_cache.enqueue("1.2.3.4")     # queue for resolution
        geo = geoip_cache.get("1.2.3.4")   # None until resolved
        if geo and geo["is_high_risk"]:
            ...
    """

    def __init__(self):
        # ip → {"country": str, "country_code": str, "flag": str, "is_high_risk": bool}
        self._cache: dict[str, dict] = {}
        self._pending: set[str]      = set()
        self._lock                   = threading.Lock()
        self._enabled                = config.GEOIP_ENABLED

        if self._enabled:
            t = threading.Thread(target=self._loop, name="geoip-resolver", daemon=True)
            t.start()
            logger.info("GeoIP resolver spuštěn")
        else:
            logger.info("GeoIP vypnuto (GEOIP_ENABLED=False)")

    # ── Public API ────────────────────────────────────────────────────────────

    def enqueue(self, ip: str):
        """Queue an IP for resolution (no-op if private, already cached, or disabled)."""
        if not self._enabled or not ip or _is_private(ip):
            return
        with self._lock:
            if ip not in self._cache:
                self._pending.add(ip)

    def get(self, ip: str) -> Optional[dict]:
        """Return cached geo dict or None if not yet resolved."""
        with self._lock:
            return self._cache.get(ip)

    def get_country_display(self, ip: str) -> str:
        """Return a human-readable label like 'RU  Russia' or '' if unknown.

        Flag emoji (🇷🇺) are intentionally omitted here because Windows GDI /
        tkinter does not render Regional Indicator symbol pairs as flag glyphs —
        they appear as bare letters (AT, RU…). Flag emoji are still used in the
        HTML report where the browser handles rendering correctly.
        """
        geo = self.get(ip)
        if not geo:
            return ""
        cc      = geo.get("country_code", "")
        country = geo.get("country", "")
        if cc and country:
            return f"{cc}  {country}"
        return country or cc

    def is_high_risk(self, ip: str) -> bool:
        geo = self.get(ip)
        return bool(geo and geo.get("is_high_risk"))

    def country_code(self, ip: str) -> str:
        geo = self.get(ip)
        return geo.get("country_code", "") if geo else ""

    # ── Background resolver ───────────────────────────────────────────────────

    def _loop(self):
        """Wake every 15 seconds and flush the pending queue."""
        while True:
            time.sleep(15)
            if not self._enabled:
                continue
            with self._lock:
                batch = list(self._pending)[:100]
                self._pending -= set(batch)
            if batch:
                self._resolve(batch)

    def _resolve(self, ips: list[str]):
        """Call ip-api.com batch endpoint and populate the cache."""
        try:
            payload = [
                {"query": ip, "fields": "status,country,countryCode,query"}
                for ip in ips
            ]
            r = requests.post(
                "http://ip-api.com/batch",
                json=payload,
                timeout=10,
            )
            if r.status_code != 200:
                logger.debug("ip-api.com vrátil %d", r.status_code)
                return

            resolved = 0
            with self._lock:
                for item in r.json():
                    if item.get("status") == "success":
                        cc      = item.get("countryCode", "")
                        country = item.get("country", "")
                        self._cache[item["query"]] = {
                            "country":      country,
                            "country_code": cc,
                            "flag":         flag_emoji(cc),
                            "is_high_risk": cc in config.HIGH_RISK_COUNTRIES,
                        }
                        resolved += 1

            logger.debug("GeoIP: přeloženo %d/%d IP", resolved, len(ips))

        except requests.exceptions.ConnectionError:
            logger.info("GeoIP: ip-api.com není dostupné — GeoIP vypínám")
            self._enabled = False
        except Exception as e:
            logger.debug("GeoIP chyba: %s", e)


# ── Module-level singleton ────────────────────────────────────────────────────
# Import this everywhere:  from geoip import geoip_cache
geoip_cache = GeoIPCache()
