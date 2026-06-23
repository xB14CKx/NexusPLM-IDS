"""GeoIP2 reader — loaded once at startup, None if .mmdb not present."""
from __future__ import annotations
import logging
from app.modules.core.config import get_settings

logger = logging.getLogger("ids.geoip")
_reader = None


def load_geoip():
    global _reader
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(get_settings().geoip_db_path)
        logger.info("GeoIP2 database loaded.")
    except Exception as e:
        logger.warning(f"GeoIP2 not available ({e}). Geo-jump detection disabled.")


def get_geoip():
    return _reader


def close_geoip():
    if _reader:
        _reader.close()


def lookup_country(ip: str) -> str | None:
    """Returns ISO country code or None."""
    if _reader is None:
        return None
    try:
        return _reader.city(ip).country.iso_code or None
    except Exception:
        return None
