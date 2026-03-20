"""
enricher.py — Enrich attacker IPs with geolocation and ASN data.

Uses ip-api.com (free, no API key required).
  - Rate limit: 45 requests/minute on the free tier.
  - This module caches results in memory so each unique IP is only
    looked up once per pipeline run, keeping well within the limit.

Enrichment fields added per IP:
    {
        "country":      str | None
        "country_code": str | None
        "region":       str | None
        "city":         str | None
        "isp":          str | None
        "org":          str | None   — typically "AS##### ORG NAME"
        "asn":          str | None   — extracted from org field
        "lat":          float | None
        "lon":          float | None
        "enriched":     bool         — False means the lookup failed
    }
"""

import logging
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ip-api.com free tier allows 45 req/min — 1.4 seconds/req is safe
_RATE_LIMIT_DELAY = 1.5
_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,lat,lon,query"

# Private/reserved ranges to skip (no point querying these)
_SKIP_PREFIXES = ("10.", "192.168.", "172.16.", "127.", "0.", "::1")

# In-memory cache: ip → enrichment dict
_cache: dict[str, dict] = {}


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _SKIP_PREFIXES)


def _extract_asn(org: Optional[str]) -> Optional[str]:
    """Pull just the AS number from ip-api's org field (e.g. 'AS12345 SomeISP')."""
    if not org:
        return None
    parts = org.split()
    if parts and parts[0].upper().startswith("AS"):
        return parts[0].upper()
    return None


def enrich_ip(ip: str) -> dict:
    """
    Look up geolocation and ASN for a single IP.
    Results are cached — identical IPs are only queried once.

    Args:
        ip: IPv4 address string.

    Returns:
        Enrichment dict (see module docstring). Always returns a dict;
        'enriched' key is False if the lookup failed or was skipped.
    """
    if ip in _cache:
        return _cache[ip]

    empty = {
        "country": None, "country_code": None, "region": None,
        "city": None, "isp": None, "org": None, "asn": None,
        "lat": None, "lon": None, "enriched": False,
    }

    if _is_private(ip):
        logger.debug("Skipping private IP: %s", ip)
        _cache[ip] = empty
        return empty

    try:
        time.sleep(_RATE_LIMIT_DELAY)
        resp = requests.get(_API_URL.format(ip=ip), timeout=10)
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "success":
            logger.warning("ip-api returned non-success for %s: %s", ip, data.get("message"))
            _cache[ip] = empty
            return empty

        org = data.get("org")
        result = {
            "country":      data.get("country"),
            "country_code": data.get("countryCode"),
            "region":       data.get("regionName"),
            "city":         data.get("city"),
            "isp":          data.get("isp"),
            "org":          org,
            "asn":          _extract_asn(org),
            "lat":          data.get("lat"),
            "lon":          data.get("lon"),
            "enriched":     True,
        }
        logger.info("Enriched %s → %s, %s (%s)", ip, result["city"], result["country"], result["asn"])
        _cache[ip] = result
        return result

    except requests.RequestException as exc:
        logger.error("Failed to enrich %s: %s", ip, exc)
        _cache[ip] = empty
        return empty


def enrich_events(events: list[dict]) -> list[dict]:
    """
    Enrich a list of normalized events in-place by adding geo/ASN data.

    Unique IPs are discovered first so we can log progress clearly
    before making any network calls.

    Args:
        events: List of normalized event dicts from parser.py.

    Returns:
        The same list, with each event updated to include a nested
        'geo' key containing the enrichment dict.
    """
    unique_ips = {e["src_ip"] for e in events if e.get("src_ip")}
    public_ips = [ip for ip in unique_ips if not _is_private(ip)]

    logger.info(
        "Enriching %d unique public IPs (cached=%d, new=%d)...",
        len(public_ips),
        sum(1 for ip in public_ips if ip in _cache),
        sum(1 for ip in public_ips if ip not in _cache),
    )

    for event in events:
        ip = event.get("src_ip")
        event["geo"] = enrich_ip(ip) if ip else {
            "country": None, "country_code": None, "region": None,
            "city": None, "isp": None, "org": None, "asn": None,
            "lat": None, "lon": None, "enriched": False,
        }

    return events