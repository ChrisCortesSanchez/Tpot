"""
parser.py — Normalize raw T-Pot honeypot logs into a unified event schema.

Updated for real T-Pot Elasticsearch exports where:
  - Field is 'dest_port' not 'dst_port'
  - Geo data is already embedded in a 'geoip' block (T-Pot pre-enriches)
  - Honeytrap HTTP request data is hex-encoded in attack_connection.payload.data_hex
  - Dionaea connection type lives in connection.protocol

Because T-Pot already includes geo enrichment, the enricher.py step is
bypassed — geo is extracted directly from the 'geoip' block in each event.

Unified event schema:
    {
        "timestamp":    str  — ISO8601
        "service":      str  — "cowrie" | "dionaea" | "honeytrap"
        "src_ip":       str
        "src_port":     int | None
        "dst_port":     int | None
        "event_type":   str  — normalized label
        "username":     str | None
        "password":     str | None
        "command":      str | None
        "uri":          str | None
        "method":       str | None
        "user_agent":   str | None
        "exploit":      str | None
        "payload_hash": str | None
        "geo":          dict — pre-populated from T-Pot's geoip block
        "raw":          dict — original event for reference
    }
"""

import json
import logging
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

# ── Cowrie eventid → normalized label ─────────────────────────────────────────
COWRIE_EVENT_MAP = {
    "cowrie.session.connect":       "connection",
    "cowrie.login.failed":          "login_failed",
    "cowrie.login.success":         "login_success",
    "cowrie.command.input":         "command_exec",
    "cowrie.session.closed":        "session_closed",
    "cowrie.session.file_download": "file_download",
    "cowrie.direct-tcpip.request":  "tcp_forward",
}


def _extract_geo(raw: dict) -> dict:
    """
    Extract geo/ASN fields from T-Pot's embedded 'geoip' block.
    This replaces the ip-api.com enrichment step entirely since
    T-Pot already enriches every event at ingest time.
    """
    g = raw.get("geoip") or {}
    asn = g.get("asn")
    as_org = g.get("as_org")
    asn_str = f"AS{asn}" if asn else None

    return {
        "country":      g.get("country_name"),
        "country_code": g.get("country_code2"),
        "region":       g.get("region_name"),
        "city":         g.get("city_name"),
        "isp":          as_org,
        "org":          f"{asn_str} {as_org}" if asn_str and as_org else as_org,
        "asn":          asn_str,
        "lat":          g.get("latitude"),
        "lon":          g.get("longitude"),
        "enriched":     bool(g),
    }


def _decode_honeytrap_payload(raw: dict) -> tuple[str | None, str | None, str | None]:
    """
    Honeytrap stores the raw HTTP request as hex in:
        attack_connection.payload.data_hex

    Decode it and parse out method, URI, and User-Agent.
    Returns (method, uri, user_agent) — any may be None.
    """
    try:
        attack = raw.get("attack_connection") or {}
        payload = attack.get("payload") or {}
        hex_data = payload.get("data_hex", "")
        if not hex_data:
            return None, None, None

        decoded = bytes.fromhex(hex_data).decode("utf-8", errors="replace")
        lines = decoded.split("\r\n")

        method, uri, user_agent = None, None, None

        # First line: "METHOD /path HTTP/x.x"
        if lines:
            parts = lines[0].split(" ")
            if len(parts) >= 2:
                method = parts[0]
                uri = parts[1]

        # Remaining lines are headers
        for line in lines[1:]:
            if line.lower().startswith("user-agent:"):
                user_agent = line.split(":", 1)[1].strip()
                break

        return method, uri, user_agent

    except Exception:
        return None, None, None


def _parse_cowrie(raw: dict) -> dict | None:
    """Parse a real T-Pot Cowrie event into the unified schema."""
    event_id = raw.get("eventid", "")
    event_type = COWRIE_EVENT_MAP.get(event_id, event_id)

    # Skip pure bookkeeping events
    if event_type == "session_closed":
        return None

    return {
        "timestamp":    raw.get("timestamp"),
        "service":      "cowrie",
        "src_ip":       raw.get("src_ip"),
        "src_port":     raw.get("src_port"),
        "dst_port":     raw.get("dest_port"),    # T-Pot uses dest_port
        "event_type":   event_type,
        "username":     raw.get("username"),
        "password":     raw.get("password"),
        "command":      raw.get("input"),
        "uri":          None,
        "method":       None,
        "user_agent":   None,
        "exploit":      None,
        "payload_hash": raw.get("shasum"),
        "geo":          _extract_geo(raw),
        "raw":          raw,
    }


def _parse_dionaea(raw: dict) -> dict | None:
    """Parse a real T-Pot Dionaea event into the unified schema."""
    connection = raw.get("connection") or {}
    protocol = connection.get("protocol", "")
    conn_type = connection.get("type", "connection")

    DIONAEA_PROTO_MAP = {
        "smbd":   "smb_connection",
        "httpd":  "http_connection",
        "ftpd":   "ftp_connection",
        "mysqld": "mysql_connection",
        "mssqld": "mssql_connection",
        "sipd":   "sip_connection",
    }
    event_type = DIONAEA_PROTO_MAP.get(protocol, conn_type or "connection")

    return {
        "timestamp":    raw.get("timestamp") or raw.get("@timestamp"),
        "service":      "dionaea",
        "src_ip":       raw.get("src_ip"),
        "src_port":     raw.get("src_port"),
        "dst_port":     raw.get("dest_port"),    # T-Pot uses dest_port
        "event_type":   event_type,
        "username":     raw.get("username"),
        "password":     raw.get("password"),
        "command":      None,
        "uri":          None,
        "method":       None,
        "user_agent":   None,
        "exploit":      raw.get("exploit"),
        "payload_hash": raw.get("md5_hash") or raw.get("sha512_hash"),
        "geo":          _extract_geo(raw),
        "raw":          raw,
    }


def _parse_honeytrap(raw: dict) -> dict | None:
    """Parse a real T-Pot Honeytrap event into the unified schema."""
    method, uri, user_agent = _decode_honeytrap_payload(raw)

    attack = raw.get("attack_connection") or {}
    payload = attack.get("payload") or {}
    payload_hash = payload.get("sha512_hash") or payload.get("md5_hash")

    return {
        "timestamp":    raw.get("start_time") or raw.get("@timestamp"),
        "service":      "honeytrap",
        "src_ip":       raw.get("src_ip"),
        "src_port":     raw.get("src_port"),
        "dst_port":     raw.get("dest_port"),    # T-Pot uses dest_port
        "event_type":   "http_request",
        "username":     None,
        "password":     None,
        "command":      None,
        "uri":          uri,
        "method":       method,
        "user_agent":   user_agent,
        "exploit":      None,
        "payload_hash": payload_hash,
        "geo":          _extract_geo(raw),
        "raw":          raw,
    }


_PARSERS = {
    "cowrie":    _parse_cowrie,
    "dionaea":   _parse_dionaea,
    "honeytrap": _parse_honeytrap,
}


def load_log_file(path: Path, service: str) -> Generator[dict, None, None]:
    """
    Load a JSON log file for the given service and yield normalized events.

    Args:
        path:    Path to a JSON file (list of objects).
        service: One of "cowrie", "dionaea", "honeytrap".

    Yields:
        Normalized event dicts (None results are silently skipped).
    """
    if service not in _PARSERS:
        raise ValueError(f"Unknown service '{service}'. Choose from: {list(_PARSERS)}")

    parser_fn = _PARSERS[service]

    with open(path, "r") as f:
        raw_events = json.load(f)

    if not isinstance(raw_events, list):
        raise ValueError(f"Expected a JSON array in {path}, got {type(raw_events)}")

    skipped = 0
    for raw in raw_events:
        parsed = parser_fn(raw)
        if parsed is None:
            skipped += 1
            continue
        yield parsed

    if skipped:
        logger.debug("Skipped %d bookkeeping events from %s", skipped, path.name)


def load_all(data_dir: Path) -> list[dict]:
    """
    Scan a directory for cowrie.json, dionaea.json, and honeytrap.json,
    parse whichever exist, and return a combined list sorted by timestamp.

    Args:
        data_dir: Directory containing the exported log files.

    Returns:
        All normalized events sorted by timestamp ascending.
    """
    events: list[dict] = []
    found = 0

    for service in ("cowrie", "dionaea", "honeytrap"):
        log_path = data_dir / f"{service}.json"
        if not log_path.exists():
            logger.warning("No log file found for %s (expected %s)", service, log_path)
            continue

        before = len(events)
        events.extend(load_log_file(log_path, service))
        count = len(events) - before
        found += 1
        logger.info("Loaded %d events from %s", count, log_path.name)

    if not found:
        raise FileNotFoundError(f"No log files found in {data_dir}")

    events.sort(key=lambda e: e.get("timestamp") or "")
    logger.info("Total events after merge: %d", len(events))
    return events