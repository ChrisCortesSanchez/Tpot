"""
parser.py — Normalize raw T-Pot honeypot logs into a unified event schema.

Each honeypot service (Cowrie, Dionaea, Honeytrap) writes logs in its own format.
This module reads those JSON exports and normalizes every event into a shared
structure so the rest of the pipeline can treat them uniformly.

Unified event schema:
    {
        "timestamp":  str  — ISO8601
        "service":    str  — "cowrie" | "dionaea" | "honeytrap"
        "src_ip":     str
        "src_port":   int | None
        "dst_port":   int | None
        "event_type": str  — normalized label (see constants below)
        "username":   str | None
        "password":   str | None
        "command":    str | None
        "uri":        str | None
        "method":     str | None
        "user_agent": str | None
        "exploit":    str | None
        "payload_hash": str | None
        "raw":        dict — original event for reference
    }
"""

import json
import logging
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

# ── Cowrie event_id → normalized label ────────────────────────────────────────
COWRIE_EVENT_MAP = {
    "cowrie.session.connect":   "connection",
    "cowrie.login.failed":      "login_failed",
    "cowrie.login.success":     "login_success",
    "cowrie.command.input":     "command_exec",
    "cowrie.session.closed":    "session_closed",
    "cowrie.session.file_download": "file_download",
    "cowrie.direct-tcpip.request":  "tcp_forward",
}


def _parse_cowrie(raw: dict) -> dict | None:
    """Parse a single Cowrie JSON event into the unified schema."""
    event_id = raw.get("eventid", "")
    event_type = COWRIE_EVENT_MAP.get(event_id, event_id)

    # Skip pure bookkeeping events that add no analytical value
    if event_type == "session_closed":
        return None

    return {
        "timestamp":    raw.get("timestamp"),
        "service":      "cowrie",
        "src_ip":       raw.get("src_ip"),
        "src_port":     raw.get("src_port"),
        "dst_port":     raw.get("dst_port"),
        "event_type":   event_type,
        "username":     raw.get("username"),
        "password":     raw.get("password"),
        "command":      raw.get("input"),          # cowrie field name
        "uri":          None,
        "method":       None,
        "user_agent":   None,
        "exploit":      None,
        "payload_hash": raw.get("shasum"),         # file download SHA
        "raw":          raw,
    }


def _parse_dionaea(raw: dict) -> dict | None:
    """Parse a single Dionaea JSON event into the unified schema."""
    return {
        "timestamp":    raw.get("timestamp"),
        "service":      "dionaea",
        "src_ip":       raw.get("src_ip"),
        "src_port":     raw.get("src_port"),
        "dst_port":     raw.get("dst_port"),
        "event_type":   raw.get("event_type", "connection"),
        "username":     raw.get("username"),
        "password":     raw.get("password"),
        "command":      None,
        "uri":          None,
        "method":       None,
        "user_agent":   None,
        "exploit":      raw.get("exploit"),
        "payload_hash": raw.get("payload_sha512"),
        "raw":          raw,
    }


def _parse_honeytrap(raw: dict) -> dict | None:
    """Parse a single Honeytrap HTTP JSON event into the unified schema."""
    return {
        "timestamp":    raw.get("timestamp"),
        "service":      "honeytrap",
        "src_ip":       raw.get("src_ip"),
        "src_port":     raw.get("src_port"),
        "dst_port":     raw.get("dst_port"),
        "event_type":   "http_request",
        "username":     None,
        "password":     None,
        "command":      None,
        "uri":          raw.get("uri"),
        "method":       raw.get("method"),
        "user_agent":   raw.get("user_agent"),
        "exploit":      None,
        "payload_hash": None,
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
    Convenience function: scan a directory for cowrie.json, dionaea.json,
    and honeytrap.json, parse whichever exist, and return a combined sorted list.

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