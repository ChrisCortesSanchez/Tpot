"""
analyzer.py — Produce threat intelligence findings from enriched events.

This module takes the normalized + enriched event list and runs a series
of analysis passes to extract meaningful findings. Each function returns
a structured dict that feeds directly into the reporter.

Analysis passes:
    1.  summary()           — high-level counts
    2.  top_ips()           — most active source IPs with geo context
    3.  top_countries()     — attack volume by country
    4.  top_asns()          — attack volume by ASN (key for botnet ID)
    5.  top_ports()         — most targeted destination ports
    6.  top_credentials()   — most attempted username/password combos (Cowrie)
    7.  repeat_offenders()  — IPs active across multiple days
    8.  credential_clusters() — group IPs sharing identical cred lists (botnet sig)
    9.  malware_samples()   — unique payload hashes from Dionaea
    10. web_recon_paths()   — most probed URIs from Honeytrap
    11. attacker_timeline() — hourly event volume for trend chart
    12. session_commands()  — post-login command sequences (Cowrie login_success)
"""

from collections import Counter, defaultdict
from datetime import datetime, timezone


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_ts(ts_str: str | None) -> datetime | None:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return None


def _day(ts_str: str | None) -> str | None:
    dt = _parse_ts(ts_str)
    return dt.strftime("%Y-%m-%d") if dt else None


def _hour_bucket(ts_str: str | None) -> str | None:
    dt = _parse_ts(ts_str)
    return dt.strftime("%Y-%m-%d %H:00") if dt else None


# ── Analysis functions ─────────────────────────────────────────────────────────

def summary(events: list[dict]) -> dict:
    """High-level event counts by service and type."""
    by_service: Counter = Counter()
    by_type: Counter = Counter()
    unique_ips: set = set()

    for e in events:
        by_service[e.get("service", "unknown")] += 1
        by_type[e.get("event_type", "unknown")] += 1
        if e.get("src_ip"):
            unique_ips.add(e["src_ip"])

    return {
        "total_events":   len(events),
        "unique_ips":     len(unique_ips),
        "by_service":     dict(by_service.most_common()),
        "by_event_type":  dict(by_type.most_common()),
    }


def top_ips(events: list[dict], n: int = 10) -> list[dict]:
    """Most active source IPs with geo context and event breakdown."""
    ip_events: dict[str, list] = defaultdict(list)
    for e in events:
        ip = e.get("src_ip")
        if ip:
            ip_events[ip].append(e)

    rows = []
    for ip, evts in sorted(ip_events.items(), key=lambda x: -len(x[1]))[:n]:
        geo = evts[0].get("geo", {})
        by_type: Counter = Counter(e.get("event_type") for e in evts)
        rows.append({
            "ip":           ip,
            "event_count":  len(evts),
            "country":      geo.get("country", "Unknown"),
            "country_code": geo.get("country_code"),
            "city":         geo.get("city"),
            "asn":          geo.get("asn"),
            "isp":          geo.get("isp"),
            "event_types":  dict(by_type.most_common(3)),
        })
    return rows


def top_countries(events: list[dict], n: int = 10) -> list[dict]:
    """Attack volume by country."""
    counter: Counter = Counter()
    for e in events:
        country = e.get("geo", {}).get("country") or "Unknown"
        counter[country] += 1

    return [
        {"country": c, "event_count": cnt}
        for c, cnt in counter.most_common(n)
    ]


def top_asns(events: list[dict], n: int = 10) -> list[dict]:
    """
    Attack volume by ASN.
    High concentration from a single ASN → likely botnet or VPS abuse.
    """
    asn_data: dict[str, dict] = {}
    for e in events:
        geo = e.get("geo", {})
        asn = geo.get("asn") or "Unknown"
        if asn not in asn_data:
            asn_data[asn] = {"asn": asn, "org": geo.get("org"), "count": 0, "ips": set()}
        asn_data[asn]["count"] += 1
        if e.get("src_ip"):
            asn_data[asn]["ips"].add(e["src_ip"])

    rows = sorted(asn_data.values(), key=lambda x: -x["count"])[:n]
    for row in rows:
        row["unique_ips"] = len(row.pop("ips"))
    return rows


def top_ports(events: list[dict], n: int = 10) -> list[dict]:
    """Most targeted destination ports with service labels."""
    PORT_LABELS = {
        22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
        445: "SMB", 1433: "MSSQL", 3306: "MySQL",
        3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
    }
    counter: Counter = Counter()
    for e in events:
        port = e.get("dst_port")
        if port:
            counter[port] += 1

    return [
        {
            "port":        port,
            "service":     PORT_LABELS.get(port, "Unknown"),
            "event_count": cnt,
        }
        for port, cnt in counter.most_common(n)
    ]


def top_credentials(events: list[dict], n: int = 15) -> list[dict]:
    """
    Most attempted username/password pairs from Cowrie.
    Useful for identifying botnet credential dictionaries.
    """
    counter: Counter = Counter()
    for e in events:
        if e.get("service") == "cowrie" and e.get("username") and e.get("password"):
            key = (e["username"], e["password"])
            counter[key] += 1

    return [
        {"username": u, "password": p, "count": c}
        for (u, p), c in counter.most_common(n)
    ]


def repeat_offenders(events: list[dict], min_days: int = 2) -> list[dict]:
    """
    IPs that appear on multiple distinct days — persistent scanners vs. one-offs.
    Persistent IPs are higher priority for blocking/reporting.
    """
    ip_days: dict[str, set] = defaultdict(set)
    ip_count: Counter = Counter()

    for e in events:
        ip = e.get("src_ip")
        day = _day(e.get("timestamp"))
        if ip and day:
            ip_days[ip].add(day)
            ip_count[ip] += 1

    rows = []
    for ip, days in ip_days.items():
        if len(days) >= min_days:
            geo = next(
                (e.get("geo", {}) for e in events if e.get("src_ip") == ip), {}
            )
            rows.append({
                "ip":          ip,
                "active_days": sorted(days),
                "day_count":   len(days),
                "total_events": ip_count[ip],
                "country":     geo.get("country"),
                "asn":         geo.get("asn"),
            })

    return sorted(rows, key=lambda x: -x["day_count"])


def credential_clusters(events: list[dict]) -> list[dict]:
    """
    Group IPs that share identical sets of attempted credentials.
    IPs sharing a cred list very likely belong to the same botnet campaign.
    """
    ip_creds: dict[str, set] = defaultdict(set)
    for e in events:
        if e.get("service") == "cowrie" and e.get("username") and e.get("password"):
            ip_creds[e["src_ip"]].add((e["username"], e["password"]))

    # Build fingerprint → IPs map
    clusters: dict[frozenset, list] = defaultdict(list)
    for ip, creds in ip_creds.items():
        clusters[frozenset(creds)].append(ip)

    rows = []
    for cred_set, ips in clusters.items():
        if len(ips) > 1:  # only interesting if shared
            rows.append({
                "ips":        ips,
                "ip_count":   len(ips),
                "credentials": [{"username": u, "password": p} for u, p in sorted(cred_set)],
                "cred_count":  len(cred_set),
            })

    return sorted(rows, key=lambda x: -x["ip_count"])


def malware_samples(events: list[dict], n: int = 50) -> tuple[list[dict], int]:
    """Unique payload hashes collected by Dionaea — capped at n for display.
    Returns (capped list, total unique count).
    """
    seen: dict[str, dict] = {}
    for e in events:
        h = e.get("payload_hash")
        if h and h not in seen:
            seen[h] = {
                "hash":      h,
                "src_ip":    e.get("src_ip"),
                "timestamp": e.get("timestamp"),
                "exploit":   e.get("exploit"),
                "dst_port":  e.get("dst_port"),
            }
    return list(seen.values())[:n], len(seen)


def web_recon_paths(events: list[dict], n: int = 15) -> list[dict]:
    """Most probed HTTP URIs from Honeytrap."""
    counter: Counter = Counter()
    for e in events:
        uri = e.get("uri")
        if uri:
            counter[uri] += 1

    return [
        {"uri": uri, "count": cnt}
        for uri, cnt in counter.most_common(n)
    ]


def attacker_timeline(events: list[dict]) -> list[dict]:
    """
    Event counts bucketed by hour — reveals scanning patterns,
    e.g. activity peaks at night UTC suggesting specific geo origins.
    """
    counter: Counter = Counter()
    for e in events:
        bucket = _hour_bucket(e.get("timestamp"))
        if bucket:
            counter[bucket] += 1

    return [
        {"hour": h, "count": c}
        for h, c in sorted(counter.items())
    ]


def session_commands(events: list[dict], n: int = 50) -> list[dict]:
    """
    For Cowrie sessions that included a successful login, return the
    full sequence of commands the attacker ran. This is the highest
    fidelity data for understanding attacker intent and TTPs.
    """
    # Find sessions that had a successful login
    successful_sessions: set = set()
    for e in events:
        if e.get("event_type") == "login_success":
            session = e.get("raw", {}).get("session")
            if session:
                successful_sessions.add(session)

    # Group commands by session
    session_data: dict[str, dict] = defaultdict(lambda: {"ip": None, "commands": [], "timestamp": None})
    for e in events:
        raw = e.get("raw", {})
        session = raw.get("session")
        if session and session in successful_sessions:
            session_data[session]["ip"] = e.get("src_ip")
            if not session_data[session]["timestamp"]:
                session_data[session]["timestamp"] = e.get("timestamp")
            if e.get("event_type") == "command_exec" and e.get("command"):
                session_data[session]["commands"].append(e["command"])

    rows = []
    for session, data in session_data.items():
        if data["commands"]:
            geo = next(
                (e.get("geo", {}) for e in events if e.get("src_ip") == data["ip"]), {}
            )
            rows.append({
                "session":   session,
                "src_ip":    data["ip"],
                "timestamp": data["timestamp"],
                "country":   geo.get("country"),
                "asn":       geo.get("asn"),
                "commands":  data["commands"],
                "cmd_count": len(data["commands"]),
            })

    return sorted(rows, key=lambda x: -x["cmd_count"])[:n]


# ── Master run ────────────────────────────────────────────────────────────────

def run_all(events: list[dict]) -> dict:
    """Run every analysis pass and return a single findings dict."""
    malware, malware_total = malware_samples(events)
    return {
        "summary":             summary(events),
        "top_ips":             top_ips(events),
        "top_countries":       top_countries(events),
        "top_asns":            top_asns(events),
        "top_ports":           top_ports(events),
        "top_credentials":     top_credentials(events),
        "repeat_offenders":    repeat_offenders(events),
        "credential_clusters": credential_clusters(events),
        "malware_samples":     malware,
        "malware_total":       malware_total,
        "web_recon_paths":     web_recon_paths(events),
        "attacker_timeline":   attacker_timeline(events),
        "session_commands":    session_commands(events),
    }