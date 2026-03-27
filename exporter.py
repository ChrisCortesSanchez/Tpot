"""
export.py — Export T-Pot honeypot logs from Elasticsearch into flat JSON files.

Run this on the T-Pot VM after stopping the T-Pot service and starting
Elasticsearch standalone. Outputs one JSON file per honeypot service,
ready to be fed directly into the pipeline on your local machine.

Usage:
    python3 export.py
    python3 export.py --host 127.0.0.1 --port 64298 --output-dir /home/bob
    python3 export.py --services cowrie,dionaea
    python3 export.py --page-size 2000

Background:
    T-Pot stores all honeypot events in Elasticsearch using date-based indices
    (logstash-YYYY.MM.DD). All services share these indices and are distinguished
    by a 'type' field (e.g. 'Cowrie', 'Dionaea', 'Honeytrap'). This script
    uses the Elasticsearch scroll API to paginate through all matching events
    and write them as a flat JSON array to disk.

Setup on the T-Pot VM (run these before this script):
    systemctl stop tpot
    cd /home/<user>/tpotce/docker/elk/elasticsearch
    docker compose up -d
    # Wait ~30 seconds for Elasticsearch to become healthy
    # Then run this script as the same user (not root)
"""

import json
import sys
import time
import argparse
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: requests is not installed. Run: pip3 install requests")
    sys.exit(1)


# ── Constants ─────────────────────────────────────────────────────────────────

# T-Pot's real Elasticsearch container is bound to 127.0.0.1:64298.
# Port 9200 is the ElasticPot honeypot — do NOT use it for export.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 64298

# All T-Pot services stored in Elasticsearch with their type field values.
# Keys are output filenames (without .json), values are the Elasticsearch type.
ALL_SERVICES = {
    "cowrie":    "Cowrie",
    "dionaea":   "Dionaea",
    "honeytrap": "Honeytrap",
}

SCROLL_TTL  = "3m"   # How long Elasticsearch keeps the scroll context alive
DEFAULT_PAGE_SIZE = 5000


# ── Helpers ───────────────────────────────────────────────────────────────────

def wait_for_elasticsearch(base_url: str, retries: int = 10, delay: int = 5) -> bool:
    """Poll Elasticsearch health endpoint until it responds or retries are exhausted."""
    print(f"Waiting for Elasticsearch at {base_url}...")
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(f"{base_url}/_cluster/health", timeout=5)
            if resp.status_code == 200:
                status = resp.json().get("status", "unknown")
                print(f"  Elasticsearch is {status} (attempt {attempt}/{retries})")
                return True
        except requests.exceptions.ConnectionError:
            pass
        print(f"  Not ready yet, retrying in {delay}s... ({attempt}/{retries})")
        time.sleep(delay)
    return False


def list_available_types(base_url: str) -> dict[str, int]:
    """
    Query the type.keyword aggregation to show what services have data
    and how many events each has. Useful for verifying data is present
    before running a full export.
    """
    resp = requests.post(
        f"{base_url}/logstash-*/_search",
        json={
            "size": 0,
            "aggs": {
                "types": {
                    "terms": {"field": "type.keyword", "size": 50}
                }
            }
        },
        timeout=60,
    )
    resp.raise_for_status()
    buckets = resp.json()["aggregations"]["types"]["buckets"]
    return {b["key"]: b["doc_count"] for b in buckets}


def export_service(
    base_url: str,
    type_name: str,
    output_path: Path,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> int:
    """
    Export all events of a given type using the Elasticsearch scroll API.
    Paginates through all results regardless of total count.

    Args:
        base_url:    Elasticsearch base URL.
        type_name:   Value of the 'type' field (e.g. 'Cowrie').
        output_path: Path to write the output JSON file.
        page_size:   Number of events to fetch per scroll page.

    Returns:
        Total number of events written.
    """
    # Initial search — opens the scroll context
    resp = requests.post(
        f"{base_url}/logstash-*/_search?scroll={SCROLL_TTL}",
        json={
            "size": page_size,
            "query": {"term": {"type.keyword": type_name}},
        },
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()

    scroll_id = data["_scroll_id"]
    hits = data["hits"]["hits"]
    all_docs = [h["_source"] for h in hits]

    # Paginate through remaining pages
    while hits:
        resp = requests.post(
            f"{base_url}/_search/scroll",
            json={"scroll": SCROLL_TTL, "scroll_id": scroll_id},
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()

        # Elasticsearch returns an error dict instead of raising if scroll expires
        if "error" in data:
            print(f"  ERROR: Scroll context expired. Try a smaller --page-size.")
            break

        hits = data["hits"]["hits"]
        all_docs.extend(h["_source"] for h in hits)
        print(f"  {len(all_docs):,} records fetched...")

    # Clean up scroll context to free Elasticsearch memory
    try:
        requests.delete(
            f"{base_url}/_search/scroll",
            json={"scroll_id": scroll_id},
            timeout=10,
        )
    except Exception:
        pass

    # Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(all_docs, f)

    return len(all_docs)


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export T-Pot honeypot logs from Elasticsearch to JSON files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 export.py
  python3 export.py --output-dir /home/bob/exports
  python3 export.py --services cowrie,dionaea
  python3 export.py --port 9200 --page-size 2000
        """,
    )
    parser.add_argument(
        "--host", default=DEFAULT_HOST,
        help=f"Elasticsearch host (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"Elasticsearch port (default: {DEFAULT_PORT}). "
             "NOTE: T-Pot binds real ES to 64298. Port 9200 is the ElasticPot honeypot.",
    )
    parser.add_argument(
        "--output-dir", default="/home/bob",
        help="Directory to write output JSON files (default: /home/bob)",
    )
    parser.add_argument(
        "--services", default="cowrie,dionaea,honeytrap",
        help="Comma-separated list of services to export (default: cowrie,dionaea,honeytrap)",
    )
    parser.add_argument(
        "--page-size", type=int, default=DEFAULT_PAGE_SIZE,
        help=f"Events per scroll page (default: {DEFAULT_PAGE_SIZE}). "
             "Reduce if Elasticsearch runs out of memory.",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List available data types and event counts, then exit.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    base_url = f"http://{args.host}:{args.port}"
    output_dir = Path(args.output_dir)

    # Wait for Elasticsearch to be ready
    if not wait_for_elasticsearch(base_url):
        print(f"\nERROR: Could not connect to Elasticsearch at {base_url}")
        print("Make sure you have started Elasticsearch standalone:")
        print("  cd /home/<user>/tpotce/docker/elk/elasticsearch")
        print("  docker compose up -d")
        sys.exit(1)

    # List mode: show available types and exit
    if args.list:
        print("\nAvailable data types in Elasticsearch:")
        types = list_available_types(base_url)
        for type_name, count in sorted(types.items(), key=lambda x: -x[1]):
            print(f"  {type_name:<20} {count:>10,} events")
        sys.exit(0)

    # Parse requested services
    requested = [s.strip().lower() for s in args.services.split(",")]
    unknown = [s for s in requested if s not in ALL_SERVICES]
    if unknown:
        print(f"ERROR: Unknown services: {unknown}")
        print(f"Available: {list(ALL_SERVICES.keys())}")
        sys.exit(1)

    # Show available event counts before starting
    print("\nChecking available event counts...")
    available = list_available_types(base_url)
    for name in requested:
        type_name = ALL_SERVICES[name]
        count = available.get(type_name, 0)
        print(f"  {name:<12} {count:>10,} events")

    print(f"\nExporting to {output_dir}/\n")

    # Export each service
    results = {}
    for name in requested:
        type_name = ALL_SERVICES[name]
        output_path = output_dir / f"{name}-backup.json"

        print(f"[{name}] Exporting '{type_name}' events...")
        count = export_service(base_url, type_name, output_path, args.page_size)
        results[name] = count
        print(f"[{name}] Done: {count:,} events written to {output_path}\n")

    # Summary
    print("=" * 50)
    print("Export complete:")
    for name, count in results.items():
        output_path = output_dir / f"{name}-backup.json"
        size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"  {name:<12} {count:>10,} events  ({size_mb:.1f} MB)")
    print("=" * 50)
    print("\nNext: scp these files to your local machine and run the pipeline.")
    print("Example:")
    for name in results:
        print(f"  scp -P 64295 <user>@YOUR_IP:{output_dir}/{name}-backup.json ./data/{name}.json")


if __name__ == "__main__":
    main()