"""
main.py — CLI entry point for the honeypot threat intelligence pipeline.

Usage examples:
    # Run full pipeline on live exported data
    python -m pipeline.main run --data-dir ./data

    # Dry run on sample data (no network enrichment calls)
    python -m pipeline.main run --data-dir ./sample_data --skip-enrichment

    # Only produce JSON output
    python -m pipeline.main run --data-dir ./data --format json

    # Specify custom output directory
    python -m pipeline.main run --data-dir ./data --output-dir ./reports
"""

import logging
import sys
from pathlib import Path

import click

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


@click.group()
def cli():
    """Honeypot Threat Intelligence Pipeline — powered by T-Pot telemetry."""
    pass


@cli.command()
@click.option(
    "--data-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("sample_data"),
    show_default=True,
    help="Directory containing cowrie.json, dionaea.json, and/or honeytrap.json",
)
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("reports"),
    show_default=True,
    help="Directory to write generated reports",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["html", "json", "both"], case_sensitive=False),
    default="both",
    show_default=True,
    help="Output format(s) to generate",
)
@click.option(
    "--skip-enrichment",
    is_flag=True,
    default=False,
    help="Skip ip-api.com lookups (useful for offline/dev runs)",
)
def run(data_dir: Path, output_dir: Path, output_format: str, skip_enrichment: bool):
    """Parse, enrich, analyze, and report on honeypot log data."""
    from pipeline import parser, enricher, analyzer, reporter

    # ── 1. Parse ───────────────────────────────────────────────────────────────
    click.echo(f"\n[1/4] 📂 Loading logs from {data_dir}/")
    try:
        events = parser.load_all(data_dir)
    except FileNotFoundError as exc:
        click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(1)

    click.echo(f"      Loaded {len(events)} events")

    # ── 2. Enrich ──────────────────────────────────────────────────────────────
    if skip_enrichment:
        click.echo("\n[2/4] ⏭️  Skipping enrichment (--skip-enrichment flag set)")
        for event in events:
            event["geo"] = {
                "country": None, "country_code": None, "region": None,
                "city": None, "isp": None, "org": None, "asn": None,
                "lat": None, "lon": None, "enriched": False,
            }
    else:
        unique_ips = len({e["src_ip"] for e in events if e.get("src_ip")})
        click.echo(f"\n[2/4] 🌐 Enriching {unique_ips} unique IPs via ip-api.com...")
        click.echo("      (Free tier: ~1.5s/IP — grab a coffee ☕)")
        enricher.enrich_events(events)
        enriched_count = sum(1 for e in events if e.get("geo", {}).get("enriched"))
        click.echo(f"      Enriched {enriched_count}/{len(events)} events")

    # ── 3. Analyze ─────────────────────────────────────────────────────────────
    click.echo("\n[3/4] 🔍 Running analysis passes...")
    findings = analyzer.run_all(events)

    # Print a quick summary to stdout
    s = findings["summary"]
    click.echo(f"\n      ┌─ Quick Summary ─────────────────────")
    click.echo(f"      │  Total events   : {s['total_events']:>6,}")
    click.echo(f"      │  Unique IPs     : {s['unique_ips']:>6,}")
    click.echo(f"      │  Post-login sess: {len(findings['session_commands']):>6,}")
    click.echo(f"      │  Malware samples: {len(findings['malware_samples']):>6,}")
    click.echo(f"      │  Botnet clusters: {len(findings['credential_clusters']):>6,}")
    click.echo(f"      └─────────────────────────────────────")

    # ── 4. Report ──────────────────────────────────────────────────────────────
    click.echo(f"\n[4/4] 📄 Writing reports to {output_dir}/")
    output_dir.mkdir(parents=True, exist_ok=True)

    if output_format in ("html", "both"):
        html_path = reporter.generate_html(findings, output_dir / "report.html")
        click.secho(f"      ✅ HTML → {html_path}", fg="green")

    if output_format in ("json", "both"):
        json_path = reporter.generate_json(findings, output_dir / "report.json")
        click.secho(f"      ✅ JSON → {json_path}", fg="green")

    click.echo("\n✨ Pipeline complete.\n")


@cli.command()
@click.option(
    "--data-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("sample_data"),
    show_default=True,
)
def validate(data_dir: Path):
    """Validate log files without running the full pipeline."""
    from pipeline import parser

    click.echo(f"\nValidating logs in {data_dir}/\n")
    all_ok = True

    for service in ("cowrie", "dionaea", "honeytrap"):
        log_path = data_dir / f"{service}.json"
        if not log_path.exists():
            click.secho(f"  ⚠️  {service}.json not found", fg="yellow")
            continue
        try:
            events = list(parser.load_log_file(log_path, service))
            click.secho(f"  ✅ {service}.json — {len(events)} valid events", fg="green")
        except Exception as exc:
            click.secho(f"  ❌ {service}.json — ERROR: {exc}", fg="red")
            all_ok = False

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    cli()