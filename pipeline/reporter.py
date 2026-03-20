"""
reporter.py — Generate HTML and JSON reports from analyzer findings.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

# Path relative to this file — works whether run from project root or pipeline/
_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


def _format_num(value: int) -> str:
    """Jinja2 filter: format integers with comma separators."""
    return f"{value:,}"


def _build_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["format_num"] = _format_num
    return env


def generate_html(findings: dict, output_path: Path) -> Path:
    """
    Render the Jinja2 HTML report and write it to output_path.

    Args:
        findings: Output of analyzer.run_all().
        output_path: Where to write the .html file.

    Returns:
        The resolved output path.
    """
    env = _build_env()
    template = env.get_template("report.html.j2")

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html = template.render(findings=findings, generated_at=generated_at)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")

    logger.info("HTML report written to %s (%d bytes)", output_path, len(html))
    return output_path.resolve()


def generate_json(findings: dict, output_path: Path) -> Path:
    """
    Write findings as pretty-printed JSON.

    The JSON output is useful for piping into other tools (SIEM ingest,
    Jupyter notebooks, further scripting).

    Args:
        findings: Output of analyzer.run_all().
        output_path: Where to write the .json file.

    Returns:
        The resolved output path.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }
    output_path.write_text(
        json.dumps(payload, indent=2, default=str),
        encoding="utf-8",
    )

    logger.info("JSON report written to %s", output_path)
    return output_path.resolve()