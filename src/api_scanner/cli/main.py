from __future__ import annotations

import json

import click

from api_scanner.reports.html import render_html_report
from api_scanner.scanners.rules import load_targets, scan_targets


@click.command()
@click.option("--url", help="Single API endpoint to scan.")
@click.option("--spec", type=click.Path(exists=True), help="Local OpenAPI YAML file.")
@click.option("--endpoints", type=click.Path(exists=True), help="Text file of METHOD URL endpoints.")
@click.option("--json-output", type=click.Path(), help="Write JSON results to this file.")
@click.option("--html-output", type=click.Path(), help="Write a local HTML report.")
@click.option("--timeout", default=3.0, show_default=True, help="HTTP timeout for live URL scans.")
def cli(url: str | None, spec: str | None, endpoints: str | None, json_output: str | None, html_output: str | None, timeout: float) -> None:
    """Scan API endpoints or OpenAPI specs for five OWASP API Top 10 risks."""
    if not any([url, spec, endpoints]):
        raise click.UsageError("Provide --url, --spec, or --endpoints.")
    targets = load_targets(url=url, spec=spec, endpoints=endpoints)
    results = scan_targets(targets, timeout=timeout)
    text = json.dumps(results, indent=2)
    click.echo(text)
    if json_output:
        with open(json_output, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    if html_output:
        render_html_report(results, html_output)


if __name__ == "__main__":
    cli()
