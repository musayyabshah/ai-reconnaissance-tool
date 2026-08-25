from __future__ import annotations

import asyncio
from pathlib import Path

import typer
import uvicorn
from rich.console import Console

from ai_recon.api.server import create_app
from ai_recon.core.config import AppConfig, write_example
from ai_recon.core.orchestrator import ReconOrchestrator
from ai_recon.core.scope import ScopeViolation
from ai_recon.reporting.reports import terminal_summary, write_html, write_json
from ai_recon.storage.database import ScanRepository

app = typer.Typer(help="Authorized defensive reconnaissance and OSINT framework.")
assets_app = typer.Typer(help="Inspect correlated assets.")
findings_app = typer.Typer(help="Inspect prioritized observations.")
app.add_typer(assets_app, name="assets")
app.add_typer(findings_app, name="findings")
console = Console()


def _config(path: str) -> AppConfig:
    return AppConfig.from_file(path) if Path(path).exists() else AppConfig.default()


@app.command()
def init(
    path: str = typer.Option("config.yaml", help="Where to write the example configuration."),
) -> None:
    """Create a safe example configuration with explicit scope placeholders."""
    write_example(path)
    console.print(f"[green]Created {path}. Edit the scope before scanning.[/green]")


@app.command()
def scan(
    target: str = typer.Option(
        ..., help="Authorized hostname, domain, IP, or other in-scope target."
    ),
    config: str = typer.Option("config.yaml", "--config", "-c"),
    output_dir: str = typer.Option("reports", help="Directory for JSON and HTML reports."),
) -> None:
    """Run the complete authorized reconnaissance pipeline."""
    settings = _config(config)
    orchestrator = ReconOrchestrator(
        settings, progress=lambda message: console.print(f"[cyan][+][/cyan] {message}")
    )
    try:
        report = asyncio.run(orchestrator.scan(target))
    except ScopeViolation as exc:
        raise typer.BadParameter(str(exc)) from exc
    repository = ScanRepository(settings.database_url)
    repository.save(report)
    output = Path(output_dir)
    write_json(report, output / f"{report.scan_id}.json")
    write_html(report, output / f"{report.scan_id}.html")
    console.print(terminal_summary(report))
    console.print(f"\n[green]Reports written to {output.resolve()}[/green]")


@assets_app.command("list")
def list_assets(
    scan_id: str | None = typer.Option(None, help="Scan ID; defaults to latest."),
    config: str = typer.Option("config.yaml", "--config", "-c"),
) -> None:
    for asset in ScanRepository(_config(config).database_url).list_assets(scan_id):
        console.print(
            f"{asset['name']} | {asset['scope_status']} | IPs={len(asset['ips'])} services={len(asset['services'])}"
        )


@findings_app.command("list")
def list_findings(
    scan_id: str | None = typer.Option(None, help="Scan ID; defaults to latest."),
    config: str = typer.Option("config.yaml", "--config", "-c"),
) -> None:
    for finding in ScanRepository(_config(config).database_url).list_findings(scan_id):
        console.print(
            f"[{finding['severity']}] {finding['target']} — {finding['type']} ({finding['score']})"
        )


@app.command()
def report(
    format: str = typer.Option("html", "--format", help="html or json"),
    scan_id: str | None = typer.Option(None, help="Scan ID; defaults to latest."),
    config: str = typer.Option("config.yaml", "--config", "-c"),
    output: str = typer.Option("report.out"),
) -> None:
    settings = _config(config)
    stored = (
        ScanRepository(settings.database_url).get(scan_id)
        if scan_id
        else ScanRepository(settings.database_url).latest()
    )
    if not stored:
        raise typer.BadParameter("No scan report available")
    if format == "json":
        write_json(stored, output)
    elif format == "html":
        write_html(stored, output)
    else:
        raise typer.BadParameter("format must be html or json")
    console.print(f"[green]Report written to {Path(output).resolve()}[/green]")


@app.command()
def api(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Serve the local FastAPI API. Do not expose publicly without authentication."""
    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    app()
