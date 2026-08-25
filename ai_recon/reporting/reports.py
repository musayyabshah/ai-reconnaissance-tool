from __future__ import annotations

import html
from pathlib import Path

from ai_recon.models.entities import ScanReport


def write_json(report: ScanReport, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(report.model_dump_json(indent=2))
    return target


def write_html(report: ScanReport, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    findings = (
        "".join(
            f"<tr><td>{html.escape(item.finding_id)}</td><td>{html.escape(item.target)}</td><td>{html.escape(item.type)}</td><td>{html.escape(item.severity.value)}</td><td>{item.score:.1f}</td><td>{html.escape('; '.join(item.evidence))}</td></tr>"
            for item in sorted(report.findings, key=lambda finding: finding.score, reverse=True)
        )
        or '<tr><td colspan="6">No findings recorded.</td></tr>'
    )
    assets = (
        "".join(
            f"<tr><td>{html.escape(asset.name)}</td><td>{html.escape(asset.scope_status.value)}</td><td>{len(asset.ips)}</td><td>{len(asset.services)}</td><td>{len(asset.http)}</td><td>{html.escape(', '.join(sorted({t.name for t in asset.technologies})))}</td></tr>"
            for asset in report.assets
        )
        or '<tr><td colspan="6">No assets recorded.</td></tr>'
    )
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>AI Recon Report — {html.escape(report.target.value)}</title>
<style>body{{font-family:system-ui,-apple-system,sans-serif;background:#0b1020;color:#e8edf7;margin:0}}main{{max-width:1200px;margin:0 auto;padding:40px}}.hero{{background:linear-gradient(135deg,#172554,#0f766e);padding:32px;border-radius:20px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin:24px 0}}.card{{background:#141b31;border:1px solid #2b375b;padding:18px;border-radius:14px}}.value{{font-size:28px;font-weight:700}}section{{background:#11182b;border:1px solid #273252;padding:24px;border-radius:16px;margin:20px 0}}table{{width:100%;border-collapse:collapse}}th,td{{padding:11px;border-bottom:1px solid #273252;text-align:left;vertical-align:top}}th{{color:#9fb0d2}}.badge{{font-weight:700;color:#7dd3fc}}.muted{{color:#9fb0d2}}</style></head>
<body><main><div class="hero"><div class="muted">AUTHORIZED DEFENSIVE ASSESSMENT</div><h1>AI Reconnaissance Report</h1><p>Target: <strong>{html.escape(report.target.value)}</strong> · Scan ID: {html.escape(report.scan_id)}</p><p class="muted">Observations are not confirmed vulnerabilities. Active probing is limited to explicitly authorized scope.</p></div>
<div class="grid"><div class="card"><div class="muted">Assets</div><div class="value">{len(report.assets)}</div></div><div class="card"><div class="muted">Services</div><div class="value">{len(report.services)}</div></div><div class="card"><div class="muted">HTTP observations</div><div class="value">{len(report.http_observations)}</div></div><div class="card"><div class="muted">High priority</div><div class="value">{report.high_priority_count}</div></div></div>
<section><h2>Attack-surface inventory</h2><table><thead><tr><th>Asset</th><th>Scope</th><th>IPs</th><th>Services</th><th>HTTP</th><th>Technologies</th></tr></thead><tbody>{assets}</tbody></table></section>
<section><h2>Priority observations</h2><table><thead><tr><th>ID</th><th>Target</th><th>Type</th><th>Priority</th><th>Score</th><th>Evidence</th></tr></thead><tbody>{findings}</tbody></table></section>
<section><h2>Collection timeline</h2><p>Started: {html.escape(report.started_at.isoformat())}</p><p>Completed: {html.escape(report.completed_at.isoformat() if report.completed_at else "incomplete")}</p><p>DNS records: {len(report.dns_records)} · Subdomains: {len(report.subdomains)} · Intelligence observations: {len(report.intelligence)} · Errors: {len(report.errors)}</p></section>
<section><h2>Safety and limitations</h2><p>Provider failures are isolated and listed as errors. AI output is treated as analysis, not ground truth. This report does not perform or claim exploitation, authentication bypass, credential attacks, stealth, or destructive testing.</p></section>
</main></body></html>"""
    target.write_text(doc)
    return target


def terminal_summary(report: ScanReport) -> str:
    lines = [
        f"AI Reconnaissance Tool — {report.target.value}",
        f"Scan: {report.scan_id} | Scope: {report.target.scope_status.value}",
        f"Assets: {len(report.assets)} | Services: {len(report.services)} | HTTP: {len(report.http_observations)} | High priority: {report.high_priority_count}",
        "",
        "Priority observations:",
    ]
    for finding in sorted(report.findings, key=lambda item: item.score, reverse=True):
        lines.append(
            f"  [{finding.severity.value}] {finding.target} — {finding.type} ({finding.score:.1f})"
        )
    if not report.findings:
        lines.append("  None")
    if report.errors:
        lines.extend(
            ["", "Provider/collector errors:", *[f"  - {error}" for error in report.errors]]
        )
    return "\n".join(lines)
