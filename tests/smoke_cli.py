from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


def run(*args: str) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return result.stdout


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = root / "config.yaml"
        database = root / "recon.db"
        output = root / "reports"
        config.write_text(
            """scope:\n  domains: [example.com]\n  ips: []\n  cidrs: []\n  allowed_subdomains: []\nrecon:\n  osint: false\n  dns: false\n  subdomains: false\n  network: false\n  http: false\n  shodan: false\n  censys: false\n  ai_analysis: false\nlimits:\n  concurrency: 2\n  request_timeout: 2\n  retry_count: 1\n  max_targets: 5\n  allow_private_networks: false\nai:\n  enabled: false\nreporting:\n  formats: [json, html]\ndatabase_url: sqlite:///PLACEHOLDER\n""".replace(
                "PLACEHOLDER", str(database)
            )
        )
        run("recon", "--help")
        run(
            "recon",
            "scan",
            "--target",
            "example.com",
            "--config",
            str(config),
            "--output-dir",
            str(output),
        )
        run("recon", "assets", "list", "--config", str(config))
        run("recon", "findings", "list", "--config", str(config))
        reports = list(output.glob("*.json"))
        assert len(reports) == 1
        scan_id = json.loads(reports[0].read_text())["scan_id"]
        run(
            "recon",
            "report",
            "--format",
            "json",
            "--scan-id",
            scan_id,
            "--config",
            str(config),
            "--output",
            str(root / "replay.json"),
        )
        run(
            "recon",
            "report",
            "--format",
            "html",
            "--scan-id",
            scan_id,
            "--config",
            str(config),
            "--output",
            str(root / "replay.html"),
        )
        assert (root / "replay.json").exists()
        assert "AI Reconnaissance Report" in (root / "replay.html").read_text()
    print("CLI smoke workflow passed")


if __name__ == "__main__":
    main()
