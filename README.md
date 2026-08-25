# AI Reconnaissance Tool

**AI Reconnaissance Tool** is an authorized, defensive attack-surface discovery and OSINT framework for internal asset discovery, security assessments, CTF/lab environments, and defensive research. It automates collection and normalization while preserving authorization boundaries and evidence.

> **Safety boundary:** This project never implements exploitation, authentication bypass, credential attacks, stealth/evasion, malware deployment, or destructive testing. Active collectors require an explicit `IN_SCOPE` result from the scope engine. AI output is analysis, not ground truth.

## Architecture

```text
Target -> Scope Engine -> Passive Discovery -> DNS -> Subdomains
       -> Safe Nmap Profile -> HTTP/HTTPS -> Headers/Technologies/Metadata
       -> Shodan/Censys (optional) -> AI Classification -> Correlation
       -> Transparent Risk Scoring -> JSON/HTML/Terminal Reports + SQLite/API
```

The implementation is intentionally modular. Collector adapters produce Pydantic models, analyzers consume normalized observations, provider integrations are isolated behind interfaces, and the orchestrator continues when a provider fails.

| Layer | Responsibility |
|---|---|
| `core` | Configuration, explicit authorization scope, orchestration |
| `collectors` | DNS, CT logs, controlled Nmap, safe HTTP, Shodan, Censys |
| `analyzers` | Headers, technologies, metadata, administrative-interface classification, AI semantics, risk |
| `models` | Structured boundaries for every observation and report |
| `storage` | SQLite persistence with a PostgreSQL-friendly data boundary |
| `reporting` | JSON, HTML, and terminal summaries |
| `api` | Local FastAPI service |
| `cli` | `recon init`, `scan`, `assets`, `findings`, `report`, and `api` |

## Installation

Python 3.11+ is required. Nmap is optional; if it is absent, the network stage records no Nmap services and the remainder of the pipeline continues.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,ai]'
```

Create configuration before scanning:

```bash
recon init --path config.yaml
# Edit config.yaml and replace example scope values with assets you are authorized to assess.
```

Optional provider credentials are read only from environment variables and are never stored in reports:

```bash
export SHODAN_API_KEY='...'
export CENSYS_API_ID='...'
export CENSYS_API_SECRET='...'
export OPENAI_API_KEY='...'
export OPENAI_API_BASE='https://api.openai.com/v1' # or another OpenAI-compatible endpoint
```

The default semantic model is `gpt-5-mini` when an OpenAI-compatible key is available. Without a key, a deterministic heuristic classifier runs so local tests and lab usage remain functional.

## CLI

```bash
recon init --path config.yaml
recon scan --target example.com --config config.yaml --output-dir reports
recon assets list --config config.yaml
recon findings list --config config.yaml
recon report --format html --output reports/latest.html --config config.yaml
recon report --format json --output reports/latest.json --config config.yaml
recon api --host 127.0.0.1 --port 8000
```

Every active scan must pass the scope engine. A domain in `scope.domains` is explicitly in scope; descendant hostnames are classified as `UNKNOWN` unless included in `allowed_subdomains`, which prevents accidental active probing of discovered names.

## Configuration

```yaml
scope:
  domains:
    - example.com
  ips:
    - 203.0.113.10
  cidrs:
    - 203.0.113.0/28
  allowed_subdomains:
    - "*.example.com"
recon:
  dns: true
  subdomains: true
  network: true
  http: true
  shodan: false
  censys: false
  ai_analysis: true
limits:
  concurrency: 10
  request_timeout: 10
  retry_count: 2
  max_targets: 100
  allow_private_networks: false
ai:
  model: gpt-5-mini
  enabled: true
reporting:
  formats: [json, html]
  output_dir: reports
```

For a deliberately authorized lab target, use a local or isolated test host and set `allow_private_networks: true` only when you own and understand that lab network. Never point the scanner at an asset without written authorization.

## API

The service defaults to localhost and should not be exposed publicly without adding authentication and deployment controls.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Health check |
| `POST` | `/scans` | Run a scoped scan with `{"target":"example.com"}` |
| `GET` | `/scans/{scan_id}` | Full report |
| `GET` | `/scans/{scan_id}/assets` | Correlated assets |
| `GET` | `/scans/{scan_id}/findings` | Prioritized observations |
| `GET` | `/scans/{scan_id}/report` | Rendered HTML report |

## Testing

Tests use mocked provider responses and fixtures; real credentials and real external scans are not required.

```bash
pytest -q
ruff check .
```

The test suite covers scope validation, DNS parsing helpers, subdomain normalization, Nmap parsing, HTTP parsing, header analysis, provider normalization, AI JSON validation/fallback, risk scoring, asset correlation, report generation, repository persistence, and API health/scan behavior.

## Docker

```bash
docker compose up --build
```

The container exposes the API on port 8000 and persists SQLite data and reports through local volumes. Nmap is installed in the image for authorized network enumeration.

## Known limitations

Certificate-transparency discovery requires outbound network access. Shodan and Censys results depend on valid credentials and provider availability. TLS metadata is intentionally conservative in the first release. PostgreSQL compatibility is preserved at the repository boundary, but SQLite is the default local backend. The API is intended for localhost until an authentication layer is added.
