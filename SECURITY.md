# Security Policy

## Authorized use

AI Reconnaissance Tool is intended for assets owned by the operator, assets covered by written authorization, internal asset discovery, approved security assessments, and isolated training labs. Configure the scope manifest before any active collection. Discovered subdomains are not automatically authorized.

## Prohibited behavior

Do not use this project for authentication bypass, credential attacks, exploit execution, destructive testing, denial of service, malware deployment, stealth or evasion, persistence, data exfiltration, or scanning systems outside the explicit authorized scope.

## Safe vulnerability indicators

The built-in rule engine is intentionally limited to bounded, read-only GET/HEAD requests against relative paths. It does not submit credentials, send exploit payloads, follow unvalidated redirects, execute arbitrary rule code, or claim confirmation solely from a technology fingerprint.

## Production deployment

Before exposing the API outside localhost, set a strong `RECON_BOOTSTRAP_KEY`, bootstrap exactly one owner, use HTTPS at the reverse proxy, restrict network access, rotate credentials, back up the database, configure log retention, and review all scope manifests. Add a durable job queue and external identity provider before using the service for high-volume enterprise operations.

## Reporting a security issue

Do not use the scanner to validate a suspected issue against an unrelated public target. Report vulnerabilities in this project privately to the repository maintainers with reproduction steps, affected commit, impact, and a safe proof that does not exploit third-party systems.
