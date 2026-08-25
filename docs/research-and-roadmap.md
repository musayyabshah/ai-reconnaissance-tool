# Mature Security Platform Research and Roadmap

## Executive position

The platform should be positioned as an **authorized defensive attack-surface and vulnerability-indicator system**, not an autonomous exploitation framework. A credible professional tool must maximize visibility, evidence quality, reproducibility, authorization enforcement, and remediation prioritization while minimizing false positives and unauthorized impact.

No scanner can honestly guarantee perfect detection or a universal 10/10 rating. The mature target is a layered system in which deterministic observations, safe verification rules, vulnerability intelligence, environmental criticality, and analyst review are kept separate.

## Lessons from comparable projects

[BloodHound][1] demonstrates the value of a graph-first model. Its official repository describes a React/Sigma.js frontend, Go REST API, PostgreSQL application database, Neo4j graph database, and separate SharpHound/AzureHound collectors. For this platform, the applicable lesson is a queryable evidence graph connecting domains, hostnames, IPs, services, technologies, findings, and owners. Identity attack paths are outside this project’s scope.

[SharpHound][2] demonstrates collector/ingestor separation and structured data contracts. Its repository is displayed under GPL-3.0, so its code must not be copied into this project without a deliberate license and architecture review. This project therefore uses independent Python implementations and only documents the design inspiration.

[Nuclei][3] demonstrates the value of a declarative YAML detection model, bounded protocol handlers, verification matchers, parallelism, and integrations. Its repository is displayed under MIT. The safe rule engine added here intentionally supports only relative GET/HEAD requests, response-size limits, no arbitrary code, no credentials, no exploit payloads, and no implicit redirects.

[OWASP ZAP][4] demonstrates the value of mature automation, extensibility, reporting, and third-party license tracking. It is displayed under Apache-2.0. A later active-testing extension should remain opt-in, scope-bound, rate-limited, auditable, and disabled by default.

## High-signal vulnerability model

A technology fingerprint is not a vulnerability. An anonymous observation is not proof of authorization failure. A CVSS score is not exploit likelihood. An EPSS probability is not evidence of exploitation. A KEV match is evidence that a CVE has been catalogued as exploited in the wild, not evidence that the affected product exists on a particular asset.

The platform should calculate a prioritization value from separate dimensions:

| Dimension | Meaning | Evidence source |
|---|---|---|
| Detection confidence | How strongly the safe check matched the observed response | Rule matcher and evidence hash |
| Technical severity | Intrinsic vulnerability severity where a CVE is known | CVSS v4 Base metrics |
| Threat likelihood | Current modeled likelihood of exploitation | EPSS score and percentile |
| Known exploitation | Whether the CVE appears in CISA KEV | CISA KEV catalog and due date |
| Environmental criticality | Importance of the asset to the organization | Tenant-owned asset metadata |
| Exposure | Internet-facing or restricted network context | Scope, DNS, and service observations |
| Verification state | Observation, indicator, review required, confirmed, rejected | Analyst workflow |

The model in the application treats these as explainable inputs. It must never silently promote an indicator to a confirmed vulnerability.

## Critical checks to prioritize

The first tier should be **safe, high-signal, and low-impact**: exposed API documentation, debug metadata, permissive CORS indicators, weak transport/security-header baselines, public administrative-interface signals, stale/deprecated API versions, exposed management services, certificate expiry, known vulnerable software versions when version evidence is reliable, and KEV/EPSS enrichment for CVEs already identified by a deterministic match.

The second tier should be **authorized review workflows**: authenticated API inventory, role-matrix checks, tenant isolation checks, object-level authorization tests, rate-limit validation, and business-flow controls. These require explicit permission, designated test accounts, approved request budgets, safe test data, and a human-approved plan. They cannot be responsibly confirmed through anonymous internet reconnaissance alone.

The system should not automate destructive payloads, password guessing, authentication bypass, exploit chains, data exfiltration, stealth, persistence, malware, or unrestricted SSRF testing. Those capabilities would increase risk and would undermine the platform’s defensive safety boundary.

## Standards and intelligence feeds

[CVSS v4.0][5] defines Base, Threat, Environmental, and Supplemental metric groups. The platform should store CVSS vectors and scores with the source and retrieval time, while keeping environmental risk separate from the vendor’s technical score.

[EPSS][6] publishes daily scores and supports small-CVE lookup and historical retrieval. Bulk workflows should use the daily dataset rather than repeatedly querying the lookup API. The application should store the score date, percentile, retrieval timestamp, and source.

[CISA KEV][7] is an authoritative catalog of vulnerabilities exploited in the wild and publishes JSON/CSV feeds. A KEV match should raise remediation urgency, attach the catalog due date when present, and remain clearly distinct from local confirmation.

[OWASP API Security Top 10][8] identifies broken object-level authorization, broken authentication, excessive resource consumption, SSRF, security misconfiguration, inventory-management, and related risks. Many of these require authenticated, role-aware testing and must be implemented as approved review workflows rather than anonymous exploit attempts.

## Maturity roadmap

| Priority | Capability | Acceptance criterion |
|---|---|---|
| P0 | Tenant isolation and RBAC | Every scan, report, job, and audit event is organization-scoped; viewers cannot start scans. |
| P0 | Authorization manifest | Every active operation records scope, operator, time, configuration hash, and approval state. |
| P0 | SSRF and redirect hardening | Every redirect and DNS resolution is revalidated against scope and private-network policy. |
| P0 | Evidence integrity | Evidence has timestamps, source, collector, response hash, and immutable audit linkage. |
| P0 | Normalized persistence | Assets, services, observations, findings, evidence, jobs, and diffs are queryable relational entities. |
| P1 | Safe rule registry | Rules are versioned, reviewed, signed or checksummed, tested, and disabled when invalid. |
| P1 | Vulnerability intelligence | NVD, EPSS, and KEV enrichment is dated, cached, rate-limited, and reproducible. |
| P1 | Scan diffing | Added, removed, and changed assets/services/findings produce analyst-visible changes. |
| P1 | TLS and certificate analysis | Subject, issuer, SAN, expiry, chain, protocol, and policy observations are collected safely. |
| P1 | Durable jobs | Background jobs survive process restarts through a persistent queue and report progress. |
| P2 | Analyst workflow | Findings support triage, assignment, comments, suppressions, verification, remediation, and reopen states. |
| P2 | Integrations | Ticketing, SIEM, email, and webhook integrations are tenant-scoped and signed. |
| P2 | Graph UX | Users can query and visualize evidence relationships without mixing speculative risk with facts. |

## Licensing and provenance policy

This project does not copy BloodHound, SharpHound, Nuclei, or ZAP source code. It records architecture lessons and links to the official projects. Any future imported rule, parser, or library must retain its license notice, provenance, version, checksum, and compatibility review. Generated or copied content should not be committed merely because it appears in a public repository.

## References

[1]: https://github.com/SpecterOps/BloodHound "SpecterOps BloodHound repository"
[2]: https://github.com/SpecterOps/SharpHound "SpecterOps SharpHound repository"
[3]: https://github.com/projectdiscovery/nuclei "ProjectDiscovery Nuclei repository"
[4]: https://github.com/zaproxy/zaproxy "OWASP ZAP repository"
[5]: https://www.first.org/cvss/v4.0/specification-document "FIRST CVSS v4.0 specification"
[6]: https://www.first.org/epss/data "FIRST EPSS data guidance"
[7]: https://www.cisa.gov/known-exploited-vulnerabilities-catalog "CISA Known Exploited Vulnerabilities catalog"
[8]: https://owasp.org/API-Security/editions/2023/en/0x11-t10/ "OWASP API Security Top 10 2023"
