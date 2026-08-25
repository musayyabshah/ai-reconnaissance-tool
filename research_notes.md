# Research notes

## BloodHound official repository
Source: https://github.com/SpecterOps/BloodHound

The official repository describes BloodHound as a monolithic web application with an embedded React frontend using Sigma.js, a Go REST API backend, PostgreSQL for application data, and Neo4j for graph data. It is fed by SharpHound and AzureHound collectors. The key reusable design lesson is separation between collection, normalized graph ingestion, and graph queries/visualization. The repository states that BloodHound is licensed under Apache-2.0 unless a lower-level license applies.

For our project, the safe design lesson is to add a graph-oriented asset and relationship layer for domains, IPs, services, identities, technologies, findings, and evidence. We should not copy code or import BloodHound’s identity-attack-path behavior because our scope is internet-facing defensive asset discovery and vulnerability indicators.

## SharpHound official repository
Source: https://github.com/SpecterOps/SharpHound

The official repository describes SharpHound as a C# data collector for BloodHound. The repository contains source, build/configuration files, release workflow material, and a README; GitHub displays a GPL-3.0 license. The key reusable design lesson is a purpose-built collector that emits structured data for a separate graph platform, rather than mixing collection and analysis. We should not copy SharpHound code into this Python project because its license is not automatically compatible with our project and its collection behavior targets Active Directory environments outside our current scope.

## Immediate architectural implications

1. Add a normalized graph model and import/export contract rather than a monolithic report-only JSON blob.
2. Add scan jobs and collector adapters that produce immutable observations, then run analyzers separately.
3. Add tenant-aware authorization and per-scan scope manifests before any active collector runs.
4. Add change detection, evidence hashes, and audit logs so findings can be reviewed over time.
5. Use compatible open-source components only after verifying their exact repository license and provenance; use design inspiration instead of copying code.

## FIRST CVSS v4.0 specification
Source: https://www.first.org/cvss/v4.0/specification-document

CVSS v4.0 is a framework for communicating vulnerability characteristics and severity. The specification defines Base, Threat, Environmental, and Supplemental metric groups. Base reflects intrinsic technical severity, Threat reflects changing exploit conditions, Environmental reflects the importance and configuration of the affected environment, and Supplemental adds context without changing the final score. A key design lesson is that severity and organizational risk must be kept separate and that a score/vector should be explainable.

## CISA Known Exploited Vulnerabilities catalog
Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

CISA describes KEV as an authoritative catalog of vulnerabilities exploited in the wild and presents it as an input to vulnerability-management prioritization. The catalog is available in CSV and JSON formats. A key design lesson is to enrich a finding with an explicit known-exploitation signal and remediation due date where the CVE is in KEV, rather than treating a high CVSS score alone as evidence of active exploitation.

## Immediate vulnerability-scoring implications

The upgraded platform should distinguish detection confidence, technical severity, exploit likelihood, asset criticality, internet exposure, and remediation urgency. It should never call a technology fingerprint a vulnerability. Verified checks should use safe, non-destructive evidence and should support a human-review state before a finding is promoted to confirmed.

## FIRST EPSS data guidance
Source: https://www.first.org/epss/data

EPSS scores are published daily. FIRST says the EPSS API is intended for lookup of one CVE or a small batch, while daily CSV or the maintained repository is appropriate for bulk workflows. The API supports historical lookup and 30-day history. A key design lesson is to store the score, percentile, score date, and retrieval timestamp so prioritization decisions are reproducible.

## OWASP API Security Top 10 (2023)
Source: https://owasp.org/API-Security/editions/2023/en/0x11-t10/

The official categories include broken object-level authorization, broken authentication, broken object-property authorization, unrestricted resource consumption, broken function-level authorization, unrestricted access to sensitive business flows, SSRF, security misconfiguration, improper inventory management, and unsafe consumption of APIs. Many of the highest-risk categories require authenticated, role-aware, application-specific testing and cannot be safely confirmed from anonymous reconnaissance alone.

For this project, safe anonymous checks should produce indicators such as exposed API documentation, deprecated API versions, missing security headers, overly permissive CORS, exposed debug metadata, missing rate-limit signals, and insecure transport. Object-level authorization, broken authentication, SSRF, and business-flow abuse should be represented as review workflows requiring explicit authorization, credentials, test accounts, request budgets, and human approval—not automated exploitation.

## ProjectDiscovery Nuclei official repository
Source: https://github.com/projectdiscovery/nuclei

Nuclei describes a YAML-based DSL for customizable vulnerability detection across HTTP, TCP, DNS, SSL, WHOIS, JavaScript, code, and cloud-related protocols. It emphasizes real-world verification steps to reduce false positives, parallel processing, request clustering, CI/CD integration, and structured integrations. GitHub displays an MIT license. The key design lesson is a signed/versioned detection-template system with explicit matchers, evidence extraction, severity, remediation references, and safe execution budgets. We should use an internal compatible rule format rather than copy Nuclei templates or code without reviewing each license and provenance.

## OWASP ZAP official repository
Source: https://github.com/zaproxy/zaproxy

ZAP is described as an open-source web application scanner supporting automated discovery and manual testing, with a large mature repository and Apache-2.0 license. The key design lesson is an extensible scanner core with separate automation and reporting capabilities, plus explicit third-party license tracking. Our project should remain narrower and safer by starting with passive and non-destructive checks, then introducing active checks only as opt-in, scope-bound, rate-limited, and auditable templates.

## Comparable-tool design conclusions

1. BloodHound’s strongest lesson is graph-based relationships and queryable attack paths; for our domain, this becomes an asset/evidence graph, not identity attack-path exploitation.
2. SharpHound’s strongest lesson is collector/ingestor separation and structured output contracts.
3. Nuclei’s strongest lesson is versioned declarative detection templates with verification matchers and community review.
4. ZAP’s strongest lesson is mature automation around web testing, reporting, and third-party license hygiene.
5. Our implementation should reference these projects in documentation as inspirations, preserve their licenses where applicable, and avoid copying their source code or templates.
