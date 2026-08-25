from ai_recon.analyzers.analysis import (
    AdminInterfaceClassifier,
    HeaderAnalyzer,
    MetadataAnalyzer,
    RiskScorer,
    TechnologyAnalyzer,
)
from ai_recon.collectors.nmap import NmapCollector
from ai_recon.collectors.subdomains import SubdomainCollector
from ai_recon.models.entities import HTTPObservation, ObservationKind, Priority


def test_subdomain_normalization() -> None:
    assert SubdomainCollector.normalize("*.API.Example.COM.") == "api.example.com"


def test_nmap_grepable_parser() -> None:
    output = "Host: example.com (203.0.113.10)\tStatus: Up\nHost: example.com (203.0.113.10)\tPorts: 443/open/tcp//https//nginx 1.25.0/, 80/open/tcp//http//Apache httpd/"
    services = NmapCollector.parse_grepable(output, "example.com")
    assert len(services) == 2
    assert services[0].port == 443
    assert services[0].service == "https"


def test_http_analyzers_and_risk() -> None:
    observation = HTTPObservation(
        host="admin.example.com",
        url="https://admin.example.com/login",
        status=200,
        title="Admin Dashboard Login",
        server="nginx",
        content_type="text/html",
        headers={"server": "nginx"},
        response_size=1200,
    )
    technologies = TechnologyAnalyzer().detect(observation)
    metadata = MetadataAnalyzer().extract(observation)
    admin = AdminInterfaceClassifier().classify(observation, metadata, technologies)
    assert admin is not None
    assert admin.kind is ObservationKind.POTENTIAL_RISK
    finding = HeaderAnalyzer().analyze(observation)[0]
    scored = RiskScorer().score(finding, sensitive=20, weak_config=10)
    assert scored.score > finding.score
    assert scored.severity in {Priority.MEDIUM, Priority.HIGH}
