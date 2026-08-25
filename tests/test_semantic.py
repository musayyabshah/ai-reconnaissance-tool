from ai_recon.analyzers.semantic import SemanticAnalyzer
from ai_recon.models.entities import HTTPObservation, Priority


def test_semantic_fallback_classifies_login_page() -> None:
    observation = HTTPObservation(
        host="app.example.com", url="https://app.example.com/login", status=200, title="Sign in"
    )
    analysis = SemanticAnalyzer(enabled=False).analyze(observation, [])
    assert analysis.application_type == "AUTHENTICATION_PORTAL"
    assert analysis.confidence <= 1
    assert analysis.priority is Priority.MEDIUM
