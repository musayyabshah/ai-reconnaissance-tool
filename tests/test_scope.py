from ai_recon.core.scope import ScopeEngine, ScopeViolation
from ai_recon.models.entities import ScopeConfig, ScopeStatus


def test_scope_engine_domains_and_wildcards() -> None:
    engine = ScopeEngine(
        ScopeConfig(
            domains=["example.com"],
            allowed_subdomains=["*.example.com"],
            ips=["203.0.113.10"],
            cidrs=["198.51.100.0/30"],
        )
    )
    assert engine.check("example.com") is ScopeStatus.IN_SCOPE
    assert engine.check("api.example.com") is ScopeStatus.IN_SCOPE
    assert engine.check("other.example.net") is ScopeStatus.OUT_OF_SCOPE
    assert engine.check("203.0.113.10") is ScopeStatus.IN_SCOPE
    assert engine.check("198.51.100.2") is ScopeStatus.IN_SCOPE


def test_descendant_is_unknown_without_explicit_wildcard() -> None:
    engine = ScopeEngine(ScopeConfig(domains=["example.com"]))
    assert engine.check("api.example.com") is ScopeStatus.UNKNOWN


def test_private_ip_is_out_of_scope_by_default() -> None:
    engine = ScopeEngine(ScopeConfig(ips=["127.0.0.1"], cidrs=["10.0.0.0/8"]))
    assert engine.check("127.0.0.1") is ScopeStatus.OUT_OF_SCOPE
    assert engine.check("10.1.2.3") is ScopeStatus.OUT_OF_SCOPE


def test_require_active_rejects_unknown() -> None:
    engine = ScopeEngine(ScopeConfig(domains=["example.com"]))
    try:
        engine.require_active("api.example.com")
    except ScopeViolation:
        pass
    else:
        raise AssertionError("unknown host should not be actively probed")
