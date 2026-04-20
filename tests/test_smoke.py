"""Smoke tests: verify imports, core computations, and API surface."""

from __future__ import annotations

from datetime import datetime, timezone


def _make_cve(score: float = 9.8, exploited: bool = True, days_ago: int = 1):
    """Build a minimal CVERecord for scorer tests."""
    from threat_lens.models import CVERecord, CVSSMetrics, Severity

    pub = datetime.now(timezone.utc).replace(day=1)
    if days_ago:
        from datetime import timedelta

        pub = datetime.now(timezone.utc) - timedelta(days=days_ago)

    sev = (
        Severity.CRITICAL
        if score >= 9
        else Severity.HIGH
        if score >= 7
        else Severity.MEDIUM
        if score >= 4
        else Severity.LOW
    )
    return CVERecord(
        cve_id="CVE-2025-99999",
        published=pub,
        last_modified=pub,
        description="Remote code execution in a public-facing web application via SQL injection.",
        cvss=CVSSMetrics(base_score=score, base_severity=sev),
        known_exploited=exploited,
    )


def test_package_imports():
    import threat_lens

    assert threat_lens.__version__


def test_models_import():
    from threat_lens.models import (
        CVERecord,
        IPIntelligence,
        MITRETechnique,
        Severity,
        ThreatEvent,
        ThreatScore,
    )

    assert Severity.CRITICAL.value == "CRITICAL"
    assert CVERecord and IPIntelligence and MITRETechnique and ThreatEvent and ThreatScore


def test_threat_scorer_high():
    from threat_lens.threat_scorer import ThreatScorer

    s = ThreatScorer()
    score = s.score(_make_cve(score=9.8, exploited=True, days_ago=1))
    assert score.composite_score >= 60
    assert score.severity.value in {"HIGH", "CRITICAL"}


def test_threat_scorer_low():
    from threat_lens.threat_scorer import ThreatScorer

    s = ThreatScorer()
    score = s.score(_make_cve(score=2.0, exploited=False, days_ago=500))
    assert score.composite_score <= 60
    assert score.severity.value in {"LOW", "MEDIUM"}


def test_threat_scorer_classify_severity():
    from threat_lens.threat_scorer import classify_severity

    assert classify_severity(95).value == "CRITICAL"
    assert classify_severity(10).value == "LOW"


def test_mitre_mapper_loads_techniques():
    from threat_lens.mitre_mapper import MITREMapper

    m = MITREMapper()
    assert len(m.list_techniques()) > 0


def test_mitre_lookup_by_id():
    from threat_lens.mitre_mapper import MITREMapper

    m = MITREMapper()
    t = m.get_technique("T1190")
    assert t is not None


def test_mitre_maps_cve():
    from threat_lens.mitre_mapper import MITREMapper

    m = MITREMapper()
    results = m.map_cve(
        "Remote attackers can exploit the public-facing web application via SQL injection."
    )
    assert isinstance(results, list)


def test_mitre_tactics():
    from threat_lens.mitre_mapper import MITREMapper

    m = MITREMapper()
    tactics = m.list_tactics()
    assert len(tactics) > 0


def test_ip_analyzer_instantiates():
    from threat_lens.ip_analyzer import IPAnalyzer

    with IPAnalyzer() as a:
        assert a is not None


def test_event_fingerprint_deterministic():
    from threat_lens.feed_aggregator import _event_fingerprint

    a = _event_fingerprint("NVD", "CVE-2025-00001", "desc")
    b = _event_fingerprint("NVD", "CVE-2025-00001", "desc")
    c = _event_fingerprint("NVD", "CVE-2025-00002", "desc")
    assert a == b
    assert a != c


def test_api_app_loads_with_healthz():
    from api import app

    paths = {r.path for r in app.routes}
    assert "/healthz" in paths


def test_api_has_cve_endpoints():
    from api import app

    paths = {r.path for r in app.routes}
    assert "/api/cves" in paths
    assert "/api/stats" in paths
