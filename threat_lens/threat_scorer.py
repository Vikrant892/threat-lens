"""Composite threat scoring engine for vulnerability prioritisation."""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Optional

from threat_lens.models import CVERecord, Severity, ThreatScore

logger = logging.getLogger(__name__)

WEIGHT_CVSS = 0.40
WEIGHT_EXPLOIT = 0.25
WEIGHT_EXPOSURE = 0.20
WEIGHT_TEMPORAL = 0.15

SEVERITY_THRESHOLDS = [
    (90, Severity.CRITICAL),
    (70, Severity.HIGH),
    (40, Severity.MEDIUM),
    (0, Severity.LOW),
]

TEMPORAL_HALF_LIFE_DAYS = 90


def classify_severity(score: float) -> Severity:
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.LOW


class ThreatScorer:
    """Score CVEs on a 0-100 composite scale.

    Components
    ----------
    - CVSS base score (40 %) — normalised to 0-100 from the 0-10 CVSS range.
    - Exploit availability (25 %) — 100 if a known-exploited flag is set, 0 otherwise.
    - Asset exposure (20 %) — derived from the number of distinct affected products
      and whether common infrastructure software is involved.
    - Temporal relevance (15 %) — exponential decay with a configurable half-life
      so freshly published CVEs rank higher than stale ones.
    """

    def __init__(
        self,
        weight_cvss: float = WEIGHT_CVSS,
        weight_exploit: float = WEIGHT_EXPLOIT,
        weight_exposure: float = WEIGHT_EXPOSURE,
        weight_temporal: float = WEIGHT_TEMPORAL,
        temporal_half_life_days: int = TEMPORAL_HALF_LIFE_DAYS,
    ):
        total = weight_cvss + weight_exploit + weight_exposure + weight_temporal
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Weights must sum to 1.0, got {total}")

        self._w_cvss = weight_cvss
        self._w_exploit = weight_exploit
        self._w_exposure = weight_exposure
        self._w_temporal = weight_temporal
        self._half_life = temporal_half_life_days

    def score(
        self,
        cve: CVERecord,
        asset_count: Optional[int] = None,
        reference_time: Optional[datetime] = None,
    ) -> ThreatScore:
        """Compute the composite threat score for a single CVE."""
        ref = reference_time or datetime.now(timezone.utc)

        cvss_component = self._cvss_component(cve)
        exploit_component = self._exploit_component(cve)
        exposure_component = self._exposure_component(cve, asset_count)
        temporal_component = self._temporal_component(cve, ref)

        composite = (
            self._w_cvss * cvss_component
            + self._w_exploit * exploit_component
            + self._w_exposure * exposure_component
            + self._w_temporal * temporal_component
        )
        composite = round(min(max(composite, 0.0), 100.0), 2)

        factors = self._explain(
            cve,
            cvss_component,
            exploit_component,
            exposure_component,
            temporal_component,
        )

        return ThreatScore(
            composite_score=composite,
            severity=classify_severity(composite),
            cvss_component=round(cvss_component, 2),
            exploit_component=round(exploit_component, 2),
            exposure_component=round(exposure_component, 2),
            temporal_component=round(temporal_component, 2),
            factors=factors,
        )

    def score_batch(
        self,
        cves: list[CVERecord],
        reference_time: Optional[datetime] = None,
    ) -> list[ThreatScore]:
        """Score multiple CVEs and return results sorted highest-risk first."""
        ref = reference_time or datetime.now(timezone.utc)
        scored = [self.score(cve, reference_time=ref) for cve in cves]
        scored.sort(key=lambda s: s.composite_score, reverse=True)
        return scored

    @staticmethod
    def _cvss_component(cve: CVERecord) -> float:
        return cve.base_score * 10.0

    @staticmethod
    def _exploit_component(cve: CVERecord) -> float:
        if cve.known_exploited:
            return 100.0

        ref_tags: set[str] = set()
        for ref in cve.references:
            ref_tags.update(tag.lower() for tag in ref.tags)

        if "exploit" in ref_tags or "third party advisory" in ref_tags:
            return 60.0

        return 0.0

    @staticmethod
    def _exposure_component(cve: CVERecord, asset_count: Optional[int] = None) -> float:
        count = asset_count if asset_count is not None else len(cve.affected_products)

        HIGH_IMPACT_VENDORS = {
            "microsoft",
            "apple",
            "google",
            "linux",
            "apache",
            "oracle",
            "cisco",
            "vmware",
            "adobe",
            "redhat",
        }

        base = min(count * 12.0, 60.0)

        vendor_bonus = 0.0
        for product in cve.affected_products:
            vendor = (
                product.split("/")[0].lower() if "/" in product else product.lower()
            )
            if vendor in HIGH_IMPACT_VENDORS:
                vendor_bonus = 40.0
                break

        return min(base + vendor_bonus, 100.0)

    def _temporal_component(self, cve: CVERecord, reference_time: datetime) -> float:
        pub = cve.published
        if pub.tzinfo is None:
            pub = pub.replace(tzinfo=timezone.utc)
        if reference_time.tzinfo is None:
            reference_time = reference_time.replace(tzinfo=timezone.utc)

        age_days = max((reference_time - pub).total_seconds() / 86400.0, 0.0)
        decay = math.exp(-math.log(2) * age_days / self._half_life)
        return decay * 100.0

    @staticmethod
    def _explain(
        cve: CVERecord,
        cvss_c: float,
        exploit_c: float,
        exposure_c: float,
        temporal_c: float,
    ) -> list[str]:
        factors: list[str] = []

        if cvss_c >= 90:
            factors.append(f"CVSS {cve.base_score}/10 — critical base score")
        elif cvss_c >= 70:
            factors.append(f"CVSS {cve.base_score}/10 — high base score")

        if exploit_c >= 100:
            factors.append("Known exploited in the wild (CISA KEV)")
        elif exploit_c > 0:
            factors.append("Exploit code or advisory references detected")

        if exposure_c >= 80:
            factors.append("Widely deployed infrastructure software affected")
        elif exposure_c >= 40:
            factors.append("Multiple affected products increase blast radius")

        if temporal_c >= 80:
            factors.append("Recently published — high temporal relevance")
        elif temporal_c < 20:
            factors.append("Aging CVE — lower temporal urgency")

        return factors
