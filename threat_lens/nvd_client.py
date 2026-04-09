"""NVD CVE API v2.0 client with rate limiting, pagination, and retry logic."""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from threat_lens.models import (
    CVERecord,
    CVSSMetrics,
    CVEReference,
    Severity,
)

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "NONE": Severity.NONE,
}


class RateLimiter:
    """Token-bucket rate limiter tuned for NVD's published limits."""

    def __init__(self, max_requests: int, window_seconds: int):
        self._max = max_requests
        self._window = window_seconds
        self._timestamps: list[float] = []

    def wait(self) -> None:
        now = time.monotonic()
        self._timestamps = [t for t in self._timestamps if now - t < self._window]
        if len(self._timestamps) >= self._max:
            sleep_for = self._window - (now - self._timestamps[0]) + 0.1
            logger.debug("Rate limit reached — sleeping %.1fs", sleep_for)
            time.sleep(sleep_for)
        self._timestamps.append(time.monotonic())


class NVDClient:
    """Thin wrapper around the NVD CVE API v2.0.

    Set the ``NVD_API_KEY`` environment variable to raise the rate limit
    from 5 req/30 s to 50 req/30 s.
    """

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        self._api_key = api_key or os.getenv("NVD_API_KEY")
        self._timeout = timeout

        if self._api_key:
            self._limiter = RateLimiter(max_requests=50, window_seconds=30)
        else:
            self._limiter = RateLimiter(max_requests=5, window_seconds=30)

        self._session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=4, pool_maxsize=4)
        session.mount("https://", adapter)

        session.headers.update({
            "User-Agent": "ThreatLens/1.0 (threat-intelligence-platform)",
            "Accept": "application/json",
        })
        if self._api_key:
            session.headers["apiKey"] = self._api_key
        return session

    def _get(self, params: dict) -> dict:
        self._limiter.wait()
        resp = self._session.get(NVD_API_BASE, params=params, timeout=self._timeout)
        resp.raise_for_status()
        return resp.json()

    def get_cve(self, cve_id: str) -> Optional[CVERecord]:
        """Fetch a single CVE by its ID (e.g. CVE-2024-1234)."""
        logger.info("Fetching CVE %s", cve_id)
        data = self._get({"cveId": cve_id})
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        return self._parse_vulnerability(vulns[0])

    def get_recent(
        self,
        days: int = 7,
        max_results: int = 100,
    ) -> list[CVERecord]:
        """Return CVEs published in the last *days* days."""
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        return self.search(
            pub_start=start,
            pub_end=end,
            max_results=max_results,
        )

    def search(
        self,
        keyword: Optional[str] = None,
        severity: Optional[str] = None,
        pub_start: Optional[datetime] = None,
        pub_end: Optional[datetime] = None,
        max_results: int = 100,
    ) -> list[CVERecord]:
        """Search CVEs with optional filters. Handles pagination automatically."""
        params: dict = {"resultsPerPage": min(max_results, 2000)}

        if keyword:
            params["keywordSearch"] = keyword
        if severity and severity.upper() in SEVERITY_MAP:
            params["cvssV3Severity"] = severity.upper()
        if pub_start:
            params["pubStartDate"] = pub_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        if pub_end:
            params["pubEndDate"] = pub_end.strftime("%Y-%m-%dT%H:%M:%S.000")

        records: list[CVERecord] = []
        start_index = 0

        while len(records) < max_results:
            params["startIndex"] = start_index
            data = self._get(params)

            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                break

            for vuln in vulnerabilities:
                rec = self._parse_vulnerability(vuln)
                if rec:
                    records.append(rec)
                    if len(records) >= max_results:
                        break

            start_index += len(vulnerabilities)
            if start_index >= total_results:
                break

        logger.info("Search returned %d CVE records", len(records))
        return records

    @staticmethod
    def _parse_vulnerability(vuln_wrapper: dict) -> Optional[CVERecord]:
        cve = vuln_wrapper.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            return None

        descriptions = cve.get("descriptions", [])
        desc_en = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "",
        )

        published = cve.get("published", "")
        last_modified = cve.get("lastModified", "")

        cvss = NVDClient._extract_cvss(cve)
        weaknesses = NVDClient._extract_weaknesses(cve)
        references = NVDClient._extract_references(cve)
        products = NVDClient._extract_products(cve)

        return CVERecord(
            cve_id=cve_id,
            source_identifier=cve.get("sourceIdentifier"),
            published=datetime.fromisoformat(published.replace("Z", "+00:00")),
            last_modified=datetime.fromisoformat(last_modified.replace("Z", "+00:00")),
            description=desc_en,
            cvss=cvss,
            weaknesses=weaknesses,
            references=references,
            affected_products=products,
        )

    @staticmethod
    def _extract_cvss(cve: dict) -> Optional[CVSSMetrics]:
        metrics = cve.get("metrics", {})

        for key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(key, [])
            if not metric_list:
                continue
            primary = next(
                (m for m in metric_list if m.get("type") == "Primary"),
                metric_list[0],
            )
            cvss_data = primary.get("cvssData", {})
            return CVSSMetrics(
                version=cvss_data.get("version", "3.1"),
                vector_string=cvss_data.get("vectorString"),
                base_score=cvss_data.get("baseScore", 0.0),
                base_severity=SEVERITY_MAP.get(
                    cvss_data.get("baseSeverity", "NONE").upper(),
                    Severity.NONE,
                ),
                exploitability_score=primary.get("exploitabilityScore"),
                impact_score=primary.get("impactScore"),
            )

        v2_list = metrics.get("cvssMetricV2", [])
        if v2_list:
            primary = next(
                (m for m in v2_list if m.get("type") == "Primary"),
                v2_list[0],
            )
            cvss_data = primary.get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            if score >= 9.0:
                sev = Severity.CRITICAL
            elif score >= 7.0:
                sev = Severity.HIGH
            elif score >= 4.0:
                sev = Severity.MEDIUM
            else:
                sev = Severity.LOW
            return CVSSMetrics(
                version="2.0",
                vector_string=cvss_data.get("vectorString"),
                base_score=score,
                base_severity=sev,
                exploitability_score=primary.get("exploitabilityScore"),
                impact_score=primary.get("impactScore"),
            )
        return None

    @staticmethod
    def _extract_weaknesses(cve: dict) -> list[str]:
        out: list[str] = []
        for w in cve.get("weaknesses", []):
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val and val != "NVD-CWE-noinfo":
                    out.append(val)
        return out

    @staticmethod
    def _extract_references(cve: dict) -> list[CVEReference]:
        return [
            CVEReference(
                url=r.get("url", ""),
                source=r.get("source"),
                tags=r.get("tags", []),
            )
            for r in cve.get("references", [])
        ]

    @staticmethod
    def _extract_products(cve: dict) -> list[str]:
        products: list[str] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    if criteria:
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            label = f"{vendor}/{product}"
                            if label not in products:
                                products.append(label)
        return products

    def close(self) -> None:
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
