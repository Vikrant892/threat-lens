"""Multi-source threat feed aggregator with deduplication and export."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from threat_lens.ip_analyzer import IPAnalyzer
from threat_lens.mitre_mapper import MITREMapper
from threat_lens.models import (
    CVERecord,
    FeedExportFormat,
    Severity,
    ThreatEvent,
    ThreatEventSource,
)
from threat_lens.nvd_client import NVDClient
from threat_lens.threat_scorer import ThreatScorer

logger = logging.getLogger(__name__)


def _event_fingerprint(source: str, title: str, description: str) -> str:
    """Deterministic ID for deduplication across feed refreshes."""
    raw = f"{source}|{title}|{description}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class FeedAggregator:
    """Combine NVD, IP intelligence, and ATT&CK mappings into a single scored feed.

    The aggregator can run in one-shot mode (``refresh`` called manually) or
    be started as a background thread that refreshes on a configurable interval.
    """

    def __init__(
        self,
        nvd_client: Optional[NVDClient] = None,
        ip_analyzer: Optional[IPAnalyzer] = None,
        mitre_mapper: Optional[MITREMapper] = None,
        scorer: Optional[ThreatScorer] = None,
        refresh_interval_seconds: int = 900,
    ):
        self._nvd = nvd_client or NVDClient()
        self._ip = ip_analyzer or IPAnalyzer()
        self._mitre = mitre_mapper or MITREMapper()
        self._scorer = scorer or ThreatScorer()
        self._refresh_interval = refresh_interval_seconds

        self._events: dict[str, ThreatEvent] = {}
        self._lock = threading.Lock()
        self._bg_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @property
    def events(self) -> list[ThreatEvent]:
        with self._lock:
            return sorted(self._events.values(), key=lambda e: e.timestamp, reverse=True)

    def refresh(self, cve_days: int = 7, cve_limit: int = 50) -> list[ThreatEvent]:
        """Pull fresh data from all sources, score, deduplicate, and return events."""
        new_events: list[ThreatEvent] = []

        cves = self._fetch_cves(cve_days, cve_limit)
        for cve in cves:
            event = self._cve_to_event(cve)
            new_events.append(event)

        with self._lock:
            for ev in new_events:
                self._events[ev.event_id] = ev

        logger.info("Feed refresh complete — %d events in store", len(self._events))
        return new_events

    def add_ip_events(self, ips: list[str]) -> list[ThreatEvent]:
        """Analyse a batch of IPs and merge them into the feed."""
        results = self._ip.analyze_bulk(ips)
        events: list[ThreatEvent] = []

        for intel in results:
            if intel.is_private:
                continue

            severity = Severity.LOW
            if intel.abuse_score >= 70:
                severity = Severity.HIGH
            elif intel.abuse_score >= 40:
                severity = Severity.MEDIUM

            eid = _event_fingerprint("IP_INTEL", intel.ip_address, intel.isp or "")
            event = ThreatEvent(
                event_id=eid,
                source=ThreatEventSource.IP_INTEL,
                title=f"IP reputation: {intel.ip_address}",
                description=(
                    f"{intel.ip_address} — ISP: {intel.isp or 'unknown'}, "
                    f"Country: {intel.country or 'unknown'}, "
                    f"Abuse score: {intel.abuse_score:.0f}/100"
                ),
                severity=severity,
                ip_intel=intel,
                tags=self._ip_tags(intel),
            )
            events.append(event)

        with self._lock:
            for ev in events:
                self._events[ev.event_id] = ev

        return events

    def export(self, fmt: FeedExportFormat = FeedExportFormat.JSON) -> str:
        """Serialise the current event store to JSON or CSV."""
        events = self.events

        if fmt == FeedExportFormat.JSON:
            return json.dumps(
                [json.loads(e.model_dump_json()) for e in events],
                indent=2,
                default=str,
            )

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "event_id", "timestamp", "source", "title",
            "severity", "composite_score", "description",
        ])
        for ev in events:
            writer.writerow([
                ev.event_id,
                ev.timestamp.isoformat(),
                ev.source.value,
                ev.title,
                ev.severity.value,
                ev.score.composite_score if ev.score else "",
                ev.description,
            ])
        return buf.getvalue()

    def start_background(self, cve_days: int = 7, cve_limit: int = 50) -> None:
        """Launch a daemon thread that refreshes the feed on the configured interval."""
        if self._bg_thread and self._bg_thread.is_alive():
            logger.warning("Background refresh thread already running")
            return

        self._stop_event.clear()

        def _loop():
            while not self._stop_event.is_set():
                try:
                    self.refresh(cve_days=cve_days, cve_limit=cve_limit)
                except Exception:
                    logger.exception("Background feed refresh failed")
                self._stop_event.wait(self._refresh_interval)

        self._bg_thread = threading.Thread(target=_loop, daemon=True, name="feed-refresh")
        self._bg_thread.start()
        logger.info("Background feed refresh started (interval=%ds)", self._refresh_interval)

    def stop_background(self) -> None:
        self._stop_event.set()
        if self._bg_thread:
            self._bg_thread.join(timeout=5)
        logger.info("Background feed refresh stopped")

    def stats(self) -> dict:
        """Summary statistics for dashboard consumption."""
        with self._lock:
            all_events = list(self._events.values())

        total = len(all_events)
        by_severity = {s.value: 0 for s in Severity}
        by_source = {s.value: 0 for s in ThreatEventSource}
        scores: list[float] = []

        for ev in all_events:
            by_severity[ev.severity.value] += 1
            by_source[ev.source.value] += 1
            if ev.score:
                scores.append(ev.score.composite_score)

        return {
            "total_events": total,
            "by_severity": by_severity,
            "by_source": by_source,
            "avg_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
            "max_score": max(scores) if scores else 0.0,
            "last_refresh": datetime.now(timezone.utc).isoformat(),
        }

    def _fetch_cves(self, days: int, limit: int) -> list[CVERecord]:
        try:
            return self._nvd.get_recent(days=days, max_results=limit)
        except Exception:
            logger.exception("Failed to fetch CVEs from NVD")
            return []

    def _cve_to_event(self, cve: CVERecord) -> ThreatEvent:
        score = self._scorer.score(cve)
        techniques = self._mitre.map_cve(cve.description, top_n=3)

        eid = _event_fingerprint("NVD", cve.cve_id, cve.description[:120])

        return ThreatEvent(
            event_id=eid,
            timestamp=cve.published,
            source=ThreatEventSource.NVD,
            title=cve.cve_id,
            description=cve.description,
            severity=score.severity,
            score=score,
            cve=cve,
            mitre_techniques=techniques,
            tags=self._cve_tags(cve, score),
        )

    @staticmethod
    def _cve_tags(cve: CVERecord, score) -> list[str]:
        tags = [cve.severity.value]
        if cve.known_exploited:
            tags.append("known-exploited")
        if cve.weaknesses:
            tags.extend(cve.weaknesses[:3])
        if score.composite_score >= 90:
            tags.append("critical-priority")
        return tags

    @staticmethod
    def _ip_tags(intel) -> list[str]:
        tags: list[str] = []
        if intel.is_proxy:
            tags.append("proxy")
        if intel.is_hosting:
            tags.append("hosting-provider")
        if intel.country_code:
            tags.append(f"geo:{intel.country_code}")
        return tags
