"""ThreatLens REST API — FastAPI application entry point."""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from threat_lens.feed_aggregator import FeedAggregator
from threat_lens.ip_analyzer import IPAnalyzer
from threat_lens.mitre_mapper import MITREMapper
from threat_lens.models import FeedExportFormat
from threat_lens.nvd_client import NVDClient
from threat_lens.threat_scorer import ThreatScorer

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger("threat_lens.api")

nvd = NVDClient()
ip_analyzer = IPAnalyzer()
mitre = MITREMapper()
scorer = ThreatScorer()
aggregator = FeedAggregator(
    nvd_client=nvd,
    ip_analyzer=ip_analyzer,
    mitre_mapper=mitre,
    scorer=scorer,
    refresh_interval_seconds=int(os.getenv("FEED_REFRESH_INTERVAL", "900")),
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.getenv("FEED_AUTO_REFRESH", "false").lower() == "true":
        aggregator.start_background()
    yield
    aggregator.stop_background()
    nvd.close()
    ip_analyzer.close()


app = FastAPI(
    title="ThreatLens",
    description="Real-Time Threat Intelligence & Vulnerability Management API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Simple sliding-window rate limiter (per-IP, in-process)
# ---------------------------------------------------------------------------
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "60"))

_request_log: dict[str, list[float]] = defaultdict(list)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window = _request_log[client_ip]
    window[:] = [ts for ts in window if now - ts < RATE_LIMIT_WINDOW]

    if len(window) >= RATE_LIMIT_MAX:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Try again later."},
        )

    window.append(now)
    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_MAX)
    response.headers["X-RateLimit-Remaining"] = str(max(RATE_LIMIT_MAX - len(window), 0))
    return response


# ---------------------------------------------------------------------------
# CVE endpoints
# ---------------------------------------------------------------------------

@app.get("/api/cves")
def list_cves(
    keyword: Optional[str] = Query(None, description="Full-text keyword filter"),
    severity: Optional[str] = Query(None, description="CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    days: int = Query(7, ge=1, le=120, description="Look-back window in days"),
    limit: int = Query(20, ge=1, le=200, description="Maximum results"),
):
    """List recent CVEs from NVD with optional filtering."""
    try:
        pub_end = datetime.utcnow()
        from datetime import timedelta
        pub_start = pub_end - timedelta(days=days)

        records = nvd.search(
            keyword=keyword,
            severity=severity,
            pub_start=pub_start,
            pub_end=pub_end,
            max_results=limit,
        )
        return {
            "count": len(records),
            "cves": [r.model_dump(mode="json") for r in records],
        }
    except Exception as exc:
        logger.exception("CVE list failed")
        raise HTTPException(status_code=502, detail=f"NVD API error: {exc}")


@app.get("/api/cves/{cve_id}")
def get_cve(cve_id: str):
    """Fetch a specific CVE with its computed threat score and ATT&CK mappings."""
    try:
        record = nvd.get_cve(cve_id)
    except Exception as exc:
        logger.exception("CVE lookup failed for %s", cve_id)
        raise HTTPException(status_code=502, detail=f"NVD API error: {exc}")

    if not record:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")

    score = scorer.score(record)
    techniques = mitre.map_cve(record.description, top_n=5)

    return {
        "cve": record.model_dump(mode="json"),
        "threat_score": score.model_dump(mode="json"),
        "mitre_techniques": [t.model_dump(mode="json") for t in techniques],
    }


# ---------------------------------------------------------------------------
# IP intelligence endpoint
# ---------------------------------------------------------------------------

@app.get("/api/ip/{ip_address}")
def analyze_ip(ip_address: str):
    """Return geolocation, reverse DNS, and abuse score for an IP."""
    try:
        intel = ip_analyzer.analyze(ip_address)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip_address}")
    except Exception as exc:
        logger.exception("IP analysis failed for %s", ip_address)
        raise HTTPException(status_code=502, detail=str(exc))

    return intel.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Aggregated threat feed
# ---------------------------------------------------------------------------

@app.get("/api/threats")
def threat_feed(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    source: Optional[str] = Query(None, description="Filter by source (NVD, IP_INTEL)"),
    limit: int = Query(50, ge=1, le=500),
    fmt: FeedExportFormat = Query(FeedExportFormat.JSON, description="Export format"),
):
    """Return the aggregated, scored threat feed."""
    events = aggregator.events

    if severity:
        sev_upper = severity.upper()
        events = [e for e in events if e.severity.value == sev_upper]
    if source:
        src_upper = source.upper()
        events = [e for e in events if e.source.value == src_upper]

    events = events[:limit]

    if fmt == FeedExportFormat.CSV:
        csv_out = aggregator.export(FeedExportFormat.CSV)
        return Response(content=csv_out, media_type="text/csv")

    return {
        "count": len(events),
        "events": [e.model_dump(mode="json") for e in events],
    }


@app.post("/api/threats/refresh")
def refresh_feed(
    days: int = Query(7, ge=1, le=120),
    limit: int = Query(50, ge=1, le=200),
):
    """Trigger an immediate feed refresh from all sources."""
    new_events = aggregator.refresh(cve_days=days, cve_limit=limit)
    return {
        "refreshed": len(new_events),
        "total": len(aggregator.events),
    }


# ---------------------------------------------------------------------------
# MITRE ATT&CK endpoints
# ---------------------------------------------------------------------------

@app.get("/api/mitre/techniques")
def list_techniques(
    tactic: Optional[str] = Query(None, description="Filter by tactic name"),
):
    """List MITRE ATT&CK techniques, optionally filtered by tactic."""
    if tactic:
        techniques = mitre.techniques_by_tactic(tactic)
    else:
        techniques = mitre.list_techniques()

    return {
        "count": len(techniques),
        "techniques": [t.model_dump(mode="json") for t in techniques],
    }


@app.get("/api/mitre/techniques/{technique_id}")
def get_technique(technique_id: str):
    """Retrieve details for a specific ATT&CK technique by ID."""
    tech = mitre.get_technique(technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    return tech.model_dump(mode="json")


@app.get("/api/mitre/tactics")
def list_tactics():
    """Return all tactic names from the loaded ATT&CK dataset."""
    return {"tactics": mitre.list_tactics()}


# ---------------------------------------------------------------------------
# Dashboard stats
# ---------------------------------------------------------------------------

@app.get("/api/stats")
def dashboard_stats():
    """Aggregated statistics for the threat dashboard."""
    return aggregator.stats()


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/healthz")
def healthz():
    return {"status": "ok"}
