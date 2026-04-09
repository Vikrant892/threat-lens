# ThreatLens

Real-Time Threat Intelligence & Vulnerability Management Platform.

## The Problem

Security Operations Centers drown in thousands of CVE alerts per week. Most are noise — low-severity findings on assets that don't exist in the environment, stale vulnerabilities that were patched months ago, or duplicates from overlapping scanners. Analysts waste hours triaging alerts that never mattered while genuinely dangerous issues sit in the queue.

ThreatLens fixes this by pulling CVE data from the NVD, enriching it with IP reputation intelligence and MITRE ATT&CK technique mappings, and running every finding through a composite scoring engine that factors in CVSS severity, exploit availability, asset exposure, and temporal relevance. The result is a single, prioritised threat feed that surfaces what actually needs attention.

## Architecture

```
                    +-----------+
                    |  FastAPI  |
                    |   /api/*  |
                    +-----+-----+
                          |
              +-----------+-----------+
              |                       |
     +--------v--------+    +--------v--------+
     | Feed Aggregator  |    |  Threat Scorer  |
     +--------+--------+    +-----------------+
              |
    +---------+---------+---------+
    |                   |         |
+---v----+       +------v-+   +--v-----------+
|  NVD   |       |  IP    |   |    MITRE     |
| Client |       |Analyzer|   |   Mapper     |
+---+----+       +---+----+   +--+-----------+
    |                |            |
    v                v            v
 NVD API v2.0   ip-api.com   Bundled ATT&CK
                + RDAP        technique set
```

## Quick Start

```bash
# Clone and install
git clone https://github.com/your-org/threat-lens.git
cd threat-lens
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run the API server
uvicorn api:app --reload

# Open the interactive docs
# http://127.0.0.1:8000/docs
```

### With Docker

```bash
docker build -t threat-lens .
docker run -p 8000:8000 threat-lens
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | *(none)* | NVD API key — raises rate limit from 5 to 50 req/30 s |
| `FEED_AUTO_REFRESH` | `false` | Start background feed refresh on boot |
| `FEED_REFRESH_INTERVAL` | `900` | Seconds between automatic feed refreshes |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `RATE_LIMIT_WINDOW` | `60` | Rate-limit sliding window in seconds |
| `RATE_LIMIT_MAX` | `60` | Max requests per window per IP |
| `LOG_LEVEL` | `INFO` | Python log level |

## API

All endpoints return JSON unless noted otherwise.

### CVEs

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/cves` | List recent CVEs (query params: `keyword`, `severity`, `days`, `limit`) |
| GET | `/api/cves/{cve_id}` | Single CVE with threat score and ATT&CK mappings |

### IP Intelligence

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/ip/{ip_address}` | Geolocation, reverse DNS, abuse score |

### Threat Feed

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/threats` | Aggregated, scored feed (query params: `severity`, `source`, `limit`, `fmt`) |
| POST | `/api/threats/refresh` | Trigger manual feed refresh |

### MITRE ATT&CK

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/mitre/techniques` | All techniques (optional `tactic` filter) |
| GET | `/api/mitre/techniques/{technique_id}` | Single technique detail |
| GET | `/api/mitre/tactics` | List of tactic names |

### Dashboard

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/stats` | Severity breakdown, source counts, avg/max score |
| GET | `/healthz` | Health check |

### Example Requests

```bash
# Recent critical CVEs
curl "http://localhost:8000/api/cves?severity=CRITICAL&days=30&limit=10"

# CVE detail with threat score
curl "http://localhost:8000/api/cves/CVE-2024-3400"

# IP reputation
curl "http://localhost:8000/api/ip/8.8.8.8"

# Aggregated feed as CSV
curl "http://localhost:8000/api/threats?fmt=csv"

# MITRE techniques for a specific tactic
curl "http://localhost:8000/api/mitre/techniques?tactic=Initial+Access"
```

## Screenshots

Screenshots are located in `docs/screenshots/`:

- `docs/screenshots/dashboard.png` — Main threat dashboard
- `docs/screenshots/cve-detail.png` — CVE detail view with threat score breakdown
- `docs/screenshots/feed.png` — Aggregated threat feed

## Tech Stack

- **Python 3.12** — Runtime
- **FastAPI** — REST API framework
- **Pydantic v2** — Data validation and serialisation
- **Requests** — HTTP client with session pooling and retry
- **NVD CVE API v2.0** — Vulnerability data source
- **ip-api.com** — IP geolocation (free tier, no key)
- **ARIN RDAP** — WHOIS data fallback
- **MITRE ATT&CK** — Technique mapping (bundled subset)
- **Docker** — Container packaging

## Project Structure

```
threat-lens/
├── api.py                          # FastAPI application
├── threat_lens/
│   ├── __init__.py
│   ├── models.py                   # Pydantic data models
│   ├── nvd_client.py               # NVD CVE API v2.0 client
│   ├── ip_analyzer.py              # IP threat intelligence
│   ├── threat_scorer.py            # Composite threat scoring
│   ├── mitre_mapper.py             # ATT&CK technique mapping
│   ├── feed_aggregator.py          # Multi-source feed aggregation
│   └── data/
│       └── mitre_techniques.json   # Curated ATT&CK technique set
├── tests/
├── Dockerfile
├── requirements.txt
└── .github/workflows/ci.yml
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Write tests before implementation (TDD)
4. Ensure `pytest --cov-fail-under=80` passes
5. Run `ruff check` and `ruff format`
6. Open a pull request against `main`

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add STIX 2.1 export support
fix: handle NVD rate-limit 403 responses gracefully
refactor: extract CVSS parsing into standalone module
```

## License

MIT License. See [LICENSE](LICENSE) for details.
