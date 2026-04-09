"""IP threat intelligence: geolocation, reverse DNS, whois, and abuse scoring."""

from __future__ import annotations

import ipaddress
import logging
import socket
from datetime import datetime
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from threat_lens.models import IPIntelligence

logger = logging.getLogger(__name__)

GEOIP_API = "http://ip-api.com/json"
GEOIP_BATCH_API = "http://ip-api.com/batch"

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

GEOIP_FIELDS = (
    "status,message,country,countryCode,regionName,city,"
    "lat,lon,isp,org,as,asname,proxy,hosting,query"
)

SUSPICIOUS_PORTS_WEIGHT = {
    22: 5,
    23: 10,
    445: 10,
    3389: 8,
    1433: 7,
    3306: 7,
    5432: 6,
    6379: 8,
    27017: 8,
    9200: 7,
}

HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR"}
HOSTING_PENALTY = 15
PROXY_PENALTY = 20


class IPAnalyzer:
    """Enrich IP addresses with geolocation, DNS, and risk scoring."""

    def __init__(self, timeout: int = 10):
        self._timeout = timeout
        self._session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 503])
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def analyze(self, ip: str) -> IPIntelligence:
        """Full analysis of a single IP address."""
        addr = ipaddress.ip_address(ip)

        if self._is_private(addr):
            return IPIntelligence(
                ip_address=ip,
                is_private=True,
                abuse_score=0.0,
                analyzed_at=datetime.utcnow(),
            )

        geo = self._geoip_lookup(ip)
        rdns = self._reverse_dns(ip)
        whois_info = self._whois_lookup(ip)

        intel = IPIntelligence(
            ip_address=ip,
            is_private=False,
            country=geo.get("country"),
            country_code=geo.get("countryCode"),
            region=geo.get("regionName"),
            city=geo.get("city"),
            latitude=geo.get("lat"),
            longitude=geo.get("lon"),
            isp=geo.get("isp"),
            org=geo.get("org"),
            as_number=self._parse_asn(geo.get("as", "")),
            as_name=geo.get("asname"),
            reverse_dns=rdns,
            is_proxy=geo.get("proxy", False),
            is_hosting=geo.get("hosting", False),
            whois_registrar=whois_info.get("registrar"),
            whois_creation_date=whois_info.get("creation_date"),
            analyzed_at=datetime.utcnow(),
        )
        intel.abuse_score = self._calculate_abuse_score(intel)
        return intel

    def analyze_bulk(self, ips: list[str]) -> list[IPIntelligence]:
        """Analyze up to 100 IPs in a single batch call to ip-api.com."""
        results: list[IPIntelligence] = []
        private_ips: list[str] = []
        public_ips: list[str] = []

        for ip in ips:
            addr = ipaddress.ip_address(ip)
            if self._is_private(addr):
                private_ips.append(ip)
            else:
                public_ips.append(ip)

        for ip in private_ips:
            results.append(
                IPIntelligence(
                    ip_address=ip,
                    is_private=True,
                    abuse_score=0.0,
                    analyzed_at=datetime.utcnow(),
                )
            )

        for chunk_start in range(0, len(public_ips), 100):
            chunk = public_ips[chunk_start : chunk_start + 100]
            batch_results = self._geoip_batch(chunk)

            for ip, geo in zip(chunk, batch_results):
                rdns = self._reverse_dns(ip)
                intel = IPIntelligence(
                    ip_address=ip,
                    is_private=False,
                    country=geo.get("country"),
                    country_code=geo.get("countryCode"),
                    region=geo.get("regionName"),
                    city=geo.get("city"),
                    latitude=geo.get("lat"),
                    longitude=geo.get("lon"),
                    isp=geo.get("isp"),
                    org=geo.get("org"),
                    as_number=self._parse_asn(geo.get("as", "")),
                    as_name=geo.get("asname"),
                    reverse_dns=rdns,
                    is_proxy=geo.get("proxy", False),
                    is_hosting=geo.get("hosting", False),
                    analyzed_at=datetime.utcnow(),
                )
                intel.abuse_score = self._calculate_abuse_score(intel)
                results.append(intel)

        return results

    def _geoip_lookup(self, ip: str) -> dict:
        try:
            resp = self._session.get(
                f"{GEOIP_API}/{ip}",
                params={"fields": GEOIP_FIELDS},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "fail":
                logger.warning("GeoIP lookup failed for %s: %s", ip, data.get("message"))
                return {}
            return data
        except requests.RequestException as exc:
            logger.error("GeoIP request error for %s: %s", ip, exc)
            return {}

    def _geoip_batch(self, ips: list[str]) -> list[dict]:
        payload = [{"query": ip, "fields": GEOIP_FIELDS} for ip in ips]
        try:
            resp = self._session.post(
                GEOIP_BATCH_API,
                json=payload,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            logger.error("GeoIP batch request error: %s", exc)
            return [{} for _ in ips]

    @staticmethod
    def _reverse_dns(ip: str) -> Optional[str]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None

    @staticmethod
    def _whois_lookup(ip: str) -> dict:
        """Best-effort WHOIS extraction via RDAP fallback (ARIN)."""
        try:
            resp = requests.get(
                f"https://rdap.arin.net/registry/ip/{ip}",
                timeout=8,
                headers={"Accept": "application/rdap+json"},
            )
            if resp.status_code != 200:
                return {}
            data = resp.json()
            registrar = data.get("name", "")
            events = data.get("events", [])
            creation = next(
                (e["eventDate"] for e in events if e.get("eventAction") == "registration"),
                None,
            )
            return {"registrar": registrar, "creation_date": creation}
        except Exception:
            return {}

    @staticmethod
    def _is_private(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        for net in PRIVATE_RANGES:
            if addr in net:
                return True
        return False

    @staticmethod
    def _parse_asn(as_field: str) -> Optional[str]:
        if not as_field:
            return None
        parts = as_field.split()
        return parts[0] if parts else None

    @staticmethod
    def _calculate_abuse_score(intel: IPIntelligence) -> float:
        """Heuristic abuse score (0-100) based on available indicators."""
        score = 0.0

        if intel.is_proxy:
            score += PROXY_PENALTY

        if intel.is_hosting:
            score += HOSTING_PENALTY

        if intel.country_code in HIGH_RISK_COUNTRIES:
            score += 15

        rdns = intel.reverse_dns or ""
        suspicious_rdns_tokens = ["dynamic", "pool", "dial", "ppp", "dhcp", "cable"]
        if any(tok in rdns.lower() for tok in suspicious_rdns_tokens):
            score += 10

        if not rdns:
            score += 5

        org = (intel.org or "").lower()
        if any(kw in org for kw in ["vps", "cloud", "hosting", "server", "data center"]):
            score += 10

        return min(score, 100.0)

    def close(self) -> None:
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
