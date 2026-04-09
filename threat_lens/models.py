"""Canonical data models for the ThreatLens pipeline."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class CVSSMetrics(BaseModel):
    version: str = "3.1"
    vector_string: Optional[str] = None
    base_score: float = Field(ge=0.0, le=10.0)
    base_severity: Severity = Severity.NONE
    exploitability_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    impact_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)


class CVEReference(BaseModel):
    url: str
    source: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class CVERecord(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    source_identifier: Optional[str] = None
    published: datetime
    last_modified: datetime
    description: str
    cvss: Optional[CVSSMetrics] = None
    weaknesses: list[str] = Field(default_factory=list)
    references: list[CVEReference] = Field(default_factory=list)
    known_exploited: bool = False
    affected_products: list[str] = Field(default_factory=list)

    @property
    def base_score(self) -> float:
        if self.cvss:
            return self.cvss.base_score
        return 0.0

    @property
    def severity(self) -> Severity:
        if self.cvss:
            return self.cvss.base_severity
        return Severity.NONE


class IPIntelligence(BaseModel):
    ip_address: str
    is_private: bool = False
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    as_number: Optional[str] = None
    as_name: Optional[str] = None
    reverse_dns: Optional[str] = None
    is_proxy: bool = False
    is_hosting: bool = False
    abuse_score: float = Field(default=0.0, ge=0.0, le=100.0)
    whois_registrar: Optional[str] = None
    whois_creation_date: Optional[str] = None
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        ipaddress.ip_address(v)
        return v


class MITRETechnique(BaseModel):
    technique_id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    description: str = ""
    platforms: list[str] = Field(default_factory=list)
    detection: str = ""
    mitigations: list[str] = Field(default_factory=list)
    url: str = ""


class ThreatScore(BaseModel):
    composite_score: float = Field(ge=0.0, le=100.0)
    severity: Severity
    cvss_component: float = Field(ge=0.0, le=100.0)
    exploit_component: float = Field(ge=0.0, le=100.0)
    exposure_component: float = Field(ge=0.0, le=100.0)
    temporal_component: float = Field(ge=0.0, le=100.0)
    factors: list[str] = Field(default_factory=list)


class ThreatEventSource(str, Enum):
    NVD = "NVD"
    IP_INTEL = "IP_INTEL"
    MITRE = "MITRE"
    AGGREGATED = "AGGREGATED"


class ThreatEvent(BaseModel):
    event_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: ThreatEventSource
    title: str
    description: str
    severity: Severity
    score: Optional[ThreatScore] = None
    cve: Optional[CVERecord] = None
    ip_intel: Optional[IPIntelligence] = None
    mitre_techniques: list[MITRETechnique] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    raw_data: Optional[dict] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class FeedExportFormat(str, Enum):
    JSON = "json"
    CSV = "csv"
