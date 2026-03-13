"""Pydantic schema definitions for the CyberSentry API."""

from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, Field, field_validator


class Software(BaseModel):
    """A single piece of software detected on an asset."""

    name: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None


class AssetOut(BaseModel):
    """An asset representation returned by the API."""

    id: int
    ip_address: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    internet_exposed: bool = False
    open_ports: List[int] = Field(default_factory=list)
    software_list: List[Software] = Field(default_factory=list)
    criticality: int
    risk_score: Optional[float] = None
    severity_label: Optional[str] = None

    @field_validator('open_ports', 'software_list', mode='before')
    @classmethod
    def null_to_empty_list(cls, v):
        return v if v is not None else []

    class Config:
        from_attributes = True


class AssetScanRequest(BaseModel):
    """Request schema for initiating a scan on an asset."""

    ip_range: str
    ports: Optional[str] = None
    use_seed: bool = False


class ScanResult(BaseModel):
    """Result returned by the scan endpoint."""

    assets_found: int
    assets_saved: int
    ip_range: str
    scan_duration: float
    timestamp: datetime
    message: str


class RiskScore(BaseModel):
    asset_id: int
    hostname: str
    score: float
    severity: str
    top_cves: List[str]
    breakdown: dict


class RiskScoreSummary(BaseModel):
    company_score: float
    severity: str
    total_assets: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    last_calculated: datetime


class RiskScoreHistory(BaseModel):
    asset_id: int
    score: float
    severity: str
    calculated_at: datetime


class FixSimulationResult(BaseModel):
    asset_id: int
    hostname: str
    fix_type: str
    fix_detail: str
    old_score: float
    new_score: float
    delta: float
    old_severity: str
    new_severity: str


class RelationshipBase(BaseModel):
    source_asset_id: int
    target_asset_id: int
    type: str
    metadata_json: Optional[dict] = None
    traversal_probability: float = 0.5


class RelationshipCreate(RelationshipBase):
    pass


class RelationshipOut(RelationshipBase):
    id: int

    class Config:
        from_attributes = True


class AttackPathNode(BaseModel):
    id: int
    hostname: str
    risk_score: float
    severity: str


class AttackPathEdge(BaseModel):
    source: int
    target: int
    type: str
    weight: float


class AttackPath(BaseModel):
    nodes: List[AttackPathNode]
    edges: List[AttackPathEdge]
    total_probability: float