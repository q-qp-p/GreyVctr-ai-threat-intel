"""
Pydantic response schemas for the Analytics API.

Defines the standard response envelope and typed item models
for each analytics endpoint.

Requirements: 10.1, 10.2
"""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class AnalyticsMeta(BaseModel):
    """Metadata included in every analytics response."""
    total_records: int = Field(..., description="Total number of records in the response data array")
    filters_applied: dict = Field(..., description="Dictionary of filter parameters that were applied")
    computed_at: datetime = Field(..., description="ISO 8601 timestamp of when the computation was performed")


class AnalyticsResponse(BaseModel):
    """Standard envelope for all analytics API responses."""
    data: list[dict] = Field(..., description="Array of result items")
    meta: AnalyticsMeta


class TrendItem(BaseModel):
    """A single time-bucket in the trends response."""
    period: str = Field(..., description="ISO 8601 date string for the bucket start")
    count: int = Field(..., description="Number of threats in this bucket")
    group: Optional[str] = Field(None, description="Group value, present when group_by is specified")


class DistributionItem(BaseModel):
    """A single category in the distributions response."""
    label: str = Field(..., description="The dimension value (e.g. 'adversarial', '7', 'NIST')")
    count: int = Field(..., description="Number of threats with this label")


class MitreHeatmapItem(BaseModel):
    """A single cell in the MITRE tactic×technique heatmap."""
    tactic: str = Field(..., description="MITRE ATLAS tactic name")
    technique: str = Field(..., description="MITRE ATLAS technique name")
    technique_id: str = Field(..., description="MITRE ATLAS technique identifier")
    count: int = Field(..., description="Number of occurrences")


class EntityClusterItem(BaseModel):
    """A cluster of threats sharing a common entity."""
    entity_value: str = Field(..., description="The shared entity value")
    entity_type: str = Field(..., description="Entity type (cve, framework, technique, system)")
    threat_count: int = Field(..., description="Number of distinct threats sharing this entity")
    threat_ids: list[str] = Field(..., description="List of threat IDs in this cluster")


class SeverityMatrixItem(BaseModel):
    """A cell in the severity × threat_type cross-tabulation."""
    severity: int = Field(..., description="Severity level (1-10)")
    threat_type: str = Field(..., description="Threat type category")
    count: int = Field(..., description="Number of threats at this intersection")
