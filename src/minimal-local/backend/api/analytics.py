"""
Analytics API endpoints for AI Shield Intelligence.

Provides REST API for threat intelligence analytics including trends,
distributions, MITRE heatmaps, entity clusters, and severity matrices.

Requirements: 3.1, 3.2, 3.7, 4.1, 4.2, 4.7, 5.1, 5.2, 6.1, 6.2, 6.3, 7.1, 7.2, 10.4
"""
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from models import get_db
from services.analytics import AnalyticsService, AnalyticsTimeoutError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])


def _validate_common_params(
    severity_min: Optional[int],
    severity_max: Optional[int],
    date_from: Optional[datetime],
    date_to: Optional[datetime],
) -> Optional[JSONResponse]:
    """Validate common filter parameters shared across all endpoints.

    Returns a JSONResponse with HTTP 400 if validation fails, or None if valid.
    """
    if severity_min is not None and severity_max is not None:
        if severity_min > severity_max:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "validation_error",
                    "detail": "severity_min cannot be greater than severity_max",
                },
            )
    if date_from is not None and date_to is not None:
        if date_from > date_to:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "validation_error",
                    "detail": "date_from cannot be after date_to",
                },
            )
    return None


@router.get("/trends")
async def get_trends(
    granularity: str = Query("month", description="Time bucket size: day, week, or month"),
    group_by: Optional[str] = Query(None, description="Group by: threat_type, severity, or source"),
    date_from: Optional[datetime] = Query(None, description="Filter threats published on or after (ISO 8601)"),
    date_to: Optional[datetime] = Query(None, description="Filter threats published on or before (ISO 8601)"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    severity_min: Optional[int] = Query(None, ge=1, le=10, description="Minimum severity (1-10)"),
    severity_max: Optional[int] = Query(None, ge=1, le=10, description="Maximum severity (1-10)"),
    source: Optional[str] = Query(None, description="Filter by source"),
    include_unknown: bool = Query(True, description="Include threats with unknown/empty threat_type"),
    db: AsyncSession = Depends(get_db),
):
    """Return time-series threat counts bucketed by granularity.

    Requirements: 3.1, 3.2, 3.5, 3.7
    """
    error_resp = _validate_common_params(severity_min, severity_max, date_from, date_to)
    if error_resp is not None:
        return error_resp

    service = AnalyticsService(db)
    try:
        return await service.get_trends(
            granularity=granularity,
            group_by=group_by,
            date_from=date_from,
            date_to=date_to,
            threat_type=threat_type,
            severity_min=severity_min,
            severity_max=severity_max,
            source=source,
            include_unknown=include_unknown,
        )
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={"error": "validation_error", "detail": str(exc)},
        )
    except AnalyticsTimeoutError as exc:
        return JSONResponse(
            status_code=504,
            content={"error": "timeout", "detail": str(exc)},
        )


@router.get("/distributions")
async def get_distributions(
    dimension: str = Query(..., description="Dimension to group by: threat_type, severity, or source"),
    date_from: Optional[datetime] = Query(None, description="Filter threats published on or after (ISO 8601)"),
    date_to: Optional[datetime] = Query(None, description="Filter threats published on or before (ISO 8601)"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    severity_min: Optional[int] = Query(None, ge=1, le=10, description="Minimum severity (1-10)"),
    severity_max: Optional[int] = Query(None, ge=1, le=10, description="Maximum severity (1-10)"),
    source: Optional[str] = Query(None, description="Filter by source"),
    include_unknown: bool = Query(True, description="Include threats with unknown/empty threat_type"),
    db: AsyncSession = Depends(get_db),
):
    """Return threat counts grouped by the requested dimension.

    Requirements: 4.1, 4.2, 4.5, 4.6, 4.7
    """
    error_resp = _validate_common_params(severity_min, severity_max, date_from, date_to)
    if error_resp is not None:
        return error_resp

    service = AnalyticsService(db)
    try:
        return await service.get_distributions(
            dimension=dimension,
            date_from=date_from,
            date_to=date_to,
            threat_type=threat_type,
            severity_min=severity_min,
            severity_max=severity_max,
            source=source,
            include_unknown=include_unknown,
        )
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={"error": "validation_error", "detail": str(exc)},
        )
    except AnalyticsTimeoutError as exc:
        return JSONResponse(
            status_code=504,
            content={"error": "timeout", "detail": str(exc)},
        )


@router.get("/mitre-heatmap")
async def get_mitre_heatmap(
    date_from: Optional[datetime] = Query(None, description="Filter threats published on or after (ISO 8601)"),
    date_to: Optional[datetime] = Query(None, description="Filter threats published on or before (ISO 8601)"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    severity_min: Optional[int] = Query(None, ge=1, le=10, description="Minimum severity (1-10)"),
    severity_max: Optional[int] = Query(None, ge=1, le=10, description="Maximum severity (1-10)"),
    source: Optional[str] = Query(None, description="Filter by source"),
    include_unknown: bool = Query(True, description="Include threats with unknown/empty threat_type"),
    db: AsyncSession = Depends(get_db),
):
    """Return MITRE tactic×technique frequency matrix.

    Requirements: 5.1, 5.2, 5.3
    """
    error_resp = _validate_common_params(severity_min, severity_max, date_from, date_to)
    if error_resp is not None:
        return error_resp

    service = AnalyticsService(db)
    try:
        return await service.get_mitre_heatmap(
            date_from=date_from,
            date_to=date_to,
            threat_type=threat_type,
            severity_min=severity_min,
            severity_max=severity_max,
            source=source,
            include_unknown=include_unknown,
        )
    except AnalyticsTimeoutError as exc:
        return JSONResponse(
            status_code=504,
            content={"error": "timeout", "detail": str(exc)},
        )


@router.get("/entity-clusters/graph")
async def get_entity_cluster_graph(
    entity_type: Optional[str] = Query(None, description="Filter by entity type: cve, framework, technique, or system"),
    min_shared: int = Query(2, ge=1, description="Minimum threats sharing an entity to form a cluster"),
    include_unknown: bool = Query(False, description="Include entities with unknown/empty type or value"),
    date_from: Optional[datetime] = Query(None, description="Filter threats published on or after (ISO 8601)"),
    date_to: Optional[datetime] = Query(None, description="Filter threats published on or before (ISO 8601)"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    severity_min: Optional[int] = Query(None, ge=1, le=10, description="Minimum severity (1-10)"),
    severity_max: Optional[int] = Query(None, ge=1, le=10, description="Maximum severity (1-10)"),
    source: Optional[str] = Query(None, description="Filter by source"),
    db: AsyncSession = Depends(get_db),
):
    """Return entity-threat relationships as a graph of nodes and edges.

    Requirements: 1.1, 1.5, 1.6, 1.7, 1.8, 1.9
    """
    error_resp = _validate_common_params(severity_min, severity_max, date_from, date_to)
    if error_resp is not None:
        return error_resp

    # Validate entity_type if provided
    valid_entity_types = ("cve", "framework", "technique", "system")
    if entity_type is not None and entity_type not in valid_entity_types:
        return JSONResponse(
            status_code=400,
            content={
                "error": "validation_error",
                "detail": f"entity_type must be one of: {', '.join(valid_entity_types)}",
            },
        )

    service = AnalyticsService(db)
    try:
        return await service.get_entity_graph(
            entity_type=entity_type,
            min_shared=min_shared,
            include_unknown=include_unknown,
            date_from=date_from,
            date_to=date_to,
            threat_type=threat_type,
            severity_min=severity_min,
            severity_max=severity_max,
            source=source,
        )
    except AnalyticsTimeoutError as exc:
        return JSONResponse(
            status_code=504,
            content={"error": "timeout", "detail": str(exc)},
        )


@router.get("/entity-clusters")
async def get_entity_clusters(
    entity_type: Optional[str] = Query(None, description="Filter by entity type: cve, framework, technique, or system"),
    min_shared: int = Query(2, ge=1, description="Minimum threats sharing an entity to form a cluster"),
    date_from: Optional[datetime] = Query(None, description="Filter threats published on or after (ISO 8601)"),
    date_to: Optional[datetime] = Query(None, description="Filter threats published on or before (ISO 8601)"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    severity_min: Optional[int] = Query(None, ge=1, le=10, description="Minimum severity (1-10)"),
    severity_max: Optional[int] = Query(None, ge=1, le=10, description="Maximum severity (1-10)"),
    source: Optional[str] = Query(None, description="Filter by source"),
    include_unknown: bool = Query(True, description="Include threats with unknown/empty threat_type"),
    db: AsyncSession = Depends(get_db),
):
    """Return groups of threats sharing common entities.

    Requirements: 6.1, 6.2, 6.3, 6.4, 6.7
    """
    error_resp = _validate_common_params(severity_min, severity_max, date_from, date_to)
    if error_resp is not None:
        return error_resp

    # Validate entity_type if provided
    valid_entity_types = ("cve", "framework", "technique", "system")
    if entity_type is not None and entity_type not in valid_entity_types:
        return JSONResponse(
            status_code=400,
            content={
                "error": "validation_error",
                "detail": f"entity_type must be one of: {', '.join(valid_entity_types)}",
            },
        )

    service = AnalyticsService(db)
    try:
        return await service.get_entity_clusters(
            entity_type=entity_type,
            min_shared=min_shared,
            date_from=date_from,
            date_to=date_to,
            threat_type=threat_type,
            severity_min=severity_min,
            severity_max=severity_max,
            source=source,
            include_unknown=include_unknown,
        )
    except AnalyticsTimeoutError as exc:
        return JSONResponse(
            status_code=504,
            content={"error": "timeout", "detail": str(exc)},
        )


@router.get("/severity-matrix")
async def get_severity_matrix(
    date_from: Optional[datetime] = Query(None, description="Filter threats published on or after (ISO 8601)"),
    date_to: Optional[datetime] = Query(None, description="Filter threats published on or before (ISO 8601)"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    severity_min: Optional[int] = Query(None, ge=1, le=10, description="Minimum severity (1-10)"),
    severity_max: Optional[int] = Query(None, ge=1, le=10, description="Maximum severity (1-10)"),
    source: Optional[str] = Query(None, description="Filter by source"),
    include_unknown: bool = Query(True, description="Include threats with unknown/empty threat_type"),
    db: AsyncSession = Depends(get_db),
):
    """Return severity × threat_type cross-tabulation counts.

    Requirements: 7.1, 7.2, 7.3
    """
    error_resp = _validate_common_params(severity_min, severity_max, date_from, date_to)
    if error_resp is not None:
        return error_resp

    service = AnalyticsService(db)
    try:
        return await service.get_severity_matrix(
            date_from=date_from,
            date_to=date_to,
            threat_type=threat_type,
            severity_min=severity_min,
            severity_max=severity_max,
            source=source,
            include_unknown=include_unknown,
        )
    except AnalyticsTimeoutError as exc:
        return JSONResponse(
            status_code=504,
            content={"error": "timeout", "detail": str(exc)},
        )
