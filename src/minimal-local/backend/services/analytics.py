"""
Analytics service for threat intelligence aggregation and clustering.

Provides SQL-level aggregation queries for trends, distributions,
MITRE heatmaps, entity clusters, and severity matrices.
All computations happen in PostgreSQL via GROUP BY, date_trunc(),
and JOIN-based queries — no raw rows are loaded into application memory.

Requirements: 8.2, 8.3
"""
import asyncio
from datetime import datetime
from typing import Optional

from sqlalchemy import select, func, cast, String
from sqlalchemy.ext.asyncio import AsyncSession


class AnalyticsTimeoutError(Exception):
    """Raised when an analytics query exceeds the 5-second timeout.

    The router should catch this and return HTTP 504 with:
    ``{ "error": "timeout", "detail": "Analytics query exceeded 5 second timeout" }``
    """
    pass

from models.threat import Threat
from models.entity import Entity
from models.mitre import MitreMapping


def build_analytics_filters(
    query,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    threat_type: Optional[str] = None,
    severity_min: Optional[int] = None,
    severity_max: Optional[int] = None,
    source: Optional[str] = None,
    include_unknown: bool = True,
):
    """
    Apply common analytics filter parameters to a SQLAlchemy query.

    Filters are applied against the Threat model columns:
    - date_from/date_to filter on published_at
    - threat_type filters on threat_type
    - severity_min/severity_max filter on severity
    - source filters on source
    - include_unknown controls whether threats with null/empty threat_type are included

    Args:
        query: A SQLAlchemy Select statement that already references the Threat table.
        date_from: Include threats published on or after this datetime.
        date_to: Include threats published on or before this datetime.
        threat_type: Filter to a specific threat type string.
        severity_min: Minimum severity (inclusive, 1-10).
        severity_max: Maximum severity (inclusive, 1-10).
        source: Filter to a specific source string.
        include_unknown: Whether to include threats with null/empty threat_type (default True).

    Returns:
        The query with filter clauses applied.
    """
    if date_from is not None:
        query = query.where(Threat.published_at >= date_from)
    if date_to is not None:
        query = query.where(Threat.published_at <= date_to)
    if threat_type is not None:
        query = query.where(Threat.threat_type == threat_type)
    if severity_min is not None:
        query = query.where(Threat.severity >= severity_min)
    if severity_max is not None:
        query = query.where(Threat.severity <= severity_max)
    if source is not None:
        query = query.where(Threat.source == source)
    if not include_unknown:
        query = query.where(
            Threat.threat_type.isnot(None),
            Threat.threat_type != "",
            Threat.threat_type != "unknown",
        )
    return query


def build_graph_data(rows: list[dict]) -> dict:
    """Transform raw entity-threat relationship rows into a graph structure.

    Deduplicates threats and entities into unique nodes, and produces one
    edge per distinct threat-entity relationship.

    Args:
        rows: List of dicts with keys: threat_id, threat_title, entity_type, entity_value

    Returns:
        Dict with:
          - nodes: list of {id: str, label: str, type: str}
          - edges: list of {source: str, target: str}
    """
    threat_nodes: dict[str, dict] = {}
    entity_nodes: dict[str, dict] = {}
    seen_edges: set[tuple[str, str]] = set()
    edges: list[dict] = []

    for row in rows:
        threat_id = str(row["threat_id"])
        threat_title = row["threat_title"]
        entity_type = row["entity_type"]
        entity_value = row["entity_value"]

        # Deduplicate threat nodes by threat_id
        if threat_id not in threat_nodes:
            threat_nodes[threat_id] = {
                "id": threat_id,
                "label": threat_title,
                "type": "threat",
            }

        # Deduplicate entity nodes by (entity_type, entity_value)
        entity_id = f"{entity_type}:{entity_value}"
        if entity_id not in entity_nodes:
            entity_nodes[entity_id] = {
                "id": entity_id,
                "label": entity_value,
                "type": entity_type,
            }

        # Deduplicate edges by (threat_id, entity_id)
        edge_key = (threat_id, entity_id)
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            edges.append({"source": threat_id, "target": entity_id})

    nodes = list(threat_nodes.values()) + list(entity_nodes.values())
    return {"nodes": nodes, "edges": edges}


class AnalyticsService:
    """
    Service class for computing analytics aggregations against the threat database.

    Each method builds and executes an async SQLAlchemy query, returning
    a dict with ``data`` and ``meta`` keys following the standard analytics
    response envelope.
    """

    def __init__(self, db: AsyncSession):
        """
        Initialize the analytics service.

        Args:
            db: SQLAlchemy async database session.
        """
        self.db = db

    async def _execute_with_timeout(self, query, timeout: float = 5.0):
        """Execute a SQLAlchemy query with a timeout guard.

        Wraps ``self.db.execute(query)`` with ``asyncio.wait_for`` to
        prevent long-running analytics queries from blocking the
        connection pool.

        Args:
            query: A SQLAlchemy executable statement.
            timeout: Maximum seconds to wait (default 5.0).

        Returns:
            The SQLAlchemy result proxy.

        Raises:
            AnalyticsTimeoutError: If the query exceeds the timeout.
        """
        try:
            return await asyncio.wait_for(self.db.execute(query), timeout=timeout)
        except asyncio.TimeoutError:
            raise AnalyticsTimeoutError(
                "Analytics query exceeded 5 second timeout"
            )

    async def get_trends(
        self,
        granularity: str = "month",
        group_by: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        threat_type: Optional[str] = None,
        severity_min: Optional[int] = None,
        severity_max: Optional[int] = None,
        source: Optional[str] = None,
        include_unknown: bool = True,
    ) -> dict:
        """Return time-series threat counts bucketed by granularity.

        Args:
            granularity: Time bucket size — one of 'day', 'week', or 'month'.
            group_by: Optional secondary grouping column (threat_type, severity, source).
            date_from: Include threats published on or after this datetime.
            date_to: Include threats published on or before this datetime.
            threat_type: Filter to a specific threat type string.
            severity_min: Minimum severity (inclusive, 1-10).
            severity_max: Maximum severity (inclusive, 1-10).
            source: Filter to a specific source string.

        Returns:
            Dict with ``data`` (list of TrendItem dicts) and ``meta`` keys.

        Raises:
            ValueError: If granularity or group_by is invalid.
        """
        valid_granularities = ("day", "week", "month")
        if granularity not in valid_granularities:
            raise ValueError(
                f"granularity must be one of: {', '.join(valid_granularities)}"
            )

        valid_group_by = ("threat_type", "severity", "source")
        if group_by is not None and group_by not in valid_group_by:
            raise ValueError(
                f"group_by must be one of: {', '.join(valid_group_by)}"
            )

        period = func.date_trunc(granularity, Threat.published_at).label("period")

        if group_by is not None:
            group_col = getattr(Threat, group_by)
            query = select(
                period,
                func.count().label("count"),
                group_col.label("group"),
            )
        else:
            query = select(
                period,
                func.count().label("count"),
            )

        query = build_analytics_filters(
            query,
            date_from=date_from,
            date_to=date_to,
            threat_type=threat_type,
            severity_min=severity_min,
            severity_max=severity_max,
            source=source,
            include_unknown=include_unknown,
        )

        # Only include rows that have a published_at value
        query = query.where(Threat.published_at.isnot(None))

        if group_by is not None:
            query = query.group_by(period, group_col).order_by(period)
        else:
            query = query.group_by(period).order_by(period)

        result = await self._execute_with_timeout(query)
        rows = result.all()

        filters_applied = {
            "granularity": granularity,
            "group_by": group_by,
            "date_from": date_from.isoformat() if date_from else None,
            "date_to": date_to.isoformat() if date_to else None,
            "threat_type": threat_type,
            "severity_min": severity_min,
            "severity_max": severity_max,
            "source": source,
        }

        data = []
        for row in rows:
            item = {
                "period": row.period.isoformat() if row.period else None,
                "count": row.count,
            }
            if group_by is not None:
                item["group"] = str(row.group) if row.group is not None else None
            else:
                item["group"] = None
            data.append(item)

        return {
            "data": data,
            "meta": {
                "total_records": len(data),
                "filters_applied": filters_applied,
                "computed_at": datetime.utcnow().isoformat(),
            },
        }

    async def get_distributions(
        self,
        dimension: str,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        threat_type: Optional[str] = None,
        severity_min: Optional[int] = None,
        severity_max: Optional[int] = None,
        source: Optional[str] = None,
        include_unknown: bool = True,
    ) -> dict:
        """Return threat counts grouped by the requested dimension.

        Args:
            dimension: Column to group by — one of 'threat_type', 'severity', or 'source'.
            date_from: Include threats published on or after this datetime.
            date_to: Include threats published on or before this datetime.
            threat_type: Filter to a specific threat type string.
            severity_min: Minimum severity (inclusive, 1-10).
            severity_max: Maximum severity (inclusive, 1-10).
            source: Filter to a specific source string.

        Returns:
            Dict with ``data`` (list of DistributionItem dicts) and ``meta`` keys.

        Raises:
            ValueError: If dimension is not one of the valid values.
        """
        valid_dimensions = ("threat_type", "severity", "source")
        if dimension not in valid_dimensions:
            raise ValueError(
                f"dimension must be one of: {', '.join(valid_dimensions)}"
            )

        dim_col = getattr(Threat, dimension)

        query = select(
            dim_col.label("label"),
            func.count().label("count"),
        )

        query = build_analytics_filters(
            query,
            date_from=date_from,
            date_to=date_to,
            threat_type=threat_type,
            severity_min=severity_min,
            severity_max=severity_max,
            source=source,
            include_unknown=include_unknown,
        )

        # Exclude rows where the dimension value is NULL
        query = query.where(dim_col.isnot(None))

        query = query.group_by(dim_col)

        # Severity orders ascending (1-10); others order by count descending
        if dimension == "severity":
            query = query.order_by(dim_col.asc())
        else:
            query = query.order_by(func.count().desc())

        result = await self._execute_with_timeout(query)
        rows = result.all()

        filters_applied = {
            "dimension": dimension,
            "date_from": date_from.isoformat() if date_from else None,
            "date_to": date_to.isoformat() if date_to else None,
            "threat_type": threat_type,
            "severity_min": severity_min,
            "severity_max": severity_max,
            "source": source,
        }

        data = [
            {"label": str(row.label), "count": row.count}
            for row in rows
        ]

        return {
            "data": data,
            "meta": {
                "total_records": len(data),
                "filters_applied": filters_applied,
                "computed_at": datetime.utcnow().isoformat(),
            },
        }

    async def get_mitre_heatmap(
        self,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        threat_type: Optional[str] = None,
        severity_min: Optional[int] = None,
        severity_max: Optional[int] = None,
        source: Optional[str] = None,
        include_unknown: bool = True,
    ) -> dict:
        """Return MITRE tactic×technique frequency matrix.

        Joins mitre_mappings with threats and groups by tactic, technique,
        and technique_id to produce a heatmap of MITRE ATLAS coverage.

        Args:
            date_from: Include threats published on or after this datetime.
            date_to: Include threats published on or before this datetime.
            threat_type: Filter to a specific threat type string.
            severity_min: Minimum severity (inclusive, 1-10).
            severity_max: Maximum severity (inclusive, 1-10).
            source: Filter to a specific source string.

        Returns:
            Dict with ``data`` (list of MitreHeatmapItem dicts) and ``meta`` keys.
        """
        query = (
            select(
                MitreMapping.tactic.label("tactic"),
                MitreMapping.technique.label("technique"),
                MitreMapping.technique_id.label("technique_id"),
                func.count().label("count"),
            )
            .join(Threat, MitreMapping.threat_id == Threat.id)
        )

        query = build_analytics_filters(
            query,
            date_from=date_from,
            date_to=date_to,
            threat_type=threat_type,
            severity_min=severity_min,
            severity_max=severity_max,
            source=source,
            include_unknown=include_unknown,
        )

        query = query.group_by(
            MitreMapping.tactic,
            MitreMapping.technique,
            MitreMapping.technique_id,
        )

        result = await self._execute_with_timeout(query)
        rows = result.all()

        filters_applied = {
            "date_from": date_from.isoformat() if date_from else None,
            "date_to": date_to.isoformat() if date_to else None,
            "threat_type": threat_type,
            "severity_min": severity_min,
            "severity_max": severity_max,
            "source": source,
        }

        data = [
            {
                "tactic": row.tactic,
                "technique": row.technique,
                "technique_id": row.technique_id,
                "count": row.count,
            }
            for row in rows
        ]

        return {
            "data": data,
            "meta": {
                "total_records": len(data),
                "filters_applied": filters_applied,
                "computed_at": datetime.utcnow().isoformat(),
            },
        }

    async def get_entity_clusters(
        self,
        entity_type: Optional[str] = None,
        min_shared: int = 2,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        threat_type: Optional[str] = None,
        severity_min: Optional[int] = None,
        severity_max: Optional[int] = None,
        source: Optional[str] = None,
        include_unknown: bool = True,
    ) -> dict:
        """Return groups of threats sharing common entities.

        Joins entities with threats and groups by entity_value and entity_type,
        returning only clusters where the distinct threat count meets the
        min_shared threshold.

        Args:
            entity_type: Optional filter to a specific entity type
                (cve, framework, technique, system).
            min_shared: Minimum number of distinct threats sharing an entity
                for it to appear as a cluster (default 2).
            date_from: Include threats published on or after this datetime.
            date_to: Include threats published on or before this datetime.
            threat_type: Filter to a specific threat type string.
            severity_min: Minimum severity (inclusive, 1-10).
            severity_max: Maximum severity (inclusive, 1-10).
            source: Filter to a specific source string.

        Returns:
            Dict with ``data`` (list of EntityClusterItem dicts) and ``meta`` keys.
        """
        threat_count_col = func.count(func.distinct(Entity.threat_id)).label(
            "threat_count"
        )
        threat_ids_col = func.array_agg(
            func.distinct(cast(Entity.threat_id, String))
        ).label("threat_ids")

        query = (
            select(
                Entity.entity_value.label("entity_value"),
                Entity.entity_type.label("entity_type"),
                threat_count_col,
                threat_ids_col,
            )
            .join(Threat, Entity.threat_id == Threat.id)
        )

        query = build_analytics_filters(
            query,
            date_from=date_from,
            date_to=date_to,
            threat_type=threat_type,
            severity_min=severity_min,
            severity_max=severity_max,
            source=source,
            include_unknown=include_unknown,
        )

        if entity_type is not None:
            query = query.where(Entity.entity_type == entity_type)

        query = (
            query.group_by(Entity.entity_value, Entity.entity_type)
            .having(func.count(func.distinct(Entity.threat_id)) >= min_shared)
            .order_by(threat_count_col.desc())
        )

        result = await self._execute_with_timeout(query)
        rows = result.all()

        filters_applied = {
            "entity_type": entity_type,
            "min_shared": min_shared,
            "date_from": date_from.isoformat() if date_from else None,
            "date_to": date_to.isoformat() if date_to else None,
            "threat_type": threat_type,
            "severity_min": severity_min,
            "severity_max": severity_max,
            "source": source,
        }

        data = [
            {
                "entity_value": row.entity_value,
                "entity_type": row.entity_type,
                "threat_count": row.threat_count,
                "threat_ids": list(row.threat_ids) if row.threat_ids else [],
            }
            for row in rows
        ]

        return {
            "data": data,
            "meta": {
                "total_records": len(data),
                "filters_applied": filters_applied,
                "computed_at": datetime.utcnow().isoformat(),
            },
        }

    async def get_entity_graph(
        self,
        entity_type: Optional[str] = None,
        min_shared: int = 2,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        threat_type: Optional[str] = None,
        severity_min: Optional[int] = None,
        severity_max: Optional[int] = None,
        source: Optional[str] = None,
        include_unknown: bool = False,
    ) -> dict:
        """Return entity-threat relationships as a graph of nodes and edges.

        Joins entities with threats, filters to entities shared across at
        least ``min_shared`` distinct threats, then passes the raw rows
        through :func:`build_graph_data` to produce a deduplicated
        node/edge structure.

        Args:
            entity_type: Optional filter to a specific entity type
                (cve, framework, technique, system).
            min_shared: Minimum number of distinct threats sharing an entity
                for it to be included (default 2).
            date_from: Include threats published on or after this datetime.
            date_to: Include threats published on or before this datetime.
            threat_type: Filter to a specific threat type string.
            severity_min: Minimum severity (inclusive, 1-10).
            severity_max: Maximum severity (inclusive, 1-10).
            source: Filter to a specific source string.

        Returns:
            Dict with ``data`` (graph nodes/edges) and ``meta`` keys.
        """
        # Subquery: entity_values shared by >= min_shared distinct threats
        shared_subquery = (
            select(Entity.entity_value)
            .group_by(Entity.entity_value, Entity.entity_type)
            .having(func.count(func.distinct(Entity.threat_id)) >= min_shared)
            .scalar_subquery()
        )

        query = (
            select(
                Threat.id.label("threat_id"),
                Threat.title.label("threat_title"),
                Entity.entity_type.label("entity_type"),
                Entity.entity_value.label("entity_value"),
            )
            .join(Threat, Entity.threat_id == Threat.id)
        )

        query = build_analytics_filters(
            query,
            date_from=date_from,
            date_to=date_to,
            threat_type=threat_type,
            severity_min=severity_min,
            severity_max=severity_max,
            source=source,
            include_unknown=include_unknown,
        )

        if entity_type is not None:
            query = query.where(Entity.entity_type == entity_type)

        if not include_unknown:
            query = query.where(
                Entity.entity_type.isnot(None),
                Entity.entity_type != "",
                Entity.entity_value.isnot(None),
                Entity.entity_value != "",
            )

        query = query.where(Entity.entity_value.in_(shared_subquery))

        result = await self._execute_with_timeout(query)
        rows = result.all()

        raw_rows = [
            {
                "threat_id": row.threat_id,
                "threat_title": row.threat_title,
                "entity_type": row.entity_type,
                "entity_value": row.entity_value,
            }
            for row in rows
        ]

        graph = build_graph_data(raw_rows)

        filters_applied = {
            "entity_type": entity_type,
            "min_shared": min_shared,
            "include_unknown": include_unknown,
            "date_from": date_from.isoformat() if date_from else None,
            "date_to": date_to.isoformat() if date_to else None,
            "threat_type": threat_type,
            "severity_min": severity_min,
            "severity_max": severity_max,
            "source": source,
        }

        return {
            "data": graph,
            "meta": {
                "total_nodes": len(graph["nodes"]),
                "total_edges": len(graph["edges"]),
                "filters_applied": filters_applied,
                "computed_at": datetime.utcnow().isoformat(),
            },
        }

    async def get_severity_matrix(
        self,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        threat_type: Optional[str] = None,
        severity_min: Optional[int] = None,
        severity_max: Optional[int] = None,
        source: Optional[str] = None,
        include_unknown: bool = True,
    ) -> dict:
        """Return severity × threat_type cross-tabulation counts.

        Groups threats by severity level and threat_type, returning the count
        at each intersection. Rows where severity or threat_type is NULL are
        excluded.

        Args:
            date_from: Include threats published on or after this datetime.
            date_to: Include threats published on or before this datetime.
            threat_type: Filter to a specific threat type string.
            severity_min: Minimum severity (inclusive, 1-10).
            severity_max: Maximum severity (inclusive, 1-10).
            source: Filter to a specific source string.

        Returns:
            Dict with ``data`` (list of SeverityMatrixItem dicts) and ``meta`` keys.
        """
        query = select(
            Threat.severity.label("severity"),
            Threat.threat_type.label("threat_type"),
            func.count().label("count"),
        )

        query = build_analytics_filters(
            query,
            date_from=date_from,
            date_to=date_to,
            threat_type=threat_type,
            severity_min=severity_min,
            severity_max=severity_max,
            source=source,
            include_unknown=include_unknown,
        )

        # Exclude rows where severity or threat_type is NULL
        query = query.where(Threat.severity.isnot(None))
        query = query.where(Threat.threat_type.isnot(None))

        query = query.group_by(Threat.severity, Threat.threat_type)

        result = await self._execute_with_timeout(query)
        rows = result.all()

        filters_applied = {
            "date_from": date_from.isoformat() if date_from else None,
            "date_to": date_to.isoformat() if date_to else None,
            "threat_type": threat_type,
            "severity_min": severity_min,
            "severity_max": severity_max,
            "source": source,
        }

        data = [
            {
                "severity": row.severity,
                "threat_type": row.threat_type,
                "count": row.count,
            }
            for row in rows
        ]

        return {
            "data": data,
            "meta": {
                "total_records": len(data),
                "filters_applied": filters_applied,
                "computed_at": datetime.utcnow().isoformat(),
            },
        }
