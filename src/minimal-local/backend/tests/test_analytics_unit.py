"""
Unit Tests: build_analytics_filters(), entity clusters, and cross-cutting concerns.

**Validates: Requirements 3.5, 4.5, 4.6, 6.3, 10.2**

Covers:
1. build_analytics_filters() — all filter combinations
2. Entity clusters — get_entity_clusters() method
3. Cross-cutting: default values, empty DB envelope across all methods
4. Gaps not covered by per-method test files
"""

import pytest
import uuid
import hashlib
from datetime import datetime, timezone

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from models.threat import Threat
from models.entity import Entity
from services.analytics import AnalyticsService, build_analytics_filters


def _make_threat(
    title: str = "Test Threat",
    source: str = "test-source",
    published_at: datetime | None = None,
    threat_type: str | None = "adversarial",
    severity: int | None = 5,
) -> Threat:
    """Helper to create a Threat instance with required fields."""
    content = f"{title}-{uuid.uuid4()}"
    return Threat(
        id=uuid.uuid4(),
        title=title,
        source=source,
        published_at=published_at,
        threat_type=threat_type,
        severity=severity,
        content_hash=hashlib.sha256(content.encode()).hexdigest(),
    )


def _make_entity(
    threat_id: uuid.UUID,
    entity_type: str = "cve",
    entity_value: str = "CVE-2024-0001",
) -> Entity:
    """Helper to create an Entity instance."""
    return Entity(
        id=uuid.uuid4(),
        threat_id=threat_id,
        entity_type=entity_type,
        entity_value=entity_value,
    )


# ---------------------------------------------------------------------------
# 1. build_analytics_filters() tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestBuildAnalyticsFilters:
    """Tests for the build_analytics_filters() helper function."""

    async def test_no_filters_returns_all(self, db_session: AsyncSession):
        """With no filter params, all threats should be returned."""
        t1 = _make_threat(severity=3, source="nist")
        t2 = _make_threat(severity=8, source="arxiv")
        db_session.add_all([t1, t2])
        await db_session.flush()

        query = select(func.count()).select_from(Threat)
        query = build_analytics_filters(query)
        result = await db_session.execute(query)
        assert result.scalar() == 2

    async def test_date_from_filter(self, db_session: AsyncSession):
        """date_from should exclude threats published before the given date."""
        t1 = _make_threat(published_at=datetime(2024, 1, 1, tzinfo=timezone.utc))
        t2 = _make_threat(published_at=datetime(2024, 6, 1, tzinfo=timezone.utc))
        db_session.add_all([t1, t2])
        await db_session.flush()

        query = select(func.count()).select_from(Threat)
        query = build_analytics_filters(query, date_from=datetime(2024, 3, 1, tzinfo=timezone.utc))
        result = await db_session.execute(query)
        assert result.scalar() == 1

    async def test_date_to_filter(self, db_session: AsyncSession):
        """date_to should exclude threats published after the given date."""
        t1 = _make_threat(published_at=datetime(2024, 1, 1, tzinfo=timezone.utc))
        t2 = _make_threat(published_at=datetime(2024, 6, 1, tzinfo=timezone.utc))
        db_session.add_all([t1, t2])
        await db_session.flush()

        query = select(func.count()).select_from(Threat)
        query = build_analytics_filters(query, date_to=datetime(2024, 3, 1, tzinfo=timezone.utc))
        result = await db_session.execute(query)
        assert result.scalar() == 1

    async def test_date_range_filter(self, db_session: AsyncSession):
        """date_from + date_to should include only threats in range."""
        t1 = _make_threat(published_at=datetime(2024, 1, 1, tzinfo=timezone.utc))
        t2 = _make_threat(published_at=datetime(2024, 5, 1, tzinfo=timezone.utc))
        t3 = _make_threat(published_at=datetime(2024, 9, 1, tzinfo=timezone.utc))
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        query = select(func.count()).select_from(Threat)
        query = build_analytics_filters(
            query,
            date_from=datetime(2024, 3, 1, tzinfo=timezone.utc),
            date_to=datetime(2024, 7, 1, tzinfo=timezone.utc),
        )
        result = await db_session.execute(query)
        assert result.scalar() == 1

    async def test_threat_type_filter(self, db_session: AsyncSession):
        """threat_type should include only matching threats."""
        t1 = _make_threat(threat_type="adversarial")
        t2 = _make_threat(threat_type="poisoning")
        db_session.add_all([t1, t2])
        await db_session.flush()

        query = select(func.count()).select_from(Threat)
        query = build_analytics_filters(query, threat_type="adversarial")
        result = await db_session.execute(query)
        assert result.scalar() == 1

    async def test_severity_min_filter(self, db_session: AsyncSession):
        """severity_min should exclude threats below the threshold."""
        t1 = _make_threat(severity=2)
        t2 = _make_threat(severity=7)
        db_session.add_all([t1, t2])
        await db_session.flush()

        query = select(func.count()).select_from(Threat)
        query = build_analytics_filters(query, severity_min=5)
        result = await db_session.execute(query)
        assert result.scalar() == 1

    async def test_severity_max_filter(self, db_session: AsyncSession):
        """severity_max should exclude threats above the threshold."""
        t1 = _make_threat(severity=2)
        t2 = _make_threat(severity=7)
        db_session.add_all([t1, t2])
        await db_session.flush()

        query = select(func.count()).select_from(Threat)
        query = build_analytics_filters(query, severity_max=5)
        result = await db_session.execute(query)
        assert result.scalar() == 1

    async def test_severity_range_filter(self, db_session: AsyncSession):
        """severity_min + severity_max should include only threats in range."""
        t1 = _make_threat(severity=2)
        t2 = _make_threat(severity=5)
        t3 = _make_threat(severity=9)
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        query = select(func.count()).select_from(Threat)
        query = build_analytics_filters(query, severity_min=4, severity_max=6)
        result = await db_session.execute(query)
        assert result.scalar() == 1

    async def test_source_filter(self, db_session: AsyncSession):
        """source should include only matching threats."""
        t1 = _make_threat(source="nist")
        t2 = _make_threat(source="arxiv")
        db_session.add_all([t1, t2])
        await db_session.flush()

        query = select(func.count()).select_from(Threat)
        query = build_analytics_filters(query, source="nist")
        result = await db_session.execute(query)
        assert result.scalar() == 1

    async def test_all_filters_combined(self, db_session: AsyncSession):
        """All filters applied together should narrow results correctly."""
        # This threat matches all filters
        t_match = _make_threat(
            published_at=datetime(2024, 5, 1, tzinfo=timezone.utc),
            threat_type="adversarial",
            severity=5,
            source="nist",
        )
        # These don't match various filters
        t_wrong_date = _make_threat(
            published_at=datetime(2023, 1, 1, tzinfo=timezone.utc),
            threat_type="adversarial", severity=5, source="nist",
        )
        t_wrong_type = _make_threat(
            published_at=datetime(2024, 5, 1, tzinfo=timezone.utc),
            threat_type="poisoning", severity=5, source="nist",
        )
        t_wrong_sev = _make_threat(
            published_at=datetime(2024, 5, 1, tzinfo=timezone.utc),
            threat_type="adversarial", severity=1, source="nist",
        )
        t_wrong_src = _make_threat(
            published_at=datetime(2024, 5, 1, tzinfo=timezone.utc),
            threat_type="adversarial", severity=5, source="arxiv",
        )
        db_session.add_all([t_match, t_wrong_date, t_wrong_type, t_wrong_sev, t_wrong_src])
        await db_session.flush()

        query = select(func.count()).select_from(Threat)
        query = build_analytics_filters(
            query,
            date_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
            date_to=datetime(2024, 12, 31, tzinfo=timezone.utc),
            threat_type="adversarial",
            severity_min=3,
            severity_max=7,
            source="nist",
        )
        result = await db_session.execute(query)
        assert result.scalar() == 1

    async def test_none_filters_are_ignored(self, db_session: AsyncSession):
        """Explicitly passing None for filters should be same as omitting them."""
        t1 = _make_threat()
        db_session.add(t1)
        await db_session.flush()

        query = select(func.count()).select_from(Threat)
        query = build_analytics_filters(
            query,
            date_from=None,
            date_to=None,
            threat_type=None,
            severity_min=None,
            severity_max=None,
            source=None,
        )
        result = await db_session.execute(query)
        assert result.scalar() == 1


# ---------------------------------------------------------------------------
# 2. Entity clusters tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetEntityClustersEnvelope:
    """Tests for entity clusters response envelope."""

    async def test_empty_database_returns_correct_envelope(self, db_session: AsyncSession):
        """Empty database should return empty data with correct meta."""
        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters()

        assert isinstance(result["data"], list)
        assert len(result["data"]) == 0
        assert result["meta"]["total_records"] == 0
        assert "filters_applied" in result["meta"]
        assert "computed_at" in result["meta"]

    async def test_meta_filters_applied_reflects_params(self, db_session: AsyncSession):
        """Meta filters_applied should reflect the parameters passed."""
        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters(
            entity_type="cve",
            min_shared=3,
            threat_type="adversarial",
            severity_min=2,
            severity_max=9,
            source="nist",
        )
        fa = result["meta"]["filters_applied"]
        assert fa["entity_type"] == "cve"
        assert fa["min_shared"] == 3
        assert fa["threat_type"] == "adversarial"
        assert fa["severity_min"] == 2
        assert fa["severity_max"] == 9
        assert fa["source"] == "nist"

    async def test_computed_at_is_iso8601(self, db_session: AsyncSession):
        """computed_at should be a valid ISO 8601 string."""
        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters()
        datetime.fromisoformat(result["meta"]["computed_at"])


@pytest.mark.asyncio
class TestGetEntityClustersDefaultMinShared:
    """Tests for the default min_shared=2 parameter."""

    async def test_default_min_shared_is_two(self, db_session: AsyncSession):
        """Default min_shared should be 2, excluding entities shared by only 1 threat."""
        t1 = _make_threat()
        t2 = _make_threat()
        db_session.add_all([t1, t2])
        await db_session.flush()

        # CVE-SHARED appears in both threats (should be included)
        db_session.add(_make_entity(t1.id, entity_value="CVE-SHARED"))
        db_session.add(_make_entity(t2.id, entity_value="CVE-SHARED"))
        # CVE-SINGLE appears in only one threat (should be excluded)
        db_session.add(_make_entity(t1.id, entity_value="CVE-SINGLE"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters()  # default min_shared=2

        assert len(result["data"]) == 1
        assert result["data"][0]["entity_value"] == "CVE-SHARED"
        assert result["data"][0]["threat_count"] == 2

    async def test_min_shared_filters_applied_shows_default(self, db_session: AsyncSession):
        """filters_applied should show min_shared=2 when using default."""
        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters()
        assert result["meta"]["filters_applied"]["min_shared"] == 2


@pytest.mark.asyncio
class TestGetEntityClustersAggregation:
    """Tests for entity cluster aggregation logic."""

    async def test_cluster_with_exact_min_shared(self, db_session: AsyncSession):
        """Entity shared by exactly min_shared threats should be included."""
        t1 = _make_threat()
        t2 = _make_threat()
        t3 = _make_threat()
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        db_session.add(_make_entity(t1.id, entity_value="CVE-2024-0001"))
        db_session.add(_make_entity(t2.id, entity_value="CVE-2024-0001"))
        db_session.add(_make_entity(t3.id, entity_value="CVE-2024-0001"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters(min_shared=3)

        assert len(result["data"]) == 1
        assert result["data"][0]["threat_count"] == 3

    async def test_cluster_below_min_shared_excluded(self, db_session: AsyncSession):
        """Entity shared by fewer than min_shared threats should be excluded."""
        t1 = _make_threat()
        t2 = _make_threat()
        db_session.add_all([t1, t2])
        await db_session.flush()

        db_session.add(_make_entity(t1.id, entity_value="CVE-2024-0001"))
        db_session.add(_make_entity(t2.id, entity_value="CVE-2024-0001"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters(min_shared=3)

        assert len(result["data"]) == 0

    async def test_threat_ids_are_correct(self, db_session: AsyncSession):
        """threat_ids should contain the IDs of threats sharing the entity."""
        t1 = _make_threat()
        t2 = _make_threat()
        db_session.add_all([t1, t2])
        await db_session.flush()

        db_session.add(_make_entity(t1.id, entity_value="CVE-2024-0001"))
        db_session.add(_make_entity(t2.id, entity_value="CVE-2024-0001"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters(min_shared=2)

        cluster = result["data"][0]
        expected_ids = {str(t1.id), str(t2.id)}
        assert set(cluster["threat_ids"]) == expected_ids

    async def test_multiple_clusters_ordered_by_count_desc(self, db_session: AsyncSession):
        """Clusters should be ordered by threat_count descending."""
        threats = [_make_threat() for _ in range(4)]
        db_session.add_all(threats)
        await db_session.flush()

        # CVE-BIG shared by 3 threats
        for t in threats[:3]:
            db_session.add(_make_entity(t.id, entity_value="CVE-BIG"))
        # CVE-SMALL shared by 2 threats
        for t in threats[:2]:
            db_session.add(_make_entity(t.id, entity_value="CVE-SMALL"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters(min_shared=2)

        assert len(result["data"]) == 2
        assert result["data"][0]["entity_value"] == "CVE-BIG"
        assert result["data"][0]["threat_count"] == 3
        assert result["data"][1]["entity_value"] == "CVE-SMALL"
        assert result["data"][1]["threat_count"] == 2

    async def test_data_items_have_required_fields(self, db_session: AsyncSession):
        """Each item should have entity_value, entity_type, threat_count, threat_ids."""
        t1 = _make_threat()
        t2 = _make_threat()
        db_session.add_all([t1, t2])
        await db_session.flush()

        db_session.add(_make_entity(t1.id, entity_value="CVE-2024-0001", entity_type="cve"))
        db_session.add(_make_entity(t2.id, entity_value="CVE-2024-0001", entity_type="cve"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters(min_shared=2)

        for item in result["data"]:
            assert "entity_value" in item
            assert "entity_type" in item
            assert "threat_count" in item
            assert "threat_ids" in item
            assert isinstance(item["threat_ids"], list)
            assert isinstance(item["threat_count"], int)

    async def test_distinct_threat_count(self, db_session: AsyncSession):
        """Multiple entities from same threat should count as one distinct threat."""
        t1 = _make_threat()
        t2 = _make_threat()
        db_session.add_all([t1, t2])
        await db_session.flush()

        # t1 has two entities with same value (e.g. extracted twice)
        db_session.add(_make_entity(t1.id, entity_value="CVE-2024-DUP", entity_type="cve"))
        db_session.add(_make_entity(t1.id, entity_value="CVE-2024-DUP", entity_type="cve"))
        db_session.add(_make_entity(t2.id, entity_value="CVE-2024-DUP", entity_type="cve"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters(min_shared=2)

        assert len(result["data"]) == 1
        assert result["data"][0]["threat_count"] == 2  # distinct threats, not entity rows


@pytest.mark.asyncio
class TestGetEntityClustersEntityTypeFilter:
    """Tests for entity_type filter on entity clusters."""

    async def test_entity_type_filter_returns_only_matching(self, db_session: AsyncSession):
        """entity_type filter should return only clusters of that type."""
        t1 = _make_threat()
        t2 = _make_threat()
        db_session.add_all([t1, t2])
        await db_session.flush()

        db_session.add(_make_entity(t1.id, entity_value="CVE-2024-0001", entity_type="cve"))
        db_session.add(_make_entity(t2.id, entity_value="CVE-2024-0001", entity_type="cve"))
        db_session.add(_make_entity(t1.id, entity_value="PyTorch", entity_type="framework"))
        db_session.add(_make_entity(t2.id, entity_value="PyTorch", entity_type="framework"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters(entity_type="cve", min_shared=2)

        assert len(result["data"]) == 1
        assert result["data"][0]["entity_type"] == "cve"

    async def test_no_entity_type_filter_returns_all_types(self, db_session: AsyncSession):
        """Without entity_type filter, clusters of all types should appear."""
        t1 = _make_threat()
        t2 = _make_threat()
        db_session.add_all([t1, t2])
        await db_session.flush()

        db_session.add(_make_entity(t1.id, entity_value="CVE-2024-0001", entity_type="cve"))
        db_session.add(_make_entity(t2.id, entity_value="CVE-2024-0001", entity_type="cve"))
        db_session.add(_make_entity(t1.id, entity_value="PyTorch", entity_type="framework"))
        db_session.add(_make_entity(t2.id, entity_value="PyTorch", entity_type="framework"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters(min_shared=2)

        types = {d["entity_type"] for d in result["data"]}
        assert "cve" in types
        assert "framework" in types


@pytest.mark.asyncio
class TestGetEntityClustersFilters:
    """Tests for common filter application on entity clusters."""

    async def test_threat_type_filter(self, db_session: AsyncSession):
        """threat_type filter should only include entities from matching threats."""
        t1 = _make_threat(threat_type="adversarial")
        t2 = _make_threat(threat_type="adversarial")
        t3 = _make_threat(threat_type="poisoning")
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        # CVE shared by t1 and t2 (adversarial) — should appear
        db_session.add(_make_entity(t1.id, entity_value="CVE-ADV"))
        db_session.add(_make_entity(t2.id, entity_value="CVE-ADV"))
        # CVE shared by t1 and t3 (mixed types) — only t1 matches filter
        db_session.add(_make_entity(t1.id, entity_value="CVE-MIX"))
        db_session.add(_make_entity(t3.id, entity_value="CVE-MIX"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters(threat_type="adversarial", min_shared=2)

        # Only CVE-ADV should appear (2 adversarial threats)
        # CVE-MIX only has 1 adversarial threat, below min_shared=2
        assert len(result["data"]) == 1
        assert result["data"][0]["entity_value"] == "CVE-ADV"

    async def test_date_range_filter(self, db_session: AsyncSession):
        """date_from/date_to should filter entity clusters by threat published_at."""
        t1 = _make_threat(published_at=datetime(2024, 6, 1, tzinfo=timezone.utc))
        t2 = _make_threat(published_at=datetime(2024, 7, 1, tzinfo=timezone.utc))
        t3 = _make_threat(published_at=datetime(2023, 1, 1, tzinfo=timezone.utc))
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        db_session.add(_make_entity(t1.id, entity_value="CVE-RECENT"))
        db_session.add(_make_entity(t2.id, entity_value="CVE-RECENT"))
        db_session.add(_make_entity(t3.id, entity_value="CVE-RECENT"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters(
            date_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
            min_shared=2,
        )

        assert len(result["data"]) == 1
        # Only t1 and t2 match the date filter
        assert result["data"][0]["threat_count"] == 2


# ---------------------------------------------------------------------------
# 3. Cross-cutting: empty DB envelope and default values across all methods
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestEmptyDatabaseAllMethods:
    """Verify every service method returns correct envelope on empty DB."""

    async def test_trends_empty(self, db_session: AsyncSession):
        svc = AnalyticsService(db_session)
        result = await svc.get_trends()
        assert result["data"] == []
        assert result["meta"]["total_records"] == 0
        assert "filters_applied" in result["meta"]
        assert "computed_at" in result["meta"]

    async def test_distributions_empty(self, db_session: AsyncSession):
        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="threat_type")
        assert result["data"] == []
        assert result["meta"]["total_records"] == 0

    async def test_mitre_heatmap_empty(self, db_session: AsyncSession):
        svc = AnalyticsService(db_session)
        result = await svc.get_mitre_heatmap()
        assert result["data"] == []
        assert result["meta"]["total_records"] == 0

    async def test_entity_clusters_empty(self, db_session: AsyncSession):
        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters()
        assert result["data"] == []
        assert result["meta"]["total_records"] == 0

    async def test_severity_matrix_empty(self, db_session: AsyncSession):
        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix()
        assert result["data"] == []
        assert result["meta"]["total_records"] == 0


@pytest.mark.asyncio
class TestDefaultValues:
    """Verify default parameter values across methods."""

    async def test_trends_default_granularity_is_month(self, db_session: AsyncSession):
        """get_trends() should default to monthly granularity."""
        svc = AnalyticsService(db_session)
        result = await svc.get_trends()
        assert result["meta"]["filters_applied"]["granularity"] == "month"

    async def test_trends_default_group_by_is_none(self, db_session: AsyncSession):
        """get_trends() should default group_by to None."""
        svc = AnalyticsService(db_session)
        result = await svc.get_trends()
        assert result["meta"]["filters_applied"]["group_by"] is None

    async def test_entity_clusters_default_min_shared_is_two(self, db_session: AsyncSession):
        """get_entity_clusters() should default min_shared to 2."""
        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters()
        assert result["meta"]["filters_applied"]["min_shared"] == 2

    async def test_entity_clusters_default_entity_type_is_none(self, db_session: AsyncSession):
        """get_entity_clusters() should default entity_type to None."""
        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters()
        assert result["meta"]["filters_applied"]["entity_type"] is None


@pytest.mark.asyncio
class TestResponseEnvelopeStructure:
    """Verify response envelope structure across all methods (Req 10.2)."""

    async def test_trends_envelope_keys(self, db_session: AsyncSession):
        svc = AnalyticsService(db_session)
        result = await svc.get_trends()
        assert "data" in result
        assert "meta" in result
        assert "total_records" in result["meta"]
        assert "filters_applied" in result["meta"]
        assert "computed_at" in result["meta"]

    async def test_distributions_envelope_keys(self, db_session: AsyncSession):
        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="severity")
        assert "data" in result
        assert "meta" in result
        assert "total_records" in result["meta"]
        assert "filters_applied" in result["meta"]
        assert "computed_at" in result["meta"]

    async def test_mitre_heatmap_envelope_keys(self, db_session: AsyncSession):
        svc = AnalyticsService(db_session)
        result = await svc.get_mitre_heatmap()
        assert "data" in result
        assert "meta" in result
        assert "total_records" in result["meta"]
        assert "filters_applied" in result["meta"]
        assert "computed_at" in result["meta"]

    async def test_entity_clusters_envelope_keys(self, db_session: AsyncSession):
        svc = AnalyticsService(db_session)
        result = await svc.get_entity_clusters()
        assert "data" in result
        assert "meta" in result
        assert "total_records" in result["meta"]
        assert "filters_applied" in result["meta"]
        assert "computed_at" in result["meta"]

    async def test_severity_matrix_envelope_keys(self, db_session: AsyncSession):
        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix()
        assert "data" in result
        assert "meta" in result
        assert "total_records" in result["meta"]
        assert "filters_applied" in result["meta"]
        assert "computed_at" in result["meta"]

    async def test_total_records_matches_data_length_all_methods(self, db_session: AsyncSession):
        """total_records should equal len(data) for all methods on empty DB."""
        svc = AnalyticsService(db_session)
        for method_name, kwargs in [
            ("get_trends", {}),
            ("get_distributions", {"dimension": "threat_type"}),
            ("get_mitre_heatmap", {}),
            ("get_entity_clusters", {}),
            ("get_severity_matrix", {}),
        ]:
            result = await getattr(svc, method_name)(**kwargs)
            assert result["meta"]["total_records"] == len(result["data"]), (
                f"{method_name}: total_records mismatch"
            )
