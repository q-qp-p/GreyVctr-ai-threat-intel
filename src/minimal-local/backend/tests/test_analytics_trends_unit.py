"""
Unit Tests: AnalyticsService.get_trends()

**Validates: Requirements 3.1, 3.2, 3.3, 3.5**

Tests for the get_trends() method including:
- Time bucketing with day/week/month granularity
- Optional group_by (threat_type, severity, source)
- Granularity validation
- Response envelope structure
- Default monthly granularity
- Empty database returns empty data with correct envelope
- Filter application
"""

import pytest
import uuid
import hashlib
from datetime import datetime, timezone, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from models.threat import Threat
from services.analytics import AnalyticsService


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


@pytest.mark.asyncio
class TestGetTrendsValidation:
    """Tests for parameter validation in get_trends()."""

    async def test_invalid_granularity_raises_value_error(self, db_session: AsyncSession):
        """Invalid granularity should raise ValueError."""
        svc = AnalyticsService(db_session)
        with pytest.raises(ValueError, match="granularity must be one of"):
            await svc.get_trends(granularity="year")

    async def test_invalid_group_by_raises_value_error(self, db_session: AsyncSession):
        """Invalid group_by should raise ValueError."""
        svc = AnalyticsService(db_session)
        with pytest.raises(ValueError, match="group_by must be one of"):
            await svc.get_trends(group_by="invalid_column")

    async def test_valid_granularities_accepted(self, db_session: AsyncSession):
        """All valid granularities (day, week, month) should be accepted."""
        svc = AnalyticsService(db_session)
        for g in ("day", "week", "month"):
            result = await svc.get_trends(granularity=g)
            assert "data" in result
            assert "meta" in result


@pytest.mark.asyncio
class TestGetTrendsEnvelope:
    """Tests for the response envelope structure."""

    async def test_empty_database_returns_correct_envelope(self, db_session: AsyncSession):
        """Empty database should return empty data with correct meta."""
        svc = AnalyticsService(db_session)
        result = await svc.get_trends()

        assert isinstance(result["data"], list)
        assert len(result["data"]) == 0
        assert result["meta"]["total_records"] == 0
        assert "filters_applied" in result["meta"]
        assert "computed_at" in result["meta"]

    async def test_meta_filters_applied_reflects_params(self, db_session: AsyncSession):
        """Meta filters_applied should reflect the parameters passed."""
        svc = AnalyticsService(db_session)
        result = await svc.get_trends(
            granularity="week",
            threat_type="adversarial",
            severity_min=3,
            severity_max=8,
            source="nist",
        )
        fa = result["meta"]["filters_applied"]
        assert fa["granularity"] == "week"
        assert fa["threat_type"] == "adversarial"
        assert fa["severity_min"] == 3
        assert fa["severity_max"] == 8
        assert fa["source"] == "nist"

    async def test_default_granularity_is_month(self, db_session: AsyncSession):
        """Default granularity should be 'month'."""
        svc = AnalyticsService(db_session)
        result = await svc.get_trends()
        assert result["meta"]["filters_applied"]["granularity"] == "month"

    async def test_computed_at_is_iso8601(self, db_session: AsyncSession):
        """computed_at should be a valid ISO 8601 string."""
        svc = AnalyticsService(db_session)
        result = await svc.get_trends()
        # Should not raise
        datetime.fromisoformat(result["meta"]["computed_at"])


@pytest.mark.asyncio
class TestGetTrendsAggregation:
    """Tests for actual data aggregation."""

    async def test_single_month_bucket(self, db_session: AsyncSession):
        """Threats in the same month should be grouped into one bucket."""
        t1 = _make_threat(published_at=datetime(2024, 3, 10, tzinfo=timezone.utc))
        t2 = _make_threat(published_at=datetime(2024, 3, 20, tzinfo=timezone.utc))
        db_session.add_all([t1, t2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_trends(granularity="month")

        # Find the March 2024 bucket
        march_items = [d for d in result["data"] if d["period"] and "2024-03" in d["period"]]
        assert len(march_items) == 1
        assert march_items[0]["count"] == 2

    async def test_multiple_month_buckets(self, db_session: AsyncSession):
        """Threats in different months should produce separate buckets."""
        t1 = _make_threat(published_at=datetime(2024, 1, 15, tzinfo=timezone.utc))
        t2 = _make_threat(published_at=datetime(2024, 2, 15, tzinfo=timezone.utc))
        t3 = _make_threat(published_at=datetime(2024, 2, 20, tzinfo=timezone.utc))
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_trends(granularity="month")

        jan_items = [d for d in result["data"] if d["period"] and "2024-01" in d["period"]]
        feb_items = [d for d in result["data"] if d["period"] and "2024-02" in d["period"]]
        assert len(jan_items) == 1
        assert jan_items[0]["count"] == 1
        assert len(feb_items) == 1
        assert feb_items[0]["count"] == 2

    async def test_day_granularity(self, db_session: AsyncSession):
        """Day granularity should bucket by individual days."""
        t1 = _make_threat(published_at=datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc))
        t2 = _make_threat(published_at=datetime(2024, 6, 1, 14, 0, tzinfo=timezone.utc))
        t3 = _make_threat(published_at=datetime(2024, 6, 2, 10, 0, tzinfo=timezone.utc))
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_trends(granularity="day")

        day1_items = [d for d in result["data"] if d["period"] and "2024-06-01" in d["period"]]
        day2_items = [d for d in result["data"] if d["period"] and "2024-06-02" in d["period"]]
        assert len(day1_items) == 1
        assert day1_items[0]["count"] == 2
        assert len(day2_items) == 1
        assert day2_items[0]["count"] == 1

    async def test_periods_ordered_ascending(self, db_session: AsyncSession):
        """Result periods should be ordered ascending."""
        t1 = _make_threat(published_at=datetime(2024, 5, 1, tzinfo=timezone.utc))
        t2 = _make_threat(published_at=datetime(2024, 1, 1, tzinfo=timezone.utc))
        t3 = _make_threat(published_at=datetime(2024, 3, 1, tzinfo=timezone.utc))
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_trends(granularity="month")

        periods = [d["period"] for d in result["data"] if d["period"]]
        assert periods == sorted(periods)


@pytest.mark.asyncio
class TestGetTrendsGroupBy:
    """Tests for group_by functionality."""

    async def test_group_by_threat_type(self, db_session: AsyncSession):
        """group_by=threat_type should produce separate entries per type."""
        t1 = _make_threat(
            published_at=datetime(2024, 4, 10, tzinfo=timezone.utc),
            threat_type="adversarial",
        )
        t2 = _make_threat(
            published_at=datetime(2024, 4, 15, tzinfo=timezone.utc),
            threat_type="poisoning",
        )
        t3 = _make_threat(
            published_at=datetime(2024, 4, 20, tzinfo=timezone.utc),
            threat_type="adversarial",
        )
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_trends(granularity="month", group_by="threat_type")

        april_items = [d for d in result["data"] if d["period"] and "2024-04" in d["period"]]
        groups = {d["group"]: d["count"] for d in april_items}
        assert groups.get("adversarial") == 2
        assert groups.get("poisoning") == 1

    async def test_group_by_source(self, db_session: AsyncSession):
        """group_by=source should produce separate entries per source."""
        t1 = _make_threat(
            published_at=datetime(2024, 7, 5, tzinfo=timezone.utc),
            source="nist",
        )
        t2 = _make_threat(
            published_at=datetime(2024, 7, 10, tzinfo=timezone.utc),
            source="arxiv",
        )
        db_session.add_all([t1, t2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_trends(granularity="month", group_by="source")

        july_items = [d for d in result["data"] if d["period"] and "2024-07" in d["period"]]
        groups = {d["group"]: d["count"] for d in july_items}
        assert groups.get("nist") == 1
        assert groups.get("arxiv") == 1

    async def test_group_by_severity(self, db_session: AsyncSession):
        """group_by=severity should produce separate entries per severity level."""
        t1 = _make_threat(
            published_at=datetime(2024, 8, 1, tzinfo=timezone.utc),
            severity=3,
        )
        t2 = _make_threat(
            published_at=datetime(2024, 8, 15, tzinfo=timezone.utc),
            severity=7,
        )
        db_session.add_all([t1, t2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_trends(granularity="month", group_by="severity")

        aug_items = [d for d in result["data"] if d["period"] and "2024-08" in d["period"]]
        groups = {d["group"]: d["count"] for d in aug_items}
        assert groups.get("3") == 1
        assert groups.get("7") == 1

    async def test_no_group_by_sets_group_to_none(self, db_session: AsyncSession):
        """When group_by is None, each item's group field should be None."""
        t1 = _make_threat(published_at=datetime(2024, 9, 1, tzinfo=timezone.utc))
        db_session.add(t1)
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_trends(granularity="month")

        for item in result["data"]:
            assert item["group"] is None


@pytest.mark.asyncio
class TestGetTrendsFilters:
    """Tests for filter application."""

    async def test_date_from_filter(self, db_session: AsyncSession):
        """date_from should exclude threats before the given date."""
        t1 = _make_threat(published_at=datetime(2024, 1, 1, tzinfo=timezone.utc))
        t2 = _make_threat(published_at=datetime(2024, 6, 1, tzinfo=timezone.utc))
        db_session.add_all([t1, t2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_trends(
            date_from=datetime(2024, 3, 1, tzinfo=timezone.utc),
        )

        # Only the June threat should appear
        assert len(result["data"]) == 1
        assert "2024-06" in result["data"][0]["period"]

    async def test_threat_type_filter(self, db_session: AsyncSession):
        """threat_type filter should only include matching threats."""
        t1 = _make_threat(
            published_at=datetime(2024, 10, 1, tzinfo=timezone.utc),
            threat_type="adversarial",
        )
        t2 = _make_threat(
            published_at=datetime(2024, 10, 15, tzinfo=timezone.utc),
            threat_type="poisoning",
        )
        db_session.add_all([t1, t2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_trends(threat_type="adversarial")

        total_count = sum(d["count"] for d in result["data"])
        assert total_count == 1

    async def test_severity_range_filter(self, db_session: AsyncSession):
        """severity_min/severity_max should filter by severity range."""
        t1 = _make_threat(
            published_at=datetime(2024, 11, 1, tzinfo=timezone.utc),
            severity=2,
        )
        t2 = _make_threat(
            published_at=datetime(2024, 11, 10, tzinfo=timezone.utc),
            severity=5,
        )
        t3 = _make_threat(
            published_at=datetime(2024, 11, 20, tzinfo=timezone.utc),
            severity=9,
        )
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_trends(severity_min=4, severity_max=6)

        total_count = sum(d["count"] for d in result["data"])
        assert total_count == 1

    async def test_null_published_at_excluded(self, db_session: AsyncSession):
        """Threats with NULL published_at should be excluded."""
        t1 = _make_threat(published_at=None)
        t2 = _make_threat(published_at=datetime(2024, 12, 1, tzinfo=timezone.utc))
        db_session.add_all([t1, t2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_trends()

        total_count = sum(d["count"] for d in result["data"])
        assert total_count == 1
