"""
Unit Tests: AnalyticsService.get_distributions()

**Validates: Requirements 4.1, 4.2, 4.5, 4.6**

Tests for the get_distributions() method including:
- Dimension validation
- Response envelope structure
- Grouping by threat_type, severity, source
- Ordering: severity ascending, others by count descending
- Filter application
- NULL dimension values excluded
"""

import pytest
import uuid
import hashlib
from datetime import datetime, timezone

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
class TestGetDistributionsValidation:
    """Tests for parameter validation in get_distributions()."""

    async def test_invalid_dimension_raises_value_error(self, db_session: AsyncSession):
        """Invalid dimension should raise ValueError."""
        svc = AnalyticsService(db_session)
        with pytest.raises(ValueError, match="dimension must be one of"):
            await svc.get_distributions(dimension="invalid")

    async def test_valid_dimensions_accepted(self, db_session: AsyncSession):
        """All valid dimensions (threat_type, severity, source) should be accepted."""
        svc = AnalyticsService(db_session)
        for dim in ("threat_type", "severity", "source"):
            result = await svc.get_distributions(dimension=dim)
            assert "data" in result
            assert "meta" in result


@pytest.mark.asyncio
class TestGetDistributionsEnvelope:
    """Tests for the response envelope structure."""

    async def test_empty_database_returns_correct_envelope(self, db_session: AsyncSession):
        """Empty database should return empty data with correct meta."""
        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="threat_type")

        assert isinstance(result["data"], list)
        assert len(result["data"]) == 0
        assert result["meta"]["total_records"] == 0
        assert "filters_applied" in result["meta"]
        assert "computed_at" in result["meta"]

    async def test_meta_filters_applied_reflects_params(self, db_session: AsyncSession):
        """Meta filters_applied should reflect the parameters passed."""
        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(
            dimension="source",
            threat_type="adversarial",
            severity_min=3,
            severity_max=8,
            source="nist",
        )
        fa = result["meta"]["filters_applied"]
        assert fa["dimension"] == "source"
        assert fa["threat_type"] == "adversarial"
        assert fa["severity_min"] == 3
        assert fa["severity_max"] == 8
        assert fa["source"] == "nist"

    async def test_computed_at_is_iso8601(self, db_session: AsyncSession):
        """computed_at should be a valid ISO 8601 string."""
        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="threat_type")
        # Should not raise
        datetime.fromisoformat(result["meta"]["computed_at"])

    async def test_data_items_have_label_and_count(self, db_session: AsyncSession):
        """Each data item should have 'label' and 'count' keys."""
        t1 = _make_threat(threat_type="adversarial")
        db_session.add(t1)
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="threat_type")

        for item in result["data"]:
            assert "label" in item
            assert "count" in item
            assert isinstance(item["label"], str)
            assert isinstance(item["count"], int)


@pytest.mark.asyncio
class TestGetDistributionsGrouping:
    """Tests for grouping by each dimension."""

    async def test_group_by_threat_type(self, db_session: AsyncSession):
        """dimension=threat_type should group threats by threat_type."""
        t1 = _make_threat(threat_type="adversarial")
        t2 = _make_threat(threat_type="adversarial")
        t3 = _make_threat(threat_type="poisoning")
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="threat_type")

        labels = {d["label"]: d["count"] for d in result["data"]}
        assert labels["adversarial"] == 2
        assert labels["poisoning"] == 1

    async def test_group_by_severity(self, db_session: AsyncSession):
        """dimension=severity should group threats by severity level."""
        t1 = _make_threat(severity=3)
        t2 = _make_threat(severity=3)
        t3 = _make_threat(severity=7)
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="severity")

        labels = {d["label"]: d["count"] for d in result["data"]}
        assert labels["3"] == 2
        assert labels["7"] == 1

    async def test_group_by_source(self, db_session: AsyncSession):
        """dimension=source should group threats by source."""
        t1 = _make_threat(source="nist")
        t2 = _make_threat(source="arxiv")
        t3 = _make_threat(source="arxiv")
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="source")

        labels = {d["label"]: d["count"] for d in result["data"]}
        assert labels["nist"] == 1
        assert labels["arxiv"] == 2

    async def test_severity_label_is_string(self, db_session: AsyncSession):
        """Severity labels should be cast to strings."""
        t1 = _make_threat(severity=5)
        db_session.add(t1)
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="severity")

        assert result["data"][0]["label"] == "5"


@pytest.mark.asyncio
class TestGetDistributionsOrdering:
    """Tests for result ordering."""

    async def test_severity_ordered_ascending(self, db_session: AsyncSession):
        """Severity dimension should order results ascending (1-10)."""
        for sev in [7, 2, 9, 1, 5]:
            db_session.add(_make_threat(severity=sev))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="severity")

        labels = [int(d["label"]) for d in result["data"]]
        assert labels == sorted(labels)

    async def test_threat_type_ordered_by_count_descending(self, db_session: AsyncSession):
        """threat_type dimension should order by count descending."""
        # 3 adversarial, 1 poisoning, 2 extraction
        for _ in range(3):
            db_session.add(_make_threat(threat_type="adversarial"))
        db_session.add(_make_threat(threat_type="poisoning"))
        for _ in range(2):
            db_session.add(_make_threat(threat_type="extraction"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="threat_type")

        counts = [d["count"] for d in result["data"]]
        assert counts == sorted(counts, reverse=True)

    async def test_source_ordered_by_count_descending(self, db_session: AsyncSession):
        """source dimension should order by count descending."""
        for _ in range(4):
            db_session.add(_make_threat(source="nist"))
        db_session.add(_make_threat(source="arxiv"))
        for _ in range(2):
            db_session.add(_make_threat(source="mitre"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="source")

        counts = [d["count"] for d in result["data"]]
        assert counts == sorted(counts, reverse=True)


@pytest.mark.asyncio
class TestGetDistributionsFilters:
    """Tests for filter application."""

    async def test_threat_type_filter(self, db_session: AsyncSession):
        """threat_type filter should only include matching threats."""
        t1 = _make_threat(threat_type="adversarial", severity=3)
        t2 = _make_threat(threat_type="poisoning", severity=5)
        db_session.add_all([t1, t2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(
            dimension="severity", threat_type="adversarial"
        )

        total = sum(d["count"] for d in result["data"])
        assert total == 1

    async def test_severity_range_filter(self, db_session: AsyncSession):
        """severity_min/severity_max should filter by severity range."""
        t1 = _make_threat(severity=2, threat_type="adversarial")
        t2 = _make_threat(severity=5, threat_type="poisoning")
        t3 = _make_threat(severity=9, threat_type="extraction")
        db_session.add_all([t1, t2, t3])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(
            dimension="threat_type", severity_min=4, severity_max=6
        )

        total = sum(d["count"] for d in result["data"])
        assert total == 1

    async def test_null_dimension_values_excluded(self, db_session: AsyncSession):
        """Threats with NULL dimension values should be excluded."""
        t1 = _make_threat(threat_type=None)
        t2 = _make_threat(threat_type="adversarial")
        db_session.add_all([t1, t2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="threat_type")

        total = sum(d["count"] for d in result["data"])
        assert total == 1

    async def test_total_records_matches_data_length(self, db_session: AsyncSession):
        """meta.total_records should equal the length of the data array."""
        for _ in range(3):
            db_session.add(_make_threat(threat_type="adversarial"))
        db_session.add(_make_threat(threat_type="poisoning"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_distributions(dimension="threat_type")

        assert result["meta"]["total_records"] == len(result["data"])
