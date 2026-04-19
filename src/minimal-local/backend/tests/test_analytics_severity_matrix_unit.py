"""
Unit Tests: AnalyticsService.get_severity_matrix()

**Validates: Requirements 7.1, 7.2, 7.3**

Tests for the get_severity_matrix() method including:
- Response envelope structure
- Cross-tabulation grouping by severity × threat_type
- NULL exclusion for severity and threat_type
- Filter application
- Data item field structure
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
class TestGetSeverityMatrixEnvelope:
    """Tests for the response envelope structure."""

    async def test_empty_database_returns_correct_envelope(self, db_session: AsyncSession):
        """Empty database should return empty data with correct meta."""
        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix()

        assert isinstance(result["data"], list)
        assert len(result["data"]) == 0
        assert result["meta"]["total_records"] == 0
        assert "filters_applied" in result["meta"]
        assert "computed_at" in result["meta"]

    async def test_meta_filters_applied_reflects_params(self, db_session: AsyncSession):
        """Meta filters_applied should reflect the parameters passed."""
        svc = AnalyticsService(db_session)
        dt_from = datetime(2024, 1, 1, tzinfo=timezone.utc)
        dt_to = datetime(2024, 12, 31, tzinfo=timezone.utc)
        result = await svc.get_severity_matrix(
            date_from=dt_from,
            date_to=dt_to,
            threat_type="adversarial",
            severity_min=3,
            severity_max=8,
            source="nist",
        )
        fa = result["meta"]["filters_applied"]
        assert fa["date_from"] == dt_from.isoformat()
        assert fa["date_to"] == dt_to.isoformat()
        assert fa["threat_type"] == "adversarial"
        assert fa["severity_min"] == 3
        assert fa["severity_max"] == 8
        assert fa["source"] == "nist"

    async def test_computed_at_is_iso8601(self, db_session: AsyncSession):
        """computed_at should be a valid ISO 8601 string."""
        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix()
        # Should not raise
        datetime.fromisoformat(result["meta"]["computed_at"])

    async def test_total_records_matches_data_length(self, db_session: AsyncSession):
        """meta.total_records should equal the length of the data array."""
        db_session.add(_make_threat(severity=3, threat_type="adversarial"))
        db_session.add(_make_threat(severity=3, threat_type="poisoning"))
        db_session.add(_make_threat(severity=7, threat_type="adversarial"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix()

        assert result["meta"]["total_records"] == len(result["data"])


@pytest.mark.asyncio
class TestGetSeverityMatrixGrouping:
    """Tests for severity × threat_type cross-tabulation."""

    async def test_groups_by_severity_and_threat_type(self, db_session: AsyncSession):
        """Should produce one row per unique (severity, threat_type) pair."""
        db_session.add(_make_threat(severity=3, threat_type="adversarial"))
        db_session.add(_make_threat(severity=3, threat_type="adversarial"))
        db_session.add(_make_threat(severity=3, threat_type="poisoning"))
        db_session.add(_make_threat(severity=7, threat_type="adversarial"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix()

        lookup = {(d["severity"], d["threat_type"]): d["count"] for d in result["data"]}
        assert lookup[(3, "adversarial")] == 2
        assert lookup[(3, "poisoning")] == 1
        assert lookup[(7, "adversarial")] == 1

    async def test_data_items_have_required_fields(self, db_session: AsyncSession):
        """Each data item should have severity, threat_type, and count."""
        db_session.add(_make_threat(severity=5, threat_type="extraction"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix()

        for item in result["data"]:
            assert "severity" in item
            assert "threat_type" in item
            assert "count" in item
            assert isinstance(item["severity"], int)
            assert isinstance(item["threat_type"], str)
            assert isinstance(item["count"], int)


@pytest.mark.asyncio
class TestGetSeverityMatrixNullExclusion:
    """Tests for NULL value exclusion."""

    async def test_null_severity_excluded(self, db_session: AsyncSession):
        """Threats with NULL severity should be excluded."""
        db_session.add(_make_threat(severity=None, threat_type="adversarial"))
        db_session.add(_make_threat(severity=5, threat_type="adversarial"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix()

        total = sum(d["count"] for d in result["data"])
        assert total == 1

    async def test_null_threat_type_excluded(self, db_session: AsyncSession):
        """Threats with NULL threat_type should be excluded."""
        db_session.add(_make_threat(severity=5, threat_type=None))
        db_session.add(_make_threat(severity=5, threat_type="adversarial"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix()

        total = sum(d["count"] for d in result["data"])
        assert total == 1

    async def test_both_null_excluded(self, db_session: AsyncSession):
        """Threats with both NULL severity and threat_type should be excluded."""
        db_session.add(_make_threat(severity=None, threat_type=None))
        db_session.add(_make_threat(severity=5, threat_type="adversarial"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix()

        total = sum(d["count"] for d in result["data"])
        assert total == 1


@pytest.mark.asyncio
class TestGetSeverityMatrixFilters:
    """Tests for filter application."""

    async def test_threat_type_filter(self, db_session: AsyncSession):
        """threat_type filter should only include matching threats."""
        db_session.add(_make_threat(severity=3, threat_type="adversarial"))
        db_session.add(_make_threat(severity=5, threat_type="poisoning"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix(threat_type="adversarial")

        total = sum(d["count"] for d in result["data"])
        assert total == 1
        assert result["data"][0]["threat_type"] == "adversarial"

    async def test_severity_range_filter(self, db_session: AsyncSession):
        """severity_min/severity_max should filter by severity range."""
        db_session.add(_make_threat(severity=2, threat_type="adversarial"))
        db_session.add(_make_threat(severity=5, threat_type="poisoning"))
        db_session.add(_make_threat(severity=9, threat_type="extraction"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix(severity_min=4, severity_max=6)

        total = sum(d["count"] for d in result["data"])
        assert total == 1
        assert result["data"][0]["severity"] == 5

    async def test_source_filter(self, db_session: AsyncSession):
        """source filter should only include matching threats."""
        db_session.add(_make_threat(severity=3, threat_type="adversarial", source="nist"))
        db_session.add(_make_threat(severity=5, threat_type="poisoning", source="arxiv"))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix(source="nist")

        total = sum(d["count"] for d in result["data"])
        assert total == 1

    async def test_date_range_filter(self, db_session: AsyncSession):
        """date_from/date_to should filter by published_at range."""
        db_session.add(_make_threat(
            severity=3, threat_type="adversarial",
            published_at=datetime(2024, 3, 15, tzinfo=timezone.utc),
        ))
        db_session.add(_make_threat(
            severity=5, threat_type="poisoning",
            published_at=datetime(2024, 8, 15, tzinfo=timezone.utc),
        ))
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_severity_matrix(
            date_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
            date_to=datetime(2024, 6, 30, tzinfo=timezone.utc),
        )

        total = sum(d["count"] for d in result["data"])
        assert total == 1
        assert result["data"][0]["severity"] == 3
