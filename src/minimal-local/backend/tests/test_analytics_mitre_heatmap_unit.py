"""
Unit Tests: AnalyticsService.get_mitre_heatmap()

**Validates: Requirements 5.1, 5.2, 5.3**

Tests for the get_mitre_heatmap() method including:
- JOIN of mitre_mappings with threats
- GROUP BY tactic, technique, technique_id
- Response envelope structure
- Filter application via build_analytics_filters()
- Empty database returns empty data with correct envelope
"""

import pytest
import uuid
import hashlib
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from models.threat import Threat
from models.mitre import MitreMapping
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


def _make_mitre(
    threat_id: uuid.UUID,
    tactic: str = "Reconnaissance",
    technique: str = "Discover ML Artifacts",
    technique_id: str = "AML.T0002",
) -> MitreMapping:
    """Helper to create a MitreMapping instance."""
    return MitreMapping(
        id=uuid.uuid4(),
        threat_id=threat_id,
        tactic=tactic,
        technique=technique,
        technique_id=technique_id,
    )


@pytest.mark.asyncio
class TestGetMitreHeatmapEnvelope:
    """Tests for the response envelope structure."""

    async def test_empty_database_returns_correct_envelope(self, db_session: AsyncSession):
        """Empty database should return empty data with correct meta."""
        svc = AnalyticsService(db_session)
        result = await svc.get_mitre_heatmap()

        assert isinstance(result["data"], list)
        assert len(result["data"]) == 0
        assert result["meta"]["total_records"] == 0
        assert "filters_applied" in result["meta"]
        assert "computed_at" in result["meta"]

    async def test_meta_filters_applied_reflects_params(self, db_session: AsyncSession):
        """Meta filters_applied should reflect the parameters passed."""
        svc = AnalyticsService(db_session)
        result = await svc.get_mitre_heatmap(
            threat_type="adversarial",
            severity_min=3,
            severity_max=8,
            source="nist",
        )
        fa = result["meta"]["filters_applied"]
        assert fa["threat_type"] == "adversarial"
        assert fa["severity_min"] == 3
        assert fa["severity_max"] == 8
        assert fa["source"] == "nist"

    async def test_computed_at_is_iso8601(self, db_session: AsyncSession):
        """computed_at should be a valid ISO 8601 string."""
        svc = AnalyticsService(db_session)
        result = await svc.get_mitre_heatmap()
        # Should not raise
        datetime.fromisoformat(result["meta"]["computed_at"])


@pytest.mark.asyncio
class TestGetMitreHeatmapAggregation:
    """Tests for actual data aggregation via JOIN and GROUP BY."""

    async def test_single_mapping_returns_one_cell(self, db_session: AsyncSession):
        """A single mitre mapping should produce one heatmap cell with count 1."""
        threat = _make_threat(published_at=datetime(2024, 3, 10, tzinfo=timezone.utc))
        db_session.add(threat)
        await db_session.flush()

        mm = _make_mitre(threat.id, tactic="Reconnaissance", technique="Discover ML Artifacts", technique_id="AML.T0002")
        db_session.add(mm)
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_mitre_heatmap()

        assert len(result["data"]) == 1
        cell = result["data"][0]
        assert cell["tactic"] == "Reconnaissance"
        assert cell["technique"] == "Discover ML Artifacts"
        assert cell["technique_id"] == "AML.T0002"
        assert cell["count"] == 1

    async def test_same_tactic_technique_aggregated(self, db_session: AsyncSession):
        """Multiple mappings with the same tactic/technique should be aggregated."""
        t1 = _make_threat(published_at=datetime(2024, 4, 1, tzinfo=timezone.utc))
        t2 = _make_threat(published_at=datetime(2024, 4, 15, tzinfo=timezone.utc))
        db_session.add_all([t1, t2])
        await db_session.flush()

        mm1 = _make_mitre(t1.id, tactic="ML Model Access", technique="Model Extraction", technique_id="AML.T0005")
        mm2 = _make_mitre(t2.id, tactic="ML Model Access", technique="Model Extraction", technique_id="AML.T0005")
        db_session.add_all([mm1, mm2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_mitre_heatmap()

        cells = [d for d in result["data"] if d["technique_id"] == "AML.T0005"]
        assert len(cells) == 1
        assert cells[0]["count"] == 2

    async def test_different_techniques_separate_cells(self, db_session: AsyncSession):
        """Different tactic/technique combos should produce separate cells."""
        threat = _make_threat(published_at=datetime(2024, 5, 1, tzinfo=timezone.utc))
        db_session.add(threat)
        await db_session.flush()

        mm1 = _make_mitre(threat.id, tactic="Reconnaissance", technique="Discover ML Artifacts", technique_id="AML.T0002")
        mm2 = _make_mitre(threat.id, tactic="ML Model Access", technique="Model Extraction", technique_id="AML.T0005")
        db_session.add_all([mm1, mm2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_mitre_heatmap()

        assert len(result["data"]) == 2
        technique_ids = {d["technique_id"] for d in result["data"]}
        assert technique_ids == {"AML.T0002", "AML.T0005"}

    async def test_item_fields_match_schema(self, db_session: AsyncSession):
        """Each item should have tactic, technique, technique_id, count fields."""
        threat = _make_threat(published_at=datetime(2024, 6, 1, tzinfo=timezone.utc))
        db_session.add(threat)
        await db_session.flush()

        mm = _make_mitre(threat.id)
        db_session.add(mm)
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_mitre_heatmap()

        for item in result["data"]:
            assert "tactic" in item
            assert "technique" in item
            assert "technique_id" in item
            assert "count" in item
            assert isinstance(item["count"], int)


@pytest.mark.asyncio
class TestGetMitreHeatmapFilters:
    """Tests for filter application on the joined Threat table."""

    async def test_threat_type_filter(self, db_session: AsyncSession):
        """threat_type filter should only include mappings for matching threats."""
        t1 = _make_threat(published_at=datetime(2024, 7, 1, tzinfo=timezone.utc), threat_type="adversarial")
        t2 = _make_threat(published_at=datetime(2024, 7, 15, tzinfo=timezone.utc), threat_type="poisoning")
        db_session.add_all([t1, t2])
        await db_session.flush()

        mm1 = _make_mitre(t1.id, tactic="Recon", technique="TechA", technique_id="AML.T0001")
        mm2 = _make_mitre(t2.id, tactic="Recon", technique="TechB", technique_id="AML.T0003")
        db_session.add_all([mm1, mm2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_mitre_heatmap(threat_type="adversarial")

        assert len(result["data"]) == 1
        assert result["data"][0]["technique_id"] == "AML.T0001"

    async def test_severity_range_filter(self, db_session: AsyncSession):
        """severity_min/severity_max should filter by severity range."""
        t1 = _make_threat(published_at=datetime(2024, 8, 1, tzinfo=timezone.utc), severity=2)
        t2 = _make_threat(published_at=datetime(2024, 8, 10, tzinfo=timezone.utc), severity=8)
        db_session.add_all([t1, t2])
        await db_session.flush()

        mm1 = _make_mitre(t1.id, tactic="T1", technique="Tech1", technique_id="AML.T0010")
        mm2 = _make_mitre(t2.id, tactic="T2", technique="Tech2", technique_id="AML.T0020")
        db_session.add_all([mm1, mm2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_mitre_heatmap(severity_min=5, severity_max=10)

        assert len(result["data"]) == 1
        assert result["data"][0]["technique_id"] == "AML.T0020"

    async def test_date_range_filter(self, db_session: AsyncSession):
        """date_from/date_to should filter by published_at range."""
        t1 = _make_threat(published_at=datetime(2024, 1, 1, tzinfo=timezone.utc))
        t2 = _make_threat(published_at=datetime(2024, 6, 1, tzinfo=timezone.utc))
        db_session.add_all([t1, t2])
        await db_session.flush()

        mm1 = _make_mitre(t1.id, tactic="Early", technique="TechE", technique_id="AML.T0100")
        mm2 = _make_mitre(t2.id, tactic="Late", technique="TechL", technique_id="AML.T0200")
        db_session.add_all([mm1, mm2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_mitre_heatmap(
            date_from=datetime(2024, 3, 1, tzinfo=timezone.utc),
        )

        assert len(result["data"]) == 1
        assert result["data"][0]["technique_id"] == "AML.T0200"

    async def test_source_filter(self, db_session: AsyncSession):
        """source filter should only include mappings for matching threats."""
        t1 = _make_threat(published_at=datetime(2024, 9, 1, tzinfo=timezone.utc), source="nist")
        t2 = _make_threat(published_at=datetime(2024, 9, 15, tzinfo=timezone.utc), source="arxiv")
        db_session.add_all([t1, t2])
        await db_session.flush()

        mm1 = _make_mitre(t1.id, tactic="TacA", technique="TechA", technique_id="AML.T0300")
        mm2 = _make_mitre(t2.id, tactic="TacB", technique="TechB", technique_id="AML.T0400")
        db_session.add_all([mm1, mm2])
        await db_session.flush()

        svc = AnalyticsService(db_session)
        result = await svc.get_mitre_heatmap(source="nist")

        assert len(result["data"]) == 1
        assert result["data"][0]["technique_id"] == "AML.T0300"
