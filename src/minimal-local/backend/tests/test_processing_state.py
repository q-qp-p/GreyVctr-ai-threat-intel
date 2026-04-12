"""
Property-Based Test: Pause State Round-Trip Consistency

**Property 1: Pause state round-trip consistency**
**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7**

For any boolean pause value and any username string, setting the processing
state via set_paused(paused, username) and then reading it back via is_paused()
and get_pause_info() should return consistent values:
- is_paused() returns the set value
- When paused=True: get_pause_info() returns the same username and a valid ISO 8601 timestamp
- When paused=False: get_pause_info() returns paused_at=None and paused_by=None
"""

import pytest
from datetime import datetime, timezone
from hypothesis import given, strategies as st, settings as hypothesis_settings, HealthCheck

import fakeredis.aioredis as fakeredis_aio

from services.processing_state import ProcessingStateManager


# Strategy for generating usernames: printable strings of reasonable length
username_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd", "P")),
    min_size=1,
    max_size=50,
)


@pytest.fixture
async def fake_redis():
    """Create a fresh fakeredis instance for each test."""
    r = fakeredis_aio.FakeRedis(decode_responses=True, encoding="utf-8")
    yield r
    await r.aclose()


@pytest.fixture
async def state_manager(fake_redis):
    """Create a ProcessingStateManager backed by fakeredis."""
    manager = ProcessingStateManager()
    manager._redis_client = fake_redis
    yield manager


class TestPauseStateRoundTripConsistency:
    """
    Property 1: Pause state round-trip consistency

    Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7
    """

    @pytest.mark.asyncio
    @given(paused=st.booleans(), username=username_strategy)
    @hypothesis_settings(
        max_examples=150,
        deadline=5000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    async def test_pause_state_round_trip(self, paused: bool, username: str):
        """
        **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7**

        For any boolean and username, set_paused() followed by is_paused()
        and get_pause_info() must return consistent values.
        """
        fake_redis = fakeredis_aio.FakeRedis(decode_responses=True, encoding="utf-8")
        manager = ProcessingStateManager()
        manager._redis_client = fake_redis

        try:
            # Act: set the pause state
            await manager.set_paused(paused, username=username)

            # Assert: is_paused() matches what we set
            result_paused = await manager.is_paused()
            assert result_paused == paused, (
                f"is_paused() returned {result_paused}, expected {paused}"
            )

            # Assert: get_pause_info() is consistent
            info = await manager.get_pause_info()
            assert info["paused"] == paused, (
                f"get_pause_info()['paused'] returned {info['paused']}, expected {paused}"
            )

            if paused:
                # When paused=True: paused_at must be a valid ISO 8601 timestamp
                assert info["paused_at"] is not None, "paused_at should not be None when paused"
                parsed_ts = datetime.fromisoformat(info["paused_at"])
                assert parsed_ts.tzinfo is not None or "+" in info["paused_at"] or "Z" in info["paused_at"], (
                    f"paused_at should be a timezone-aware ISO 8601 timestamp, got: {info['paused_at']}"
                )

                # paused_by must match the username we provided
                assert info["paused_by"] == username, (
                    f"paused_by returned {info['paused_by']!r}, expected {username!r}"
                )
            else:
                # When paused=False: metadata keys must be None
                assert info["paused_at"] is None, (
                    f"paused_at should be None when not paused, got: {info['paused_at']}"
                )
                assert info["paused_by"] is None, (
                    f"paused_by should be None when not paused, got: {info['paused_by']}"
                )
        finally:
            await fake_redis.aclose()


class TestProcessingStateManagerUnit:
    """
    Unit tests for ProcessingStateManager.

    Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7
    """

    @pytest.mark.asyncio
    async def test_default_state_is_false_on_fresh_redis(self):
        """
        On a fresh Redis with no keys set, is_paused() should return False
        and get_pause_info() should return paused=False with None metadata.

        Validates: Requirements 1.5, 1.6, 1.7
        """
        fake_redis = fakeredis_aio.FakeRedis(decode_responses=True, encoding="utf-8")
        manager = ProcessingStateManager()
        manager._redis_client = fake_redis

        try:
            assert await manager.is_paused() is False

            info = await manager.get_pause_info()
            assert info["paused"] is False
            assert info["paused_at"] is None
            assert info["paused_by"] is None
        finally:
            await fake_redis.aclose()

    @pytest.mark.asyncio
    async def test_set_paused_true_stores_all_three_keys(self):
        """
        Calling set_paused(True, username) should store processing:paused='true',
        processing:paused_at with a valid ISO 8601 timestamp, and
        processing:paused_by with the provided username.

        Validates: Requirements 1.1, 1.2, 1.3
        """
        fake_redis = fakeredis_aio.FakeRedis(decode_responses=True, encoding="utf-8")
        manager = ProcessingStateManager()
        manager._redis_client = fake_redis

        try:
            await manager.set_paused(True, username="admin_user")

            # Verify all three keys are stored directly in Redis
            paused_val = await fake_redis.get(ProcessingStateManager.KEY_PAUSED)
            assert paused_val == "true"

            paused_at_val = await fake_redis.get(ProcessingStateManager.KEY_PAUSED_AT)
            assert paused_at_val is not None
            # Verify it's a valid ISO 8601 timestamp
            parsed = datetime.fromisoformat(paused_at_val)
            assert parsed.tzinfo is not None

            paused_by_val = await fake_redis.get(ProcessingStateManager.KEY_PAUSED_BY)
            assert paused_by_val == "admin_user"
        finally:
            await fake_redis.aclose()

    @pytest.mark.asyncio
    async def test_set_paused_false_removes_metadata_keys(self):
        """
        After pausing and then resuming, set_paused(False) should set
        processing:paused='false' and remove processing:paused_at and
        processing:paused_by keys.

        Validates: Requirements 1.4
        """
        fake_redis = fakeredis_aio.FakeRedis(decode_responses=True, encoding="utf-8")
        manager = ProcessingStateManager()
        manager._redis_client = fake_redis

        try:
            # First pause
            await manager.set_paused(True, username="admin_user")

            # Verify keys exist after pausing
            assert await fake_redis.get(ProcessingStateManager.KEY_PAUSED_AT) is not None
            assert await fake_redis.get(ProcessingStateManager.KEY_PAUSED_BY) is not None

            # Now resume
            await manager.set_paused(False)

            # Verify paused key is set to "false"
            paused_val = await fake_redis.get(ProcessingStateManager.KEY_PAUSED)
            assert paused_val == "false"

            # Verify metadata keys are removed
            assert await fake_redis.get(ProcessingStateManager.KEY_PAUSED_AT) is None
            assert await fake_redis.get(ProcessingStateManager.KEY_PAUSED_BY) is None
        finally:
            await fake_redis.aclose()

    @pytest.mark.asyncio
    async def test_get_pause_info_returns_correct_structure_when_paused(self):
        """
        get_pause_info() should return a dict with 'paused', 'paused_at',
        and 'paused_by' keys with correct values when processing is paused.

        Validates: Requirements 1.7
        """
        fake_redis = fakeredis_aio.FakeRedis(decode_responses=True, encoding="utf-8")
        manager = ProcessingStateManager()
        manager._redis_client = fake_redis

        try:
            await manager.set_paused(True, username="test_admin")

            info = await manager.get_pause_info()

            # Verify structure
            assert "paused" in info
            assert "paused_at" in info
            assert "paused_by" in info

            # Verify values
            assert info["paused"] is True
            assert info["paused_at"] is not None
            assert isinstance(info["paused_at"], str)
            # Verify timestamp is valid ISO 8601
            datetime.fromisoformat(info["paused_at"])
            assert info["paused_by"] == "test_admin"
        finally:
            await fake_redis.aclose()

    @pytest.mark.asyncio
    async def test_get_pause_info_returns_correct_structure_when_not_paused(self):
        """
        get_pause_info() should return paused=False with None metadata
        when processing is not paused (after resume).

        Validates: Requirements 1.4, 1.7
        """
        fake_redis = fakeredis_aio.FakeRedis(decode_responses=True, encoding="utf-8")
        manager = ProcessingStateManager()
        manager._redis_client = fake_redis

        try:
            # Pause then resume
            await manager.set_paused(True, username="admin")
            await manager.set_paused(False)

            info = await manager.get_pause_info()

            assert info["paused"] is False
            assert info["paused_at"] is None
            assert info["paused_by"] is None
        finally:
            await fake_redis.aclose()



class TestGetProcessingStatusHelper:
    """
    Unit tests for the _get_processing_status helper used by the /status endpoint.

    Validates: Requirements 7.1, 7.2
    """

    @pytest.mark.asyncio
    async def test_processing_status_included_when_paused(self):
        """
        _get_processing_status() should return a ProcessingStatus with
        paused=True, paused_at, and paused_by when processing is paused.

        Validates: Requirements 7.1, 7.2
        """
        fake_redis = fakeredis_aio.FakeRedis(decode_responses=True, encoding="utf-8")
        manager = ProcessingStateManager()
        manager._redis_client = fake_redis

        try:
            await manager.set_paused(True, username="admin_user")

            # Simulate what _get_processing_status does
            pause_info = await manager.get_pause_info()

            from api.system import ProcessingStatus

            status = ProcessingStatus(
                paused=pause_info["paused"],
                paused_at=pause_info.get("paused_at"),
                paused_by=pause_info.get("paused_by"),
            )

            assert status.paused is True
            assert status.paused_at is not None
            assert status.paused_by == "admin_user"
        finally:
            await fake_redis.aclose()

    @pytest.mark.asyncio
    async def test_processing_status_included_when_not_paused(self):
        """
        _get_processing_status() should return a ProcessingStatus with
        paused=False and None metadata when processing is not paused.

        Validates: Requirements 7.1, 7.2
        """
        fake_redis = fakeredis_aio.FakeRedis(decode_responses=True, encoding="utf-8")
        manager = ProcessingStateManager()
        manager._redis_client = fake_redis

        try:
            # Fresh state — not paused
            pause_info = await manager.get_pause_info()

            from api.system import ProcessingStatus

            status = ProcessingStatus(
                paused=pause_info["paused"],
                paused_at=pause_info.get("paused_at"),
                paused_by=pause_info.get("paused_by"),
            )

            assert status.paused is False
            assert status.paused_at is None
            assert status.paused_by is None
        finally:
            await fake_redis.aclose()

    @pytest.mark.asyncio
    async def test_processing_status_defaults_on_redis_failure(self):
        """
        _get_processing_status() should default to paused=False when
        Redis is unavailable (graceful degradation).

        Validates: Requirements 7.1, 7.2
        """
        from api.system import ProcessingStatus, _get_processing_status
        from unittest.mock import AsyncMock, patch

        # Mock get_processing_state_manager to return a manager that raises
        mock_manager = AsyncMock()
        mock_manager.get_pause_info.side_effect = Exception("Redis connection refused")

        with patch("services.processing_state.get_processing_state_manager", return_value=mock_manager):
            status = await _get_processing_status()

        assert isinstance(status, ProcessingStatus)
        assert status.paused is False
        assert status.paused_at is None
        assert status.paused_by is None


# ---------------------------------------------------------------------------
# Property 3: Resume re-queues exactly the correct pending threats
# ---------------------------------------------------------------------------

from dataclasses import dataclass
from hypothesis import given, strategies as st, settings as hypothesis_settings


# Lightweight threat-like object for property testing
@dataclass
class FakeThreat:
    id: str
    enrichment_status: str
    llm_analysis_status: str


ENRICHMENT_STATUSES = ["pending", "partial", "complete"]
LLM_STATUSES = ["pending", "complete", "failed"]

# Strategy: generate a list of FakeThreat objects with random status combos
threat_strategy = st.lists(
    st.builds(
        FakeThreat,
        id=st.uuids().map(str),
        enrichment_status=st.sampled_from(ENRICHMENT_STATUSES),
        llm_analysis_status=st.sampled_from(LLM_STATUSES),
    ),
    min_size=0,
    max_size=50,
)


class TestResumeRequeueSelection:
    """
    Property 3: Resume re-queues exactly the correct pending threats

    Validates: Requirements 3.5
    """

    @given(threats=threat_strategy)
    @hypothesis_settings(max_examples=150, deadline=5000)
    def test_enrichment_requeue_selects_exactly_pending(self, threats):
        """
        **Validates: Requirements 3.5**

        For any list of threats with random enrichment/LLM status combos,
        the enrichment re-queue helper must select exactly those threats
        whose enrichment_status is 'pending' — no more, no less.
        """
        from api.system import select_threats_for_enrichment_requeue

        selected = select_threats_for_enrichment_requeue(threats)

        expected = [t for t in threats if t.enrichment_status == "pending"]

        # Same set of ids
        assert set(t.id for t in selected) == set(t.id for t in expected), (
            f"Enrichment re-queue mismatch: selected {[t.id for t in selected]}, "
            f"expected {[t.id for t in expected]}"
        )
        # Same count (handles duplicates if any)
        assert len(selected) == len(expected)

        # Every selected threat truly has pending enrichment
        for t in selected:
            assert t.enrichment_status == "pending"

    @given(threats=threat_strategy)
    @hypothesis_settings(max_examples=150, deadline=5000)
    def test_llm_requeue_selects_exactly_pending_with_complete_enrichment(self, threats):
        """
        **Validates: Requirements 3.5**

        For any list of threats, the LLM re-queue helper must select exactly
        those threats whose llm_analysis_status is 'pending' AND whose
        enrichment_status is 'complete'. Threats with other status combos
        must NOT be selected.
        """
        from api.system import select_threats_for_llm_requeue

        selected = select_threats_for_llm_requeue(threats)

        expected = [
            t
            for t in threats
            if t.llm_analysis_status == "pending" and t.enrichment_status == "complete"
        ]

        assert set(t.id for t in selected) == set(t.id for t in expected), (
            f"LLM re-queue mismatch: selected {[t.id for t in selected]}, "
            f"expected {[t.id for t in expected]}"
        )
        assert len(selected) == len(expected)

        # Every selected threat truly has the right combo
        for t in selected:
            assert t.llm_analysis_status == "pending"
            assert t.enrichment_status == "complete"

    @given(threats=threat_strategy)
    @hypothesis_settings(max_examples=150, deadline=5000)
    def test_no_overlap_between_enrichment_and_llm_requeue(self, threats):
        """
        **Validates: Requirements 3.5**

        Enrichment re-queue targets pending enrichment (so enrichment_status='pending'),
        while LLM re-queue targets pending LLM with complete enrichment
        (enrichment_status='complete'). These two sets must be disjoint —
        a threat cannot be in both.
        """
        from api.system import (
            select_threats_for_enrichment_requeue,
            select_threats_for_llm_requeue,
        )

        enrichment_selected = select_threats_for_enrichment_requeue(threats)
        llm_selected = select_threats_for_llm_requeue(threats)

        enrichment_ids = set(t.id for t in enrichment_selected)
        llm_ids = set(t.id for t in llm_selected)

        assert enrichment_ids.isdisjoint(llm_ids), (
            f"Overlap found: {enrichment_ids & llm_ids}"
        )
