"""
Property-Based Test: Processing tasks skip when paused

**Property 2: Processing tasks skip when paused**
**Validates: Requirements 4.1, 4.2, 4.3, 5.1, 5.2**

For any threat ID string, when the processing pause state is set to true,
both `enrich_threat` and `analyze_with_llm` tasks should return a result
with `status` equal to `"skipped_paused"` and the correct `threat_id`,
without performing any enrichment or LLM analysis work and without chaining
to downstream tasks.
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from hypothesis import given, strategies as st, settings as hypothesis_settings, HealthCheck

# Strategy: generate UUID-like strings (hex with dashes)
uuid_strategy = st.uuids().map(str)


class TestProcessingTasksSkipWhenPaused:
    """
    Property 2: Processing tasks skip when paused

    Validates: Requirements 4.1, 4.2, 4.3, 5.1, 5.2
    """

    @given(threat_id=uuid_strategy)
    @hypothesis_settings(
        max_examples=150,
        deadline=5000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_enrich_threat_skips_when_paused(self, threat_id: str):
        """
        **Validates: Requirements 4.1, 4.2, 4.3**

        For any threat ID, when processing is paused, enrich_threat must:
        - Return {'status': 'skipped_paused', 'threat_id': threat_id}
        - NOT perform any enrichment work (EnrichmentService not called)
        - NOT chain to analyze_with_llm
        """
        mock_manager = MagicMock()
        mock_manager.is_paused = AsyncMock(return_value=True)
        mock_manager.close = AsyncMock()

        with patch(
            "services.processing_state.ProcessingStateManager",
            return_value=mock_manager,
        ), patch("tasks.analyze_with_llm") as mock_analyze:

            from tasks import enrich_threat

            # Call the underlying function directly (bypass Celery)
            result = enrich_threat(threat_id)

            # Verify skip result
            assert result == {
                "status": "skipped_paused",
                "threat_id": threat_id,
            }, f"Expected skipped_paused result for threat {threat_id}, got {result}"

            # Verify is_paused was checked
            mock_manager.is_paused.assert_awaited_once()
            mock_manager.close.assert_awaited_once()

            # Verify analyze_with_llm was NOT chained
            mock_analyze.delay.assert_not_called()

    @given(threat_id=uuid_strategy)
    @hypothesis_settings(
        max_examples=150,
        deadline=5000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_analyze_with_llm_skips_when_paused(self, threat_id: str):
        """
        **Validates: Requirements 5.1, 5.2**

        For any threat ID, when processing is paused, analyze_with_llm must:
        - Return {'status': 'skipped_paused', 'threat_id': threat_id}
        - NOT perform any LLM analysis work (analysis service not called)
        """
        mock_manager = MagicMock()
        mock_manager.is_paused = AsyncMock(return_value=True)
        mock_manager.close = AsyncMock()

        with patch(
            "services.processing_state.ProcessingStateManager",
            return_value=mock_manager,
        ):

            from tasks import analyze_with_llm

            # Call the underlying function directly (bypass Celery)
            result = analyze_with_llm(threat_id)

            # Verify skip result
            assert result == {
                "status": "skipped_paused",
                "threat_id": threat_id,
            }, f"Expected skipped_paused result for threat {threat_id}, got {result}"

            # Verify is_paused was checked
            mock_manager.is_paused.assert_awaited_once()
            mock_manager.close.assert_awaited_once()

    @given(threat_id=uuid_strategy)
    @hypothesis_settings(
        max_examples=150,
        deadline=5000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_enrich_threat_no_enrichment_work_when_paused(self, threat_id: str):
        """
        **Validates: Requirements 4.1, 4.2**

        For any threat ID, when processing is paused, enrich_threat must
        NOT create a database engine, session, or EnrichmentService.
        """
        mock_manager = MagicMock()
        mock_manager.is_paused = AsyncMock(return_value=True)
        mock_manager.close = AsyncMock()

        with patch(
            "services.processing_state.ProcessingStateManager",
            return_value=mock_manager,
        ), patch(
            "services.enrichment.EnrichmentService"
        ) as mock_enrichment_svc, patch(
            "tasks.analyze_with_llm"
        ) as mock_analyze:

            from tasks import enrich_threat

            result = enrich_threat(threat_id)

            assert result["status"] == "skipped_paused"

            # No enrichment work should have been performed
            mock_enrichment_svc.assert_not_called()
            mock_analyze.delay.assert_not_called()

    @given(threat_id=uuid_strategy)
    @hypothesis_settings(
        max_examples=150,
        deadline=5000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_analyze_with_llm_no_analysis_work_when_paused(self, threat_id: str):
        """
        **Validates: Requirements 5.1, 5.2**

        For any threat ID, when processing is paused, analyze_with_llm must
        NOT create a database engine, session, or analysis service.
        """
        mock_manager = MagicMock()
        mock_manager.is_paused = AsyncMock(return_value=True)
        mock_manager.close = AsyncMock()

        with patch(
            "services.processing_state.ProcessingStateManager",
            return_value=mock_manager,
        ), patch(
            "services.analysis.get_analysis_service"
        ) as mock_analysis_svc:

            from tasks import analyze_with_llm

            result = analyze_with_llm(threat_id)

            assert result["status"] == "skipped_paused"

            # No analysis work should have been performed
            mock_analysis_svc.assert_not_called()
