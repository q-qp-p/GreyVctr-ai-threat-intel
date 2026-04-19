"""
Unit Tests: AnalyticsService query timeout handling

Verifies that _execute_with_timeout raises AnalyticsTimeoutError
when a query exceeds the timeout, and passes through results normally
when the query completes in time.

**Validates: Requirements 8.2**
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from services.analytics import AnalyticsService, AnalyticsTimeoutError


class TestExecuteWithTimeout:
    """Tests for AnalyticsService._execute_with_timeout."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock AsyncSession."""
        return AsyncMock()

    async def test_returns_result_when_query_completes_in_time(self, mock_session):
        """Normal queries should return their result unchanged."""
        expected = MagicMock()
        mock_session.execute.return_value = expected

        svc = AnalyticsService(mock_session)
        result = await svc._execute_with_timeout("fake_query", timeout=5.0)

        assert result is expected
        mock_session.execute.assert_called_once_with("fake_query")

    async def test_raises_analytics_timeout_error_on_slow_query(self, mock_session):
        """Queries exceeding the timeout should raise AnalyticsTimeoutError."""

        async def slow_execute(query):
            await asyncio.sleep(10)

        mock_session.execute = slow_execute

        svc = AnalyticsService(mock_session)
        with pytest.raises(AnalyticsTimeoutError, match="5 second timeout"):
            await svc._execute_with_timeout("fake_query", timeout=0.05)

    async def test_timeout_error_message(self, mock_session):
        """AnalyticsTimeoutError should carry the expected message."""

        async def slow_execute(query):
            await asyncio.sleep(10)

        mock_session.execute = slow_execute

        svc = AnalyticsService(mock_session)
        with pytest.raises(AnalyticsTimeoutError) as exc_info:
            await svc._execute_with_timeout("fake_query", timeout=0.05)

        assert "Analytics query exceeded 5 second timeout" in str(exc_info.value)

    async def test_default_timeout_is_five_seconds(self, mock_session):
        """The default timeout parameter should be 5.0 seconds."""
        import inspect

        sig = inspect.signature(AnalyticsService._execute_with_timeout)
        assert sig.parameters["timeout"].default == 5.0

    async def test_analytics_timeout_error_is_exception(self):
        """AnalyticsTimeoutError should be a subclass of Exception."""
        assert issubclass(AnalyticsTimeoutError, Exception)
