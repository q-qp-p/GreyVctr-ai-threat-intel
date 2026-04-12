"""
Unit Tests: Pause Processing API Endpoint

Tests for the pause processing endpoint:
- POST /api/v1/system/pause-processing
- Returns success with paused_at on first call
- Returns already_paused on subsequent calls
- Requires admin authentication
"""

import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timezone

from fastapi.testclient import TestClient


class TestPauseProcessingEndpoint:
    """Unit tests for pause-processing endpoint"""

    @pytest.fixture
    def mock_state_manager(self):
        """Mock ProcessingStateManager"""
        manager = AsyncMock()
        manager.is_paused = AsyncMock(return_value=False)
        manager.set_paused = AsyncMock()
        manager.get_pause_info = AsyncMock(return_value={
            "paused": True,
            "paused_at": datetime.now(timezone.utc).isoformat(),
            "paused_by": "admin",
        })
        return manager

    @pytest.fixture
    def mock_admin_user(self):
        """Mock admin user for auth dependency"""
        from unittest.mock import MagicMock
        user = MagicMock()
        user.username = "admin"
        user.role = "admin"
        return user

    def test_pause_endpoint_exists(self):
        """
        Test POST /api/v1/system/pause-processing endpoint exists

        Validates: Requirements 2.1, 2.3
        """
        from main import app

        client = TestClient(app)
        response = client.post("/api/v1/system/pause-processing")

        # A 401/403 means the endpoint exists but requires auth
        # A 404 means the endpoint doesn't exist
        assert response.status_code != 404, "Pause endpoint should exist"

    def test_pause_requires_auth(self):
        """
        Test POST /api/v1/system/pause-processing requires admin auth

        Validates: Requirements 2.3
        """
        from main import app

        client = TestClient(app)
        response = client.post("/api/v1/system/pause-processing")

        # Should return 401 or 403 without auth
        assert response.status_code in (401, 403), \
            "Pause endpoint should require authentication"

    def test_pause_success(self, mock_state_manager, mock_admin_user):
        """
        Test POST /api/v1/system/pause-processing returns success

        Validates: Requirements 2.1, 2.4
        """
        from main import app
        from api.auth import get_current_admin_user

        app.dependency_overrides[get_current_admin_user] = lambda: mock_admin_user

        try:
            with patch(
                'services.processing_state.get_processing_state_manager',
                return_value=mock_state_manager,
            ):
                client = TestClient(app)
                response = client.post("/api/v1/system/pause-processing")

                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "success"
                assert data["message"] == "Processing paused successfully"
                assert data["paused_at"] is not None
        finally:
            app.dependency_overrides.clear()

    def test_pause_already_paused(self, mock_state_manager, mock_admin_user):
        """
        Test POST /api/v1/system/pause-processing returns already_paused

        Validates: Requirements 2.2
        """
        from main import app
        from api.auth import get_current_admin_user

        mock_state_manager.is_paused = AsyncMock(return_value=True)

        app.dependency_overrides[get_current_admin_user] = lambda: mock_admin_user

        try:
            with patch(
                'services.processing_state.get_processing_state_manager',
                return_value=mock_state_manager,
            ):
                client = TestClient(app)
                response = client.post("/api/v1/system/pause-processing")

                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "already_paused"
                assert "already paused" in data["message"].lower()
        finally:
            app.dependency_overrides.clear()

    def test_pause_response_shape(self, mock_state_manager, mock_admin_user):
        """
        Test pause response contains required fields: status, message, paused_at

        Validates: Requirements 2.4
        """
        from main import app
        from api.auth import get_current_admin_user

        app.dependency_overrides[get_current_admin_user] = lambda: mock_admin_user

        try:
            with patch(
                'services.processing_state.get_processing_state_manager',
                return_value=mock_state_manager,
            ):
                client = TestClient(app)
                response = client.post("/api/v1/system/pause-processing")

                assert response.status_code == 200
                data = response.json()
                assert "status" in data
                assert "message" in data
                assert "paused_at" in data
        finally:
            app.dependency_overrides.clear()

    def test_pause_redis_failure_returns_500(self, mock_admin_user):
        """
        Test pause endpoint returns 500 when Redis is unavailable
        """
        from main import app
        from api.auth import get_current_admin_user

        mock_manager = AsyncMock()
        mock_manager.is_paused = AsyncMock(side_effect=Exception("Redis connection refused"))

        app.dependency_overrides[get_current_admin_user] = lambda: mock_admin_user

        try:
            with patch(
                'services.processing_state.get_processing_state_manager',
                return_value=mock_manager,
            ):
                client = TestClient(app)
                response = client.post("/api/v1/system/pause-processing")

                assert response.status_code == 500
        finally:
            app.dependency_overrides.clear()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
