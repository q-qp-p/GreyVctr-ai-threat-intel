"""
Unit Tests: Entity Cluster Graph API Endpoint

**Validates: Requirements 1.1, 1.6, 1.7, 1.8, 1.9**

Tests for GET /api/v1/analytics/entity-clusters/graph including:
- Response structure contains data.nodes, data.edges, meta
- build_graph_data([]) returns empty arrays
- severity_min > severity_max → 400
- date_from > date_to → 400
- Invalid entity_type → 400
- Timeout → 504
"""
import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from services.analytics import build_graph_data


class TestBuildGraphDataEmpty:
    """Test build_graph_data with empty input."""

    def test_empty_input_returns_empty_nodes_and_edges(self):
        """
        build_graph_data([]) should return empty nodes and edges arrays.

        Validates: Requirements 1.1
        """
        result = build_graph_data([])
        assert result == {"nodes": [], "edges": []}

    def test_empty_input_nodes_is_list(self):
        """Nodes should be a list type."""
        result = build_graph_data([])
        assert isinstance(result["nodes"], list)

    def test_empty_input_edges_is_list(self):
        """Edges should be a list type."""
        result = build_graph_data([])
        assert isinstance(result["edges"], list)


class TestGraphEndpointResponseStructure:
    """
    Test that the graph endpoint returns the correct response structure.

    Validates: Requirements 1.1, 1.9
    """

    def test_response_contains_data_and_meta(self):
        """Response should contain top-level 'data' and 'meta' keys."""
        mock_graph_result = {
            "data": {
                "nodes": [
                    {"id": "1", "label": "Threat A", "type": "threat"},
                    {"id": "cve:CVE-2024-001", "label": "CVE-2024-001", "type": "cve"},
                ],
                "edges": [
                    {"source": "1", "target": "cve:CVE-2024-001"},
                ],
            },
            "meta": {
                "total_nodes": 2,
                "total_edges": 1,
                "filters_applied": {},
                "computed_at": "2025-01-01T00:00:00",
            },
        }

        with patch("api.analytics.AnalyticsService") as MockService:
            instance = AsyncMock()
            instance.get_entity_graph.return_value = mock_graph_result
            MockService.return_value = instance

            from main import app
            client = TestClient(app)
            response = client.get("/api/v1/analytics/entity-clusters/graph")

        assert response.status_code == 200
        body = response.json()
        assert "data" in body
        assert "meta" in body

    def test_data_contains_nodes_and_edges(self):
        """data should contain 'nodes' and 'edges' arrays."""
        mock_graph_result = {
            "data": {
                "nodes": [{"id": "1", "label": "T", "type": "threat"}],
                "edges": [],
            },
            "meta": {
                "total_nodes": 1,
                "total_edges": 0,
                "filters_applied": {},
                "computed_at": "2025-01-01T00:00:00",
            },
        }

        with patch("api.analytics.AnalyticsService") as MockService:
            instance = AsyncMock()
            instance.get_entity_graph.return_value = mock_graph_result
            MockService.return_value = instance

            from main import app
            client = TestClient(app)
            response = client.get("/api/v1/analytics/entity-clusters/graph")

        body = response.json()
        assert "nodes" in body["data"]
        assert "edges" in body["data"]
        assert isinstance(body["data"]["nodes"], list)
        assert isinstance(body["data"]["edges"], list)

    def test_meta_contains_required_fields(self):
        """meta should contain total_nodes, total_edges, filters_applied, computed_at."""
        mock_graph_result = {
            "data": {"nodes": [], "edges": []},
            "meta": {
                "total_nodes": 0,
                "total_edges": 0,
                "filters_applied": {"entity_type": None, "min_shared": 2},
                "computed_at": "2025-01-01T00:00:00",
            },
        }

        with patch("api.analytics.AnalyticsService") as MockService:
            instance = AsyncMock()
            instance.get_entity_graph.return_value = mock_graph_result
            MockService.return_value = instance

            from main import app
            client = TestClient(app)
            response = client.get("/api/v1/analytics/entity-clusters/graph")

        meta = response.json()["meta"]
        assert "total_nodes" in meta
        assert "total_edges" in meta
        assert "filters_applied" in meta
        assert "computed_at" in meta


class TestGraphEndpointValidation:
    """
    Test validation error responses (HTTP 400).

    Validates: Requirements 1.6, 1.7
    """

    def test_severity_min_greater_than_severity_max_returns_400(self):
        """
        severity_min > severity_max should return HTTP 400.

        Validates: Requirements 1.6
        """
        from main import app
        client = TestClient(app)
        response = client.get(
            "/api/v1/analytics/entity-clusters/graph",
            params={"severity_min": 8, "severity_max": 3},
        )
        assert response.status_code == 400
        body = response.json()
        assert body["error"] == "validation_error"
        assert "severity_min" in body["detail"]

    def test_date_from_after_date_to_returns_400(self):
        """
        date_from > date_to should return HTTP 400.

        Validates: Requirements 1.7
        """
        from main import app
        client = TestClient(app)
        response = client.get(
            "/api/v1/analytics/entity-clusters/graph",
            params={
                "date_from": "2025-06-01T00:00:00",
                "date_to": "2025-01-01T00:00:00",
            },
        )
        assert response.status_code == 400
        body = response.json()
        assert body["error"] == "validation_error"
        assert "date_from" in body["detail"]

    def test_invalid_entity_type_returns_400(self):
        """
        Invalid entity_type should return HTTP 400.

        Validates: Requirements 1.6
        """
        from main import app
        client = TestClient(app)
        response = client.get(
            "/api/v1/analytics/entity-clusters/graph",
            params={"entity_type": "invalid_type"},
        )
        assert response.status_code == 400
        body = response.json()
        assert body["error"] == "validation_error"
        assert "entity_type" in body["detail"]


class TestGraphEndpointTimeout:
    """
    Test timeout handling (HTTP 504).

    Validates: Requirements 1.8
    """

    def test_timeout_returns_504(self):
        """
        Database timeout should return HTTP 504 with timeout error.

        Validates: Requirements 1.8
        """
        from services.analytics import AnalyticsTimeoutError

        with patch("api.analytics.AnalyticsService") as MockService:
            instance = AsyncMock()
            instance.get_entity_graph.side_effect = AnalyticsTimeoutError(
                "Analytics query exceeded 5 second timeout"
            )
            MockService.return_value = instance

            from main import app
            client = TestClient(app)
            response = client.get("/api/v1/analytics/entity-clusters/graph")

        assert response.status_code == 504
        body = response.json()
        assert body["error"] == "timeout"
        assert "5 second timeout" in body["detail"]
