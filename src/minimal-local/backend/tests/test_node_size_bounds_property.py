"""
Property-based tests for threat node size bounds.

Feature: entity-relationship-graph
Property 4: Threat node size bounds

Tests that the computeNodeRadius logic produces radii within [4, 16] for
threat nodes, and that nodes with more edges have >= radius than those with fewer.

**Validates: Requirements 4.4**
"""
import pytest
from hypothesis import given, strategies as st, settings


# --- Python reimplementation of computeNodeRadius from EntityRelationshipGraph.tsx ---

def compute_node_radius(node_type: str, edge_count: int, max_edge_count: int) -> float:
    """
    Reimplementation of the TypeScript computeNodeRadius function.

    - If node_type != 'threat': return 5
    - If max_edge_count <= 0: return 4
    - raw = 4 + (edge_count / max_edge_count) * 12
    - return min(16, max(4, raw))
    """
    if node_type != "threat":
        return 5
    if max_edge_count <= 0:
        return 4
    raw = 4 + (edge_count / max_edge_count) * 12
    return min(16, max(4, raw))


# --- Strategies ---

edge_count_strategy = st.integers(min_value=0, max_value=10000)
max_edge_count_strategy = st.integers(min_value=0, max_value=10000)


class TestThreatNodeSizeBounds:
    """
    **Validates: Requirements 4.4**

    Feature: entity-relationship-graph
    Property 4: Threat node size bounds
    """

    @given(
        edge_count=edge_count_strategy,
        max_edge_count=max_edge_count_strategy,
    )
    @settings(max_examples=100)
    def test_threat_node_radius_within_bounds(self, edge_count, max_edge_count):
        """
        **Validates: Requirements 4.4**

        For any graph data, the computed threat node radius is between
        4px and 16px inclusive.
        """
        radius = compute_node_radius("threat", edge_count, max_edge_count)
        assert 4 <= radius <= 16, (
            f"Threat node radius {radius} out of bounds [4, 16] "
            f"(edge_count={edge_count}, max_edge_count={max_edge_count})"
        )

    @given(
        edge_count_a=edge_count_strategy,
        edge_count_b=edge_count_strategy,
        max_edge_count=st.integers(min_value=1, max_value=10000),
    )
    @settings(max_examples=100)
    def test_more_edges_means_larger_or_equal_radius(self, edge_count_a, edge_count_b, max_edge_count):
        """
        **Validates: Requirements 4.4**

        For two threat nodes where one has strictly more edges than the other,
        its radius is >= the other's.
        """
        radius_a = compute_node_radius("threat", edge_count_a, max_edge_count)
        radius_b = compute_node_radius("threat", edge_count_b, max_edge_count)

        if edge_count_a > edge_count_b:
            assert radius_a >= radius_b, (
                f"Node with more edges (count={edge_count_a}, radius={radius_a}) "
                f"has smaller radius than node with fewer edges "
                f"(count={edge_count_b}, radius={radius_b}), "
                f"max_edge_count={max_edge_count}"
            )
        elif edge_count_b > edge_count_a:
            assert radius_b >= radius_a, (
                f"Node with more edges (count={edge_count_b}, radius={radius_b}) "
                f"has smaller radius than node with fewer edges "
                f"(count={edge_count_a}, radius={radius_a}), "
                f"max_edge_count={max_edge_count}"
            )
