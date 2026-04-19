"""
Property-based tests for build_graph_data pure transformer.

Feature: entity-relationship-graph
Property 1: Node completeness and uniqueness

Tests that build_graph_data produces exactly the right set of deduplicated
nodes for any valid input of entity-threat relationship rows.
"""
import pytest
from hypothesis import given, strategies as st, settings

from services.analytics import build_graph_data


# --- Strategies ---

ENTITY_TYPES = ["cve", "framework", "technique", "system"]

entity_type_strategy = st.sampled_from(ENTITY_TYPES)

entity_value_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), min_codepoint=48, max_codepoint=122),
    min_size=1,
    max_size=30,
)

threat_id_strategy = st.integers(min_value=1, max_value=10000)

threat_title_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd", "Zs"), min_codepoint=32, max_codepoint=122),
    min_size=1,
    max_size=50,
)


@st.composite
def entity_threat_row(draw):
    """Generate a single entity-threat relationship row dict."""
    return {
        "threat_id": draw(threat_id_strategy),
        "threat_title": draw(threat_title_strategy),
        "entity_type": draw(entity_type_strategy),
        "entity_value": draw(entity_value_strategy),
    }


entity_threat_rows_strategy = st.lists(entity_threat_row(), min_size=0, max_size=100)


class TestNodeCompletenessAndUniqueness:
    """
    **Validates: Requirements 1.2, 1.3, 2.1, 2.2, 2.4**

    Feature: entity-relationship-graph
    Property 1: Node completeness and uniqueness
    """

    @given(rows=entity_threat_rows_strategy)
    @settings(max_examples=100)
    def test_one_node_per_distinct_threat(self, rows):
        """
        **Validates: Requirements 1.2, 2.1**

        For any list of entity-threat rows, build_graph_data produces exactly
        one node per distinct threat_id with type="threat", correct label, and
        id equal to str(threat_id).
        """
        result = build_graph_data(rows)
        nodes = result["nodes"]

        threat_nodes = [n for n in nodes if n["type"] == "threat"]

        # Collect expected distinct threats (first occurrence wins for title)
        expected_threats: dict[str, str] = {}
        for row in rows:
            tid = str(row["threat_id"])
            if tid not in expected_threats:
                expected_threats[tid] = row["threat_title"]

        # Exactly one node per distinct threat_id
        assert len(threat_nodes) == len(expected_threats), (
            f"Expected {len(expected_threats)} threat nodes, got {len(threat_nodes)}"
        )

        # Each threat node has correct id, label, and type
        threat_node_map = {n["id"]: n for n in threat_nodes}
        for tid, title in expected_threats.items():
            assert tid in threat_node_map, f"Missing threat node for id={tid}"
            assert threat_node_map[tid]["label"] == title
            assert threat_node_map[tid]["type"] == "threat"

        # No duplicate threat node ids
        threat_ids = [n["id"] for n in threat_nodes]
        assert len(threat_ids) == len(set(threat_ids)), "Duplicate threat node ids found"

    @given(rows=entity_threat_rows_strategy)
    @settings(max_examples=100)
    def test_one_node_per_distinct_entity(self, rows):
        """
        **Validates: Requirements 1.3, 2.2, 2.4**

        For any list of entity-threat rows, build_graph_data produces exactly
        one node per distinct (entity_type, entity_value) pair with correct
        type, label, and composite id.
        """
        result = build_graph_data(rows)
        nodes = result["nodes"]

        entity_nodes = [n for n in nodes if n["type"] != "threat"]

        # Collect expected distinct entities
        expected_entities: dict[str, dict] = {}
        for row in rows:
            key = f"{row['entity_type']}:{row['entity_value']}"
            if key not in expected_entities:
                expected_entities[key] = {
                    "type": row["entity_type"],
                    "label": row["entity_value"],
                }

        # Exactly one node per distinct (entity_type, entity_value)
        assert len(entity_nodes) == len(expected_entities), (
            f"Expected {len(expected_entities)} entity nodes, got {len(entity_nodes)}"
        )

        # Each entity node has correct id, label, and type
        entity_node_map = {n["id"]: n for n in entity_nodes}
        for eid, expected in expected_entities.items():
            assert eid in entity_node_map, f"Missing entity node for id={eid}"
            assert entity_node_map[eid]["label"] == expected["label"]
            assert entity_node_map[eid]["type"] == expected["type"]

        # No duplicate entity node ids
        entity_ids = [n["id"] for n in entity_nodes]
        assert len(entity_ids) == len(set(entity_ids)), "Duplicate entity node ids found"

    @given(rows=entity_threat_rows_strategy)
    @settings(max_examples=100)
    def test_total_node_count(self, rows):
        """
        **Validates: Requirements 2.1, 2.2**

        For any list of entity-threat rows, the total node count equals
        the number of distinct threats plus the number of distinct entities.
        """
        result = build_graph_data(rows)
        nodes = result["nodes"]

        distinct_threats = {str(r["threat_id"]) for r in rows}
        distinct_entities = {
            f"{r['entity_type']}:{r['entity_value']}" for r in rows
        }

        expected_count = len(distinct_threats) + len(distinct_entities)
        assert len(nodes) == expected_count, (
            f"Expected {expected_count} total nodes "
            f"({len(distinct_threats)} threats + {len(distinct_entities)} entities), "
            f"got {len(nodes)}"
        )


class TestEdgeCompletenessAndUniqueness:
    """
    **Validates: Requirements 1.4, 2.3**

    Feature: entity-relationship-graph
    Property 2: Edge completeness and uniqueness
    """

    @given(rows=entity_threat_rows_strategy)
    @settings(max_examples=100)
    def test_one_edge_per_distinct_relationship(self, rows):
        """
        **Validates: Requirements 1.4, 2.3**

        For any list of entity-threat rows, build_graph_data produces exactly
        one edge per distinct (threat_id, entity_type, entity_value) triple.
        """
        result = build_graph_data(rows)
        edges = result["edges"]

        # Compute expected distinct relationships
        expected_triples = {
            (str(r["threat_id"]), r["entity_type"], r["entity_value"])
            for r in rows
        }

        assert len(edges) == len(expected_triples), (
            f"Expected {len(expected_triples)} edges, got {len(edges)}"
        )

        # Each edge should be unique (no duplicate source-target pairs)
        edge_pairs = [(e["source"], e["target"]) for e in edges]
        assert len(edge_pairs) == len(set(edge_pairs)), "Duplicate edges found"

    @given(rows=entity_threat_rows_strategy)
    @settings(max_examples=100)
    def test_edge_source_and_target_correctness(self, rows):
        """
        **Validates: Requirements 1.4, 2.3**

        For any list of entity-threat rows, each edge has source equal to the
        threat node id (str(threat_id)) and target equal to the entity node id
        ("{entity_type}:{entity_value}").
        """
        result = build_graph_data(rows)
        edges = result["edges"]
        nodes = result["nodes"]

        # Build lookup sets for validation
        threat_node_ids = {n["id"] for n in nodes if n["type"] == "threat"}
        entity_node_ids = {n["id"] for n in nodes if n["type"] != "threat"}

        for edge in edges:
            assert edge["source"] in threat_node_ids, (
                f"Edge source '{edge['source']}' is not a threat node id"
            )
            assert edge["target"] in entity_node_ids, (
                f"Edge target '{edge['target']}' is not an entity node id"
            )

    @given(rows=entity_threat_rows_strategy)
    @settings(max_examples=100)
    def test_total_edge_count_equals_distinct_relationships(self, rows):
        """
        **Validates: Requirements 2.3**

        For any list of entity-threat rows, the total edge count equals the
        number of distinct (threat_id, entity_type, entity_value) relationships.
        """
        result = build_graph_data(rows)
        edges = result["edges"]

        distinct_relationships = {
            (str(r["threat_id"]), f"{r['entity_type']}:{r['entity_value']}")
            for r in rows
        }

        assert len(edges) == len(distinct_relationships), (
            f"Expected {len(distinct_relationships)} edges for "
            f"{len(distinct_relationships)} distinct relationships, "
            f"got {len(edges)}"
        )


class TestGraphRoundTripReconstruction:
    """
    **Validates: Requirements 2.6**

    Feature: entity-relationship-graph
    Property 3: Graph round-trip reconstruction
    """

    @given(rows=entity_threat_rows_strategy)
    @settings(max_examples=100)
    def test_round_trip_reconstruction(self, rows):
        """
        **Validates: Requirements 2.6**

        For any list of entity-threat rows, transforming via build_graph_data
        and then reconstructing (threat_id, entity_type, entity_value) triples
        from nodes + edges produces a set equivalent to the distinct triples
        in the original input.
        """
        result = build_graph_data(rows)
        nodes = result["nodes"]
        edges = result["edges"]

        # Build a node lookup by id for reconstruction
        node_map = {n["id"]: n for n in nodes}

        # Reconstruct triples from edges
        reconstructed = set()
        for edge in edges:
            source_node = node_map[edge["source"]]
            target_node = node_map[edge["target"]]

            # source is a threat node → threat_id is the node id
            threat_id = source_node["id"]

            # target is an entity node → id is "{entity_type}:{entity_value}"
            entity_id = target_node["id"]
            entity_type, entity_value = entity_id.split(":", 1)

            reconstructed.add((threat_id, entity_type, entity_value))

        # Expected: distinct triples from original input
        expected = {
            (str(r["threat_id"]), r["entity_type"], r["entity_value"])
            for r in rows
        }

        assert reconstructed == expected, (
            f"Round-trip mismatch.\n"
            f"Expected {len(expected)} triples, got {len(reconstructed)}.\n"
            f"Missing: {expected - reconstructed}\n"
            f"Extra: {reconstructed - expected}"
        )
