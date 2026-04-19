# Analytics Feature

The Analytics page provides visual insight into threat intelligence data collected by AI Shield Intelligence. It surfaces trends, distributions, MITRE ATLAS heatmaps, entity co-occurrence clusters, and severity cross-tabulations — all computed via SQL aggregation in PostgreSQL.

Access the Analytics page at **http://localhost:3000/analytics** (requires authentication).

## API Endpoints

All analytics endpoints live under `/api/v1/analytics/` and share a common response envelope:

```json
{
  "data": [ ... ],
  "meta": {
    "total_records": 42,
    "filters_applied": { ... },
    "computed_at": "2025-01-15T10:30:00"
  }
}
```

### Common Filter Parameters

Every endpoint accepts these optional query parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `date_from` | ISO 8601 datetime | Include threats published on or after this date |
| `date_to` | ISO 8601 datetime | Include threats published on or before this date |
| `threat_type` | string | Filter by threat type (e.g., `adversarial`, `prompt_injection`) |
| `severity_min` | int (1–10) | Minimum severity (inclusive) |
| `severity_max` | int (1–10) | Maximum severity (inclusive) |
| `source` | string | Filter by source name |
| `include_unknown` | boolean | Include threats with unknown/empty threat_type (default: `true`) |

Validation rules:
- `severity_min` must not exceed `severity_max` (HTTP 400)
- `date_from` must not be after `date_to` (HTTP 400)

---

### GET /api/v1/analytics/trends

Returns time-series threat counts bucketed by time granularity.

**Endpoint-specific parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `granularity` | string | `month` | Time bucket: `day`, `week`, or `month` |
| `group_by` | string | _(none)_ | Optional grouping: `threat_type`, `severity`, or `source` |

**Example request:**

```
GET /api/v1/analytics/trends?granularity=month&group_by=threat_type&severity_min=5
```

**Example response:**

```json
{
  "data": [
    { "period": "2025-01-01T00:00:00", "count": 12, "group": "adversarial" },
    { "period": "2025-01-01T00:00:00", "count": 8, "group": "prompt_injection" },
    { "period": "2025-02-01T00:00:00", "count": 15, "group": "adversarial" },
    { "period": "2025-02-01T00:00:00", "count": 5, "group": "prompt_injection" }
  ],
  "meta": {
    "total_records": 4,
    "filters_applied": {
      "granularity": "month",
      "group_by": "threat_type",
      "date_from": null,
      "date_to": null,
      "threat_type": null,
      "severity_min": 5,
      "severity_max": null,
      "source": null
    },
    "computed_at": "2025-01-15T10:30:00"
  }
}
```

**Error responses:**
- `400` — Invalid `granularity` or `group_by` value

---

### GET /api/v1/analytics/distributions

Returns threat counts grouped by a categorical dimension.

**Endpoint-specific parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `dimension` | string | Yes | Dimension to group by: `threat_type`, `severity`, or `source` |

**Example request:**

```
GET /api/v1/analytics/distributions?dimension=threat_type
```

**Example response:**

```json
{
  "data": [
    { "label": "adversarial", "count": 45 },
    { "label": "prompt_injection", "count": 32 },
    { "label": "extraction", "count": 18 },
    { "label": "poisoning", "count": 12 }
  ],
  "meta": {
    "total_records": 4,
    "filters_applied": {
      "dimension": "threat_type",
      "date_from": null,
      "date_to": null,
      "threat_type": null,
      "severity_min": null,
      "severity_max": null,
      "source": null
    },
    "computed_at": "2025-01-15T10:30:00"
  }
}
```

**Ordering:**
- `severity` dimension: ordered ascending (1 through 10)
- `threat_type` and `source` dimensions: ordered by count descending

**Error responses:**
- `400` — Invalid `dimension` value

---

### GET /api/v1/analytics/mitre-heatmap

Returns MITRE ATLAS tactic × technique frequency counts.

This endpoint uses only the common filter parameters (no endpoint-specific params).

**Example request:**

```
GET /api/v1/analytics/mitre-heatmap?threat_type=adversarial
```

**Example response:**

```json
{
  "data": [
    { "tactic": "Reconnaissance", "technique": "Search for Victim's Publicly Available ML Artifacts", "technique_id": "AML.T0002", "count": 14 },
    { "tactic": "ML Attack Staging", "technique": "Craft Adversarial Data", "technique_id": "AML.T0043", "count": 9 },
    { "tactic": "Initial Access", "technique": "ML Supply Chain Compromise", "technique_id": "AML.T0010", "count": 6 }
  ],
  "meta": {
    "total_records": 3,
    "filters_applied": {
      "date_from": null,
      "date_to": null,
      "threat_type": "adversarial",
      "severity_min": null,
      "severity_max": null,
      "source": null
    },
    "computed_at": "2025-01-15T10:30:00"
  }
}
```

---

### GET /api/v1/analytics/entity-clusters

Returns groups of threats that share common extracted entities, revealing natural clusters in the data.

**Endpoint-specific parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `entity_type` | string | _(none)_ | Filter by entity type: `cve`, `framework`, `technique`, or `system` |
| `min_shared` | int | `2` | Minimum number of threats sharing an entity to form a cluster |

**Example request:**

```
GET /api/v1/analytics/entity-clusters?entity_type=cve&min_shared=3
```

**Example response:**

```json
{
  "data": [
    {
      "entity_value": "CVE-2024-1234",
      "entity_type": "cve",
      "threat_count": 5,
      "threat_ids": ["abc-123", "def-456", "ghi-789", "jkl-012", "mno-345"]
    },
    {
      "entity_value": "CVE-2024-5678",
      "entity_type": "cve",
      "threat_count": 3,
      "threat_ids": ["pqr-678", "stu-901", "vwx-234"]
    }
  ],
  "meta": {
    "total_records": 2,
    "filters_applied": {
      "entity_type": "cve",
      "min_shared": 3,
      "date_from": null,
      "date_to": null,
      "threat_type": null,
      "severity_min": null,
      "severity_max": null,
      "source": null
    },
    "computed_at": "2025-01-15T10:30:00"
  }
}
```

**Error responses:**
- `400` — Invalid `entity_type` value

---

### GET /api/v1/analytics/entity-clusters/graph

Returns entity-threat relationships as a graph of nodes and edges, suitable for force-directed network visualization. Nodes represent threats or entities; edges represent relationships between them.

**Endpoint-specific parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `entity_type` | string | _(none)_ | Filter by entity type: `cve`, `framework`, `technique`, or `system` |
| `min_shared` | int | `2` | Minimum number of threats sharing an entity to be included |
| `include_unknown` | boolean | `false` | Include entities with unknown/empty type or value (overrides the common filter default of `true`) |

**Example request:**

```
GET /api/v1/analytics/entity-clusters/graph?entity_type=cve&min_shared=3
```

**Example response:**

```json
{
  "data": {
    "nodes": [
      { "id": "abc-123", "label": "Adversarial Attack on GPT-4", "type": "threat" },
      { "id": "def-456", "label": "Prompt Injection via PDF", "type": "threat" },
      { "id": "cve:CVE-2024-1234", "label": "CVE-2024-1234", "type": "cve" }
    ],
    "edges": [
      { "source": "abc-123", "target": "cve:CVE-2024-1234" },
      { "source": "def-456", "target": "cve:CVE-2024-1234" }
    ]
  },
  "meta": {
    "total_nodes": 3,
    "total_edges": 2,
    "filters_applied": {
      "entity_type": "cve",
      "min_shared": 3,
      "date_from": null,
      "date_to": null,
      "threat_type": null,
      "severity_min": null,
      "severity_max": null,
      "source": null
    },
    "computed_at": "2025-01-15T10:30:00"
  }
}
```

**Node types:**
- Threat nodes: `id` = threat UUID, `label` = threat title, `type` = `"threat"`
- Entity nodes: `id` = `"{entity_type}:{entity_value}"`, `label` = entity value, `type` = entity type

**Error responses:**
- `400` — Invalid `entity_type` value

---

### GET /api/v1/analytics/severity-matrix

Returns a cross-tabulation of threat counts at each severity level × threat type intersection.

This endpoint uses only the common filter parameters (no endpoint-specific params).

**Example request:**

```
GET /api/v1/analytics/severity-matrix?source=arXiv
```

**Example response:**

```json
{
  "data": [
    { "severity": 3, "threat_type": "adversarial", "count": 7 },
    { "severity": 5, "threat_type": "adversarial", "count": 12 },
    { "severity": 7, "threat_type": "prompt_injection", "count": 9 },
    { "severity": 8, "threat_type": "extraction", "count": 4 }
  ],
  "meta": {
    "total_records": 4,
    "filters_applied": {
      "date_from": null,
      "date_to": null,
      "threat_type": null,
      "severity_min": null,
      "severity_max": null,
      "source": "arXiv"
    },
    "computed_at": "2025-01-15T10:30:00"
  }
}
```

---

## Visualizations

The Analytics page renders five chart sections, each driven by one of the API endpoints above. A shared Filter Panel at the top constrains all visualizations simultaneously.

### Filter Panel

A toolbar with date range pickers, threat type dropdown, severity range inputs, source dropdown, an "Include unknown / unclassified threats" checkbox, and a Reset Filters button. Changing any filter re-fetches all visible charts. Dropdown options are populated from the database. The unknown filter is checked by default; unchecking it excludes threats with null, empty, or "unknown" threat types from all visualizations.

### Trend Chart

Displays threat volume over time as a line/area chart (Recharts). Includes a granularity toggle (day / week / month) and an optional group-by selector. When grouped, each series is color-coded with a legend. Defaults to monthly granularity.

**Data source:** `GET /api/v1/analytics/trends`

### Distribution Chart

A bar chart showing the breakdown of threats by a selected dimension (threat type, severity, or source). Severity bars are ordered 1–10; other dimensions are ordered by count descending.

**Data source:** `GET /api/v1/analytics/distributions`

### MITRE Heatmap

A grid visualization mapping MITRE ATLAS tactics against techniques. Cell color intensity represents frequency — darker cells indicate higher counts. Hovering over a cell shows a tooltip with the tactic name, technique name, technique ID, and exact count.

**Data source:** `GET /api/v1/analytics/mitre-heatmap`

### Entity Cluster View

A bar chart showing clusters of threats that share common entities (CVEs, techniques, frameworks, systems). Each bar represents an entity with its threat count. Clicking a cluster expands a detail panel listing the threats in that cluster with their title, severity, and threat type.

A toggle above the chart lets users switch between "Bar Chart" and "Graph" views. The graph view renders a force-directed network where threat nodes and entity nodes are connected by edges, color-coded by type (threat, CVE, framework, technique, system). Threat nodes are sized proportionally to their connection count. Hovering shows a tooltip; clicking a node highlights its connections and opens a detail panel. The graph supports zoom (0.1x–10x) and pan. A warning appears when the dataset exceeds 200 nodes.

**Data source:** `GET /api/v1/analytics/entity-clusters` (bar chart), `GET /api/v1/analytics/entity-clusters/graph` (graph view)

### Severity Matrix

A heatmap or stacked bar chart showing threat counts at the intersection of severity levels (rows, 1–10) and threat types (columns). Helps identify which threat categories tend to be most severe.

**Data source:** `GET /api/v1/analytics/severity-matrix`

---

## Error Handling

| Scenario | HTTP Status | Response |
|----------|-------------|----------|
| Invalid parameter value | 400 | `{ "error": "validation_error", "detail": "..." }` |
| Query timeout (>5s) | 504 | `{ "error": "timeout", "detail": "Analytics query exceeded 5 second timeout" }` |
| Database unavailable | 503 | `{ "error": "service_unavailable", "detail": "..." }` |

On the frontend, failed API calls show a "Failed to load data" message with a retry button. Empty datasets display a "No data available" placeholder.
