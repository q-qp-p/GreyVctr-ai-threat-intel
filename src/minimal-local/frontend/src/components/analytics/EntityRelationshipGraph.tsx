import { useState, useMemo, useCallback, useRef, useEffect } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import type { GraphData, GraphNode } from '../../services/api'

// --- Color mapping ---
const NODE_COLORS: Record<string, string> = {
  threat: '#6366f1',
  cve: '#ef4444',
  framework: '#6366f1',
  technique: '#f59e0b',
  system: '#10b981',
}

const DEFAULT_NODE_COLOR = '#9ca3af'

const LEGEND_ITEMS: { type: string; color: string }[] = [
  { type: 'threat', color: '#6366f1' },
  { type: 'cve', color: '#ef4444' },
  { type: 'framework', color: '#6366f1' },
  { type: 'technique', color: '#f59e0b' },
  { type: 'system', color: '#10b981' },
]

// --- Node sizing ---
export function computeNodeRadius(
  nodeType: string,
  edgeCount: number,
  maxEdgeCount: number
): number {
  if (nodeType !== 'threat') return 5
  if (maxEdgeCount <= 0) return 4
  const raw = 4 + (edgeCount / maxEdgeCount) * 12
  return Math.min(16, Math.max(4, raw))
}

// --- Types for internal graph data ---
interface InternalNode extends GraphNode {
  edgeCount: number
  color: string
  radius: number
  x?: number
  y?: number
}

interface InternalLink {
  source: string
  target: string
}

interface EntityRelationshipGraphProps {
  data: GraphData
}

export default function EntityRelationshipGraph({ data }: EntityRelationshipGraphProps) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 })

  // Resize observer — tracks both width and height
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect
        setDimensions({
          width: Math.max(300, width),
          height: Math.max(400, height),
        })
      }
    })
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  // Precompute edge counts and max
  const edgeCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const edge of data.edges) {
      counts[edge.source] = (counts[edge.source] || 0) + 1
      counts[edge.target] = (counts[edge.target] || 0) + 1
    }
    return counts
  }, [data.edges])

  const maxEdgeCount = useMemo(() => {
    let max = 0
    for (const node of data.nodes) {
      if (node.type === 'threat') {
        const count = edgeCounts[node.id] || 0
        if (count > max) max = count
      }
    }
    return max
  }, [data.nodes, edgeCounts])

  // Build internal nodes with precomputed properties
  const internalNodes: InternalNode[] = useMemo(
    () =>
      data.nodes.map((n) => {
        const ec = edgeCounts[n.id] || 0
        return {
          ...n,
          edgeCount: ec,
          color: NODE_COLORS[n.type] ?? DEFAULT_NODE_COLOR,
          radius: computeNodeRadius(n.type, ec, maxEdgeCount),
        }
      }),
    [data.nodes, edgeCounts, maxEdgeCount]
  )

  const internalLinks: InternalLink[] = useMemo(
    () => data.edges.map((e) => ({ source: e.source, target: e.target })),
    [data.edges]
  )

  const graphData = useMemo(
    () => ({ nodes: internalNodes, links: internalLinks }),
    [internalNodes, internalLinks]
  )

  // Connected set for highlighting
  const connectedSet = useMemo(() => {
    if (!selectedNodeId) return new Set<string>()
    const set = new Set<string>([selectedNodeId])
    for (const edge of data.edges) {
      if (edge.source === selectedNodeId) set.add(edge.target)
      if (edge.target === selectedNodeId) set.add(edge.source)
    }
    return set
  }, [selectedNodeId, data.edges])

  // Selected node detail
  const selectedNode = useMemo(() => {
    if (!selectedNodeId) return null
    return internalNodes.find((n) => n.id === selectedNodeId) ?? null
  }, [selectedNodeId, internalNodes])

  const selectedNodeThreatCount = useMemo(() => {
    if (!selectedNode || selectedNode.type === 'threat') return 0
    let count = 0
    for (const edge of data.edges) {
      if (edge.target === selectedNode.id) count++
    }
    return count
  }, [selectedNode, data.edges])

  // Handlers
  const handleNodeClick = useCallback(
    (node: { id?: string | number }) => {
      if (node.id != null) {
        setSelectedNodeId(String(node.id))
      }
    },
    []
  )

  const handleBackgroundClick = useCallback(() => {
    setSelectedNodeId(null)
  }, [])

  // Canvas node renderer
  const paintNode = useCallback(
    (node: InternalNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const x = node.x ?? 0
      const y = node.y ?? 0
      const r = node.radius
      const isHighlighted = selectedNodeId ? connectedSet.has(node.id) : true
      const alpha = isHighlighted ? 1 : 0.15

      ctx.beginPath()
      ctx.arc(x, y, r, 0, 2 * Math.PI)
      ctx.fillStyle = node.color
      ctx.globalAlpha = alpha
      ctx.fill()

      // Selection ring
      if (node.id === selectedNodeId) {
        ctx.strokeStyle = '#ffffff'
        ctx.lineWidth = 2 / globalScale
        ctx.stroke()
      }

      ctx.globalAlpha = 1

      // Label for larger scales
      if (globalScale > 1.5) {
        const fontSize = Math.max(10 / globalScale, 2)
        ctx.font = `${fontSize}px sans-serif`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'top'
        ctx.fillStyle = isHighlighted ? '#e5e7eb' : 'rgba(229,231,235,0.3)'
        ctx.fillText(node.label, x, y + r + 2 / globalScale)
      }
    },
    [selectedNodeId, connectedSet]
  )

  // Pointer area for hit detection
  const paintPointerArea = useCallback(
    (node: InternalNode, color: string, ctx: CanvasRenderingContext2D) => {
      const x = node.x ?? 0
      const y = node.y ?? 0
      ctx.beginPath()
      ctx.arc(x, y, node.radius + 2, 0, 2 * Math.PI)
      ctx.fillStyle = color
      ctx.fill()
    },
    []
  )

  // Tooltip
  const nodeLabel = useCallback(
    (node: InternalNode) =>
      `<div style="background:#1f2937;color:#e5e7eb;padding:6px 10px;border-radius:6px;font-size:13px;border:1px solid #374151">
        <strong>${node.label}</strong><br/>
        Type: ${node.type}<br/>
        Connections: ${node.edgeCount}
      </div>`,
    []
  )

  // Link styling
  const linkColor = useCallback(
    (link: { source?: string | { id?: string }; target?: string | { id?: string } }) => {
      if (!selectedNodeId) return 'rgba(156,163,175,0.3)'
      const srcId = typeof link.source === 'object' ? link.source?.id : link.source
      const tgtId = typeof link.target === 'object' ? link.target?.id : link.target
      if (srcId === selectedNodeId || tgtId === selectedNodeId) return 'rgba(99,102,241,0.7)'
      return 'rgba(156,163,175,0.08)'
    },
    [selectedNodeId]
  )

  const linkWidth = useCallback(
    (link: { source?: string | { id?: string }; target?: string | { id?: string } }) => {
      if (!selectedNodeId) return 0.5
      const srcId = typeof link.source === 'object' ? link.source?.id : link.source
      const tgtId = typeof link.target === 'object' ? link.target?.id : link.target
      if (srcId === selectedNodeId || tgtId === selectedNodeId) return 1.5
      return 0.3
    },
    [selectedNodeId]
  )

  const isLargeDataset = data.nodes.length > 200

  return (
    <div>
      {/* Large dataset warning */}
      {isLargeDataset && (
        <div className="mb-3 px-3 py-2 bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-700 rounded-md text-xs text-yellow-800 dark:text-yellow-200">
          Large dataset ({data.nodes.length} nodes). Performance may be affected.
        </div>
      )}

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-3 mb-3">
        {LEGEND_ITEMS.map((item) => (
          <div
            key={item.type}
            className="flex items-center gap-1.5 text-xs text-gray-600 dark:text-gray-400"
          >
            <span
              className="inline-block w-3 h-3 rounded-full"
              style={{ backgroundColor: item.color }}
            />
            <span className="capitalize">{item.type}</span>
          </div>
        ))}
      </div>

      {/* Graph container */}
      <div
        ref={containerRef}
        className="relative border border-gray-200 dark:border-gray-600 rounded-md overflow-hidden"
        style={{ minHeight: 400, height: 'calc(100vh - 420px)' }}
      >
        <ForceGraph2D
          graphData={graphData}
          width={dimensions.width}
          height={dimensions.height}
          nodeCanvasObject={paintNode as any}
          nodeCanvasObjectMode={() => 'replace'}
          nodePointerAreaPaint={paintPointerArea as any}
          nodeLabel={nodeLabel as any}
          linkColor={linkColor as any}
          linkWidth={linkWidth as any}
          onNodeClick={handleNodeClick as any}
          onBackgroundClick={handleBackgroundClick}
          minZoom={0.1}
          maxZoom={10}
          cooldownTicks={100}
          enablePanInteraction={true}
          enableZoomInteraction={true}
        />
      </div>

      {/* Detail panel */}
      {selectedNode && (
        <div className="mt-4 border border-gray-200 dark:border-gray-600 rounded-md p-4 bg-gray-50 dark:bg-gray-700/50">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100">
                {selectedNode.label}
              </h3>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                <span
                  className="inline-block w-2 h-2 rounded-full mr-1"
                  style={{ backgroundColor: selectedNode.color }}
                />
                <span className="capitalize">{selectedNode.type}</span>
                {' · '}
                {selectedNode.edgeCount} connection{selectedNode.edgeCount !== 1 ? 's' : ''}
              </p>
            </div>
            <button
              onClick={() => setSelectedNodeId(null)}
              className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 text-sm"
              aria-label="Close detail panel"
            >
              ✕
            </button>
          </div>

          {selectedNode.type === 'threat' ? (
            <a
              href={`/threats/${selectedNode.id}`}
              className="inline-flex items-center text-sm text-indigo-600 dark:text-indigo-400 hover:underline"
            >
              View threat details →
            </a>
          ) : (
            <div className="text-xs text-gray-600 dark:text-gray-300 space-y-1">
              <p>
                Value: <span className="font-mono">{selectedNode.label}</span>
              </p>
              <p>
                Type: <span className="capitalize">{selectedNode.type}</span>
              </p>
              <p>Connected threats: {selectedNodeThreatCount}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
