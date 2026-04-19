import { useState, useMemo } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import type { EntityClusterItem } from '../../services/api'

const ENTITY_TYPE_COLORS: Record<string, string> = {
  cve: '#ef4444',
  framework: '#6366f1',
  technique: '#f59e0b',
  system: '#10b981',
}

const DEFAULT_COLOR = '#8b5cf6'

function getEntityColor(entityType: string): string {
  return ENTITY_TYPE_COLORS[entityType] ?? DEFAULT_COLOR
}

interface EntityClusterViewProps {
  data: EntityClusterItem[]
}

export default function EntityClusterView({ data }: EntityClusterViewProps) {
  const [selectedCluster, setSelectedCluster] = useState<EntityClusterItem | null>(null)

  const chartData = useMemo(
    () =>
      [...data]
        .sort((a, b) => b.threat_count - a.threat_count)
        .slice(0, 30),
    [data]
  )

  const entityTypes = useMemo(() => {
    const types = new Set(chartData.map((d) => d.entity_type))
    return [...types].sort()
  }, [chartData])

  const handleBarClick = (_: unknown, index: number) => {
    const clicked = chartData[index]
    if (!clicked) return
    setSelectedCluster((prev) =>
      prev?.entity_value === clicked.entity_value && prev?.entity_type === clicked.entity_type
        ? null
        : clicked
    )
  }

  return (
    <div>
      {/* Legend */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        {entityTypes.map((type) => (
          <div key={type} className="flex items-center gap-1.5 text-xs text-gray-600 dark:text-gray-400">
            <span
              className="inline-block w-3 h-3 rounded-sm"
              style={{ backgroundColor: getEntityColor(type) }}
            />
            <span className="capitalize">{type}</span>
          </div>
        ))}
      </div>

      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={chartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
          <XAxis
            dataKey="entity_value"
            tick={{ fontSize: 11 }}
            interval={0}
            angle={-35}
            textAnchor="end"
            height={80}
            className="text-gray-600 dark:text-gray-400"
          />
          <YAxis
            allowDecimals={false}
            tick={{ fontSize: 12 }}
            className="text-gray-600 dark:text-gray-400"
            label={{ value: 'Threat Count', angle: -90, position: 'insideLeft', style: { fontSize: 12 } }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'var(--tooltip-bg, #1f2937)',
              border: '1px solid #374151',
              borderRadius: '6px',
              fontSize: '13px',
              color: '#e5e7eb',
            }}
            formatter={(value: number, _name: string, props: { payload: EntityClusterItem }) => [
              `${value} threats`,
              props.payload.entity_type,
            ]}
            labelFormatter={(label) => `${label}`}
          />
          <Bar
            dataKey="threat_count"
            name="Threats"
            radius={[4, 4, 0, 0]}
            cursor="pointer"
            onClick={handleBarClick}
          >
            {chartData.map((entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={getEntityColor(entry.entity_type)}
                opacity={
                  selectedCluster &&
                  selectedCluster.entity_value === entry.entity_value &&
                  selectedCluster.entity_type === entry.entity_type
                    ? 1
                    : 0.8
                }
                stroke={
                  selectedCluster &&
                  selectedCluster.entity_value === entry.entity_value &&
                  selectedCluster.entity_type === entry.entity_type
                    ? '#1e1b4b'
                    : 'none'
                }
                strokeWidth={2}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      {/* Detail panel */}
      {selectedCluster && (
        <div className="mt-4 border border-gray-200 dark:border-gray-600 rounded-md p-4 bg-gray-50 dark:bg-gray-700/50">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100">
                {selectedCluster.entity_value}
              </h3>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                <span
                  className="inline-block w-2 h-2 rounded-sm mr-1"
                  style={{ backgroundColor: getEntityColor(selectedCluster.entity_type) }}
                />
                <span className="capitalize">{selectedCluster.entity_type}</span>
                {' · '}
                {selectedCluster.threat_count} threat{selectedCluster.threat_count !== 1 ? 's' : ''}
              </p>
            </div>
            <button
              onClick={() => setSelectedCluster(null)}
              className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 text-sm"
              aria-label="Close detail panel"
            >
              ✕
            </button>
          </div>

          <div className="space-y-1 max-h-48 overflow-y-auto">
            {selectedCluster.threat_ids.map((id) => (
              <div
                key={id}
                className="flex items-center gap-2 text-xs px-2 py-1.5 rounded bg-white dark:bg-gray-800 border border-gray-100 dark:border-gray-600"
              >
                <span className="font-mono text-gray-700 dark:text-gray-300 truncate">
                  {id}
                </span>
                <a
                  href={`/threats/${id}`}
                  className="ml-auto text-indigo-600 dark:text-indigo-400 hover:underline whitespace-nowrap"
                >
                  View →
                </a>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
