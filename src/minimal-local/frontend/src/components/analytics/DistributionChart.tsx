import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import type { DistributionItem, DistributionsParams } from '../../services/api'

const DIMENSION_OPTIONS: { value: DistributionsParams['dimension']; label: string }[] = [
  { value: 'threat_type', label: 'Threat Type' },
  { value: 'severity', label: 'Severity' },
  { value: 'source', label: 'Source' },
]

interface DistributionChartProps {
  data: DistributionItem[]
  filters: DistributionsParams
  onFilterChange: (filters: DistributionsParams) => void
}

export default function DistributionChart({ data, filters, onFilterChange }: DistributionChartProps) {
  const dimension = (filters as DistributionsParams).dimension || 'threat_type'

  const handleDimensionChange = (value: DistributionsParams['dimension']) => {
    onFilterChange({ ...filters, dimension: value })
  }

  const btnBase =
    'px-3 py-1 text-sm rounded-md border transition-colors'
  const btnActive =
    'bg-indigo-600 text-white border-indigo-600'
  const btnInactive =
    'bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-600'

  return (
    <div>
      <div className="flex items-center gap-1 mb-4">
        <span className="text-sm text-gray-500 dark:text-gray-400 mr-1">Dimension:</span>
        {DIMENSION_OPTIONS.map((opt) => (
          <button
            key={opt.value}
            onClick={() => handleDimensionChange(opt.value)}
            className={`${btnBase} ${dimension === opt.value ? btnActive : btnInactive}`}
          >
            {opt.label}
          </button>
        ))}
      </div>

      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
          <XAxis
            dataKey="label"
            tick={{ fontSize: 12 }}
            className="text-gray-600 dark:text-gray-400"
          />
          <YAxis
            allowDecimals={false}
            tick={{ fontSize: 12 }}
            className="text-gray-600 dark:text-gray-400"
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'var(--tooltip-bg, #fff)',
              border: '1px solid #e5e7eb',
              borderRadius: '6px',
              fontSize: '13px',
            }}
          />
          <Bar dataKey="count" name="Threats" fill="#6366f1" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
