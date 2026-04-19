import { useMemo } from 'react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'
import type { TrendItem, AnalyticsFilterParams, TrendsParams } from '../../services/api'

const GRANULARITY_OPTIONS: { value: TrendsParams['granularity']; label: string }[] = [
  { value: 'day', label: 'Day' },
  { value: 'week', label: 'Week' },
  { value: 'month', label: 'Month' },
]

const GROUP_BY_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'None' },
  { value: 'threat_type', label: 'Threat Type' },
  { value: 'severity', label: 'Severity' },
  { value: 'source', label: 'Source' },
]

const SERIES_COLORS = [
  '#6366f1', '#f59e0b', '#10b981', '#ef4444', '#8b5cf6',
  '#ec4899', '#14b8a6', '#f97316', '#3b82f6', '#84cc16',
]

interface TrendChartProps {
  data: TrendItem[]
  filters: AnalyticsFilterParams
  onFilterChange: (filters: AnalyticsFilterParams & { granularity?: string; group_by?: string }) => void
}

function formatDateLabel(period: string, granularity: string): string {
  const date = new Date(period)
  if (isNaN(date.getTime())) return period
  if (granularity === 'day') {
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
  }
  if (granularity === 'week') {
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
  }
  return date.toLocaleDateString('en-US', { month: 'short', year: 'numeric' })
}

export default function TrendChart({ data, filters, onFilterChange }: TrendChartProps) {
  const granularity = (filters as TrendsParams).granularity || 'month'
  const groupBy = (filters as TrendsParams).group_by || ''

  const { chartData, groupKeys } = useMemo(() => {
    if (!groupBy) {
      // Single series: just map period -> count
      const sorted = [...data].sort(
        (a, b) => new Date(a.period).getTime() - new Date(b.period).getTime()
      )
      return {
        chartData: sorted.map((item) => ({
          period: item.period,
          label: formatDateLabel(item.period, granularity),
          count: item.count,
        })),
        groupKeys: [] as string[],
      }
    }

    // Grouped series: pivot data so each period row has keys per group
    const periodMap = new Map<string, Record<string, number>>()
    const groups = new Set<string>()

    for (const item of data) {
      const group = item.group ?? 'unknown'
      groups.add(group)
      if (!periodMap.has(item.period)) {
        periodMap.set(item.period, {})
      }
      const row = periodMap.get(item.period)!
      row[group] = (row[group] || 0) + item.count
    }

    const sortedPeriods = [...periodMap.keys()].sort(
      (a, b) => new Date(a).getTime() - new Date(b).getTime()
    )

    const keys = [...groups].sort()

    return {
      chartData: sortedPeriods.map((period) => ({
        period,
        label: formatDateLabel(period, granularity),
        ...periodMap.get(period),
      })),
      groupKeys: keys,
    }
  }, [data, groupBy, granularity])

  const handleGranularityChange = (value: string) => {
    onFilterChange({ ...filters, granularity: value })
  }

  const handleGroupByChange = (value: string) => {
    const updated = { ...filters } as TrendsParams
    if (value) {
      updated.group_by = value as TrendsParams['group_by']
    } else {
      delete updated.group_by
    }
    updated.granularity = granularity
    onFilterChange(updated)
  }

  const btnBase =
    'px-3 py-1 text-sm rounded-md border transition-colors'
  const btnActive =
    'bg-indigo-600 text-white border-indigo-600'
  const btnInactive =
    'bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-600'

  return (
    <div>
      <div className="flex flex-wrap items-center gap-4 mb-4">
        {/* Granularity toggle */}
        <div className="flex items-center gap-1">
          <span className="text-sm text-gray-500 dark:text-gray-400 mr-1">Granularity:</span>
          {GRANULARITY_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              onClick={() => handleGranularityChange(opt.value!)}
              className={`${btnBase} ${granularity === opt.value ? btnActive : btnInactive}`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        {/* Group by selector */}
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-500 dark:text-gray-400">Group by:</span>
          <select
            value={groupBy}
            onChange={(e) => handleGroupByChange(e.target.value)}
            className="text-sm border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 rounded-md px-2 py-1 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
          >
            {GROUP_BY_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={chartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
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
          {groupKeys.length > 0 ? (
            <>
              <Legend />
              {groupKeys.map((key, idx) => (
                <Area
                  key={key}
                  type="monotone"
                  dataKey={key}
                  name={key.replace(/_/g, ' ')}
                  stroke={SERIES_COLORS[idx % SERIES_COLORS.length]}
                  fill={SERIES_COLORS[idx % SERIES_COLORS.length]}
                  fillOpacity={0.15}
                  stackId="grouped"
                />
              ))}
            </>
          ) : (
            <Area
              type="monotone"
              dataKey="count"
              name="Threats"
              stroke="#6366f1"
              fill="#6366f1"
              fillOpacity={0.2}
            />
          )}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
