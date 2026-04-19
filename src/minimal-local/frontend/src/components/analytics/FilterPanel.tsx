import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { RotateCcw } from 'lucide-react'
import { searchApi, type AnalyticsFilterParams } from '../../services/api'

interface FilterPanelProps {
  onFilterChange: (filters: AnalyticsFilterParams) => void
}

export default function FilterPanel({ onFilterChange }: FilterPanelProps) {
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [threatType, setThreatType] = useState('')
  const [severityMin, setSeverityMin] = useState<number | undefined>()
  const [severityMax, setSeverityMax] = useState<number | undefined>()
  const [source, setSource] = useState('')
  const [includeUnknown, setIncludeUnknown] = useState(true)

  const { data: threatTypesData } = useQuery({
    queryKey: ['threatTypes'],
    queryFn: () => searchApi.threatTypes(),
  })

  const { data: statisticsData } = useQuery({
    queryKey: ['searchStatistics'],
    queryFn: () => searchApi.statistics(),
  })

  const sourceOptions: string[] = statisticsData?.top_sources
    ? Object.keys(statisticsData.top_sources)
    : []

  const buildFilters = (overrides: Partial<{
    dateFrom: string
    dateTo: string
    threatType: string
    severityMin: number | undefined
    severityMax: number | undefined
    source: string
    includeUnknown: boolean
  }> = {}): AnalyticsFilterParams => {
    const df = overrides.dateFrom ?? dateFrom
    const dt = overrides.dateTo ?? dateTo
    const tt = overrides.threatType ?? threatType
    const sMin = overrides.severityMin !== undefined ? overrides.severityMin : severityMin
    const sMax = overrides.severityMax !== undefined ? overrides.severityMax : severityMax
    const src = overrides.source ?? source
    const iu = overrides.includeUnknown ?? includeUnknown

    const filters: AnalyticsFilterParams = {}
    if (df) filters.date_from = df
    if (dt) filters.date_to = dt
    if (tt) filters.threat_type = tt
    if (sMin !== undefined) filters.severity_min = sMin
    if (sMax !== undefined) filters.severity_max = sMax
    if (src) filters.source = src
    if (!iu) filters.include_unknown = false
    return filters
  }

  const handleDateFromChange = (value: string) => {
    setDateFrom(value)
    onFilterChange(buildFilters({ dateFrom: value }))
  }

  const handleDateToChange = (value: string) => {
    setDateTo(value)
    onFilterChange(buildFilters({ dateTo: value }))
  }

  const handleThreatTypeChange = (value: string) => {
    setThreatType(value)
    onFilterChange(buildFilters({ threatType: value }))
  }

  const handleSeverityMinChange = (value: string) => {
    const parsed = value ? Number(value) : undefined
    setSeverityMin(parsed)
    onFilterChange(buildFilters({ severityMin: parsed }))
  }

  const handleSeverityMaxChange = (value: string) => {
    const parsed = value ? Number(value) : undefined
    setSeverityMax(parsed)
    onFilterChange(buildFilters({ severityMax: parsed }))
  }

  const handleSourceChange = (value: string) => {
    setSource(value)
    onFilterChange(buildFilters({ source: value }))
  }

  const handleIncludeUnknownChange = (checked: boolean) => {
    setIncludeUnknown(checked)
    onFilterChange(buildFilters({ includeUnknown: checked }))
  }

  const handleReset = () => {
    setDateFrom('')
    setDateTo('')
    setThreatType('')
    setSeverityMin(undefined)
    setSeverityMax(undefined)
    setSource('')
    setIncludeUnknown(true)
    onFilterChange({})
  }

  const selectClass =
    'block w-full pl-3 pr-10 py-2 text-sm border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 rounded-md'
  const inputClass =
    'block w-full px-3 py-2 text-sm border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-gray-200 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 rounded-md'
  const labelClass = 'block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1'

  return (
    <div className="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100">Filters</h3>
        <button
          type="button"
          onClick={handleReset}
          className="text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 flex items-center"
        >
          <RotateCcw className="h-4 w-4 mr-1" />
          Reset Filters
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Date From */}
        <div>
          <label className={labelClass}>Date From</label>
          <input
            type="date"
            value={dateFrom}
            onChange={(e) => handleDateFromChange(e.target.value)}
            className={inputClass}
          />
        </div>

        {/* Date To */}
        <div>
          <label className={labelClass}>Date To</label>
          <input
            type="date"
            value={dateTo}
            onChange={(e) => handleDateToChange(e.target.value)}
            className={inputClass}
          />
        </div>

        {/* Threat Type */}
        <div>
          <label className={labelClass}>Threat Type</label>
          <select
            value={threatType}
            onChange={(e) => handleThreatTypeChange(e.target.value)}
            className={selectClass}
          >
            <option value="">All Types</option>
            {threatTypesData?.threat_types?.map((type: string) => (
              <option key={type} value={type}>
                {type.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())}
              </option>
            ))}
          </select>
        </div>

        {/* Severity Min */}
        <div>
          <label className={labelClass}>Min Severity</label>
          <select
            value={severityMin ?? ''}
            onChange={(e) => handleSeverityMinChange(e.target.value)}
            className={selectClass}
          >
            <option value="">Any</option>
            {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((val) => (
              <option key={val} value={val}>
                {val}
              </option>
            ))}
          </select>
        </div>

        {/* Severity Max */}
        <div>
          <label className={labelClass}>Max Severity</label>
          <select
            value={severityMax ?? ''}
            onChange={(e) => handleSeverityMaxChange(e.target.value)}
            className={selectClass}
          >
            <option value="">Any</option>
            {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((val) => (
              <option key={val} value={val}>
                {val}
              </option>
            ))}
          </select>
        </div>

        {/* Source */}
        <div>
          <label className={labelClass}>Source</label>
          <select
            value={source}
            onChange={(e) => handleSourceChange(e.target.value)}
            className={selectClass}
          >
            <option value="">All Sources</option>
            {sourceOptions.map((src) => (
              <option key={src} value={src}>
                {src}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Include unknown toggle */}
      <div className="pt-2 border-t border-gray-200 dark:border-gray-700">
        <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={includeUnknown}
            onChange={(e) => handleIncludeUnknownChange(e.target.checked)}
            className="rounded border-gray-300 dark:border-gray-600 text-indigo-600 focus:ring-indigo-500"
          />
          Include unknown / unclassified threats
        </label>
      </div>
    </div>
  )
}
