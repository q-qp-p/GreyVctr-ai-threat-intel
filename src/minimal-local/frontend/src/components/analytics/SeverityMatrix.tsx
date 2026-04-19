import { useMemo, useState } from 'react'
import type { SeverityMatrixItem } from '../../services/api'

interface SeverityMatrixProps {
  data: SeverityMatrixItem[]
}

/** Interpolate cell background + text color based on count relative to max. */
function getCellStyle(count: number, maxCount: number): React.CSSProperties {
  if (maxCount === 0 || count === 0) {
    return { backgroundColor: '#f9fafb', color: '#9ca3af' }
  }
  const ratio = count / maxCount
  // Light amber (#fef3c7) → dark red (#991b1b)
  const lightR = 254, lightG = 243, lightB = 199
  const darkR = 153, darkG = 27, darkB = 27
  const r = Math.round(lightR + (darkR - lightR) * ratio)
  const g = Math.round(lightG + (darkG - lightG) * ratio)
  const b = Math.round(lightB + (darkB - lightB) * ratio)
  return {
    backgroundColor: `rgb(${r}, ${g}, ${b})`,
    color: ratio > 0.45 ? '#ffffff' : '#92400e',
  }
}

export default function SeverityMatrix({ data }: SeverityMatrixProps) {
  const [tooltip, setTooltip] = useState<{
    severity: number
    threatType: string
    count: number
    x: number
    y: number
  } | null>(null)

  const { severityLevels, threatTypes, countMap, maxCount } = useMemo(() => {
    const typeSet = new Set<string>()
    const map = new Map<string, number>()
    let max = 0

    for (const item of data) {
      typeSet.add(item.threat_type)
      const key = `${item.severity}::${item.threat_type}`
      map.set(key, item.count)
      if (item.count > max) max = item.count
    }

    return {
      severityLevels: Array.from({ length: 10 }, (_, i) => i + 1),
      threatTypes: [...typeSet].sort(),
      countMap: map,
      maxCount: max,
    }
  }, [data])

  const handleMouseEnter = (
    e: React.MouseEvent<HTMLDivElement>,
    severity: number,
    threatType: string,
    count: number
  ) => {
    const rect = e.currentTarget.getBoundingClientRect()
    setTooltip({
      severity,
      threatType,
      count,
      x: rect.left + rect.width / 2,
      y: rect.top,
    })
  }

  const handleMouseLeave = () => setTooltip(null)

  return (
    <div className="relative overflow-x-auto">
      {/* Legend */}
      <div className="flex items-center gap-2 mb-4 text-xs text-gray-500 dark:text-gray-400">
        <span>Low</span>
        <div className="flex h-3">
          {[0.01, 0.25, 0.5, 0.75, 1].map((ratio) => (
            <div
              key={ratio}
              className="w-6 h-3"
              style={getCellStyle(ratio * maxCount, maxCount)}
            />
          ))}
        </div>
        <span>High</span>
      </div>

      {/* Grid */}
      <div
        className="grid gap-px"
        style={{
          gridTemplateColumns: `80px repeat(${threatTypes.length}, minmax(80px, 1fr))`,
        }}
      >
        {/* Header row */}
        <div className="text-xs font-medium text-gray-500 dark:text-gray-400 p-1" />
        {threatTypes.map((type) => (
          <div
            key={type}
            className="text-xs font-medium text-gray-700 dark:text-gray-300 p-1 text-center truncate"
            title={type}
          >
            {type}
          </div>
        ))}

        {/* Data rows — severity 1 to 10 */}
        {severityLevels.map((severity) => (
          <>
            <div
              key={`label-${severity}`}
              className="text-xs font-medium text-gray-700 dark:text-gray-300 p-1 flex items-center"
            >
              Severity {severity}
            </div>
            {threatTypes.map((type) => {
              const count = countMap.get(`${severity}::${type}`) ?? 0
              return (
                <div
                  key={`${severity}-${type}`}
                  className="rounded text-xs font-medium text-center py-2 cursor-default transition-transform hover:scale-105"
                  style={getCellStyle(count, maxCount)}
                  onMouseEnter={(e) => handleMouseEnter(e, severity, type, count)}
                  onMouseLeave={handleMouseLeave}
                >
                  {count > 0 ? count : '—'}
                </div>
              )
            })}
          </>
        ))}
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="fixed z-50 pointer-events-none px-3 py-2 rounded-md shadow-lg text-xs bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-600"
          style={{
            left: tooltip.x,
            top: tooltip.y - 8,
            transform: 'translate(-50%, -100%)',
          }}
        >
          <div className="font-semibold text-gray-900 dark:text-gray-100">
            {tooltip.threatType}
          </div>
          <div className="text-gray-500 dark:text-gray-400 mt-0.5">
            Severity: {tooltip.severity}
          </div>
          <div className="mt-1 font-semibold text-red-600 dark:text-red-400">
            Count: {tooltip.count}
          </div>
        </div>
      )}
    </div>
  )
}
