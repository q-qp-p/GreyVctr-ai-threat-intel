import { useMemo, useState } from 'react'
import type { MitreHeatmapItem } from '../../services/api'

interface MitreHeatmapProps {
  data: MitreHeatmapItem[]
}

/** Map a count to a Tailwind-compatible indigo background + appropriate text color. */
function getCellStyle(count: number, maxCount: number): React.CSSProperties {
  if (maxCount === 0) {
    return { backgroundColor: '#eef2ff', color: '#6366f1' }
  }
  // Normalize 0..1
  const ratio = count / maxCount
  // Interpolate from light indigo (#eef2ff) to dark indigo (#3730a3)
  const lightR = 238, lightG = 242, lightB = 255
  const darkR = 55, darkG = 48, darkB = 163
  const r = Math.round(lightR + (darkR - lightR) * ratio)
  const g = Math.round(lightG + (darkG - lightG) * ratio)
  const b = Math.round(lightB + (darkB - lightB) * ratio)
  return {
    backgroundColor: `rgb(${r}, ${g}, ${b})`,
    color: ratio > 0.45 ? '#ffffff' : '#4338ca',
  }
}

export default function MitreHeatmap({ data }: MitreHeatmapProps) {
  const [tooltip, setTooltip] = useState<{
    item: MitreHeatmapItem
    x: number
    y: number
  } | null>(null)

  const { tactics, techniquesByTactic, maxCount } = useMemo(() => {
    // Group data by tactic
    const tacticMap = new Map<string, MitreHeatmapItem[]>()
    let max = 0

    for (const item of data) {
      if (!tacticMap.has(item.tactic)) {
        tacticMap.set(item.tactic, [])
      }
      tacticMap.get(item.tactic)!.push(item)
      if (item.count > max) max = item.count
    }

    // Sort tactics alphabetically, techniques by count desc within each tactic
    const sortedTactics = [...tacticMap.keys()].sort()
    const grouped = new Map<string, MitreHeatmapItem[]>()
    for (const tactic of sortedTactics) {
      grouped.set(
        tactic,
        tacticMap.get(tactic)!.sort((a, b) => b.count - a.count)
      )
    }

    return { tactics: sortedTactics, techniquesByTactic: grouped, maxCount: max }
  }, [data])

  const handleMouseEnter = (
    e: React.MouseEvent<HTMLDivElement>,
    item: MitreHeatmapItem
  ) => {
    const rect = e.currentTarget.getBoundingClientRect()
    setTooltip({ item, x: rect.left + rect.width / 2, y: rect.top })
  }

  const handleMouseLeave = () => {
    setTooltip(null)
  }

  return (
    <div className="relative overflow-x-auto">
      {/* Legend */}
      <div className="flex items-center gap-2 mb-4 text-xs text-gray-500 dark:text-gray-400">
        <span>Low</span>
        <div className="flex h-3">
          {[0, 0.25, 0.5, 0.75, 1].map((ratio) => (
            <div
              key={ratio}
              className="w-6 h-3"
              style={getCellStyle(ratio * maxCount, maxCount)}
            />
          ))}
        </div>
        <span>High</span>
      </div>

      {/* Heatmap grid — one row per tactic */}
      <div className="space-y-3">
        {tactics.map((tactic) => {
          const techniques = techniquesByTactic.get(tactic)!
          return (
            <div key={tactic}>
              <div className="text-xs font-medium text-gray-700 dark:text-gray-300 mb-1 truncate">
                {tactic}
              </div>
              <div className="flex flex-wrap gap-1">
                {techniques.map((item) => (
                  <div
                    key={`${item.tactic}-${item.technique_id}`}
                    className="rounded px-2 py-1 text-xs font-medium cursor-default transition-transform hover:scale-105 min-w-[60px] text-center"
                    style={getCellStyle(item.count, maxCount)}
                    onMouseEnter={(e) => handleMouseEnter(e, item)}
                    onMouseLeave={handleMouseLeave}
                  >
                    {item.technique_id}
                  </div>
                ))}
              </div>
            </div>
          )
        })}
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
            {tooltip.item.technique}
          </div>
          <div className="text-gray-500 dark:text-gray-400 mt-0.5">
            {tooltip.item.technique_id}
          </div>
          <div className="text-gray-500 dark:text-gray-400">
            Tactic: {tooltip.item.tactic}
          </div>
          <div className="mt-1 font-semibold text-indigo-600 dark:text-indigo-400">
            Count: {tooltip.item.count}
          </div>
        </div>
      )}
    </div>
  )
}
