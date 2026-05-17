import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { BarChart3, RefreshCw } from 'lucide-react'
import FilterPanel from './analytics/FilterPanel'
import TrendChart from './analytics/TrendChart'
import DistributionChart from './analytics/DistributionChart'
import MitreHeatmap from './analytics/MitreHeatmap'
import EntityClusterView from './analytics/EntityClusterView'
import SeverityMatrix from './analytics/SeverityMatrix'
import EntityRelationshipGraph from './analytics/EntityRelationshipGraph'
import {
  analyticsApi,
  type AnalyticsFilterParams,
  type AnalyticsResponse,
  type TrendItem,
  type DistributionItem,
  type MitreHeatmapItem,
  type EntityClusterItem,
  type SeverityMatrixItem,
  type TrendsParams,
  type DistributionsParams,
  type GraphData,
} from '../services/api'

function ChartSection({
  title,
  isLoading,
  isError,
  refetch,
  isEmpty,
  children,
}: {
  title: string
  isLoading: boolean
  isError: boolean
  refetch: () => void
  isEmpty: boolean
  children?: React.ReactNode
}) {
  return (
    <div className="bg-white dark:bg-gray-800 shadow rounded-md p-6">
      <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">{title}</h2>
      {isLoading ? (
        <div className="flex items-center justify-center h-48 text-gray-500 dark:text-gray-400">
          <RefreshCw className="h-5 w-5 animate-spin mr-2" />
          Loading...
        </div>
      ) : isError ? (
        <div className="flex flex-col items-center justify-center h-48 text-gray-500 dark:text-gray-400">
          <p className="mb-3">Failed to load data</p>
          <button
            onClick={refetch}
            className="inline-flex items-center px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
          >
            <RefreshCw className="h-4 w-4 mr-1" />
            Retry
          </button>
        </div>
      ) : isEmpty ? (
        <div className="flex items-center justify-center h-48 text-gray-500 dark:text-gray-400">
          No data available
        </div>
      ) : (
        children
      )}
    </div>
  )
}

export default function AnalyticsPage() {
  const [filters, setFilters] = useState<AnalyticsFilterParams>({})
  const [trendParams, setTrendParams] = useState<{ granularity: TrendsParams['granularity']; group_by?: TrendsParams['group_by'] }>({ granularity: 'month' })
  const [distributionDimension, setDistributionDimension] = useState<DistributionsParams['dimension']>('threat_type')
  const [entityClusterView, setEntityClusterView] = useState<'bar' | 'graph'>('bar')

  const entityGraphQuery = useQuery<AnalyticsResponse<GraphData>>({
    queryKey: ['analytics', 'entityClusterGraph', filters],
    queryFn: () => analyticsApi.entityClusterGraph(filters),
    enabled: entityClusterView === 'graph',
  })

  const trendsQuery = useQuery<AnalyticsResponse<TrendItem>>({
    queryKey: ['analytics', 'trends', filters, trendParams],
    queryFn: () => analyticsApi.trends({ ...filters, ...trendParams }),
  })

  const distributionsQuery = useQuery<AnalyticsResponse<DistributionItem>>({
    queryKey: ['analytics', 'distributions', filters, distributionDimension],
    queryFn: () => analyticsApi.distributions({ ...filters, dimension: distributionDimension }),
  })

  const mitreHeatmapQuery = useQuery<AnalyticsResponse<MitreHeatmapItem>>({
    queryKey: ['analytics', 'mitreHeatmap', filters],
    queryFn: () => analyticsApi.mitreHeatmap(filters),
  })

  const entityClustersQuery = useQuery<AnalyticsResponse<EntityClusterItem>>({
    queryKey: ['analytics', 'entityClusters', filters],
    queryFn: () => analyticsApi.entityClusters(filters),
  })

  const severityMatrixQuery = useQuery<AnalyticsResponse<SeverityMatrixItem>>({
    queryKey: ['analytics', 'severityMatrix', filters],
    queryFn: () => analyticsApi.severityMatrix(filters),
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 flex items-center">
          <BarChart3 className="h-7 w-7 mr-2" />
          Analytics
        </h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Explore threat intelligence trends, distributions, and clusters
        </p>
      </div>

      <FilterPanel onFilterChange={setFilters} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="lg:col-span-2">
          <ChartSection
            title="Threat Trends"
            isLoading={trendsQuery.isLoading}
            isError={trendsQuery.isError}
            refetch={() => trendsQuery.refetch()}
            isEmpty={!trendsQuery.data?.data?.length}
          >
            <TrendChart
              data={trendsQuery.data?.data ?? []}
              filters={{ ...filters, ...trendParams }}
              onFilterChange={(updated) => {
                const { granularity, group_by } = updated as TrendsParams
                setTrendParams({ granularity: granularity || 'month', group_by })
              }}
            />
          </ChartSection>
        </div>

        <ChartSection
          title="Threat Distribution"
          isLoading={distributionsQuery.isLoading}
          isError={distributionsQuery.isError}
          refetch={() => distributionsQuery.refetch()}
          isEmpty={!distributionsQuery.data?.data?.length}
        >
          <DistributionChart
            data={distributionsQuery.data?.data ?? []}
            filters={{ ...filters, dimension: distributionDimension }}
            onFilterChange={(updated) => {
              const { dimension } = updated as DistributionsParams
              if (dimension) setDistributionDimension(dimension)
            }}
          />
        </ChartSection>

        <div className={`bg-white dark:bg-gray-800 shadow rounded-md p-6 ${entityClusterView === 'graph' ? 'lg:col-span-2' : ''}`}>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Entity Clusters</h2>

          {/* View toggle */}
          <div className="flex items-center gap-4 mb-4">
            <div className="flex gap-1" role="radiogroup" aria-label="Entity cluster view mode">
              <button
                role="radio"
                aria-checked={entityClusterView === 'bar'}
                onClick={() => setEntityClusterView('bar')}
                onKeyDown={(e) => {
                  if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
                    e.preventDefault()
                    setEntityClusterView('graph')
                  }
                }}
                tabIndex={entityClusterView === 'bar' ? 0 : -1}
                className={`px-3 py-1.5 text-sm rounded-md font-medium transition-colors ${
                  entityClusterView === 'bar'
                    ? 'bg-indigo-600 text-white'
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                }`}
              >
                Bar Chart
              </button>
              <button
                role="radio"
                aria-checked={entityClusterView === 'graph'}
                onClick={() => setEntityClusterView('graph')}
                onKeyDown={(e) => {
                  if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
                    e.preventDefault()
                    setEntityClusterView('bar')
                  }
                }}
                tabIndex={entityClusterView === 'graph' ? 0 : -1}
                className={`px-3 py-1.5 text-sm rounded-md font-medium transition-colors ${
                  entityClusterView === 'graph'
                    ? 'bg-indigo-600 text-white'
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                }`}
              >
                Graph
              </button>
            </div>
          </div>

          {/* Bar chart view */}
          {entityClusterView === 'bar' && (
            entityClustersQuery.isLoading ? (
              <div className="flex items-center justify-center h-48 text-gray-500 dark:text-gray-400">
                <RefreshCw className="h-5 w-5 animate-spin mr-2" />
                Loading...
              </div>
            ) : entityClustersQuery.isError ? (
              <div className="flex flex-col items-center justify-center h-48 text-gray-500 dark:text-gray-400">
                <p className="mb-3">Failed to load data</p>
                <button
                  onClick={() => entityClustersQuery.refetch()}
                  className="inline-flex items-center px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
                >
                  <RefreshCw className="h-4 w-4 mr-1" />
                  Retry
                </button>
              </div>
            ) : !entityClustersQuery.data?.data?.length ? (
              <div className="flex items-center justify-center h-48 text-gray-500 dark:text-gray-400">
                No data available
              </div>
            ) : (
              <EntityClusterView data={entityClustersQuery.data?.data ?? []} />
            )
          )}

          {/* Graph view */}
          {entityClusterView === 'graph' && (
            entityGraphQuery.isLoading ? (
              <div className="flex items-center justify-center h-48 text-gray-500 dark:text-gray-400">
                <RefreshCw className="h-5 w-5 animate-spin mr-2" />
                Loading...
              </div>
            ) : entityGraphQuery.isError ? (
              <div className="flex flex-col items-center justify-center h-48 text-gray-500 dark:text-gray-400">
                <p className="mb-3">Failed to load data</p>
                <button
                  onClick={() => entityGraphQuery.refetch()}
                  className="inline-flex items-center px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
                >
                  <RefreshCw className="h-4 w-4 mr-1" />
                  Retry
                </button>
              </div>
            ) : !entityGraphQuery.data?.data || (entityGraphQuery.data.data as unknown as GraphData).nodes?.length === 0 ? (
              <div className="flex items-center justify-center h-48 text-gray-500 dark:text-gray-400">
                No data available
              </div>
            ) : (
              <EntityRelationshipGraph data={entityGraphQuery.data.data as unknown as GraphData} />
            )
          )}
        </div>

        <div className="lg:col-span-2">
          <ChartSection
            title="MITRE ATT&CK Heatmap"
            isLoading={mitreHeatmapQuery.isLoading}
            isError={mitreHeatmapQuery.isError}
            refetch={() => mitreHeatmapQuery.refetch()}
            isEmpty={!mitreHeatmapQuery.data?.data?.length}
          >
            <MitreHeatmap data={mitreHeatmapQuery.data?.data ?? []} />
          </ChartSection>
        </div>

        <div className="lg:col-span-2">
          <ChartSection
            title="Severity × Type Matrix"
            isLoading={severityMatrixQuery.isLoading}
            isError={severityMatrixQuery.isError}
            refetch={() => severityMatrixQuery.refetch()}
            isEmpty={!severityMatrixQuery.data?.data?.length}
          >
            <SeverityMatrix data={severityMatrixQuery.data?.data ?? []} />
          </ChartSection>
        </div>
      </div>
    </div>
  )
}
