import { useEffect, useState, useCallback } from 'react'
import {
  Bell, BellOff, Check, CheckCheck, Filter, AlertTriangle,
  Shield, Activity, Wifi, Monitor, ChevronDown,
} from 'lucide-react'
import { getAlerts, getAlertCounts, acknowledgeAlert, resolveAlert } from '../utils/api'

const SEVERITY_STYLES = {
  CRITICAL: 'bg-attack-red/10 border-attack-red/30 text-attack-red',
  HIGH: 'bg-red-400/10 border-red-400/30 text-red-400',
  MEDIUM: 'bg-warn-yellow/10 border-warn-yellow/30 text-warn-yellow',
  LOW: 'bg-gray-400/10 border-gray-400/20 text-gray-400',
  INFO: 'bg-info-blue/10 border-info-blue/20 text-info-blue',
}

const CATEGORY_ICONS = {
  SECURITY: Shield,
  PERFORMANCE: Activity,
  NETWORK_CHANGE: Wifi,
  DEVICE_STATUS: Monitor,
}

const CATEGORY_LABELS = {
  SECURITY: 'Security',
  PERFORMANCE: 'Performance',
  NETWORK_CHANGE: 'Network Change',
  DEVICE_STATUS: 'Device Status',
}

function AlertCard({ alert, index, onAcknowledge, onResolve }) {
  const CategoryIcon = CATEGORY_ICONS[alert.category] || AlertTriangle
  const isActive = alert.status === 'ACTIVE'
  const isAcknowledged = alert.status === 'ACKNOWLEDGED'

  return (
    <div className={`p-3 rounded-lg border ${SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.LOW} ${
      !isActive ? 'opacity-60' : ''
    }`}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 flex-1 min-w-0">
          <CategoryIcon className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-medium">{alert.title}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded-full border border-current opacity-60 uppercase">
                {alert.severity}
              </span>
              <span className="text-[10px] opacity-50">
                {CATEGORY_LABELS[alert.category] || alert.category}
              </span>
            </div>
            <p className="text-xs opacity-70 mt-1 break-words">{alert.description}</p>
            {(alert.source_ip || alert.source_mac) && (
              <p className="text-[10px] opacity-50 mt-1 font-mono">
                {alert.source_ip && `IP: ${alert.source_ip}`}
                {alert.source_ip && alert.source_mac && ' · '}
                {alert.source_mac && `MAC: ${alert.source_mac}`}
              </p>
            )}
          </div>
        </div>
        <div className="flex flex-col items-end gap-1 flex-shrink-0">
          <span className="text-[10px] opacity-50 whitespace-nowrap">
            {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : ''}
          </span>
          {isActive && (
            <div className="flex gap-1">
              <button
                onClick={() => onAcknowledge(index)}
                className="text-[10px] px-2 py-0.5 rounded bg-white/5 hover:bg-white/10 transition-colors"
                title="Acknowledge"
              >
                <Check className="w-3 h-3" />
              </button>
              <button
                onClick={() => onResolve(index)}
                className="text-[10px] px-2 py-0.5 rounded bg-white/5 hover:bg-white/10 transition-colors"
                title="Resolve"
              >
                <CheckCheck className="w-3 h-3" />
              </button>
            </div>
          )}
          {isAcknowledged && (
            <button
              onClick={() => onResolve(index)}
              className="text-[10px] px-2 py-0.5 rounded bg-white/5 hover:bg-white/10 transition-colors"
              title="Resolve"
            >
              <CheckCheck className="w-3 h-3" />
            </button>
          )}
          {alert.status === 'RESOLVED' && (
            <span className="text-[10px] text-matrix-green">Resolved</span>
          )}
        </div>
      </div>
    </div>
  )
}

export default function AlertCenter() {
  const [alerts, setAlerts] = useState([])
  const [counts, setCounts] = useState({ total_active: 0, by_category: {}, by_severity: {} })
  const [categoryFilter, setCategoryFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  const loadData = useCallback(async () => {
    try {
      const params = {}
      if (categoryFilter) params.category = categoryFilter
      if (severityFilter) params.severity = severityFilter
      if (statusFilter) params.status = statusFilter
      params.limit = '200'

      const [alertData, countData] = await Promise.all([
        getAlerts(params),
        getAlertCounts(),
      ])
      setAlerts(alertData)
      setCounts(countData)
    } catch {
      // not ready
    }
  }, [categoryFilter, severityFilter, statusFilter])

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 10000)
    return () => clearInterval(interval)
  }, [loadData])

  const handleAcknowledge = async (index) => {
    try {
      await acknowledgeAlert(index)
      loadData()
    } catch {
      // failed
    }
  }

  const handleResolve = async (index) => {
    try {
      await resolveAlert(index)
      loadData()
    } catch {
      // failed
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-200">Alert Center</h1>
        <div className="flex items-center gap-2">
          {counts.total_active > 0 ? (
            <span className="flex items-center gap-1.5 px-3 py-1 bg-attack-red/10 text-attack-red border border-attack-red/30 rounded-full text-xs">
              <Bell className="w-3 h-3" />
              {counts.total_active} active
            </span>
          ) : (
            <span className="flex items-center gap-1.5 px-3 py-1 bg-matrix-green/10 text-matrix-green border border-matrix-green/30 rounded-full text-xs">
              <BellOff className="w-3 h-3" />
              All clear
            </span>
          )}
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          { label: 'Security', key: 'SECURITY', icon: Shield, color: 'attack-red' },
          { label: 'Performance', key: 'PERFORMANCE', icon: Activity, color: 'warn-yellow' },
          { label: 'Network', key: 'NETWORK_CHANGE', icon: Wifi, color: 'info-blue' },
          { label: 'Devices', key: 'DEVICE_STATUS', icon: Monitor, color: 'matrix-green' },
        ].map(({ label, key, icon: Icon, color }) => (
          <button
            key={key}
            onClick={() => setCategoryFilter(categoryFilter === key ? '' : key)}
            className={`cyber-card transition-all ${
              categoryFilter === key ? `border-${color}/50` : ''
            }`}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-500">{label}</p>
                <p className={`text-xl font-bold text-${color}`}>
                  {counts.by_category?.[key] || 0}
                </p>
              </div>
              <Icon className={`w-6 h-6 text-${color} opacity-50`} />
            </div>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-1.5 bg-cyber-surface border border-cyber-border rounded-lg text-xs text-gray-300 focus:border-matrix-green/50 focus:outline-none"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="INFO">Info</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-1.5 bg-cyber-surface border border-cyber-border rounded-lg text-xs text-gray-300 focus:border-matrix-green/50 focus:outline-none"
        >
          <option value="">All Statuses</option>
          <option value="ACTIVE">Active</option>
          <option value="ACKNOWLEDGED">Acknowledged</option>
          <option value="RESOLVED">Resolved</option>
        </select>

        {(categoryFilter || severityFilter || statusFilter) && (
          <button
            onClick={() => { setCategoryFilter(''); setSeverityFilter(''); setStatusFilter('') }}
            className="px-3 py-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Alert list */}
      <div className="space-y-2">
        {alerts.length === 0 ? (
          <div className="cyber-card text-center py-12">
            <BellOff className="w-12 h-12 text-gray-600 mx-auto mb-3" />
            <p className="text-gray-500">
              {categoryFilter || severityFilter || statusFilter
                ? 'No alerts match your filters.'
                : 'No alerts recorded yet. The system is monitoring for events.'}
            </p>
          </div>
        ) : (
          alerts.map((alert, i) => (
            <AlertCard
              key={i}
              alert={alert}
              index={i}
              onAcknowledge={handleAcknowledge}
              onResolve={handleResolve}
            />
          ))
        )}
      </div>
    </div>
  )
}
