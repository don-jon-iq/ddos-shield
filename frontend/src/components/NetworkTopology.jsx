/**
 * Network Topology — interactive SVG-based network map.
 *
 * Orchestrates data fetching, state management, and composes:
 *   - TopologySummaryBar (network grade, counts, health)
 *   - NetworkSvgMap (SVG diagram with nodes, edges, interactions)
 *   - DeviceDetailPanel (slide-in detail panel with tabs)
 *   - Filter bar and legend
 */

import { useEffect, useState, useCallback, useRef } from 'react'
import {
  getDevices, getManagedDevices, getBandwidth,
  getSecurityGrade, getAlerts, getHealth,
} from '../utils/api'
import { COLORS, DEVICE_TYPES, mergeDeviceData } from './topology/topologyUtils'
import TopologySummaryBar from './topology/TopologySummaryBar'
import NetworkSvgMap from './topology/NetworkSvgMap'
import DeviceDetailPanel from './topology/DeviceDetailPanel'

const REFRESH_INTERVAL = 10_000

export default function NetworkTopology({ traffic }) {
  const [devices, setDevices] = useState([])
  const [grade, setGrade] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [health, setHealth] = useState(null)
  const [selectedDevice, setSelectedDevice] = useState(null)
  const [filters, setFilters] = useState({
    deviceType: 'all',
    riskLevel: 'all',
    onlineOnly: false,
  })
  const mountedRef = useRef(true)

  const fetchAll = useCallback(async () => {
    try {
      const [rawDevices, managed, bandwidth, gradeData, alertData, healthData] =
        await Promise.allSettled([
          getDevices(),
          getManagedDevices(),
          getBandwidth(),
          getSecurityGrade(),
          getAlerts({ limit: '50' }),
          getHealth(),
        ])

      if (!mountedRef.current) return

      const merged = mergeDeviceData(
        rawDevices.status === 'fulfilled' ? rawDevices.value : [],
        managed.status === 'fulfilled' ? managed.value : [],
        bandwidth.status === 'fulfilled' ? bandwidth.value : [],
        traffic,
      )
      setDevices(merged)

      if (gradeData.status === 'fulfilled') setGrade(gradeData.value)
      if (alertData.status === 'fulfilled') {
        setAlerts(Array.isArray(alertData.value) ? alertData.value : alertData.value?.alerts || [])
      }
      if (healthData.status === 'fulfilled') setHealth(healthData.value)
    } catch {
      // Individual failures handled by allSettled
    }
  }, [traffic])

  useEffect(() => {
    mountedRef.current = true
    fetchAll()
    const interval = setInterval(fetchAll, REFRESH_INTERVAL)
    return () => {
      mountedRef.current = false
      clearInterval(interval)
    }
  }, [fetchAll])

  // Re-merge when traffic updates (live pps)
  useEffect(() => {
    if (devices.length > 0 && traffic?.length > 0) {
      setDevices((prev) => prev.map((d) => {
        const live = traffic.find((t) => t.mac_address === d.mac_address)
        if (!live) return d
        return { ...d, pps: live.total_pps || 0 }
      }))
    }
  }, [traffic])

  const handleSelect = useCallback((device) => {
    setSelectedDevice((prev) =>
      prev?.mac_address === device.mac_address ? null : device
    )
  }, [])

  const updateFilter = (key, value) => {
    setFilters((prev) => ({ ...prev, [key]: value }))
  }

  const deviceTypes = ['all', ...new Set(devices.map((d) => d.device_type).filter(Boolean))]

  return (
    <div className="flex flex-col h-[calc(100vh-3rem)] gap-3">
      {/* Summary bar */}
      <TopologySummaryBar devices={devices} grade={grade} alerts={alerts} health={health} />

      {/* Filter bar */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Device type filter */}
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] font-mono" style={{ color: COLORS.textDim }}>Type:</span>
          <div className="flex gap-1">
            {deviceTypes.map((type) => (
              <FilterBtn key={type}
                label={type === 'all' ? 'All' : (DEVICE_TYPES[type]?.label || type)}
                active={filters.deviceType === type}
                onClick={() => updateFilter('deviceType', type)}
              />
            ))}
          </div>
        </div>

        {/* Risk filter */}
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] font-mono" style={{ color: COLORS.textDim }}>Risk:</span>
          <div className="flex gap-1">
            {['all', 'high', 'medium', 'low'].map((level) => (
              <FilterBtn key={level} label={level}
                active={filters.riskLevel === level}
                onClick={() => updateFilter('riskLevel', level)}
                color={level === 'high' ? COLORS.blocked : level === 'medium' ? COLORS.suspicious : undefined}
              />
            ))}
          </div>
        </div>

        {/* Online only toggle */}
        <button
          onClick={() => updateFilter('onlineOnly', !filters.onlineOnly)}
          className="flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono transition-colors border"
          style={{
            background: filters.onlineOnly ? COLORS.normal + '15' : 'transparent',
            borderColor: filters.onlineOnly ? COLORS.normal + '44' : COLORS.border,
            color: filters.onlineOnly ? COLORS.normal : COLORS.textDim,
          }}
        >
          <span className="w-1.5 h-1.5 rounded-full"
            style={{ background: filters.onlineOnly ? COLORS.normal : COLORS.textDim }} />
          Online only
        </button>
      </div>

      {/* Main area: map + optional detail panel */}
      <div className="flex flex-1 min-h-0 gap-0">
        <NetworkSvgMap
          devices={devices}
          onSelect={handleSelect}
          selectedMac={selectedDevice?.mac_address}
          filters={filters}
        />
        {selectedDevice && (
          <DeviceDetailPanel
            device={selectedDevice}
            onClose={() => setSelectedDevice(null)}
          />
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-5 flex-wrap px-2 py-2 rounded border"
        style={{ background: COLORS.surface, borderColor: COLORS.border }}>
        <LegendSection title="Devices">
          {Object.entries(DEVICE_TYPES).filter(([k]) => k !== 'unknown').map(([key, cfg]) => (
            <LegendItem key={key} icon={cfg.icon} label={cfg.label} />
          ))}
        </LegendSection>
        <div className="w-px h-6" style={{ background: COLORS.border }} />
        <LegendSection title="Connection">
          <LegendLine color={COLORS.normal} label="Normal" />
          <LegendLine color={COLORS.suspicious} label="Suspicious" />
          <LegendLine color={COLORS.blocked} label="Blocked" />
        </LegendSection>
        <div className="w-px h-6" style={{ background: COLORS.border }} />
        <LegendSection title="Score">
          <LegendDot color={COLORS.normal} label="80+" />
          <LegendDot color={COLORS.suspicious} label="60-80" />
          <LegendDot color={COLORS.blocked} label="<60" />
        </LegendSection>
      </div>
    </div>
  )
}

/* --- Filter button --- */
function FilterBtn({ label, active, onClick, color }) {
  const activeColor = color || COLORS.info
  return (
    <button onClick={onClick}
      className="px-2 py-0.5 rounded text-[10px] font-mono capitalize transition-colors border"
      style={{
        background: active ? activeColor + '18' : 'transparent',
        borderColor: active ? activeColor + '44' : COLORS.border,
        color: active ? activeColor : COLORS.textDim,
      }}>
      {label}
    </button>
  )
}

/* --- Legend pieces --- */
function LegendSection({ title, children }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-[9px] font-mono uppercase" style={{ color: COLORS.textDim }}>{title}:</span>
      <div className="flex items-center gap-2">{children}</div>
    </div>
  )
}

function LegendItem({ icon, label }) {
  return (
    <span className="flex items-center gap-1 text-[10px]" style={{ color: COLORS.textMid }}>
      <span className="text-sm">{icon}</span>{label}
    </span>
  )
}

function LegendLine({ color, label }) {
  return (
    <span className="flex items-center gap-1 text-[10px]" style={{ color: COLORS.textMid }}>
      <span className="w-4 h-0.5 rounded" style={{ background: color }} />{label}
    </span>
  )
}

function LegendDot({ color, label }) {
  return (
    <span className="flex items-center gap-1 text-[10px]" style={{ color: COLORS.textMid }}>
      <span className="w-2 h-2 rounded-full" style={{ background: color }} />{label}
    </span>
  )
}
