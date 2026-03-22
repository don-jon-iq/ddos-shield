import { useEffect, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Monitor,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Zap,
  Heart,
  BarChart3,
  RefreshCw,
  FileText,
  Server,
  Smartphone,
  Cpu,
  Router,
  Printer,
  Camera,
  HardDrive,
  Wifi,
} from 'lucide-react'
import {
  getStatus, getAttackStats, getProtectionSummary,
  getSecurityGrade, getAlertCounts, getHealth, getTopTalkers,
  getDiscoveredDevices,
} from '../utils/api'
import TrafficChart from './TrafficChart'

const GRADE_COLORS = {
  A: 'text-matrix-green border-matrix-green bg-matrix-green/10',
  B: 'text-info-blue border-info-blue bg-info-blue/10',
  C: 'text-warn-yellow border-warn-yellow bg-warn-yellow/10',
  D: 'text-orange-400 border-orange-400 bg-orange-400/10',
  F: 'text-attack-red border-attack-red bg-attack-red/10',
}

const HEALTH_COLORS = {
  healthy: 'text-matrix-green',
  degraded: 'text-warn-yellow',
  unhealthy: 'text-orange-400',
  critical: 'text-attack-red',
  unknown: 'text-gray-500',
}

const TYPE_ICONS = {
  router: Router,
  server: Server,
  client: Monitor,
  phone: Smartphone,
  iot: Cpu,
  printer: Printer,
  camera: Camera,
  nas: HardDrive,
}

function StatCard({ label, value, icon: Icon, color = 'green', glow = false }) {
  const colorMap = {
    green: 'text-matrix-green border-matrix-green/30',
    red: 'text-attack-red border-attack-red/30',
    blue: 'text-info-blue border-info-blue/30',
    yellow: 'text-warn-yellow border-warn-yellow/30',
  }
  const glowMap = {
    green: 'glow-green',
    red: 'glow-red',
    blue: 'glow-blue',
    yellow: 'glow-yellow',
  }

  return (
    <div className={`cyber-card ${colorMap[color]} ${glow ? glowMap[color] : ''}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
          <p className={`text-2xl font-bold mt-1 ${colorMap[color].split(' ')[0]}`}>
            {value}
          </p>
        </div>
        <Icon className={`w-8 h-8 opacity-50 ${colorMap[color].split(' ')[0]}`} />
      </div>
    </div>
  )
}

function formatBytes(bytes) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

export default function Dashboard({ traffic, alerts, alertHistory, trafficHistory, activeDevices, wsClients }) {
  const [stats, setStats] = useState({ total_attacks: 0, by_type: {}, by_severity: {} })
  const [status, setStatus] = useState(null)
  const [protectionSummary, setProtectionSummary] = useState(null)
  const [gradeData, setGradeData] = useState(null)
  const [alertCounts, setAlertCounts] = useState(null)
  const [healthData, setHealthData] = useState(null)
  const [topTalkers, setTopTalkers] = useState([])
  const [deviceTypes, setDeviceTypes] = useState({})

  useEffect(() => {
    const load = async () => {
      try {
        const [st, as_, ps, grade, ac, health, tt, devices] = await Promise.all([
          getStatus(),
          getAttackStats(),
          getProtectionSummary(),
          getSecurityGrade(),
          getAlertCounts(),
          getHealth(),
          getTopTalkers(5),
          getDiscoveredDevices(),
        ])
        setStatus(st)
        setStats(as_)
        setProtectionSummary(ps)
        setGradeData(grade)
        setAlertCounts(ac)
        setHealthData(health)
        setTopTalkers(tt)

        // Count device types
        const types = {}
        devices.forEach(d => {
          const t = d.device_type || 'unknown'
          types[t] = (types[t] || 0) + 1
        })
        setDeviceTypes(types)
      } catch {
        // API may not be ready yet
      }
    }
    load()
    const interval = setInterval(load, 15000)
    return () => clearInterval(interval)
  }, [])

  const grade = gradeData?.grade || '?'
  const gradeScore = gradeData?.score || 0
  const healthScore = healthData?.score?.score || 0
  const healthStatus = healthData?.score?.status || 'unknown'
  const activeAlerts = alertCounts?.total_active || 0
  const criticalAlerts = alertCounts?.by_severity?.CRITICAL || 0
  const highAlerts = alertCounts?.by_severity?.HIGH || 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-200">Dashboard Overview</h1>
        {status?.simulation_mode && (
          <span className="px-3 py-1 text-xs bg-warn-yellow/10 text-warn-yellow border border-warn-yellow/30 rounded-full">
            SIMULATION MODE
          </span>
        )}
      </div>

      {/* Top row: Grade + Health + Key Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Security Grade Badge */}
        <div className={`cyber-card flex items-center gap-3 border-2 ${GRADE_COLORS[grade] || GRADE_COLORS.F}`}>
          <div className={`text-5xl font-black ${(GRADE_COLORS[grade] || '').split(' ')[0]}`}>
            {grade}
          </div>
          <div>
            <p className="text-[10px] text-gray-500 uppercase">Security Grade</p>
            <p className={`text-lg font-bold ${(GRADE_COLORS[grade] || '').split(' ')[0]}`}>
              {gradeScore}/100
            </p>
          </div>
        </div>

        {/* Health */}
        <div className="cyber-card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-wider">Network Health</p>
              <p className={`text-2xl font-bold mt-1 ${HEALTH_COLORS[healthStatus]}`}>
                {healthScore}%
              </p>
              <p className={`text-[10px] capitalize ${HEALTH_COLORS[healthStatus]}`}>{healthStatus}</p>
            </div>
            <Heart className={`w-8 h-8 opacity-50 ${HEALTH_COLORS[healthStatus]}`} />
          </div>
        </div>

        {/* Active Devices */}
        <StatCard
          label="Devices"
          value={activeDevices || Object.values(deviceTypes).reduce((a, b) => a + b, 0)}
          icon={Monitor}
          color="blue"
        />

        {/* Active Threats */}
        <StatCard
          label="Active Threats"
          value={activeAlerts}
          icon={activeAlerts > 0 ? ShieldAlert : ShieldCheck}
          color={criticalAlerts > 0 ? 'red' : activeAlerts > 0 ? 'yellow' : 'green'}
          glow={criticalAlerts > 0}
        />

        {/* Total Attacks */}
        <StatCard
          label="Total Attacks"
          value={stats.total_attacks}
          icon={AlertTriangle}
          color={stats.total_attacks > 0 ? 'yellow' : 'green'}
        />
      </div>

      {/* Device type breakdown + Alert summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Device breakdown */}
        <div className="cyber-card">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
            Device Breakdown
          </h2>
          <div className="grid grid-cols-2 gap-2">
            {Object.entries(deviceTypes).sort((a, b) => b[1] - a[1]).map(([type, count]) => {
              const Icon = TYPE_ICONS[type] || Wifi
              return (
                <div key={type} className="flex items-center gap-2 text-sm">
                  <Icon className="w-4 h-4 text-gray-500" />
                  <span className="text-gray-400 capitalize">{type.replace('_', ' ')}</span>
                  <span className="text-gray-200 font-bold ml-auto">{count}</span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Vulnerability summary */}
        <div className="cyber-card">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
            Vulnerabilities
          </h2>
          <div className="space-y-2">
            {[
              { label: 'Critical', count: gradeData?.critical_count || 0, color: 'text-attack-red' },
              { label: 'High', count: gradeData?.high_count || 0, color: 'text-red-400' },
              { label: 'Medium', count: gradeData?.medium_count || 0, color: 'text-warn-yellow' },
              { label: 'Low', count: gradeData?.low_count || 0, color: 'text-gray-400' },
            ].map(({ label, count, color }) => (
              <div key={label} className="flex items-center justify-between">
                <span className="text-sm text-gray-400">{label}</span>
                <span className={`text-sm font-bold ${color}`}>{count}</span>
              </div>
            ))}
            <div className="border-t border-cyber-border pt-2 mt-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-400">Total</span>
                <span className="text-sm font-bold text-gray-200">
                  {gradeData?.total_vulnerabilities || 0}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Mini bandwidth - top talkers */}
        <div className="cyber-card">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
            <BarChart3 className="w-4 h-4 inline mr-1" />
            Top Bandwidth
          </h2>
          {topTalkers.length > 0 ? (
            <div className="space-y-2">
              {topTalkers.map((d, i) => {
                const total = (d.bytes_sent || 0) + (d.bytes_received || 0)
                const maxTotal = (topTalkers[0]?.bytes_sent || 0) + (topTalkers[0]?.bytes_received || 0)
                const pct = maxTotal > 0 ? (total / maxTotal) * 100 : 0
                return (
                  <div key={i}>
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-gray-400 font-mono">{d.ip_address}</span>
                      <span className="text-gray-500">{formatBytes(total)}</span>
                    </div>
                    <div className="w-full h-1.5 bg-cyber-bg rounded-full mt-1">
                      <div
                        className="h-full bg-matrix-green/60 rounded-full"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <p className="text-gray-600 text-xs">No bandwidth data yet</p>
          )}
        </div>
      </div>

      {/* Protected Devices Widget */}
      {protectionSummary && protectionSummary.protected_devices > 0 && (
        <div className="cyber-card border-matrix-green/20">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
              <Shield className="w-4 h-4 inline mr-1 text-matrix-green" />
              Protected Devices
            </h2>
            <span className="text-xs text-matrix-green bg-matrix-green/10 px-2 py-0.5 rounded-full">
              {protectionSummary.total_attacks_blocked} attacks blocked
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {protectionSummary.devices.map((device) => (
              <div
                key={device.id}
                className={`flex items-center justify-between px-3 py-2 rounded border ${
                  device.is_online
                    ? 'bg-matrix-green/5 border-matrix-green/20'
                    : 'bg-attack-red/5 border-attack-red/20'
                }`}
              >
                <div className="flex items-center gap-2">
                  <ShieldCheck
                    className={`w-4 h-4 ${
                      device.is_online ? 'text-matrix-green' : 'text-attack-red'
                    }`}
                  />
                  <div>
                    <p className="text-sm text-gray-200">{device.name}</p>
                    <p className="text-[10px] text-gray-500">{device.ip_address}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-xs text-matrix-green font-bold">
                    {device.uptime_percent}%
                  </p>
                  <p className="text-[10px] text-gray-500">uptime</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Traffic chart */}
      <div className="cyber-card">
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
          Real-Time Traffic (packets/sec)
        </h2>
        <TrafficChart trafficHistory={trafficHistory} />
      </div>

      {/* Recent alerts */}
      <div className="cyber-card">
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
          <Zap className="w-4 h-4 inline mr-1 text-attack-red" />
          Recent Alerts
        </h2>
        {alertHistory.length === 0 ? (
          <p className="text-gray-600 text-sm">
            No attacks detected yet.{' '}
            {activeDevices === 0
              ? 'Waiting for traffic data...'
              : 'Network is clean.'}
          </p>
        ) : (
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {alertHistory.slice(0, 10).map((alert) => (
              <div
                key={alert.id}
                className={`flex items-center justify-between px-3 py-2 rounded text-sm border ${
                  alert.severity === 'CRITICAL'
                    ? 'bg-attack-red/10 border-attack-red/30 text-attack-red'
                    : alert.severity === 'HIGH'
                    ? 'bg-attack-red/5 border-attack-red/20 text-red-400'
                    : alert.severity === 'MEDIUM'
                    ? 'bg-warn-yellow/10 border-warn-yellow/30 text-warn-yellow'
                    : 'bg-info-blue/10 border-info-blue/30 text-info-blue'
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className="font-bold text-xs">{alert.severity}</span>
                  {alert.ip_address && (
                    <span className="text-info-blue text-xs font-mono">{alert.ip_address}</span>
                  )}
                  <span className="text-gray-300">{alert.mac_address}</span>
                  <span className="opacity-75">{alert.attack_type}</span>
                </div>
                <span className="text-gray-500 text-xs">
                  {alert.pps?.toFixed(0)} pps
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
