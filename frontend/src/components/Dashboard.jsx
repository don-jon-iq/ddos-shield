import { useEffect, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Monitor,
  ShieldCheck,
  ShieldAlert,
  Zap,
} from 'lucide-react'
import { getStatus, getAttackStats } from '../utils/api'
import TrafficChart from './TrafficChart'

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
    <div
      className={`cyber-card ${colorMap[color]} ${glow ? glowMap[color] : ''}`}
    >
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

export default function Dashboard({ traffic, alerts, alertHistory, trafficHistory, activeDevices, wsClients }) {
  const [stats, setStats] = useState({ total_attacks: 0, by_type: {}, by_severity: {} })
  const [status, setStatus] = useState(null)

  useEffect(() => {
    const load = async () => {
      try {
        const [st, as] = await Promise.all([getStatus(), getAttackStats()])
        setStatus(st)
        setStats(as)
      } catch {
        // API may not be ready yet
      }
    }
    load()
    const interval = setInterval(load, 15000)
    return () => clearInterval(interval)
  }, [])

  const criticalCount = stats.by_severity?.CRITICAL || 0
  const highCount = stats.by_severity?.HIGH || 0

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

      {/* Stats grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Active Devices"
          value={activeDevices}
          icon={Monitor}
          color="blue"
        />
        <StatCard
          label="Live Alerts"
          value={alerts.length}
          icon={alerts.length > 0 ? ShieldAlert : ShieldCheck}
          color={alerts.length > 0 ? 'red' : 'green'}
          glow={alerts.length > 0}
        />
        <StatCard
          label="Total Attacks"
          value={stats.total_attacks}
          icon={AlertTriangle}
          color={stats.total_attacks > 0 ? 'yellow' : 'green'}
        />
        <StatCard
          label="WS Clients"
          value={wsClients}
          icon={Activity}
          color="blue"
        />
      </div>

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
          <p className="text-gray-600 text-sm">No attacks detected yet. Network is clean.</p>
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
