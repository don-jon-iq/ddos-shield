import { useEffect, useState } from 'react'
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Clock,
  Zap,
  Ban,
  CheckCircle,
  XCircle,
} from 'lucide-react'
import {
  getProtectionSummary,
  getProtectionLogs,
  getProtectionStatus,
} from '../utils/api'

function ProtectedDeviceCard({ device }) {
  const [logs, setLogs] = useState([])
  const [showLogs, setShowLogs] = useState(false)

  useEffect(() => {
    if (showLogs) {
      getProtectionLogs(device.id, 20)
        .then(setLogs)
        .catch(() => {})
    }
  }, [showLogs, device.id])

  return (
    <div className="cyber-card border-matrix-green/30 glow-green">
      {/* Device header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-matrix-green/20 rounded-lg">
            <ShieldCheck className="w-6 h-6 text-matrix-green" />
          </div>
          <div>
            <h3 className="text-gray-200 font-semibold">{device.name}</h3>
            <span className="text-xs text-info-blue font-mono">
              {device.ip_address}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          {device.is_online ? (
            <>
              <CheckCircle className="w-4 h-4 text-matrix-green" />
              <span className="text-xs text-matrix-green font-medium">
                Online
              </span>
            </>
          ) : (
            <>
              <XCircle className="w-4 h-4 text-attack-red" />
              <span className="text-xs text-attack-red font-medium">
                Offline
              </span>
            </>
          )}
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-3 gap-3 mb-4">
        <div className="text-center p-2 bg-cyber-bg rounded">
          <div className="flex items-center justify-center gap-1 mb-1">
            <Ban className="w-3 h-3 text-attack-red" />
          </div>
          <p className="text-xl font-bold text-attack-red">
            {device.attacks_blocked}
          </p>
          <p className="text-[10px] text-gray-500 uppercase">
            Attacks Blocked
          </p>
        </div>
        <div className="text-center p-2 bg-cyber-bg rounded">
          <div className="flex items-center justify-center gap-1 mb-1">
            <Activity className="w-3 h-3 text-matrix-green" />
          </div>
          <p className="text-xl font-bold text-matrix-green">
            {device.uptime_percent}%
          </p>
          <p className="text-[10px] text-gray-500 uppercase">Uptime</p>
        </div>
        <div className="text-center p-2 bg-cyber-bg rounded">
          <div className="flex items-center justify-center gap-1 mb-1">
            <Clock className="w-3 h-3 text-info-blue" />
          </div>
          <p className="text-xs font-bold text-info-blue mt-1">
            {device.last_attack_time
              ? new Date(device.last_attack_time).toLocaleTimeString()
              : 'Never'}
          </p>
          <p className="text-[10px] text-gray-500 uppercase">Last Attack</p>
        </div>
      </div>

      {/* Protection log toggle */}
      <button
        onClick={() => setShowLogs(!showLogs)}
        className="w-full text-xs text-gray-400 hover:text-matrix-green py-2 border-t border-cyber-border transition-colors"
      >
        {showLogs ? 'Hide' : 'Show'} Protection Log
      </button>

      {/* Protection logs */}
      {showLogs && (
        <div className="mt-2 space-y-1.5 max-h-48 overflow-y-auto">
          {logs.length === 0 ? (
            <p className="text-xs text-gray-600 text-center py-3">
              No protection events yet
            </p>
          ) : (
            logs.map((log) => (
              <div
                key={log.id}
                className="flex items-center justify-between px-2 py-1.5 bg-cyber-bg rounded text-xs"
              >
                <div className="flex items-center gap-2">
                  <Zap className="w-3 h-3 text-attack-red" />
                  <span className="text-gray-300">{log.attack_type}</span>
                  <span className="text-gray-500 font-mono">
                    {log.attacker_ip || log.attacker_mac}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-matrix-green font-medium">
                    {log.action_taken}
                  </span>
                  <span className="text-gray-600">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  )
}

export default function ProtectionStatus() {
  const [summary, setSummary] = useState(null)
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const [sum, stat] = await Promise.all([
          getProtectionSummary(),
          getProtectionStatus(),
        ])
        setSummary(sum)
        setStatus(stat)
      } catch {
        // API may not be ready
      } finally {
        setLoading(false)
      }
    }
    load()
    const interval = setInterval(load, 5000)
    return () => clearInterval(interval)
  }, [])

  if (loading) {
    return (
      <div className="text-center py-12 text-gray-500">
        Loading protection status...
      </div>
    )
  }

  const devices = summary?.devices || []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-200">
            Protection Dashboard
          </h1>
          <p className="text-xs text-gray-500 mt-1">
            Active defense monitoring for protected devices
          </p>
        </div>
        {summary && (
          <div className="flex items-center gap-2 px-3 py-1.5 bg-matrix-green/10 border border-matrix-green/30 rounded-full">
            <ShieldCheck className="w-4 h-4 text-matrix-green" />
            <span className="text-xs text-matrix-green font-semibold">
              {summary.protected_devices} Device
              {summary.protected_devices !== 1 ? 's' : ''} Protected
            </span>
          </div>
        )}
      </div>

      {/* Summary stats */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="cyber-card border-matrix-green/20">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">
                  Protected Devices
                </p>
                <p className="text-3xl font-bold text-matrix-green mt-1">
                  {summary.protected_devices}
                </p>
              </div>
              <Shield className="w-10 h-10 text-matrix-green/30" />
            </div>
          </div>
          <div className="cyber-card border-attack-red/20">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">
                  Attacks Blocked
                </p>
                <p className="text-3xl font-bold text-attack-red mt-1">
                  {summary.total_attacks_blocked}
                </p>
              </div>
              <Ban className="w-10 h-10 text-attack-red/30" />
            </div>
          </div>
          <div className="cyber-card border-info-blue/20">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">
                  Average Uptime
                </p>
                <p className="text-3xl font-bold text-info-blue mt-1">
                  {summary.average_uptime_percent}%
                </p>
              </div>
              <Activity className="w-10 h-10 text-info-blue/30" />
            </div>
          </div>
        </div>
      )}

      {/* Protected device cards */}
      {devices.length === 0 ? (
        <div className="text-center py-12">
          <ShieldAlert className="w-16 h-16 text-gray-700 mx-auto mb-4" />
          <h3 className="text-gray-400 font-semibold mb-2">
            No Devices Protected
          </h3>
          <p className="text-gray-600 text-sm max-w-md mx-auto">
            Go to the Device Manager and enable protection on devices you want
            to defend against DDoS attacks.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {devices.map((device) => (
            <ProtectedDeviceCard key={device.id} device={device} />
          ))}
        </div>
      )}

      {/* Blocked attackers section */}
      {status?.blocked_attackers &&
        Object.keys(status.blocked_attackers).length > 0 && (
          <div className="cyber-card">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
              <Ban className="w-4 h-4 inline mr-1 text-attack-red" />
              Blocked Attackers
            </h2>
            <div className="space-y-2">
              {Object.entries(status.blocked_attackers).map(
                ([deviceId, macs]) => (
                  <div
                    key={deviceId}
                    className="flex items-center gap-3 px-3 py-2 bg-attack-red/5 border border-attack-red/20 rounded text-sm"
                  >
                    <Ban className="w-4 h-4 text-attack-red" />
                    <span className="text-gray-400">
                      Device #{deviceId}:
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {macs.map((mac) => (
                        <span
                          key={mac}
                          className="px-2 py-0.5 bg-attack-red/10 text-attack-red text-xs font-mono rounded"
                        >
                          {mac}
                        </span>
                      ))}
                    </div>
                  </div>
                )
              )}
            </div>
          </div>
        )}
    </div>
  )
}
