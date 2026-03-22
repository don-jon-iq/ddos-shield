import { useEffect, useState, useCallback } from 'react'
import {
  X, Shield, ShieldAlert, ShieldCheck, Activity, AlertTriangle,
  Lock, Unlock, Globe, Server, Monitor, Wifi, ArrowLeft,
} from 'lucide-react'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from 'recharts'
import { getDeviceDetail, scanDevicePorts, assessDeviceSecurity } from '../utils/api'

const RISK_COLORS = {
  CRITICAL: 'text-attack-red bg-attack-red/10',
  HIGH: 'text-red-400 bg-red-400/10',
  MEDIUM: 'text-warn-yellow bg-warn-yellow/10',
  LOW: 'text-gray-400 bg-gray-400/10',
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

export default function DeviceDetail({ device, onClose }) {
  const [detail, setDetail] = useState(null)
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState('overview')

  const ip = device?.ip_address

  const loadDetail = useCallback(async () => {
    if (!ip) return
    setLoading(true)
    try {
      const data = await getDeviceDetail(ip)
      setDetail(data)
    } catch {
      // failed
    }
    setLoading(false)
  }, [ip])

  useEffect(() => {
    loadDetail()
  }, [loadDetail])

  const handleScanPorts = async () => {
    if (!ip) return
    try {
      await scanDevicePorts(ip, device.mac_address || '')
      loadDetail()
    } catch {
      // failed
    }
  }

  if (!device) return null

  const assessment = detail?.assessment
  const ports = detail?.ports || []
  const bwHistory = detail?.bandwidth_history || []
  const connections = detail?.connections || []
  const deviceAlerts = detail?.alerts || []
  const scoreColor =
    (assessment?.security_score || 100) >= 90 ? 'text-matrix-green' :
    (assessment?.security_score || 100) >= 75 ? 'text-info-blue' :
    (assessment?.security_score || 100) >= 50 ? 'text-warn-yellow' :
    (assessment?.security_score || 100) >= 25 ? 'text-orange-400' : 'text-attack-red'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-cyber-surface border border-cyber-border rounded-xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-cyber-border">
          <div className="flex items-center gap-3">
            <Monitor className="w-5 h-5 text-matrix-green" />
            <div>
              <h2 className="text-lg font-bold text-gray-200">
                {device.hostname || device.ip_address}
              </h2>
              <p className="text-xs text-gray-500">
                {device.ip_address} · {device.mac_address} · {device.vendor || 'Unknown vendor'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-white/5 text-gray-500 hover:text-gray-300 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 p-2 border-b border-cyber-border bg-cyber-bg/50">
          {[
            { id: 'overview', label: 'Overview' },
            { id: 'ports', label: `Ports (${ports.length})` },
            { id: 'bandwidth', label: 'Bandwidth' },
            { id: 'connections', label: `Connections (${connections.length})` },
            { id: 'alerts', label: `Alerts (${deviceAlerts.length})` },
          ].map(({ id, label }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
                tab === id
                  ? 'bg-matrix-green/10 text-matrix-green'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4">
          {loading ? (
            <div className="text-center py-8 text-gray-500">Loading device details...</div>
          ) : (
            <>
              {/* Overview */}
              {tab === 'overview' && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                    <div className="p-3 rounded-lg bg-cyber-bg border border-cyber-border">
                      <p className="text-[10px] text-gray-500 uppercase">Security Score</p>
                      <p className={`text-2xl font-black ${scoreColor}`}>
                        {assessment?.security_score ?? '—'}
                      </p>
                    </div>
                    <div className="p-3 rounded-lg bg-cyber-bg border border-cyber-border">
                      <p className="text-[10px] text-gray-500 uppercase">Open Ports</p>
                      <p className="text-2xl font-bold text-gray-200">{ports.length}</p>
                    </div>
                    <div className="p-3 rounded-lg bg-cyber-bg border border-cyber-border">
                      <p className="text-[10px] text-gray-500 uppercase">OS</p>
                      <p className="text-sm text-gray-300 mt-1">{device.os_info || '—'}</p>
                    </div>
                    <div className="p-3 rounded-lg bg-cyber-bg border border-cyber-border">
                      <p className="text-[10px] text-gray-500 uppercase">Type</p>
                      <p className="text-sm text-gray-300 mt-1 capitalize">{device.device_type || '—'}</p>
                    </div>
                  </div>

                  {assessment?.vulnerabilities?.length > 0 && (
                    <div>
                      <h3 className="text-sm font-semibold text-gray-400 mb-2">Vulnerabilities</h3>
                      <div className="space-y-2">
                        {assessment.vulnerabilities.map((v, i) => (
                          <div key={i} className={`p-2 rounded border text-xs ${RISK_COLORS[v.risk_level] || ''} border-current/20`}>
                            <span className="font-bold">Port {v.port} ({v.service})</span>
                            <span className="ml-2 opacity-70">{v.description}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <p className="text-xs text-gray-500">{assessment?.risk_summary || ''}</p>

                  <button
                    onClick={handleScanPorts}
                    className="text-xs px-3 py-1.5 bg-matrix-green/10 text-matrix-green border border-matrix-green/30 rounded-lg hover:bg-matrix-green/20 transition-colors"
                  >
                    Rescan Ports
                  </button>
                </div>
              )}

              {/* Ports */}
              {tab === 'ports' && (
                <div className="overflow-x-auto">
                  {ports.length > 0 ? (
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-gray-500 text-xs uppercase border-b border-cyber-border">
                          <th className="text-left pb-2">Port</th>
                          <th className="text-left pb-2">Service</th>
                          <th className="text-left pb-2">Version</th>
                          <th className="text-left pb-2">Risk</th>
                          <th className="text-left pb-2">State</th>
                        </tr>
                      </thead>
                      <tbody>
                        {ports.map((p, i) => (
                          <tr key={i} className="border-b border-cyber-border/30">
                            <td className="py-1.5 text-info-blue font-mono">{p.port}</td>
                            <td className="py-1.5 text-gray-300">{p.service_name}</td>
                            <td className="py-1.5 text-gray-500 text-xs">{p.service_version || '—'}</td>
                            <td className="py-1.5">
                              <span className={`text-[10px] px-1.5 py-0.5 rounded ${RISK_COLORS[p.risk_level] || RISK_COLORS.LOW}`}>
                                {p.risk_level}
                              </span>
                            </td>
                            <td className="py-1.5 text-matrix-green text-xs">{p.state}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p className="text-gray-500 text-sm text-center py-8">
                      No port scan data. Click "Rescan Ports" in Overview.
                    </p>
                  )}
                </div>
              )}

              {/* Bandwidth */}
              {tab === 'bandwidth' && (
                <div>
                  {bwHistory.length > 0 ? (
                    <ResponsiveContainer width="100%" height={300}>
                      <LineChart data={bwHistory.slice(-50)}>
                        <XAxis
                          dataKey="timestamp"
                          tickFormatter={(t) => new Date(t).toLocaleTimeString()}
                          stroke="#4b5563"
                          fontSize={10}
                        />
                        <YAxis
                          tickFormatter={(v) => formatBytes(v)}
                          stroke="#4b5563"
                          fontSize={10}
                        />
                        <Tooltip
                          formatter={(val) => formatBytes(val)}
                          contentStyle={{
                            backgroundColor: '#1a1f3a',
                            border: '1px solid #2d3555',
                            borderRadius: '8px',
                          }}
                        />
                        <Line type="monotone" dataKey="bytes_sent" stroke="#00ff41" dot={false} name="Sent" />
                        <Line type="monotone" dataKey="bytes_received" stroke="#3b82f6" dot={false} name="Received" />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <p className="text-gray-500 text-sm text-center py-8">
                      No bandwidth history for this device yet.
                    </p>
                  )}
                </div>
              )}

              {/* Connections */}
              {tab === 'connections' && (
                <div className="overflow-x-auto">
                  {connections.length > 0 ? (
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-gray-500 text-xs uppercase border-b border-cyber-border">
                          <th className="text-left pb-2">Destination</th>
                          <th className="text-right pb-2">Port</th>
                          <th className="text-right pb-2">Bytes</th>
                          <th className="text-right pb-2">Packets</th>
                        </tr>
                      </thead>
                      <tbody>
                        {connections.map((c, i) => (
                          <tr key={i} className="border-b border-cyber-border/30">
                            <td className="py-1.5 text-gray-300 font-mono text-xs">{c.dst_ip}</td>
                            <td className="text-right text-info-blue text-xs">{c.dst_port}</td>
                            <td className="text-right text-gray-400 text-xs">{formatBytes(c.bytes_transferred)}</td>
                            <td className="text-right text-gray-500 text-xs">{c.packet_count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <p className="text-gray-500 text-sm text-center py-8">No connections tracked.</p>
                  )}
                </div>
              )}

              {/* Alerts */}
              {tab === 'alerts' && (
                <div className="space-y-2">
                  {deviceAlerts.length > 0 ? (
                    deviceAlerts.map((alert, i) => (
                      <div key={i} className={`p-2 rounded border text-xs ${
                        alert.severity === 'CRITICAL' ? 'bg-attack-red/10 border-attack-red/30 text-attack-red' :
                        alert.severity === 'HIGH' ? 'bg-red-400/10 border-red-400/30 text-red-400' :
                        alert.severity === 'MEDIUM' ? 'bg-warn-yellow/10 border-warn-yellow/30 text-warn-yellow' :
                        'bg-info-blue/10 border-info-blue/20 text-info-blue'
                      }`}>
                        <div className="flex justify-between">
                          <span className="font-medium">{alert.title}</span>
                          <span className="opacity-50 text-[10px]">
                            {new Date(alert.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <p className="opacity-70 mt-0.5">{alert.description}</p>
                      </div>
                    ))
                  ) : (
                    <p className="text-gray-500 text-sm text-center py-8">No alerts for this device.</p>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
