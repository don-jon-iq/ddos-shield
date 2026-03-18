import { useEffect, useState } from 'react'
import { Monitor, Server, Cpu, Search, RefreshCw } from 'lucide-react'
import { getDevices } from '../utils/api'

const STATUS_STYLES = {
  NORMAL: 'bg-matrix-green/10 text-matrix-green border-matrix-green/30',
  SUSPICIOUS: 'bg-warn-yellow/10 text-warn-yellow border-warn-yellow/30',
  BLOCKED: 'bg-attack-red/10 text-attack-red border-attack-red/30',
}

export default function DeviceList({ traffic }) {
  const [devices, setDevices] = useState([])
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all') // all | vm | physical | suspicious
  const [loading, setLoading] = useState(false)

  const loadDevices = async () => {
    setLoading(true)
    try {
      const data = await getDevices()
      setDevices(data)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadDevices()
    const interval = setInterval(loadDevices, 10000)
    return () => clearInterval(interval)
  }, [])

  // Merge live traffic data with device list
  const enrichedDevices = devices.map((device) => {
    const liveTraffic = traffic.find(
      (t) => t.mac_address === device.mac_address
    )
    return { ...device, live: liveTraffic }
  })

  const filtered = enrichedDevices.filter((d) => {
    const matchesSearch =
      d.mac_address.toLowerCase().includes(search.toLowerCase()) ||
      d.vendor.toLowerCase().includes(search.toLowerCase())
    const matchesFilter =
      filter === 'all' ||
      (filter === 'vm' && d.is_vm) ||
      (filter === 'physical' && !d.is_vm) ||
      (filter === 'suspicious' && d.status !== 'NORMAL')
    return matchesSearch && matchesFilter
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-200">Network Devices</h1>
        <button
          onClick={loadDevices}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-cyber-surface border border-cyber-border rounded hover:border-matrix-green/50 transition-colors"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 max-w-xs">
          <Search className="w-4 h-4 text-gray-600 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search MAC or vendor..."
            className="w-full pl-9 pr-3 py-2 bg-cyber-bg border border-cyber-border rounded text-sm text-gray-300 focus:outline-none focus:border-matrix-green/50"
          />
        </div>
        <div className="flex gap-1">
          {['all', 'vm', 'physical', 'suspicious'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 text-xs rounded capitalize transition-colors ${
                filter === f
                  ? 'bg-matrix-green/10 text-matrix-green border border-matrix-green/30'
                  : 'bg-cyber-bg text-gray-500 border border-cyber-border hover:text-gray-300'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Device table */}
      <div className="cyber-card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-500 text-xs uppercase tracking-wider border-b border-cyber-border">
              <th className="text-left py-3 px-2">Device</th>
              <th className="text-left py-3 px-2">MAC Address</th>
              <th className="text-left py-3 px-2">Vendor</th>
              <th className="text-right py-3 px-2">Total PPS</th>
              <th className="text-right py-3 px-2">Packets</th>
              <th className="text-center py-3 px-2">Type</th>
              <th className="text-center py-3 px-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((device) => (
              <tr
                key={device.mac_address}
                className="border-b border-cyber-border/50 hover:bg-white/5 transition-colors"
              >
                <td className="py-3 px-2">
                  {device.is_vm ? (
                    <Server className="w-4 h-4 text-info-blue" />
                  ) : (
                    <Monitor className="w-4 h-4 text-gray-400" />
                  )}
                </td>
                <td className="py-3 px-2 font-mono text-matrix-green text-xs">
                  {device.mac_address}
                </td>
                <td className="py-3 px-2 text-gray-400">{device.vendor}</td>
                <td className="py-3 px-2 text-right font-mono">
                  {device.live?.total_pps?.toFixed(1) || '—'}
                </td>
                <td className="py-3 px-2 text-right font-mono text-gray-400">
                  {device.total_packets?.toLocaleString()}
                </td>
                <td className="py-3 px-2 text-center">
                  <span className="text-xs px-2 py-0.5 rounded bg-cyber-bg">
                    {device.is_vm ? 'VM' : 'Physical'}
                  </span>
                </td>
                <td className="py-3 px-2 text-center">
                  <span
                    className={`text-xs px-2 py-0.5 rounded border ${STATUS_STYLES[device.status]}`}
                  >
                    {device.status}
                  </span>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="py-8 text-center text-gray-600">
                  No devices found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
