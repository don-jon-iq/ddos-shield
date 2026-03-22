import { useEffect, useState, useCallback } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts'
import { ArrowUpDown, Download, Upload, Activity, Globe } from 'lucide-react'
import {
  getTopTalkers, getProtocols, getConnections, getBandwidth,
  getDnsQueries,
} from '../utils/api'

const PROTOCOL_COLORS = {
  HTTPS: '#00ff41',
  HTTP: '#3b82f6',
  DNS: '#eab308',
  SSH: '#ef4444',
  Other: '#6b7280',
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

function formatBps(bps) {
  if (bps === 0) return '0 bps'
  const k = 1000
  const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps']
  const i = Math.floor(Math.log(Math.abs(bps)) / Math.log(k))
  return `${(bps / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

export default function BandwidthMonitor() {
  const [topTalkers, setTopTalkers] = useState([])
  const [protocols, setProtocols] = useState({})
  const [connections, setConnections] = useState([])
  const [dnsQueries, setDnsQueries] = useState([])
  const [bandwidth, setBandwidth] = useState([])
  const [tab, setTab] = useState('top-talkers')

  const loadData = useCallback(async () => {
    try {
      const [tt, proto, conns, bw, dns] = await Promise.all([
        getTopTalkers(15),
        getProtocols(),
        getConnections(),
        getBandwidth(),
        getDnsQueries(null, 50),
      ])
      setTopTalkers(tt)
      setProtocols(proto)
      setConnections(conns)
      setBandwidth(bw)
      setDnsQueries(dns)
    } catch {
      // API not ready
    }
  }, [])

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 10000)
    return () => clearInterval(interval)
  }, [loadData])

  // Prepare chart data
  const barData = topTalkers.map((d) => ({
    name: d.ip_address || d.mac_address?.substring(0, 8),
    sent: d.bytes_sent || 0,
    received: d.bytes_received || 0,
    total: (d.bytes_sent || 0) + (d.bytes_received || 0),
  }))

  const pieData = Object.entries(protocols)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  const totalBandwidth = bandwidth.reduce(
    (acc, d) => acc + (d.bytes_sent || 0) + (d.bytes_received || 0),
    0
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-200">Bandwidth Monitor</h1>
        <div className="flex items-center gap-4 text-sm">
          <div className="flex items-center gap-2 text-matrix-green">
            <Activity className="w-4 h-4" />
            <span>{bandwidth.length} active devices</span>
          </div>
          <div className="text-gray-400">
            Total: {formatBytes(totalBandwidth)}
          </div>
        </div>
      </div>

      {/* Tab navigation */}
      <div className="flex gap-1 bg-cyber-surface p-1 rounded-lg border border-cyber-border w-fit">
        {[
          { id: 'top-talkers', label: 'Top Talkers' },
          { id: 'protocols', label: 'Protocols' },
          { id: 'connections', label: 'Connections' },
          { id: 'dns', label: 'DNS Queries' },
        ].map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`px-4 py-1.5 text-sm rounded-md transition-colors ${
              tab === id
                ? 'bg-matrix-green/10 text-matrix-green'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Top Talkers */}
      {tab === 'top-talkers' && (
        <div className="space-y-4">
          <div className="cyber-card">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
              Top Talkers by Bandwidth
            </h2>
            {barData.length > 0 ? (
              <ResponsiveContainer width="100%" height={400}>
                <BarChart data={barData} layout="vertical" margin={{ left: 80 }}>
                  <XAxis
                    type="number"
                    tickFormatter={formatBytes}
                    stroke="#4b5563"
                    fontSize={11}
                  />
                  <YAxis
                    type="category"
                    dataKey="name"
                    stroke="#4b5563"
                    fontSize={11}
                    width={75}
                  />
                  <Tooltip
                    formatter={(val) => formatBytes(val)}
                    contentStyle={{
                      backgroundColor: '#1a1f3a',
                      border: '1px solid #2d3555',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                  <Bar dataKey="sent" fill="#00ff41" name="Sent" stackId="bw" />
                  <Bar dataKey="received" fill="#3b82f6" name="Received" stackId="bw" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-gray-600 text-sm text-center py-8">
                No bandwidth data available yet.
              </p>
            )}
          </div>

          {/* Device bandwidth table */}
          <div className="cyber-card">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
              Per-Device Bandwidth
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-500 text-xs uppercase border-b border-cyber-border">
                    <th className="text-left pb-2">Device</th>
                    <th className="text-right pb-2">
                      <Upload className="w-3 h-3 inline mr-1" />Sent
                    </th>
                    <th className="text-right pb-2">
                      <Download className="w-3 h-3 inline mr-1" />Received
                    </th>
                    <th className="text-right pb-2">Speed</th>
                    <th className="text-right pb-2">Packets</th>
                  </tr>
                </thead>
                <tbody>
                  {topTalkers.map((d, i) => (
                    <tr key={i} className="border-b border-cyber-border/30 hover:bg-white/5">
                      <td className="py-2">
                        <div className="text-gray-200 font-mono text-xs">{d.ip_address}</div>
                        <div className="text-gray-600 text-[10px]">{d.mac_address}</div>
                      </td>
                      <td className="text-right text-matrix-green text-xs">
                        {formatBytes(d.bytes_sent || 0)}
                      </td>
                      <td className="text-right text-info-blue text-xs">
                        {formatBytes(d.bytes_received || 0)}
                      </td>
                      <td className="text-right text-gray-400 text-xs">
                        {formatBps(d.bps_sent || 0)}
                      </td>
                      <td className="text-right text-gray-500 text-xs">
                        {(d.packets_sent || 0) + (d.packets_received || 0)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Protocol Distribution */}
      {tab === 'protocols' && (
        <div className="cyber-card">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
            Protocol Distribution
          </h2>
          {pieData.length > 0 ? (
            <div className="flex items-center justify-center">
              <ResponsiveContainer width="100%" height={350}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={80}
                    outerRadius={130}
                    dataKey="value"
                    label={({ name, percent }) =>
                      `${name} ${(percent * 100).toFixed(0)}%`
                    }
                    labelLine={false}
                  >
                    {pieData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={PROTOCOL_COLORS[entry.name] || '#6b7280'}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    formatter={(val) => formatBytes(val)}
                    contentStyle={{
                      backgroundColor: '#1a1f3a',
                      border: '1px solid #2d3555',
                      borderRadius: '8px',
                    }}
                  />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="text-gray-600 text-sm text-center py-8">
              No protocol data available yet.
            </p>
          )}
        </div>
      )}

      {/* Connections */}
      {tab === 'connections' && (
        <div className="cyber-card">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
            Active Connections ({connections.length})
          </h2>
          <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-cyber-surface">
                <tr className="text-gray-500 text-xs uppercase border-b border-cyber-border">
                  <th className="text-left pb-2">Source</th>
                  <th className="text-center pb-2">→</th>
                  <th className="text-left pb-2">Destination</th>
                  <th className="text-right pb-2">Port</th>
                  <th className="text-right pb-2">Bytes</th>
                  <th className="text-right pb-2">Packets</th>
                </tr>
              </thead>
              <tbody>
                {connections.slice(0, 100).map((c, i) => (
                  <tr key={i} className="border-b border-cyber-border/30 hover:bg-white/5">
                    <td className="py-1.5">
                      <span className="text-gray-300 font-mono text-xs">{c.src_ip}</span>
                    </td>
                    <td className="text-center text-gray-600">→</td>
                    <td className="py-1.5">
                      <span className="text-gray-300 font-mono text-xs">{c.dst_ip}</span>
                    </td>
                    <td className="text-right text-info-blue text-xs">{c.dst_port}</td>
                    <td className="text-right text-gray-400 text-xs">
                      {formatBytes(c.bytes_transferred || 0)}
                    </td>
                    <td className="text-right text-gray-500 text-xs">{c.packet_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {connections.length === 0 && (
              <p className="text-gray-600 text-sm text-center py-8">
                No active connections tracked yet.
              </p>
            )}
          </div>
        </div>
      )}

      {/* DNS Queries */}
      {tab === 'dns' && (
        <div className="cyber-card">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
            <Globe className="w-4 h-4 inline mr-1" />
            Recent DNS Queries ({dnsQueries.length})
          </h2>
          <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-cyber-surface">
                <tr className="text-gray-500 text-xs uppercase border-b border-cyber-border">
                  <th className="text-left pb-2">Device</th>
                  <th className="text-left pb-2">Domain</th>
                  <th className="text-left pb-2">Type</th>
                  <th className="text-right pb-2">Time</th>
                </tr>
              </thead>
              <tbody>
                {dnsQueries.map((q, i) => (
                  <tr key={i} className="border-b border-cyber-border/30 hover:bg-white/5">
                    <td className="py-1.5">
                      <span className="text-gray-400 font-mono text-xs">{q.ip_address}</span>
                    </td>
                    <td className="py-1.5">
                      <span className={`text-xs ${
                        q.domain?.length > 50 ? 'text-attack-red' : 'text-gray-300'
                      }`}>
                        {q.domain}
                      </span>
                    </td>
                    <td className="text-gray-500 text-xs">{q.query_type}</td>
                    <td className="text-right text-gray-600 text-xs">
                      {q.timestamp ? new Date(q.timestamp).toLocaleTimeString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {dnsQueries.length === 0 && (
              <p className="text-gray-600 text-sm text-center py-8">
                No DNS queries logged yet.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
