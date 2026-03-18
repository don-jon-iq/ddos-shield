import { useEffect, useState } from 'react'
import { Search, Filter, Download } from 'lucide-react'
import { getAttacks } from '../utils/api'

const SEVERITY_STYLES = {
  CRITICAL: 'text-attack-red',
  HIGH: 'text-red-400',
  MEDIUM: 'text-warn-yellow',
  LOW: 'text-info-blue',
}

export default function AttackHistory({ onShowEducational }) {
  const [attacks, setAttacks] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [filters, setFilters] = useState({
    severity: '',
    attack_type: '',
    mac_address: '',
  })
  const [loading, setLoading] = useState(false)
  const limit = 25

  const loadAttacks = async () => {
    setLoading(true)
    try {
      const params = {
        limit,
        offset: page * limit,
        ...(filters.severity && { severity: filters.severity }),
        ...(filters.attack_type && { attack_type: filters.attack_type }),
        ...(filters.mac_address && { mac_address: filters.mac_address }),
      }
      const data = await getAttacks(params)
      setAttacks(data.data)
      setTotal(data.total)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadAttacks()
  }, [page, filters])

  const totalPages = Math.ceil(total / limit)

  const updateFilter = (key, value) => {
    setFilters((prev) => ({ ...prev, [key]: value }))
    setPage(0)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-200">Attack History</h1>
        <span className="text-sm text-gray-500">{total} total records</span>
      </div>

      {/* Filters */}
      <div className="cyber-card">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="w-4 h-4 text-gray-600 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={filters.mac_address}
              onChange={(e) => updateFilter('mac_address', e.target.value)}
              placeholder="Filter by MAC..."
              className="w-full pl-9 pr-3 py-2 bg-cyber-bg border border-cyber-border rounded text-sm text-gray-300 focus:outline-none focus:border-matrix-green/50"
            />
          </div>
          <select
            value={filters.severity}
            onChange={(e) => updateFilter('severity', e.target.value)}
            className="bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-sm text-gray-300 focus:outline-none"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select
            value={filters.attack_type}
            onChange={(e) => updateFilter('attack_type', e.target.value)}
            className="bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-sm text-gray-300 focus:outline-none"
          >
            <option value="">All Types</option>
            <option value="SYN_FLOOD">SYN Flood</option>
            <option value="UDP_FLOOD">UDP Flood</option>
            <option value="ICMP_FLOOD">ICMP Flood</option>
            <option value="HTTP_FLOOD">HTTP Flood</option>
            <option value="ARP_SPOOF">ARP Spoof</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="cyber-card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-500 text-xs uppercase tracking-wider border-b border-cyber-border">
              <th className="text-left py-3 px-2">Time</th>
              <th className="text-left py-3 px-2">MAC Address</th>
              <th className="text-left py-3 px-2">Attack Type</th>
              <th className="text-center py-3 px-2">Severity</th>
              <th className="text-right py-3 px-2">PPS</th>
              <th className="text-right py-3 px-2">Z-Score</th>
              <th className="text-center py-3 px-2">Mitigated</th>
            </tr>
          </thead>
          <tbody>
            {attacks.map((attack) => (
              <tr
                key={attack.id}
                className="border-b border-cyber-border/50 hover:bg-white/5 transition-colors"
              >
                <td className="py-2.5 px-2 text-xs text-gray-400">
                  {new Date(attack.timestamp).toLocaleString()}
                </td>
                <td className="py-2.5 px-2 font-mono text-matrix-green text-xs">
                  {attack.mac_address}
                </td>
                <td className="py-2.5 px-2">
                  <button
                    onClick={() => onShowEducational?.(attack.attack_type)}
                    className="text-info-blue text-xs hover:underline"
                  >
                    {attack.attack_type}
                  </button>
                </td>
                <td className="py-2.5 px-2 text-center">
                  <span className={`text-xs font-bold ${SEVERITY_STYLES[attack.severity]}`}>
                    {attack.severity}
                  </span>
                </td>
                <td className="py-2.5 px-2 text-right font-mono text-xs">
                  {attack.packets_per_second?.toFixed(0)}
                </td>
                <td className="py-2.5 px-2 text-right font-mono text-xs text-gray-500">
                  {attack.z_score?.toFixed(2) || '—'}
                </td>
                <td className="py-2.5 px-2 text-center">
                  {attack.mitigated ? (
                    <span className="text-matrix-green text-xs">Yes</span>
                  ) : (
                    <span className="text-gray-600 text-xs">No</span>
                  )}
                </td>
              </tr>
            ))}
            {attacks.length === 0 && (
              <tr>
                <td colSpan={7} className="py-8 text-center text-gray-600">
                  {loading ? 'Loading...' : 'No attack records found'}
                </td>
              </tr>
            )}
          </tbody>
        </table>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-4 pt-3 border-t border-cyber-border">
            <span className="text-xs text-gray-500">
              Page {page + 1} of {totalPages}
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="px-3 py-1 text-xs bg-cyber-bg border border-cyber-border rounded disabled:opacity-30 hover:border-matrix-green/50"
              >
                Previous
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="px-3 py-1 text-xs bg-cyber-bg border border-cyber-border rounded disabled:opacity-30 hover:border-matrix-green/50"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
