import { useState, useEffect } from 'react'
import {
  ShieldBan,
  ShieldCheck,
  Gauge,
  Unplug,
  AlertTriangle,
  Loader2,
  Trash2,
} from 'lucide-react'
import { blockMAC, unblockMAC, rateLimitMAC, isolateMAC, getBlocked } from '../utils/api'

export default function RescuePanel() {
  const [mac, setMac] = useState('')
  const [reason, setReason] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [blocked, setBlocked] = useState([])

  const loadBlocked = async () => {
    try {
      const data = await getBlocked()
      setBlocked(data)
    } catch {
      // ignore
    }
  }

  useEffect(() => {
    loadBlocked()
    const interval = setInterval(loadBlocked, 10000)
    return () => clearInterval(interval)
  }, [])

  const execute = async (action) => {
    if (!mac.trim()) return
    setLoading(true)
    setResult(null)
    try {
      let data
      switch (action) {
        case 'block':
          data = await blockMAC(mac, reason)
          break
        case 'unblock':
          data = await unblockMAC(mac)
          break
        case 'rate_limit':
          data = await rateLimitMAC(mac)
          break
        case 'isolate':
          data = await isolateMAC(mac)
          break
      }
      setResult({ success: true, data })
      loadBlocked()
    } catch (err) {
      setResult({ success: false, error: err.message })
    } finally {
      setLoading(false)
    }
  }

  const handleUnblock = async (blockedMac) => {
    try {
      await unblockMAC(blockedMac)
      loadBlocked()
    } catch {
      // ignore
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-gray-200">Rescue Panel</h1>
      <p className="text-gray-500 text-sm">
        Manual mitigation controls. Enter a MAC address and choose an action.
      </p>

      {/* Action form */}
      <div className="cyber-card space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs text-gray-500 uppercase tracking-wider mb-1">
              MAC Address
            </label>
            <input
              type="text"
              value={mac}
              onChange={(e) => setMac(e.target.value)}
              placeholder="AA:BB:CC:DD:EE:FF"
              className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-matrix-green font-mono text-sm focus:outline-none focus:border-matrix-green/50"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-500 uppercase tracking-wider mb-1">
              Reason (optional)
            </label>
            <input
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Manual block — suspicious activity"
              className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-gray-300 text-sm focus:outline-none focus:border-matrix-green/50"
            />
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => execute('block')}
            disabled={loading || !mac.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-attack-red/10 border border-attack-red/30 text-attack-red rounded hover:bg-attack-red/20 transition-colors disabled:opacity-40 text-sm"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldBan className="w-4 h-4" />}
            Block MAC
          </button>
          <button
            onClick={() => execute('unblock')}
            disabled={loading || !mac.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-matrix-green/10 border border-matrix-green/30 text-matrix-green rounded hover:bg-matrix-green/20 transition-colors disabled:opacity-40 text-sm"
          >
            <ShieldCheck className="w-4 h-4" />
            Unblock MAC
          </button>
          <button
            onClick={() => execute('rate_limit')}
            disabled={loading || !mac.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-warn-yellow/10 border border-warn-yellow/30 text-warn-yellow rounded hover:bg-warn-yellow/20 transition-colors disabled:opacity-40 text-sm"
          >
            <Gauge className="w-4 h-4" />
            Rate Limit
          </button>
          <button
            onClick={() => execute('isolate')}
            disabled={loading || !mac.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-red-900/20 border border-red-800/30 text-red-300 rounded hover:bg-red-900/30 transition-colors disabled:opacity-40 text-sm"
          >
            <Unplug className="w-4 h-4" />
            Full Isolate
          </button>
        </div>

        {/* Result feedback */}
        {result && (
          <div
            className={`px-3 py-2 rounded text-sm border ${
              result.success
                ? 'bg-matrix-green/10 border-matrix-green/30 text-matrix-green'
                : 'bg-attack-red/10 border-attack-red/30 text-attack-red'
            }`}
          >
            {result.success ? (
              <pre className="text-xs overflow-x-auto">
                {JSON.stringify(result.data, null, 2)}
              </pre>
            ) : (
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                {result.error}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Blocked MACs list */}
      <div className="cyber-card">
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
          Currently Blocked ({blocked.length})
        </h2>
        {blocked.length === 0 ? (
          <p className="text-gray-600 text-sm">No MACs currently blocked.</p>
        ) : (
          <div className="space-y-2">
            {blocked.map((b) => (
              <div
                key={b.mac_address}
                className="flex items-center justify-between px-3 py-2 rounded bg-attack-red/5 border border-attack-red/20"
              >
                <div>
                  <span className="font-mono text-sm text-attack-red">
                    {b.mac_address}
                  </span>
                  <span className="text-xs text-gray-600 ml-3">{b.reason}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-600">
                    {b.expires_at
                      ? `Expires: ${new Date(b.expires_at).toLocaleString()}`
                      : 'Permanent'}
                  </span>
                  <button
                    onClick={() => handleUnblock(b.mac_address)}
                    className="text-gray-500 hover:text-matrix-green transition-colors"
                    title="Unblock"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
