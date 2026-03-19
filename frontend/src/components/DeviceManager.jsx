import { useEffect, useState, useCallback } from 'react'
import {
  Shield,
  ShieldCheck,
  ShieldOff,
  Plus,
  Search,
  RefreshCw,
  Trash2,
  Edit3,
  X,
  Server,
  Laptop,
  Router,
  HelpCircle,
  Circle,
} from 'lucide-react'
import {
  getManagedDevices,
  addManagedDevice,
  deleteManagedDevice,
  toggleDeviceProtection,
  scanNetwork,
  getDiscoveredDevices,
} from '../utils/api'

const DEVICE_ICONS = {
  server: Server,
  client: Laptop,
  router: Router,
  unknown: HelpCircle,
}

const DEVICE_LABELS = {
  server: 'Server',
  client: 'Client',
  router: 'Router',
  unknown: 'Unknown',
}

function DeviceCard({ device, onToggleProtection, onDelete }) {
  const [toggling, setToggling] = useState(false)
  const Icon = DEVICE_ICONS[device.device_type] || HelpCircle

  const handleToggle = async () => {
    setToggling(true)
    try {
      await onToggleProtection(device.id)
    } finally {
      setToggling(false)
    }
  }

  const isProtected = device.is_protected

  return (
    <div
      className={`cyber-card relative transition-all duration-300 ${
        isProtected
          ? 'border-matrix-green/50 glow-green'
          : 'border-cyber-border'
      }`}
    >
      {/* Protection badge */}
      {isProtected && (
        <div className="absolute -top-2 -right-2 bg-matrix-green text-black text-xs font-bold px-2 py-0.5 rounded-full">
          PROTECTED
        </div>
      )}

      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <div
            className={`p-2 rounded-lg ${
              isProtected ? 'bg-matrix-green/20' : 'bg-gray-800'
            }`}
          >
            <Icon
              className={`w-6 h-6 ${
                isProtected ? 'text-matrix-green' : 'text-gray-400'
              }`}
            />
          </div>
          <div>
            <h3 className="text-gray-200 font-semibold text-sm">
              {device.name || 'Unnamed Device'}
            </h3>
            <span className="text-xs text-gray-500">
              {DEVICE_LABELS[device.device_type]}
            </span>
          </div>
        </div>

        {/* Online status */}
        <div className="flex items-center gap-1">
          <Circle
            className={`w-2.5 h-2.5 fill-current ${
              device.is_online ? 'text-matrix-green' : 'text-attack-red'
            }`}
          />
          <span
            className={`text-xs ${
              device.is_online ? 'text-matrix-green' : 'text-attack-red'
            }`}
          >
            {device.is_online ? 'Online' : 'Offline'}
          </span>
        </div>
      </div>

      {/* Details */}
      <div className="space-y-1.5 text-xs mb-4">
        <div className="flex justify-between">
          <span className="text-gray-500">MAC</span>
          <span className="text-gray-300 font-mono">{device.mac_address}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-gray-500">IP</span>
          <span className="text-info-blue font-mono">
            {device.ip_address || '—'}
          </span>
        </div>
        {device.hostname && (
          <div className="flex justify-between">
            <span className="text-gray-500">Host</span>
            <span className="text-gray-300">{device.hostname}</span>
          </div>
        )}
        {device.os_info && (
          <div className="flex justify-between">
            <span className="text-gray-500">OS</span>
            <span className="text-gray-400">{device.os_info}</span>
          </div>
        )}
      </div>

      {/* Protection stats (when protected) */}
      {isProtected && (
        <div className="grid grid-cols-2 gap-2 mb-4 p-2 bg-matrix-green/5 rounded border border-matrix-green/20">
          <div className="text-center">
            <p className="text-lg font-bold text-matrix-green">
              {device.attacks_blocked}
            </p>
            <p className="text-[10px] text-gray-500 uppercase">Blocked</p>
          </div>
          <div className="text-center">
            <p className="text-lg font-bold text-matrix-green">
              {device.uptime_percent}%
            </p>
            <p className="text-[10px] text-gray-500 uppercase">Uptime</p>
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center justify-between pt-3 border-t border-cyber-border">
        {/* Protection toggle */}
        <button
          onClick={handleToggle}
          disabled={toggling}
          className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-semibold transition-all ${
            isProtected
              ? 'bg-matrix-green/20 text-matrix-green hover:bg-matrix-green/30 border border-matrix-green/30'
              : 'bg-gray-800 text-gray-400 hover:text-matrix-green hover:bg-gray-700 border border-gray-700'
          } ${toggling ? 'opacity-50 cursor-wait' : ''}`}
        >
          {isProtected ? (
            <ShieldCheck className="w-4 h-4" />
          ) : (
            <ShieldOff className="w-4 h-4" />
          )}
          {toggling
            ? '...'
            : isProtected
            ? 'Protected'
            : 'Enable Protection'}
        </button>

        <button
          onClick={() => onDelete(device.id)}
          className="p-1.5 text-gray-600 hover:text-attack-red transition-colors"
          title="Remove device"
        >
          <Trash2 className="w-4 h-4" />
        </button>
      </div>
    </div>
  )
}

function AddDeviceModal({ onClose, onAdd, discoveredDevices }) {
  const [tab, setTab] = useState('manual')
  const [form, setForm] = useState({
    name: '',
    mac_address: '',
    ip_address: '',
    device_type: 'unknown',
    hostname: '',
    os_info: '',
    notes: '',
  })
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!form.name || !form.mac_address) {
      setError('Name and MAC address are required')
      return
    }
    setSubmitting(true)
    setError('')
    try {
      await onAdd(form)
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  const handleImport = async (discovered) => {
    setSubmitting(true)
    try {
      await onAdd({
        name: discovered.hostname || `Device-${discovered.ip_address}`,
        mac_address: discovered.mac_address,
        ip_address: discovered.ip_address,
        hostname: discovered.hostname,
        os_info: discovered.os_info,
        device_type: 'unknown',
      })
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-cyber-surface border border-cyber-border rounded-xl w-full max-w-lg mx-4 max-h-[80vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-cyber-border">
          <h2 className="text-gray-200 font-semibold">Add Device</h2>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-300"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-cyber-border">
          <button
            onClick={() => setTab('manual')}
            className={`flex-1 py-2.5 text-sm font-medium ${
              tab === 'manual'
                ? 'text-matrix-green border-b-2 border-matrix-green'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            Manual Entry
          </button>
          <button
            onClick={() => setTab('discovered')}
            className={`flex-1 py-2.5 text-sm font-medium ${
              tab === 'discovered'
                ? 'text-matrix-green border-b-2 border-matrix-green'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            From Scan ({discoveredDevices.length})
          </button>
        </div>

        {error && (
          <div className="mx-4 mt-3 p-2 bg-attack-red/10 border border-attack-red/30 rounded text-attack-red text-xs">
            {error}
          </div>
        )}

        {tab === 'manual' ? (
          <form onSubmit={handleSubmit} className="p-4 space-y-3">
            <div>
              <label className="text-xs text-gray-500 block mb-1">Name *</label>
              <input
                type="text"
                value={form.name}
                onChange={(e) =>
                  setForm({ ...form, name: e.target.value })
                }
                className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-sm text-gray-200 focus:border-matrix-green/50 focus:outline-none"
                placeholder="e.g. File Server"
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">
                MAC Address *
              </label>
              <input
                type="text"
                value={form.mac_address}
                onChange={(e) =>
                  setForm({ ...form, mac_address: e.target.value })
                }
                className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-sm text-gray-200 font-mono focus:border-matrix-green/50 focus:outline-none"
                placeholder="AA:BB:CC:DD:EE:FF"
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">
                IP Address
              </label>
              <input
                type="text"
                value={form.ip_address}
                onChange={(e) =>
                  setForm({ ...form, ip_address: e.target.value })
                }
                className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-sm text-gray-200 font-mono focus:border-matrix-green/50 focus:outline-none"
                placeholder="192.168.1.100"
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">Type</label>
              <select
                value={form.device_type}
                onChange={(e) =>
                  setForm({ ...form, device_type: e.target.value })
                }
                className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-sm text-gray-200 focus:border-matrix-green/50 focus:outline-none"
              >
                <option value="server">Server</option>
                <option value="client">Client</option>
                <option value="router">Router</option>
                <option value="unknown">Unknown</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">Notes</label>
              <textarea
                value={form.notes}
                onChange={(e) =>
                  setForm({ ...form, notes: e.target.value })
                }
                rows={2}
                className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-sm text-gray-200 focus:border-matrix-green/50 focus:outline-none resize-none"
                placeholder="Optional notes..."
              />
            </div>
            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2 bg-matrix-green/20 text-matrix-green font-semibold rounded border border-matrix-green/30 hover:bg-matrix-green/30 transition-colors disabled:opacity-50"
            >
              {submitting ? 'Adding...' : 'Add Device'}
            </button>
          </form>
        ) : (
          <div className="p-4 space-y-2 max-h-96 overflow-y-auto">
            {discoveredDevices.length === 0 ? (
              <p className="text-gray-500 text-sm text-center py-8">
                No discovered devices. Click "Scan Network" first.
              </p>
            ) : (
              discoveredDevices.map((d) => (
                <div
                  key={d.mac_address}
                  className="flex items-center justify-between p-3 bg-cyber-bg rounded border border-cyber-border hover:border-matrix-green/30 transition-colors"
                >
                  <div>
                    <p className="text-sm text-gray-200">
                      {d.hostname || 'Unknown'}
                    </p>
                    <p className="text-xs text-gray-500 font-mono">
                      {d.ip_address} | {d.mac_address}
                    </p>
                    {d.os_info && (
                      <p className="text-xs text-gray-600">{d.os_info}</p>
                    )}
                  </div>
                  <button
                    onClick={() => handleImport(d)}
                    disabled={submitting}
                    className="px-3 py-1 text-xs bg-matrix-green/10 text-matrix-green rounded border border-matrix-green/30 hover:bg-matrix-green/20 transition-colors disabled:opacity-50"
                  >
                    Import
                  </button>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default function DeviceManager() {
  const [devices, setDevices] = useState([])
  const [discovered, setDiscovered] = useState([])
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')
  const [showAddModal, setShowAddModal] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [loading, setLoading] = useState(true)

  const loadDevices = useCallback(async () => {
    try {
      const [managed, disc] = await Promise.all([
        getManagedDevices(),
        getDiscoveredDevices(),
      ])
      setDevices(managed)
      setDiscovered(disc)
    } catch {
      // API may not be ready
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadDevices()
    const interval = setInterval(loadDevices, 10000)
    return () => clearInterval(interval)
  }, [loadDevices])

  const handleScan = async () => {
    setScanning(true)
    try {
      const results = await scanNetwork()
      setDiscovered(results)
    } catch {
      // scan failed
    } finally {
      setScanning(false)
    }
  }

  const handleAddDevice = async (data) => {
    await addManagedDevice(data)
    await loadDevices()
  }

  const handleToggleProtection = async (deviceId) => {
    await toggleDeviceProtection(deviceId)
    await loadDevices()
  }

  const handleDelete = async (deviceId) => {
    await deleteManagedDevice(deviceId)
    await loadDevices()
  }

  const filteredDevices = devices.filter((d) => {
    const matchesSearch =
      !search ||
      d.name?.toLowerCase().includes(search.toLowerCase()) ||
      d.mac_address?.toLowerCase().includes(search.toLowerCase()) ||
      d.ip_address?.includes(search) ||
      d.hostname?.toLowerCase().includes(search.toLowerCase())

    const matchesFilter =
      filter === 'all' ||
      (filter === 'protected' && d.is_protected) ||
      (filter === 'unprotected' && !d.is_protected) ||
      (filter === 'servers' && d.device_type === 'server') ||
      (filter === 'online' && d.is_online)

    return matchesSearch && matchesFilter
  })

  const protectedCount = devices.filter((d) => d.is_protected).length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-200">Device Manager</h1>
          <p className="text-xs text-gray-500 mt-1">
            {devices.length} devices | {protectedCount} protected
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleScan}
            disabled={scanning}
            className={`flex items-center gap-2 px-3 py-2 text-xs font-medium rounded border transition-colors ${
              scanning
                ? 'text-info-blue border-info-blue/30 bg-info-blue/10 cursor-wait'
                : 'text-info-blue border-info-blue/30 hover:bg-info-blue/10'
            }`}
          >
            <RefreshCw
              className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`}
            />
            {scanning ? 'Scanning...' : 'Scan Network'}
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-3 py-2 text-xs font-medium text-matrix-green border border-matrix-green/30 rounded hover:bg-matrix-green/10 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add Device
          </button>
        </div>
      </div>

      {/* Search and filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name, MAC, IP, or hostname..."
            className="w-full bg-cyber-surface border border-cyber-border rounded pl-10 pr-4 py-2 text-sm text-gray-200 focus:border-matrix-green/50 focus:outline-none"
          />
        </div>
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="bg-cyber-surface border border-cyber-border rounded px-3 py-2 text-sm text-gray-300 focus:border-matrix-green/50 focus:outline-none"
        >
          <option value="all">All Devices</option>
          <option value="protected">Protected</option>
          <option value="unprotected">Unprotected</option>
          <option value="servers">Servers</option>
          <option value="online">Online</option>
        </select>
      </div>

      {/* Device grid */}
      {loading ? (
        <div className="text-center py-12 text-gray-500">Loading devices...</div>
      ) : filteredDevices.length === 0 ? (
        <div className="text-center py-12">
          <Shield className="w-12 h-12 text-gray-700 mx-auto mb-3" />
          <p className="text-gray-500 text-sm">
            {devices.length === 0
              ? 'No devices discovered yet. Make sure you are running with sudo and connected to a network.'
              : 'No devices match your search.'}
          </p>
          {devices.length === 0 && (
            <p className="text-gray-600 text-xs mt-2">
              Click "Scan Network" to discover devices on your local network.
            </p>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filteredDevices.map((device) => (
            <DeviceCard
              key={device.id}
              device={device}
              onToggleProtection={handleToggleProtection}
              onDelete={handleDelete}
            />
          ))}
        </div>
      )}

      {/* Add Device Modal */}
      {showAddModal && (
        <AddDeviceModal
          onClose={() => setShowAddModal(false)}
          onAdd={handleAddDevice}
          discoveredDevices={discovered}
        />
      )}
    </div>
  )
}
