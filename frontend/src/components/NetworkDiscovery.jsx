import { useEffect, useState, useCallback } from 'react'
import {
  Search, RefreshCw, Wifi, Server, Monitor, Smartphone, Printer,
  Camera, HardDrive, Tv, Cpu, Router, Radio, ChevronDown, ChevronUp,
  Shield, AlertTriangle, Eye,
} from 'lucide-react'
import { getDiscoveredDevices, scanNetwork, getScanStatus } from '../utils/api'

const DEVICE_ICONS = {
  router: Router,
  switch: Server,
  access_point: Radio,
  server: Server,
  client: Monitor,
  phone: Smartphone,
  iot: Cpu,
  printer: Printer,
  camera: Camera,
  nas: HardDrive,
  smart_tv: Tv,
  unknown: Wifi,
}

const TYPE_LABELS = {
  router: 'Router',
  switch: 'Switch',
  access_point: 'Access Point',
  server: 'Server',
  client: 'PC/Laptop',
  phone: 'Phone',
  iot: 'IoT Device',
  printer: 'Printer',
  camera: 'Camera',
  nas: 'NAS',
  smart_tv: 'Smart TV',
  unknown: 'Unknown',
}

function DeviceCard({ device, onSelect }) {
  const Icon = DEVICE_ICONS[device.device_type] || Wifi
  const portCount = device.open_ports?.length || 0
  const hasHighRiskPorts = device.open_ports?.some(p => [23, 445, 3389, 5900].includes(p))

  return (
    <button
      onClick={() => onSelect(device)}
      className="cyber-card hover:border-matrix-green/40 transition-all text-left w-full"
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-matrix-green/10">
            <Icon className="w-5 h-5 text-matrix-green" />
          </div>
          <div>
            <p className="text-sm font-medium text-gray-200">
              {device.hostname || device.ip_address}
            </p>
            <p className="text-xs text-gray-500">{device.ip_address}</p>
          </div>
        </div>
        <span className="text-[10px] px-2 py-0.5 rounded-full bg-info-blue/10 text-info-blue border border-info-blue/20">
          {TYPE_LABELS[device.device_type] || 'Unknown'}
        </span>
      </div>

      <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
        <div>
          <span className="text-gray-500">MAC:</span>
          <span className="ml-1 text-gray-400 font-mono text-[10px]">{device.mac_address}</span>
        </div>
        <div>
          <span className="text-gray-500">Vendor:</span>
          <span className="ml-1 text-gray-400">{device.vendor || 'Unknown'}</span>
        </div>
        <div>
          <span className="text-gray-500">OS:</span>
          <span className="ml-1 text-gray-400">{device.os_info || '—'}</span>
        </div>
        <div>
          <span className="text-gray-500">Ports:</span>
          <span className={`ml-1 ${hasHighRiskPorts ? 'text-attack-red' : 'text-gray-400'}`}>
            {portCount > 0 ? `${portCount} open` : 'None scanned'}
          </span>
        </div>
      </div>

      {device.services?.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {device.services.slice(0, 6).map((svc) => (
            <span
              key={svc}
              className="text-[10px] px-1.5 py-0.5 rounded bg-cyber-bg text-gray-500 border border-cyber-border"
            >
              {svc}
            </span>
          ))}
          {device.services.length > 6 && (
            <span className="text-[10px] text-gray-600">+{device.services.length - 6}</span>
          )}
        </div>
      )}

      <div className="mt-2 flex items-center gap-2 text-[10px] text-gray-600">
        <span className="uppercase">{device.discovery_method || 'arp'}</span>
      </div>
    </button>
  )
}

export default function NetworkDiscovery({ onSelectDevice }) {
  const [devices, setDevices] = useState([])
  const [scanning, setScanning] = useState(false)
  const [filter, setFilter] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [sortBy, setSortBy] = useState('hostname')
  const [sortAsc, setSortAsc] = useState(true)

  const loadDevices = useCallback(async () => {
    try {
      const data = await getDiscoveredDevices()
      setDevices(data)
    } catch {
      // API may not be ready
    }
  }, [])

  useEffect(() => {
    loadDevices()
    const interval = setInterval(loadDevices, 30000)
    return () => clearInterval(interval)
  }, [loadDevices])

  const handleScan = async () => {
    setScanning(true)
    try {
      const data = await scanNetwork()
      setDevices(data)
    } catch {
      // scan failed
    }
    setScanning(false)
  }

  const toggleSort = (field) => {
    if (sortBy === field) {
      setSortAsc(!sortAsc)
    } else {
      setSortBy(field)
      setSortAsc(true)
    }
  }

  // Filter and sort devices
  const filtered = devices
    .filter((d) => {
      if (typeFilter !== 'all' && d.device_type !== typeFilter) return false
      if (!filter) return true
      const q = filter.toLowerCase()
      return (
        (d.hostname || '').toLowerCase().includes(q) ||
        (d.ip_address || '').toLowerCase().includes(q) ||
        (d.mac_address || '').toLowerCase().includes(q) ||
        (d.vendor || '').toLowerCase().includes(q)
      )
    })
    .sort((a, b) => {
      const valA = (a[sortBy] || '').toString().toLowerCase()
      const valB = (b[sortBy] || '').toString().toLowerCase()
      const cmp = valA.localeCompare(valB)
      return sortAsc ? cmp : -cmp
    })

  // Count by type
  const typeCounts = {}
  devices.forEach((d) => {
    typeCounts[d.device_type] = (typeCounts[d.device_type] || 0) + 1
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-200">Network Discovery</h1>
        <div className="flex items-center gap-3">
          <span className="text-sm text-gray-500">
            {devices.length} device{devices.length !== 1 ? 's' : ''} found
          </span>
          <button
            onClick={handleScan}
            disabled={scanning}
            className="flex items-center gap-2 px-4 py-2 bg-matrix-green/10 text-matrix-green border border-matrix-green/30 rounded-lg hover:bg-matrix-green/20 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`} />
            {scanning ? 'Scanning...' : 'Scan Now'}
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Search by hostname, IP, MAC, or vendor..."
            className="w-full pl-10 pr-4 py-2 bg-cyber-surface border border-cyber-border rounded-lg text-sm text-gray-200 placeholder-gray-600 focus:border-matrix-green/50 focus:outline-none"
          />
        </div>

        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="px-3 py-2 bg-cyber-surface border border-cyber-border rounded-lg text-sm text-gray-300 focus:border-matrix-green/50 focus:outline-none"
        >
          <option value="all">All Types ({devices.length})</option>
          {Object.entries(typeCounts).sort().map(([type, count]) => (
            <option key={type} value={type}>
              {TYPE_LABELS[type] || type} ({count})
            </option>
          ))}
        </select>
      </div>

      {/* Device grid */}
      {filtered.length === 0 ? (
        <div className="cyber-card text-center py-12">
          <Wifi className="w-12 h-12 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-500">
            {devices.length === 0
              ? 'No devices discovered yet. Click "Scan Now" to discover devices on your network.'
              : 'No devices match your filter.'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((device) => (
            <DeviceCard
              key={device.mac_address}
              device={device}
              onSelect={onSelectDevice || (() => {})}
            />
          ))}
        </div>
      )}
    </div>
  )
}
