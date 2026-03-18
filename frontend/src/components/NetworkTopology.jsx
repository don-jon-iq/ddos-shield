/**
 * Network topology visualization.
 *
 * Educational note:
 *   This component shows all discovered devices arranged in a visual map.
 *   Devices are color-coded by status and sized by traffic volume, giving
 *   students an intuitive view of the network — suspicious devices
 *   literally "stand out" with red glow effects.
 */

import { useEffect, useState } from 'react'
import { Monitor, Server, Wifi, Router } from 'lucide-react'
import { getDevices } from '../utils/api'

const STATUS_COLORS = {
  NORMAL: '#00ff41',
  SUSPICIOUS: '#ffaa00',
  BLOCKED: '#ff0040',
}

export default function NetworkTopology({ traffic }) {
  const [devices, setDevices] = useState([])
  const [viewMode, setViewMode] = useState('all') // all | vm | physical

  useEffect(() => {
    const load = async () => {
      try {
        setDevices(await getDevices())
      } catch {
        // ignore
      }
    }
    load()
    const interval = setInterval(load, 10000)
    return () => clearInterval(interval)
  }, [])

  const filtered = devices.filter((d) => {
    if (viewMode === 'vm') return d.is_vm
    if (viewMode === 'physical') return !d.is_vm
    return true
  })

  // Merge live traffic
  const enriched = filtered.map((d) => {
    const live = traffic.find((t) => t.mac_address === d.mac_address)
    return { ...d, pps: live?.total_pps || 0 }
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-200">Network Topology</h1>
        <div className="flex gap-1">
          {['all', 'vm', 'physical'].map((mode) => (
            <button
              key={mode}
              onClick={() => setViewMode(mode)}
              className={`px-3 py-1.5 text-xs rounded capitalize transition-colors ${
                viewMode === mode
                  ? 'bg-matrix-green/10 text-matrix-green border border-matrix-green/30'
                  : 'bg-cyber-bg text-gray-500 border border-cyber-border hover:text-gray-300'
              }`}
            >
              {mode}
            </button>
          ))}
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-xs text-gray-500">
        <div className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-full bg-matrix-green" />
          Normal
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-full bg-warn-yellow" />
          Suspicious
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded-full bg-attack-red" />
          Blocked
        </div>
        <div className="flex items-center gap-1.5 ml-4">
          <Monitor className="w-3 h-3" />
          Physical
        </div>
        <div className="flex items-center gap-1.5">
          <Server className="w-3 h-3" />
          Virtual
        </div>
      </div>

      {/* Topology grid */}
      <div className="cyber-card min-h-[400px]">
        {enriched.length === 0 ? (
          <div className="flex items-center justify-center h-64 text-gray-600">
            No devices discovered yet
          </div>
        ) : (
          <div className="relative">
            {/* Central router/gateway */}
            <div className="flex justify-center mb-8">
              <div className="flex flex-col items-center">
                <div className="w-16 h-16 rounded-full bg-info-blue/10 border-2 border-info-blue flex items-center justify-center glow-blue">
                  <Router className="w-8 h-8 text-info-blue" />
                </div>
                <span className="text-xs text-info-blue mt-2">Gateway</span>
              </div>
            </div>

            {/* Devices in a grid radiating from center */}
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-4">
              {enriched.map((device) => {
                const color = STATUS_COLORS[device.status] || STATUS_COLORS.NORMAL
                const isAttacking = device.status !== 'NORMAL'
                const Icon = device.is_vm ? Server : Monitor

                return (
                  <div
                    key={device.mac_address}
                    className={`flex flex-col items-center p-3 rounded-lg border transition-all ${
                      isAttacking
                        ? 'bg-attack-red/5 border-attack-red/30'
                        : 'bg-cyber-bg border-cyber-border hover:border-matrix-green/30'
                    }`}
                    style={
                      isAttacking
                        ? { boxShadow: `0 0 15px ${color}33` }
                        : undefined
                    }
                  >
                    <div
                      className="w-10 h-10 rounded-full flex items-center justify-center border-2 mb-2"
                      style={{ borderColor: color, backgroundColor: `${color}11` }}
                    >
                      <Icon className="w-5 h-5" style={{ color }} />
                    </div>
                    <span className="font-mono text-[10px] text-gray-400 text-center break-all">
                      {device.mac_address}
                    </span>
                    <span className="text-[10px] text-gray-600 mt-0.5">
                      {device.vendor}
                    </span>
                    <div className="flex items-center gap-1 mt-1">
                      <Wifi className="w-3 h-3" style={{ color }} />
                      <span className="text-[10px] font-mono" style={{ color }}>
                        {device.pps.toFixed(0)} pps
                      </span>
                    </div>
                    {device.is_vm && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-info-blue/10 text-info-blue mt-1">
                        VM
                      </span>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
