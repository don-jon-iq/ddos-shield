/**
 * SVG-based interactive network map with circular layout.
 * Renders gateway at center, devices in rings, connection lines, and handles interactions.
 */

import { useState, useRef, useCallback, useMemo } from 'react'
import {
  COLORS, DEVICE_TYPES, computeLayout,
  getDeviceStatusColor, getScoreColor, bandwidthToStroke, formatBps,
} from './topologyUtils'

const VIEW_SIZE = 900
const CENTER = VIEW_SIZE / 2

export default function NetworkSvgMap({ devices, onSelect, selectedMac, filters }) {
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [hoveredMac, setHoveredMac] = useState(null)
  const [searchTerm, setSearchTerm] = useState('')
  const svgRef = useRef(null)
  const dragRef = useRef(null)

  // Filter devices
  const filtered = useMemo(() => {
    let list = devices
    if (filters.onlineOnly) list = list.filter((d) => d.is_online)
    if (filters.deviceType !== 'all') list = list.filter((d) => d.device_type === filters.deviceType)
    if (filters.riskLevel !== 'all') {
      list = list.filter((d) => {
        const s = d.security_score
        if (filters.riskLevel === 'high') return s != null && s < 60
        if (filters.riskLevel === 'medium') return s != null && s >= 60 && s < 80
        if (filters.riskLevel === 'low') return s == null || s >= 80
        return true
      })
    }
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase()
      list = list.filter((d) =>
        (d.name || '').toLowerCase().includes(q) ||
        (d.ip_address || '').includes(q) ||
        (d.mac_address || '').toLowerCase().includes(q)
      )
    }
    return list
  }, [devices, filters, searchTerm])

  // Compute positions
  const positions = useMemo(
    () => computeLayout(filtered, CENTER, CENTER),
    [filtered]
  )

  // Zoom handlers
  const zoomIn = () => setZoom((z) => Math.min(z + 0.2, 3))
  const zoomOut = () => setZoom((z) => Math.max(z - 0.2, 0.4))
  const resetView = () => { setZoom(1); setPan({ x: 0, y: 0 }) }

  // Pan handlers
  const handleMouseDown = useCallback((e) => {
    if (e.target.closest('.topo-node')) return
    dragRef.current = { startX: e.clientX - pan.x, startY: e.clientY - pan.y }
  }, [pan])

  const handleMouseMove = useCallback((e) => {
    if (!dragRef.current) return
    setPan({ x: e.clientX - dragRef.current.startX, y: e.clientY - dragRef.current.startY })
  }, [])

  const handleMouseUp = useCallback(() => { dragRef.current = null }, [])

  const handleWheel = useCallback((e) => {
    e.preventDefault()
    setZoom((z) => Math.max(0.4, Math.min(3, z - e.deltaY * 0.001)))
  }, [])

  const hovered = hoveredMac ? filtered.find((d) => d.mac_address === hoveredMac) : null
  const hoveredPos = hoveredMac ? positions.get(hoveredMac) : null

  return (
    <div className="relative flex-1 min-h-0 rounded-lg border overflow-hidden"
      style={{ background: COLORS.bg, borderColor: COLORS.border }}>

      {/* Search bar */}
      <div className="absolute top-3 left-3 z-20">
        <input
          type="text"
          placeholder="Search devices..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="px-3 py-1.5 rounded text-xs font-mono w-52 outline-none border"
          style={{
            background: COLORS.surface + 'ee',
            borderColor: COLORS.border,
            color: COLORS.textBright,
          }}
        />
      </div>

      {/* Zoom controls */}
      <div className="absolute top-3 right-3 z-20 flex flex-col gap-1">
        {[
          { label: '+', fn: zoomIn },
          { label: '−', fn: zoomOut },
          { label: '⟳', fn: resetView },
        ].map(({ label, fn }) => (
          <button key={label} onClick={fn}
            className="w-7 h-7 rounded flex items-center justify-center text-sm font-bold border transition-colors hover:border-[#00d4ff44]"
            style={{ background: COLORS.surface, borderColor: COLORS.border, color: COLORS.textBright }}>
            {label}
          </button>
        ))}
      </div>

      {/* Device count */}
      <div className="absolute bottom-3 left-3 z-20 text-[10px] font-mono"
        style={{ color: COLORS.textDim }}>
        {filtered.length} device{filtered.length !== 1 ? 's' : ''}
      </div>

      {/* SVG Map */}
      <svg
        ref={svgRef}
        viewBox={`0 0 ${VIEW_SIZE} ${VIEW_SIZE}`}
        className="w-full h-full cursor-grab active:cursor-grabbing"
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
        style={{ minHeight: 500 }}
      >
        <defs>
          {/* Animated dash pattern */}
          <pattern id="grid-dots" width="40" height="40" patternUnits="userSpaceOnUse">
            <circle cx="20" cy="20" r="0.5" fill={COLORS.border} />
          </pattern>
          {/* Glow filters */}
          <filter id="glow-green">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <filter id="glow-red">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <filter id="glow-selected">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {/* Background grid */}
        <rect width={VIEW_SIZE} height={VIEW_SIZE} fill="url(#grid-dots)" />

        <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}
          style={{ transformOrigin: `${CENTER}px ${CENTER}px` }}>

          {/* Ring guides */}
          {[160, 280, 380].map((r) => (
            <circle key={r} cx={CENTER} cy={CENTER} r={r}
              fill="none" stroke={COLORS.border} strokeWidth="0.5" strokeDasharray="4 8" opacity="0.5" />
          ))}

          {/* Connection lines */}
          {filtered.map((d) => {
            const pos = positions.get(d.mac_address)
            if (!pos) return null
            const color = getDeviceStatusColor(d)
            const stroke = bandwidthToStroke(d.bps_up, d.bps_down)
            const isActive = (d.bps_up || 0) + (d.bps_down || 0) > 0
            return (
              <line key={`line-${d.mac_address}`}
                x1={CENTER} y1={CENTER} x2={pos.x} y2={pos.y}
                stroke={color} strokeWidth={stroke} opacity={0.35}
                strokeDasharray={isActive ? '6 4' : 'none'}
                className={isActive ? 'topology-dash-anim' : ''}
              />
            )
          })}

          {/* Gateway node */}
          <GatewayNode cx={CENTER} cy={CENTER} />

          {/* Device nodes */}
          {filtered.map((d) => {
            const pos = positions.get(d.mac_address)
            if (!pos) return null
            return (
              <DeviceNode
                key={d.mac_address}
                device={d}
                x={pos.x}
                y={pos.y}
                isSelected={selectedMac === d.mac_address}
                isHovered={hoveredMac === d.mac_address}
                onSelect={() => onSelect(d)}
                onHover={() => setHoveredMac(d.mac_address)}
                onLeave={() => setHoveredMac(null)}
              />
            )
          })}
        </g>

        {/* Tooltip (outside transform group so it doesn't scale) */}
        {hovered && hoveredPos && (
          <Tooltip device={hovered} x={hoveredPos.x * zoom + pan.x} y={hoveredPos.y * zoom + pan.y} zoom={zoom} />
        )}
      </svg>
    </div>
  )
}

/* --- Gateway node at center --- */
function GatewayNode({ cx, cy }) {
  return (
    <g>
      <circle cx={cx} cy={cy} r="32" fill={COLORS.info + '15'} stroke={COLORS.info} strokeWidth="2"
        filter="url(#glow-green)" />
      <circle cx={cx} cy={cy} r="24" fill={COLORS.surface} stroke={COLORS.info + '44'} strokeWidth="1" />
      <text x={cx} y={cy + 1} textAnchor="middle" dominantBaseline="central"
        fontSize="20" className="select-none">📡</text>
      <text x={cx} y={cy + 46} textAnchor="middle" fontSize="10" fill={COLORS.info}
        fontFamily="monospace" fontWeight="bold">Gateway</text>
    </g>
  )
}

/* --- Individual device node --- */
function DeviceNode({ device, x, y, isSelected, isHovered, onSelect, onHover, onLeave }) {
  const color = getDeviceStatusColor(device)
  const cfg = DEVICE_TYPES[device.device_type] || DEVICE_TYPES.unknown
  const isAttacked = device.status === 'BLOCKED' || device.status === 'SUSPICIOUS'
  const scoreColor = getScoreColor(device.security_score)
  const r = 24

  return (
    <g className="topo-node cursor-pointer" onClick={onSelect}
      onMouseEnter={onHover} onMouseLeave={onLeave}>

      {/* Outer glow ring for attacks */}
      {isAttacked && (
        <circle cx={x} cy={y} r={r + 8} fill="none" stroke={color} strokeWidth="1.5"
          opacity="0.4" className="topology-pulse" />
      )}

      {/* Selection ring */}
      {isSelected && (
        <circle cx={x} cy={y} r={r + 6} fill="none" stroke={COLORS.info} strokeWidth="2"
          filter="url(#glow-selected)" opacity="0.8" />
      )}

      {/* Main circle */}
      <circle cx={x} cy={y} r={r} fill={COLORS.surface}
        stroke={isHovered ? COLORS.info : color}
        strokeWidth={isSelected ? 2.5 : 1.5}
        filter={isAttacked ? 'url(#glow-red)' : undefined}
      />

      {/* Device icon */}
      <text x={x} y={y + 1} textAnchor="middle" dominantBaseline="central"
        fontSize="16" className="select-none pointer-events-none">{cfg.icon}</text>

      {/* Online/offline dot */}
      <circle cx={x + r - 4} cy={y - r + 4} r="4"
        fill={device.is_online ? COLORS.normal : COLORS.textDim}
        stroke={COLORS.surface} strokeWidth="1.5" />

      {/* Security score badge */}
      {device.security_score != null && (
        <g>
          <rect x={x - 12} y={y - r - 14} width="24" height="13" rx="3"
            fill={COLORS.surface} stroke={scoreColor + '66'} strokeWidth="0.8" />
          <text x={x} y={y - r - 6} textAnchor="middle" fontSize="8"
            fill={scoreColor} fontFamily="monospace" fontWeight="bold">
            {Math.round(device.security_score)}
          </text>
        </g>
      )}

      {/* Device name */}
      <text x={x} y={y + r + 14} textAnchor="middle" fontSize="9" fill={COLORS.textBright}
        fontFamily="monospace" className="pointer-events-none">
        {truncate(device.name, 14)}
      </text>

      {/* IP address */}
      <text x={x} y={y + r + 26} textAnchor="middle" fontSize="8" fill={COLORS.info}
        fontFamily="monospace" className="pointer-events-none" opacity="0.8">
        {device.ip_address || '—'}
      </text>
    </g>
  )
}

/* --- Hover tooltip --- */
function Tooltip({ device, x, y, zoom }) {
  const cfg = DEVICE_TYPES[device.device_type] || DEVICE_TYPES.unknown
  const color = getDeviceStatusColor(device)
  // Position tooltip to the right of the node, clamped within view
  const tx = Math.min(x + 30, VIEW_SIZE - 160)
  const ty = Math.max(y - 40, 10)

  return (
    <g className="pointer-events-none">
      <rect x={tx} y={ty} width="150" height="80" rx="6"
        fill={COLORS.surface + 'f0'} stroke={COLORS.border} strokeWidth="1" />
      <text x={tx + 8} y={ty + 16} fontSize="10" fill={COLORS.textBright} fontWeight="bold"
        fontFamily="monospace">{truncate(device.name, 18)}</text>
      <text x={tx + 8} y={ty + 30} fontSize="9" fill={COLORS.info} fontFamily="monospace">
        {device.ip_address || '—'}
      </text>
      <text x={tx + 8} y={ty + 43} fontSize="9" fill={COLORS.textDim} fontFamily="monospace">
        {cfg.label} • {device.is_online ? 'Online' : 'Offline'}
      </text>
      <text x={tx + 8} y={ty + 56} fontSize="9" fill={color} fontFamily="monospace">
        {device.status || 'NORMAL'}
      </text>
      <text x={tx + 8} y={ty + 69} fontSize="8" fill={COLORS.textDim} fontFamily="monospace">
        ↑{formatBps(device.bps_up)} ↓{formatBps(device.bps_down)}
      </text>
    </g>
  )
}

function truncate(str, max) {
  if (!str) return '—'
  return str.length > max ? str.slice(0, max - 1) + '…' : str
}
