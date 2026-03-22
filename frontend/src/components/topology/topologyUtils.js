/**
 * Topology layout utilities — constants, device grouping, and circular placement.
 */

// --- Theme colors ---
export const COLORS = {
  normal: '#00ff41',
  suspicious: '#ffaa00',
  blocked: '#ff0040',
  info: '#00d4ff',
  surface: '#111111',
  border: '#1a1a1a',
  bg: '#0a0a0a',
  textDim: '#666666',
  textMid: '#999999',
  textBright: '#cccccc',
}

// --- Device type config ---
export const DEVICE_TYPES = {
  router:  { icon: '📡', label: 'Router',  ring: 0 },
  server:  { icon: '🖥️', label: 'Server',  ring: 1 },
  nas:     { icon: '💾', label: 'NAS',     ring: 1 },
  client:  { icon: '💻', label: 'PC',      ring: 2 },
  phone:   { icon: '📱', label: 'Phone',   ring: 2 },
  camera:  { icon: '📷', label: 'Camera',  ring: 3 },
  printer: { icon: '🖨️', label: 'Printer', ring: 3 },
  iot:     { icon: '🌐', label: 'IoT',     ring: 3 },
  unknown: { icon: '❓', label: 'Unknown', ring: 3 },
}

// Ring radii (SVG units)
const RING_RADII = [0, 160, 280, 380]

// Arc ranges per ring (degrees) — spread devices evenly around
const RING_ARCS = {
  1: { start: 0, end: 360 },
  2: { start: 0, end: 360 },
  3: { start: 0, end: 360 },
}

/**
 * Determine connection status color based on device data.
 */
export function getDeviceStatusColor(device) {
  if (device.status === 'BLOCKED') return COLORS.blocked
  if (device.status === 'SUSPICIOUS') return COLORS.suspicious
  if (device.security_score != null && device.security_score < 60) return COLORS.blocked
  if (device.security_score != null && device.security_score < 80) return COLORS.suspicious
  return COLORS.normal
}

/**
 * Get the security score color.
 */
export function getScoreColor(score) {
  if (score == null) return COLORS.textDim
  if (score >= 80) return COLORS.normal
  if (score >= 60) return COLORS.suspicious
  return COLORS.blocked
}

/**
 * Get grade color for network grade letter.
 */
export function getGradeColor(grade) {
  if (!grade) return COLORS.textDim
  const g = grade.toUpperCase()
  if (g === 'A' || g === 'A+') return COLORS.normal
  if (g === 'B') return '#66ff66'
  if (g === 'C') return COLORS.suspicious
  return COLORS.blocked
}

/**
 * Merge raw devices, managed devices, and bandwidth into unified topology nodes.
 * Returns array of enriched device objects.
 */
export function mergeDeviceData(devices, managed, bandwidth, traffic) {
  const managedByIp = new Map()
  const managedByMac = new Map()
  for (const m of (managed || [])) {
    if (m.ip_address) managedByIp.set(m.ip_address, m)
    if (m.mac_address) managedByMac.set(m.mac_address, m)
  }

  const bwByMac = new Map()
  const bwByIp = new Map()
  for (const b of (bandwidth || [])) {
    if (b.mac_address) bwByMac.set(b.mac_address, b)
    if (b.ip_address) bwByIp.set(b.ip_address, b)
  }

  const trafficByMac = new Map()
  for (const t of (traffic || [])) {
    if (t.mac_address) trafficByMac.set(t.mac_address, t)
  }

  return (devices || []).map((d) => {
    const m = managedByMac.get(d.mac_address) || managedByIp.get(d.ip_address) || {}
    const bw = bwByMac.get(d.mac_address) || bwByIp.get(d.ip_address) || {}
    const live = trafficByMac.get(d.mac_address) || {}
    const deviceType = normalizeType(m.device_type, d)

    return {
      ...d,
      name: m.name || m.hostname || d.hostname || d.vendor || d.ip_address || 'Unknown',
      device_type: deviceType,
      os_info: m.os_info || d.os_info || '',
      security_score: m.security_score ?? null,
      is_protected: m.is_protected ?? false,
      is_online: m.is_online ?? (d.status !== 'OFFLINE'),
      open_ports_count: m.open_ports_count ?? 0,
      managed_id: m.id ?? null,
      bytes_sent: bw.bytes_sent ?? 0,
      bytes_received: bw.bytes_received ?? 0,
      bps_up: bw.bps_sent ?? bw.bps_up ?? 0,
      bps_down: bw.bps_received ?? bw.bps_down ?? 0,
      pps: live.total_pps ?? 0,
    }
  })
}

function normalizeType(type, device) {
  if (type && DEVICE_TYPES[type]) return type
  if (device.is_vm) return 'server'
  return 'unknown'
}

/**
 * Compute (x, y) positions for all devices in a circular layout.
 * Returns a Map of mac_address → { x, y }.
 */
export function computeLayout(devices, centerX, centerY) {
  const positions = new Map()

  // Group by ring
  const rings = { 1: [], 2: [], 3: [] }
  for (const d of devices) {
    const cfg = DEVICE_TYPES[d.device_type] || DEVICE_TYPES.unknown
    const ring = cfg.ring || 3
    if (ring > 0) {
      rings[ring].push(d)
    }
  }

  for (const [ringNum, ringDevices] of Object.entries(rings)) {
    const radius = RING_RADII[Number(ringNum)]
    const arc = RING_ARCS[Number(ringNum)]
    const count = ringDevices.length
    if (count === 0) continue

    const startRad = (arc.start * Math.PI) / 180
    const endRad = (arc.end * Math.PI) / 180
    const totalArc = endRad - startRad
    const step = count === 1 ? 0 : totalArc / count

    ringDevices.forEach((d, i) => {
      const angle = startRad + step * i + (count === 1 ? 0 : step * 0.5)
      // Offset starting angle by -90° so first device is at top
      const adjustedAngle = angle - Math.PI / 2
      positions.set(d.mac_address, {
        x: centerX + radius * Math.cos(adjustedAngle),
        y: centerY + radius * Math.sin(adjustedAngle),
      })
    })
  }

  return positions
}

/**
 * Format bytes to human readable.
 */
export function formatBytes(bytes) {
  if (bytes == null || bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const val = bytes / Math.pow(1024, i)
  return `${val < 10 ? val.toFixed(1) : Math.round(val)} ${units[i]}`
}

/**
 * Format bps to human readable.
 */
export function formatBps(bps) {
  if (bps == null || bps === 0) return '0 bps'
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps']
  const i = Math.min(Math.floor(Math.log(bps) / Math.log(1000)), units.length - 1)
  const val = bps / Math.pow(1000, i)
  return `${val < 10 ? val.toFixed(1) : Math.round(val)} ${units[i]}`
}

/**
 * Determine line thickness from bandwidth.
 */
export function bandwidthToStroke(bpsUp, bpsDown) {
  const total = (bpsUp || 0) + (bpsDown || 0)
  if (total === 0) return 1
  if (total < 1000) return 1.5
  if (total < 10000) return 2
  if (total < 100000) return 3
  if (total < 1000000) return 4
  return 5
}
