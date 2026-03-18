/**
 * Real-time traffic chart using Recharts.
 *
 * Educational note:
 *   This chart shows aggregate network traffic over time, broken down
 *   by protocol (SYN, UDP, ICMP, HTTP, ARP).  Spikes in a single
 *   protocol are a strong indicator of a flood attack.
 */

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'

const PROTOCOL_COLORS = {
  syn: '#ff0040',   // attack-red
  udp: '#00d4ff',   // info-blue
  icmp: '#ffaa00',  // warn-yellow
  http: '#00ff41',  // matrix-green
  arp: '#a855f7',   // purple
}

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload) return null

  return (
    <div className="bg-cyber-surface border border-cyber-border rounded p-3 text-xs shadow-lg">
      <p className="text-gray-400 mb-2">{label}</p>
      {payload.map((entry) => (
        <div key={entry.name} className="flex items-center gap-2">
          <span
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: entry.color }}
          />
          <span className="text-gray-300 uppercase">{entry.name}:</span>
          <span className="font-bold" style={{ color: entry.color }}>
            {entry.value?.toFixed(1)} pps
          </span>
        </div>
      ))}
    </div>
  )
}

export default function TrafficChart({ trafficHistory }) {
  // Aggregate all device traffic per timestamp into protocol totals
  const chartData = trafficHistory.map((entry) => {
    const totals = { time: new Date(entry.timestamp).toLocaleTimeString() }
    for (const device of entry.devices) {
      totals.syn = (totals.syn || 0) + (device.syn_pps || 0)
      totals.udp = (totals.udp || 0) + (device.udp_pps || 0)
      totals.icmp = (totals.icmp || 0) + (device.icmp_pps || 0)
      totals.http = (totals.http || 0) + (device.http_pps || 0)
      totals.arp = (totals.arp || 0) + (device.arp_pps || 0)
    }
    return totals
  })

  if (chartData.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-gray-600 text-sm">
        Waiting for traffic data...
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <AreaChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1a1a1a" />
        <XAxis
          dataKey="time"
          stroke="#333"
          tick={{ fill: '#666', fontSize: 10 }}
        />
        <YAxis
          stroke="#333"
          tick={{ fill: '#666', fontSize: 10 }}
          label={{
            value: 'pps',
            angle: -90,
            position: 'insideLeft',
            fill: '#666',
            fontSize: 10,
          }}
        />
        <Tooltip content={<CustomTooltip />} />
        <Legend
          wrapperStyle={{ fontSize: '11px', color: '#666' }}
          formatter={(value) => value.toUpperCase()}
        />
        {Object.entries(PROTOCOL_COLORS).map(([key, color]) => (
          <Area
            key={key}
            type="monotone"
            dataKey={key}
            stroke={color}
            fill={color}
            fillOpacity={0.15}
            strokeWidth={1.5}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  )
}
