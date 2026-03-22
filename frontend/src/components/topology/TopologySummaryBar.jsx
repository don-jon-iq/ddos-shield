/**
 * Network summary bar — grade badge, device counts, bandwidth, health.
 */

import { COLORS, getGradeColor, formatBps } from './topologyUtils'

export default function TopologySummaryBar({ devices, grade, alerts, health }) {
  const total = devices.length
  const online = devices.filter((d) => d.is_online).length
  const offline = total - online
  const threats = (alerts || []).filter(
    (a) => a.severity === 'critical' || a.severity === 'high'
  ).length
  const totalBps = devices.reduce((s, d) => s + (d.bps_up || 0) + (d.bps_down || 0), 0)

  const gradeColor = getGradeColor(grade?.grade)
  const healthOk = health?.status === 'healthy' || health?.status === 'ok'

  return (
    <div className="flex items-center gap-4 flex-wrap px-4 py-3 rounded-lg border"
      style={{ background: COLORS.surface, borderColor: COLORS.border }}>

      {/* Network Grade */}
      <div className="flex items-center gap-2">
        <div className="w-10 h-10 rounded-lg flex items-center justify-center font-bold text-xl font-mono border"
          style={{
            color: gradeColor,
            borderColor: gradeColor + '44',
            background: gradeColor + '11',
            textShadow: `0 0 8px ${gradeColor}66`,
          }}>
          {grade?.grade || '—'}
        </div>
        <div className="text-xs">
          <div style={{ color: COLORS.textBright }}>Network Grade</div>
          <div style={{ color: COLORS.textDim }}>
            {grade?.score != null ? `${grade.score.toFixed(1)}/100` : '—'}
          </div>
        </div>
      </div>

      <div className="w-px h-8" style={{ background: COLORS.border }} />

      {/* Device counts */}
      <StatBadge label="Devices" value={total} color={COLORS.info} />
      <StatBadge label="Online" value={online} color={COLORS.normal} />
      <StatBadge label="Offline" value={offline} color={COLORS.textDim} />

      <div className="w-px h-8" style={{ background: COLORS.border }} />

      {/* Threats */}
      <StatBadge
        label="Threats"
        value={threats}
        color={threats > 0 ? COLORS.blocked : COLORS.normal}
        pulse={threats > 0}
      />

      <div className="w-px h-8" style={{ background: COLORS.border }} />

      {/* Bandwidth */}
      <StatBadge label="Bandwidth" value={formatBps(totalBps)} color={COLORS.info} />

      {/* Health */}
      <div className="flex items-center gap-1.5 ml-auto">
        <div className="w-2.5 h-2.5 rounded-full"
          style={{
            background: healthOk ? COLORS.normal : COLORS.blocked,
            boxShadow: `0 0 6px ${healthOk ? COLORS.normal : COLORS.blocked}66`,
          }} />
        <span className="text-xs" style={{ color: COLORS.textMid }}>
          {healthOk ? 'Healthy' : 'Degraded'}
        </span>
      </div>
    </div>
  )
}

function StatBadge({ label, value, color, pulse }) {
  return (
    <div className="flex flex-col items-center min-w-[48px]">
      <span
        className={`text-base font-bold font-mono ${pulse ? 'topology-pulse' : ''}`}
        style={{ color }}
      >
        {value}
      </span>
      <span className="text-[10px]" style={{ color: COLORS.textDim }}>{label}</span>
    </div>
  )
}
