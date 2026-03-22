/**
 * Slide-in device detail panel with tabbed interface.
 * Tabs: Overview | Ports | Security | Alerts | Remediation
 */

import { useState, useEffect } from 'react'
import {
  COLORS, DEVICE_TYPES, getDeviceStatusColor, getScoreColor,
  formatBytes, formatBps,
} from './topologyUtils'
import {
  getDevicePorts, assessDeviceSecurity, getAlerts,
  getRemediations, applyFix, toggleDeviceProtection, blockMAC, unblockMAC,
} from '../../utils/api'

const TABS = ['Overview', 'Ports', 'Security', 'Alerts', 'Remediation']

export default function DeviceDetailPanel({ device, onClose }) {
  const [tab, setTab] = useState('Overview')
  const [ports, setPorts] = useState(null)
  const [security, setSecurity] = useState(null)
  const [alerts, setAlerts] = useState(null)
  const [remediation, setRemediation] = useState(null)
  const [loading, setLoading] = useState({})
  const [actionMsg, setActionMsg] = useState(null)

  // Reset tab when device changes
  useEffect(() => { setTab('Overview') }, [device?.mac_address])

  // Fetch tab data on demand
  useEffect(() => {
    if (!device) return
    const ip = device.ip_address
    if (!ip) return

    if (tab === 'Ports' && ports === null) {
      setLoading((s) => ({ ...s, ports: true }))
      getDevicePorts(ip)
        .then(setPorts)
        .catch(() => setPorts([]))
        .finally(() => setLoading((s) => ({ ...s, ports: false })))
    }
    if (tab === 'Security' && security === null) {
      setLoading((s) => ({ ...s, security: true }))
      assessDeviceSecurity(ip, device.mac_address || '')
        .then(setSecurity)
        .catch(() => setSecurity({}))
        .finally(() => setLoading((s) => ({ ...s, security: false })))
    }
    if (tab === 'Alerts' && alerts === null) {
      setLoading((s) => ({ ...s, alerts: true }))
      getAlerts({ ip_address: ip, limit: '20' })
        .then((data) => setAlerts(Array.isArray(data) ? data : data.alerts || []))
        .catch(() => setAlerts([]))
        .finally(() => setLoading((s) => ({ ...s, alerts: false })))
    }
    if (tab === 'Remediation' && remediation === null) {
      setLoading((s) => ({ ...s, remediation: true }))
      getRemediations(ip, device.mac_address || '')
        .then(setRemediation)
        .catch(() => setRemediation({ recommendations: [] }))
        .finally(() => setLoading((s) => ({ ...s, remediation: false })))
    }
  }, [tab, device, ports, security, alerts, remediation])

  // Clear cached data when device changes
  useEffect(() => {
    setPorts(null)
    setSecurity(null)
    setAlerts(null)
    setRemediation(null)
    setActionMsg(null)
  }, [device?.mac_address])

  if (!device) return null

  const cfg = DEVICE_TYPES[device.device_type] || DEVICE_TYPES.unknown
  const statusColor = getDeviceStatusColor(device)

  const handleAction = async (action) => {
    try {
      setActionMsg(null)
      if (action === 'protect' && device.managed_id) {
        await toggleDeviceProtection(device.managed_id)
        setActionMsg('Protection toggled')
      } else if (action === 'block') {
        await blockMAC(device.mac_address, 'Manual block from topology')
        setActionMsg('Device blocked')
      } else if (action === 'unblock') {
        await unblockMAC(device.mac_address)
        setActionMsg('Device unblocked')
      }
    } catch (err) {
      setActionMsg(`Error: ${err.message}`)
    }
  }

  const handleApplyFix = async (vulnId) => {
    try {
      await applyFix(device.ip_address, vulnId)
      setActionMsg('Fix applied')
      setRemediation(null) // refetch
    } catch (err) {
      setActionMsg(`Error: ${err.message}`)
    }
  }

  return (
    <div className="topology-panel-slide" style={{
      width: 380, background: COLORS.surface, borderLeft: `1px solid ${COLORS.border}`,
      display: 'flex', flexDirection: 'column', height: '100%',
    }}>
      {/* Header */}
      <div className="flex items-center gap-3 p-4 border-b" style={{ borderColor: COLORS.border }}>
        <span className="text-2xl">{cfg.icon}</span>
        <div className="flex-1 min-w-0">
          <div className="font-bold font-mono text-sm truncate" style={{ color: COLORS.textBright }}>
            {device.name}
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-[10px] px-1.5 py-0.5 rounded font-mono"
              style={{ background: statusColor + '22', color: statusColor, border: `1px solid ${statusColor}44` }}>
              {device.status || 'NORMAL'}
            </span>
            <span className="text-[10px] font-mono" style={{ color: COLORS.textDim }}>
              {device.is_online ? '● Online' : '○ Offline'}
            </span>
          </div>
        </div>
        <button onClick={onClose} className="text-lg px-1 hover:opacity-70 transition-opacity"
          style={{ color: COLORS.textDim }}>✕</button>
      </div>

      {/* Tabs */}
      <div className="flex border-b overflow-x-auto" style={{ borderColor: COLORS.border }}>
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className="px-3 py-2 text-xs font-mono whitespace-nowrap transition-colors"
            style={{
              color: tab === t ? COLORS.info : COLORS.textDim,
              borderBottom: tab === t ? `2px solid ${COLORS.info}` : '2px solid transparent',
            }}>
            {t}
          </button>
        ))}
      </div>

      {/* Action message */}
      {actionMsg && (
        <div className="px-4 py-2 text-xs font-mono" style={{
          color: actionMsg.startsWith('Error') ? COLORS.blocked : COLORS.normal,
          background: actionMsg.startsWith('Error') ? COLORS.blocked + '11' : COLORS.normal + '11',
        }}>
          {actionMsg}
        </div>
      )}

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {tab === 'Overview' && <OverviewTab device={device} onAction={handleAction} />}
        {tab === 'Ports' && <PortsTab ports={ports} loading={loading.ports} />}
        {tab === 'Security' && <SecurityTab device={device} security={security} loading={loading.security} />}
        {tab === 'Alerts' && <AlertsTab alerts={alerts} loading={loading.alerts} />}
        {tab === 'Remediation' && (
          <RemediationTab remediation={remediation} loading={loading.remediation} onApplyFix={handleApplyFix} />
        )}
      </div>
    </div>
  )
}

/* --- Tab components --- */

function OverviewTab({ device, onAction }) {
  return (
    <>
      <InfoRow label="IP Address" value={device.ip_address} color={COLORS.info} />
      <InfoRow label="MAC" value={device.mac_address} />
      <InfoRow label="Vendor" value={device.vendor} />
      <InfoRow label="OS" value={device.os_info || '—'} />
      <InfoRow label="Type" value={(DEVICE_TYPES[device.device_type] || DEVICE_TYPES.unknown).label} />
      <InfoRow label="Protected" value={device.is_protected ? 'Yes' : 'No'}
        color={device.is_protected ? COLORS.normal : COLORS.textDim} />
      <InfoRow label="Open Ports" value={String(device.open_ports_count || 0)} />

      <div className="pt-2 border-t" style={{ borderColor: COLORS.border }}>
        <div className="text-[10px] font-mono mb-2" style={{ color: COLORS.textDim }}>Bandwidth</div>
        <div className="flex gap-4">
          <BwStat label="Upload" value={formatBps(device.bps_up)} color={COLORS.normal} />
          <BwStat label="Download" value={formatBps(device.bps_down)} color={COLORS.info} />
        </div>
        <div className="flex gap-4 mt-1">
          <BwStat label="Sent" value={formatBytes(device.bytes_sent)} color={COLORS.textMid} />
          <BwStat label="Received" value={formatBytes(device.bytes_received)} color={COLORS.textMid} />
        </div>
      </div>

      {/* Actions */}
      <div className="flex gap-2 pt-3">
        {device.managed_id && (
          <ActionBtn label={device.is_protected ? 'Unprotect' : 'Protect'}
            color={COLORS.info} onClick={() => onAction('protect')} />
        )}
        <ActionBtn label={device.status === 'BLOCKED' ? 'Unblock' : 'Block'}
          color={device.status === 'BLOCKED' ? COLORS.normal : COLORS.blocked}
          onClick={() => onAction(device.status === 'BLOCKED' ? 'unblock' : 'block')} />
      </div>
    </>
  )
}

function PortsTab({ ports, loading }) {
  if (loading) return <Loader />
  if (!ports || ports.length === 0) return <EmptyState text="No open ports found" />

  const portList = Array.isArray(ports) ? ports : ports.ports || []
  return (
    <div className="space-y-1.5">
      {portList.map((p, i) => {
        const risk = portRisk(p)
        return (
          <div key={i} className="flex items-center justify-between px-2 py-1.5 rounded text-xs font-mono"
            style={{ background: COLORS.bg, border: `1px solid ${COLORS.border}` }}>
            <div>
              <span style={{ color: COLORS.info }}>{p.port}</span>
              <span style={{ color: COLORS.textDim }}>/{p.protocol || 'tcp'}</span>
              {p.service && <span style={{ color: COLORS.textMid }}> — {p.service}</span>}
            </div>
            <span className="px-1.5 py-0.5 rounded text-[9px]" style={{
              color: risk.color, background: risk.color + '18', border: `1px solid ${risk.color}33`,
            }}>{risk.label}</span>
          </div>
        )
      })}
    </div>
  )
}

function SecurityTab({ device, security, loading }) {
  if (loading) return <Loader />
  const score = security?.security_score ?? device.security_score
  const scoreColor = getScoreColor(score)
  const vulns = security?.vulnerabilities || security?.issues || []

  return (
    <>
      {/* Score gauge */}
      <div className="flex items-center gap-4 pb-3 border-b" style={{ borderColor: COLORS.border }}>
        <div className="w-16 h-16 rounded-full flex items-center justify-center border-2 font-bold text-xl font-mono"
          style={{ borderColor: scoreColor, color: scoreColor, background: scoreColor + '11' }}>
          {score != null ? Math.round(score) : '—'}
        </div>
        <div>
          <div className="text-xs font-mono" style={{ color: COLORS.textBright }}>Security Score</div>
          <div className="text-[10px]" style={{ color: COLORS.textDim }}>
            {score >= 80 ? 'Good' : score >= 60 ? 'Fair' : score != null ? 'Poor' : 'Unknown'}
          </div>
        </div>
      </div>

      {vulns.length > 0 ? (
        <div className="space-y-1.5 pt-2">
          {vulns.map((v, i) => (
            <div key={i} className="px-2 py-1.5 rounded text-xs font-mono"
              style={{ background: COLORS.bg, border: `1px solid ${COLORS.border}` }}>
              <div style={{ color: vulnSeverityColor(v.severity) }}>
                [{v.severity || 'info'}] {v.title || v.description || v.id || 'Issue'}
              </div>
              {v.description && v.title && (
                <div className="mt-0.5 text-[10px]" style={{ color: COLORS.textDim }}>{v.description}</div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <EmptyState text="No vulnerabilities found" />
      )}
    </>
  )
}

function AlertsTab({ alerts, loading }) {
  if (loading) return <Loader />
  if (!alerts || alerts.length === 0) return <EmptyState text="No recent alerts" />

  return (
    <div className="space-y-1.5">
      {alerts.map((a, i) => (
        <div key={i} className="px-2 py-1.5 rounded text-xs font-mono"
          style={{ background: COLORS.bg, border: `1px solid ${COLORS.border}` }}>
          <div className="flex items-center justify-between">
            <span style={{ color: vulnSeverityColor(a.severity) }}>
              {a.severity || 'info'}
            </span>
            <span className="text-[9px]" style={{ color: COLORS.textDim }}>
              {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : ''}
            </span>
          </div>
          <div className="mt-0.5" style={{ color: COLORS.textMid }}>
            {a.message || a.title || a.type || 'Alert'}
          </div>
        </div>
      ))}
    </div>
  )
}

function RemediationTab({ remediation, loading, onApplyFix }) {
  if (loading) return <Loader />
  const recs = remediation?.recommendations || remediation?.fixes || []
  if (recs.length === 0) return <EmptyState text="No recommendations" />

  return (
    <div className="space-y-2">
      {recs.map((r, i) => (
        <div key={i} className="px-3 py-2 rounded text-xs"
          style={{ background: COLORS.bg, border: `1px solid ${COLORS.border}` }}>
          <div className="font-mono font-bold" style={{ color: COLORS.textBright }}>
            {r.title || r.description || 'Fix'}
          </div>
          {r.description && r.title && (
            <div className="mt-1 text-[10px]" style={{ color: COLORS.textDim }}>{r.description}</div>
          )}
          {r.vuln_id && (
            <button onClick={() => onApplyFix(r.vuln_id)}
              className="mt-2 px-2 py-1 rounded text-[10px] font-mono transition-colors"
              style={{
                background: COLORS.info + '22', color: COLORS.info,
                border: `1px solid ${COLORS.info}44`,
              }}>
              Apply Fix
            </button>
          )}
        </div>
      ))}
    </div>
  )
}

/* --- Shared pieces --- */

function InfoRow({ label, value, color }) {
  return (
    <div className="flex justify-between items-center text-xs font-mono">
      <span style={{ color: COLORS.textDim }}>{label}</span>
      <span style={{ color: color || COLORS.textMid }}>{value || '—'}</span>
    </div>
  )
}

function BwStat({ label, value, color }) {
  return (
    <div className="text-center">
      <div className="text-xs font-mono font-bold" style={{ color }}>{value}</div>
      <div className="text-[9px]" style={{ color: COLORS.textDim }}>{label}</div>
    </div>
  )
}

function ActionBtn({ label, color, onClick }) {
  return (
    <button onClick={onClick}
      className="flex-1 px-3 py-1.5 rounded text-xs font-mono font-bold transition-all hover:brightness-125"
      style={{ background: color + '22', color, border: `1px solid ${color}44` }}>
      {label}
    </button>
  )
}

function Loader() {
  return (
    <div className="flex items-center justify-center py-8">
      <div className="text-xs font-mono topology-pulse" style={{ color: COLORS.info }}>Loading...</div>
    </div>
  )
}

function EmptyState({ text }) {
  return (
    <div className="flex items-center justify-center py-8">
      <div className="text-xs font-mono" style={{ color: COLORS.textDim }}>{text}</div>
    </div>
  )
}

function portRisk(port) {
  const risky = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3306, 3389, 5432, 5900, 8080]
  const critical = [23, 135, 139, 445, 3389, 5900]
  const p = port.port || port
  if (critical.includes(p)) return { label: 'CRITICAL', color: COLORS.blocked }
  if (risky.includes(p)) return { label: 'MEDIUM', color: COLORS.suspicious }
  return { label: 'LOW', color: COLORS.normal }
}

function vulnSeverityColor(severity) {
  const s = (severity || '').toLowerCase()
  if (s === 'critical' || s === 'high') return COLORS.blocked
  if (s === 'medium' || s === 'warning') return COLORS.suspicious
  return COLORS.info
}
