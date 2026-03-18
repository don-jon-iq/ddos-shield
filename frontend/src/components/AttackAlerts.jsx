import { AlertTriangle, ShieldAlert, Info, Zap } from 'lucide-react'

const SEVERITY_STYLES = {
  CRITICAL: {
    bg: 'bg-attack-red/10',
    border: 'border-attack-red/40',
    text: 'text-attack-red',
    glow: 'glow-red animate-pulse-glow',
    icon: ShieldAlert,
  },
  HIGH: {
    bg: 'bg-attack-red/5',
    border: 'border-attack-red/20',
    text: 'text-red-400',
    glow: '',
    icon: AlertTriangle,
  },
  MEDIUM: {
    bg: 'bg-warn-yellow/10',
    border: 'border-warn-yellow/30',
    text: 'text-warn-yellow',
    glow: '',
    icon: Zap,
  },
  LOW: {
    bg: 'bg-info-blue/10',
    border: 'border-info-blue/30',
    text: 'text-info-blue',
    glow: '',
    icon: Info,
  },
}

export default function AttackAlerts({ alerts, alertHistory, onShowEducational }) {
  const liveAlerts = alerts || []

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-gray-200">Attack Alerts</h1>

      {/* Live alerts (current window) */}
      {liveAlerts.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-attack-red uppercase tracking-wider flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-attack-red animate-pulse" />
            Live Attacks
          </h2>
          {liveAlerts.map((alert, idx) => {
            const style = SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.LOW
            const Icon = style.icon
            return (
              <div
                key={`live-${idx}`}
                className={`cyber-card ${style.bg} ${style.border} ${style.glow}`}
              >
                <div className="flex items-start gap-3">
                  <Icon className={`w-5 h-5 mt-0.5 ${style.text}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-bold px-2 py-0.5 rounded ${style.bg} ${style.text} border ${style.border}`}>
                          {alert.severity}
                        </span>
                        {alert.ip_address && (
                          <span className="font-mono text-sm text-info-blue">
                            {alert.ip_address}
                          </span>
                        )}
                        <span className="font-mono text-sm text-matrix-green">
                          {alert.mac_address}
                        </span>
                      </div>
                      <span className="text-xs text-gray-500 font-mono">
                        {alert.pps?.toFixed(0)} pps
                      </span>
                    </div>
                    <div className="mt-2 flex items-center gap-2">
                      <button
                        onClick={() => onShowEducational?.(alert.attack_type)}
                        className="text-xs px-2 py-1 rounded bg-cyber-bg border border-cyber-border text-info-blue hover:border-info-blue/50 transition-colors"
                      >
                        {alert.attack_type}
                      </button>
                      {alert.z_score && (
                        <span className="text-xs text-gray-500">
                          z-score: {alert.z_score}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-500 mt-1">{alert.description}</p>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Alert history */}
      <div>
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
          Alert History ({alertHistory.length})
        </h2>
        {alertHistory.length === 0 ? (
          <div className="cyber-card text-center py-12">
            <ShieldAlert className="w-12 h-12 text-gray-700 mx-auto mb-3" />
            <p className="text-gray-600">No attacks detected yet</p>
            <p className="text-gray-700 text-xs mt-1">
              The system is monitoring network traffic for anomalies
            </p>
          </div>
        ) : (
          <div className="space-y-2 max-h-[600px] overflow-y-auto">
            {alertHistory.map((alert) => {
              const style = SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.LOW
              return (
                <div
                  key={alert.id}
                  className={`flex items-center gap-3 px-3 py-2 rounded border text-sm ${style.bg} ${style.border}`}
                >
                  <span className={`text-xs font-bold w-16 ${style.text}`}>
                    {alert.severity}
                  </span>
                  <span className="font-mono text-xs text-info-blue w-24">
                    {alert.ip_address || '—'}
                  </span>
                  <span className="font-mono text-xs text-matrix-green w-36">
                    {alert.mac_address}
                  </span>
                  <button
                    onClick={() => onShowEducational?.(alert.attack_type)}
                    className="text-xs text-info-blue hover:underline"
                  >
                    {alert.attack_type}
                  </button>
                  <span className="text-xs text-gray-500 ml-auto">
                    {alert.pps?.toFixed(0)} pps
                  </span>
                  <span className="text-xs text-gray-600">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
