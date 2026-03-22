import { useEffect, useState } from 'react'
import {
  FileText, Shield, AlertTriangle, Activity, Download,
  RefreshCw, CheckCircle, XCircle, ChevronDown, ChevronUp,
} from 'lucide-react'
import { getAuditReport } from '../utils/api'

const GRADE_COLORS = {
  A: 'text-matrix-green',
  B: 'text-info-blue',
  C: 'text-warn-yellow',
  D: 'text-orange-400',
  F: 'text-attack-red',
}

const RISK_COLORS = {
  CRITICAL: 'text-attack-red',
  HIGH: 'text-red-400',
  MEDIUM: 'text-warn-yellow',
  LOW: 'text-gray-400',
}

const URGENCY_COLORS = {
  IMMEDIATE: 'bg-attack-red/10 border-attack-red/30 text-attack-red',
  HIGH: 'bg-red-400/10 border-red-400/30 text-red-400',
  RECOMMENDED: 'bg-info-blue/10 border-info-blue/30 text-info-blue',
}

function formatBytes(bytes) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

export default function ReportPage() {
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [expandedSections, setExpandedSections] = useState({
    devices: true,
    vulns: false,
    firewall: false,
    bandwidth: false,
  })

  useEffect(() => {
    const load = async () => {
      try {
        const data = await getAuditReport()
        setReport(data)
      } catch {
        // not ready
      }
      setLoading(false)
    }
    load()
  }, [])

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section],
    }))
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <RefreshCw className="w-8 h-8 text-matrix-green animate-spin mx-auto mb-3" />
          <p className="text-gray-500 text-sm">Generating audit report...</p>
        </div>
      </div>
    )
  }

  if (!report) {
    return (
      <div className="cyber-card text-center py-12">
        <FileText className="w-12 h-12 text-gray-600 mx-auto mb-3" />
        <p className="text-gray-500">Could not generate report. Run a security scan first.</p>
      </div>
    )
  }

  const exec = report.executive_summary || {}
  const grade = exec.grade || '?'

  return (
    <div className="space-y-6 max-w-4xl mx-auto print:max-w-none">
      {/* Header */}
      <div className="flex items-center justify-between print:hidden">
        <h1 className="text-xl font-bold text-gray-200">
          <FileText className="w-5 h-5 inline mr-2" />
          Network Audit Report
        </h1>
        <button
          onClick={() => window.print()}
          className="flex items-center gap-2 px-4 py-2 bg-matrix-green/10 text-matrix-green border border-matrix-green/30 rounded-lg hover:bg-matrix-green/20 transition-colors"
        >
          <Download className="w-4 h-4" />
          Print / PDF
        </button>
      </div>

      {/* Executive Summary */}
      <div className="cyber-card print:border print:border-gray-300">
        <h2 className="text-lg font-bold text-gray-200 mb-4">Executive Summary</h2>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
          <div className="text-center">
            <div className={`text-5xl font-black ${GRADE_COLORS[grade] || GRADE_COLORS.F}`}>
              {grade}
            </div>
            <p className="text-xs text-gray-500 mt-1">Security Grade</p>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-gray-200">{exec.score || 0}</div>
            <p className="text-xs text-gray-500 mt-1">Score / 100</p>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-gray-200">{exec.device_count || 0}</div>
            <p className="text-xs text-gray-500 mt-1">Devices Scanned</p>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-warn-yellow">{exec.total_vulnerabilities || 0}</div>
            <p className="text-xs text-gray-500 mt-1">Vulnerabilities</p>
          </div>
        </div>
        <p className="text-sm text-gray-300 leading-relaxed">{exec.summary}</p>
        <div className="mt-3 flex items-center gap-4 text-xs text-gray-500">
          <span>Health: {exec.health_status} ({exec.health_score}%)</span>
          <span>Critical issues: {exec.critical_issues || 0}</span>
          <span>Generated: {report.report_generated_at ? new Date(report.report_generated_at).toLocaleString() : 'N/A'}</span>
        </div>
      </div>

      {/* Top Recommendations */}
      {report.top_recommendations?.length > 0 && (
        <div className="cyber-card">
          <h2 className="text-lg font-bold text-gray-200 mb-4">
            <AlertTriangle className="w-5 h-5 inline mr-2 text-warn-yellow" />
            Top Recommendations
          </h2>
          <div className="space-y-2">
            {report.top_recommendations.map((rec, i) => (
              <div
                key={i}
                className={`p-3 rounded-lg border ${URGENCY_COLORS[rec.urgency] || URGENCY_COLORS.RECOMMENDED}`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium">{rec.title}</span>
                  <span className="text-[10px] font-bold uppercase">{rec.urgency}</span>
                </div>
                <p className="text-xs opacity-70">{rec.description}</p>
                {rec.affected_device && (
                  <p className="text-[10px] opacity-50 mt-1 font-mono">{rec.affected_device}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Device Inventory */}
      <div className="cyber-card">
        <button
          onClick={() => toggleSection('devices')}
          className="w-full flex items-center justify-between mb-2"
        >
          <h2 className="text-lg font-bold text-gray-200">
            <Shield className="w-5 h-5 inline mr-2" />
            Device Security ({report.devices?.length || 0} devices)
          </h2>
          {expandedSections.devices ? <ChevronUp className="w-5 h-5 text-gray-500" /> : <ChevronDown className="w-5 h-5 text-gray-500" />}
        </button>
        {expandedSections.devices && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-500 text-xs uppercase border-b border-cyber-border">
                  <th className="text-left pb-2">Device</th>
                  <th className="text-center pb-2">Score</th>
                  <th className="text-center pb-2">Ports</th>
                  <th className="text-center pb-2">Vulns</th>
                  <th className="text-left pb-2">Risk Summary</th>
                </tr>
              </thead>
              <tbody>
                {(report.devices || []).map((dev, i) => {
                  const scoreColor =
                    dev.security_score >= 90 ? 'text-matrix-green' :
                    dev.security_score >= 75 ? 'text-info-blue' :
                    dev.security_score >= 50 ? 'text-warn-yellow' :
                    'text-attack-red'
                  return (
                    <tr key={i} className="border-b border-cyber-border/30">
                      <td className="py-2">
                        <span className="text-gray-200 font-mono text-xs">{dev.ip_address}</span>
                        <br />
                        <span className="text-gray-600 text-[10px]">{dev.mac_address}</span>
                      </td>
                      <td className={`text-center font-bold ${scoreColor}`}>{dev.security_score}</td>
                      <td className="text-center text-gray-400">{dev.open_ports}</td>
                      <td className="text-center text-warn-yellow">{dev.vulnerabilities?.length || 0}</td>
                      <td className="text-gray-500 text-xs">{dev.risk_summary}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Vulnerability Details */}
      <div className="cyber-card">
        <button
          onClick={() => toggleSection('vulns')}
          className="w-full flex items-center justify-between mb-2"
        >
          <h2 className="text-lg font-bold text-gray-200">
            All Vulnerabilities ({report.all_vulnerabilities?.length || 0})
          </h2>
          {expandedSections.vulns ? <ChevronUp className="w-5 h-5 text-gray-500" /> : <ChevronDown className="w-5 h-5 text-gray-500" />}
        </button>
        {expandedSections.vulns && (
          <div className="space-y-2">
            {(report.all_vulnerabilities || []).map((vuln, i) => (
              <div key={i} className="flex items-center gap-3 p-2 rounded border border-cyber-border/30">
                <span className={`text-xs font-bold w-16 ${RISK_COLORS[vuln.risk_level] || 'text-gray-400'}`}>
                  {vuln.risk_level}
                </span>
                <span className="text-xs text-info-blue font-mono w-24">{vuln.device_ip}</span>
                <span className="text-xs text-gray-400 w-16">:{vuln.port}</span>
                <span className="text-xs text-gray-300 flex-1">{vuln.description}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Firewall Suggestions */}
      {report.firewall_suggestions?.length > 0 && (
        <div className="cyber-card">
          <button
            onClick={() => toggleSection('firewall')}
            className="w-full flex items-center justify-between mb-2"
          >
            <h2 className="text-lg font-bold text-gray-200">
              Firewall Rules ({report.firewall_suggestions.length})
            </h2>
            {expandedSections.firewall ? <ChevronUp className="w-5 h-5 text-gray-500" /> : <ChevronDown className="w-5 h-5 text-gray-500" />}
          </button>
          {expandedSections.firewall && (
            <div className="space-y-2">
              {report.firewall_suggestions.map((rule, i) => (
                <div key={i} className="p-3 rounded border border-cyber-border/30">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-gray-200">{rule.description}</span>
                    <span className={`text-[10px] font-bold ${RISK_COLORS[rule.risk_level]}`}>{rule.risk_level}</span>
                  </div>
                  <code className="text-xs text-matrix-green bg-black/30 px-2 py-1 rounded block mt-1 font-mono">
                    {rule.rule_iptables || rule.rule_ufw}
                  </code>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Bandwidth Top Talkers */}
      {report.bandwidth_top_talkers?.length > 0 && (
        <div className="cyber-card">
          <button
            onClick={() => toggleSection('bandwidth')}
            className="w-full flex items-center justify-between mb-2"
          >
            <h2 className="text-lg font-bold text-gray-200">
              <Activity className="w-5 h-5 inline mr-2" />
              Bandwidth Analysis
            </h2>
            {expandedSections.bandwidth ? <ChevronUp className="w-5 h-5 text-gray-500" /> : <ChevronDown className="w-5 h-5 text-gray-500" />}
          </button>
          {expandedSections.bandwidth && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-500 text-xs uppercase border-b border-cyber-border">
                    <th className="text-left pb-2">Device</th>
                    <th className="text-right pb-2">Sent</th>
                    <th className="text-right pb-2">Received</th>
                    <th className="text-right pb-2">Total</th>
                  </tr>
                </thead>
                <tbody>
                  {report.bandwidth_top_talkers.map((d, i) => (
                    <tr key={i} className="border-b border-cyber-border/30">
                      <td className="py-1.5 text-gray-300 font-mono text-xs">{d.ip_address}</td>
                      <td className="text-right text-matrix-green text-xs">{formatBytes(d.bytes_sent)}</td>
                      <td className="text-right text-info-blue text-xs">{formatBytes(d.bytes_received)}</td>
                      <td className="text-right text-gray-400 text-xs">{formatBytes((d.bytes_sent || 0) + (d.bytes_received || 0))}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
