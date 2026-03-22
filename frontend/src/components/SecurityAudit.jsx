import { useEffect, useState, useCallback } from 'react'
import {
  Shield, ShieldAlert, ShieldCheck, ShieldOff, AlertTriangle,
  RefreshCw, Lock, Unlock, Info,
} from 'lucide-react'
import { getSecurityGrade, scanAllDevices } from '../utils/api'

const GRADE_COLORS = {
  A: 'text-matrix-green border-matrix-green',
  B: 'text-info-blue border-info-blue',
  C: 'text-warn-yellow border-warn-yellow',
  D: 'text-orange-400 border-orange-400',
  F: 'text-attack-red border-attack-red',
}

const GRADE_BG = {
  A: 'bg-matrix-green/10',
  B: 'bg-info-blue/10',
  C: 'bg-warn-yellow/10',
  D: 'bg-orange-400/10',
  F: 'bg-attack-red/10',
}

const RISK_COLORS = {
  CRITICAL: 'text-attack-red bg-attack-red/10 border-attack-red/30',
  HIGH: 'text-red-400 bg-red-400/10 border-red-400/30',
  MEDIUM: 'text-warn-yellow bg-warn-yellow/10 border-warn-yellow/30',
  LOW: 'text-gray-400 bg-gray-400/10 border-gray-400/30',
}

function GradeBadge({ grade, score }) {
  return (
    <div className={`flex items-center gap-4 p-6 rounded-xl border-2 ${GRADE_COLORS[grade] || GRADE_COLORS.F} ${GRADE_BG[grade] || GRADE_BG.F}`}>
      <div className={`text-6xl font-black ${(GRADE_COLORS[grade] || '').split(' ')[0]}`}>
        {grade}
      </div>
      <div>
        <p className="text-sm text-gray-400">Network Security Grade</p>
        <p className={`text-2xl font-bold ${(GRADE_COLORS[grade] || '').split(' ')[0]}`}>
          {score}/100
        </p>
      </div>
    </div>
  )
}

function ScoreBar({ score }) {
  const color =
    score >= 90 ? 'bg-matrix-green' :
    score >= 75 ? 'bg-info-blue' :
    score >= 50 ? 'bg-warn-yellow' :
    score >= 25 ? 'bg-orange-400' : 'bg-attack-red'

  return (
    <div className="w-full h-2 bg-cyber-bg rounded-full overflow-hidden">
      <div
        className={`h-full ${color} rounded-full transition-all duration-500`}
        style={{ width: `${score}%` }}
      />
    </div>
  )
}

export default function SecurityAudit() {
  const [gradeData, setGradeData] = useState(null)
  const [assessments, setAssessments] = useState([])
  const [scanning, setScanning] = useState(false)
  const [expandedDevice, setExpandedDevice] = useState(null)

  const loadGrade = useCallback(async () => {
    try {
      const data = await getSecurityGrade()
      setGradeData(data)
    } catch {
      // not ready
    }
  }, [])

  useEffect(() => {
    loadGrade()
  }, [loadGrade])

  const handleFullScan = async () => {
    setScanning(true)
    try {
      const result = await scanAllDevices()
      setAssessments(result.assessments || [])
      setGradeData(result.grade)
    } catch {
      // scan failed
    }
    setScanning(false)
  }

  const grade = gradeData?.grade || '?'
  const score = gradeData?.score || 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-200">Security Audit</h1>
        <button
          onClick={handleFullScan}
          disabled={scanning}
          className="flex items-center gap-2 px-4 py-2 bg-matrix-green/10 text-matrix-green border border-matrix-green/30 rounded-lg hover:bg-matrix-green/20 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${scanning ? 'animate-spin' : ''}`} />
          {scanning ? 'Scanning All Devices...' : 'Full Security Scan'}
        </button>
      </div>

      {/* Grade + Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <GradeBadge grade={grade} score={score} />

        <div className="cyber-card">
          <h3 className="text-sm text-gray-500 uppercase tracking-wider mb-3">Vulnerability Summary</h3>
          <div className="space-y-2">
            {[
              { label: 'Critical', count: gradeData?.critical_count || 0, color: 'text-attack-red' },
              { label: 'High', count: gradeData?.high_count || 0, color: 'text-red-400' },
              { label: 'Medium', count: gradeData?.medium_count || 0, color: 'text-warn-yellow' },
              { label: 'Low', count: gradeData?.low_count || 0, color: 'text-gray-400' },
            ].map(({ label, count, color }) => (
              <div key={label} className="flex items-center justify-between">
                <span className="text-sm text-gray-400">{label}</span>
                <span className={`text-sm font-bold ${color}`}>{count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="cyber-card">
          <h3 className="text-sm text-gray-500 uppercase tracking-wider mb-3">Statistics</h3>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Devices Scanned</span>
              <span className="text-sm text-gray-200 font-bold">{gradeData?.total_devices || 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Total Vulnerabilities</span>
              <span className="text-sm text-warn-yellow font-bold">{gradeData?.total_vulnerabilities || 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Assessments</span>
              <span className="text-sm text-gray-200 font-bold">{assessments.length}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Per-Device Assessments */}
      {assessments.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
            Device Security Assessments
          </h2>
          {assessments
            .sort((a, b) => a.security_score - b.security_score)
            .map((device, idx) => {
              const isExpanded = expandedDevice === idx
              const scoreColor =
                device.security_score >= 90 ? 'text-matrix-green' :
                device.security_score >= 75 ? 'text-info-blue' :
                device.security_score >= 50 ? 'text-warn-yellow' :
                device.security_score >= 25 ? 'text-orange-400' : 'text-attack-red'

              return (
                <div key={idx} className="cyber-card">
                  <button
                    onClick={() => setExpandedDevice(isExpanded ? null : idx)}
                    className="w-full flex items-center justify-between"
                  >
                    <div className="flex items-center gap-4">
                      <div className={`text-2xl font-black ${scoreColor}`}>
                        {device.security_score}
                      </div>
                      <div className="text-left">
                        <p className="text-sm font-medium text-gray-200">{device.ip_address}</p>
                        <p className="text-xs text-gray-500">
                          {device.open_ports} open port{device.open_ports !== 1 ? 's' : ''} ·{' '}
                          {device.vulnerabilities?.length || 0} issue{(device.vulnerabilities?.length || 0) !== 1 ? 's' : ''}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <ScoreBar score={device.security_score} />
                      {device.vulnerabilities?.length > 0 ? (
                        <ShieldAlert className="w-5 h-5 text-warn-yellow" />
                      ) : (
                        <ShieldCheck className="w-5 h-5 text-matrix-green" />
                      )}
                    </div>
                  </button>

                  {isExpanded && device.vulnerabilities?.length > 0 && (
                    <div className="mt-4 space-y-2 border-t border-cyber-border pt-4">
                      <p className="text-xs text-gray-500 mb-2">{device.risk_summary}</p>
                      {device.vulnerabilities.map((vuln, vi) => (
                        <div
                          key={vi}
                          className={`p-3 rounded-lg border ${RISK_COLORS[vuln.risk_level] || RISK_COLORS.LOW}`}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs font-bold">
                              Port {vuln.port} ({vuln.service})
                            </span>
                            <span className="text-[10px] font-bold uppercase">
                              {vuln.risk_level}
                            </span>
                          </div>
                          <p className="text-xs opacity-80">{vuln.description}</p>
                          <div className="mt-2 flex items-start gap-1">
                            <Info className="w-3 h-3 mt-0.5 flex-shrink-0 opacity-60" />
                            <p className="text-[10px] opacity-60">{vuln.recommendation}</p>
                          </div>
                          {vuln.cve_examples?.length > 0 && (
                            <div className="mt-1 flex gap-1 flex-wrap">
                              {vuln.cve_examples.map((cve, ci) => (
                                <span key={ci} className="text-[10px] px-1.5 py-0.5 rounded bg-black/30 font-mono">
                                  {cve}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
        </div>
      )}

      {assessments.length === 0 && !scanning && (
        <div className="cyber-card text-center py-12">
          <Shield className="w-12 h-12 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-500 mb-2">
            No security assessments yet.
          </p>
          <p className="text-gray-600 text-sm">
            Click "Full Security Scan" to scan all discovered devices for vulnerabilities.
          </p>
        </div>
      )}
    </div>
  )
}
