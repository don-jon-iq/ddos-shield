/**
 * Full-page educational view listing all attack types with summaries.
 *
 * Students can browse attack types in a card layout and click
 * "Learn More" to open the detailed EducationalPopup modal.
 */

import { useEffect, useState } from 'react'
import {
  BookOpen,
  AlertTriangle,
  Layers,
  ChevronRight,
  Loader2,
} from 'lucide-react'
import { getAttackTypes } from '../utils/api'

const SEVERITY_STYLES = {
  CRITICAL: 'bg-attack-red/10 text-attack-red border-attack-red/30',
  HIGH: 'bg-red-900/20 text-red-400 border-red-800/30',
  MEDIUM: 'bg-warn-yellow/10 text-warn-yellow border-warn-yellow/30',
  LOW: 'bg-info-blue/10 text-info-blue border-info-blue/30',
}

const ATTACK_ICONS = {
  SYN_FLOOD: '🔁',
  UDP_FLOOD: '📡',
  ICMP_FLOOD: '🏓',
  HTTP_FLOOD: '🌐',
  ARP_SPOOF: '🎭',
}

const ATTACK_SUMMARIES = {
  SYN_FLOOD:
    'Exploits the TCP three-way handshake by flooding with SYN packets, filling the connection table.',
  UDP_FLOOD:
    'Overwhelms the target with UDP datagrams to random ports, consuming bandwidth and CPU.',
  ICMP_FLOOD:
    'Sends massive ICMP Echo Requests (pings), consuming bandwidth in both directions.',
  HTTP_FLOOD:
    'Layer 7 attack using seemingly legitimate HTTP requests to exhaust server resources.',
  ARP_SPOOF:
    'Forges ARP messages to intercept traffic — a classic Man-in-the-Middle attack.',
}

export default function EducationalPage({ onShowDetail }) {
  const [attackTypes, setAttackTypes] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    getAttackTypes()
      .then(setAttackTypes)
      .catch(() => setAttackTypes(null))
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 text-matrix-green animate-spin" />
      </div>
    )
  }

  if (!attackTypes) {
    return (
      <div className="text-center text-gray-500 py-16">
        Failed to load educational content. Is the backend running?
      </div>
    )
  }

  const entries = Object.entries(attackTypes)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <BookOpen className="w-5 h-5 text-info-blue" />
          <h1 className="text-xl font-bold text-gray-200">
            Attack Encyclopedia
          </h1>
        </div>
        <p className="text-sm text-gray-500">
          Learn about common DDoS attack types, how they work, how to detect
          them, and how to defend against them.
        </p>
      </div>

      {/* Attack cards grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {entries.map(([key, info]) => (
          <button
            key={key}
            onClick={() => onShowDetail(key)}
            className="text-left bg-cyber-surface border border-cyber-border rounded-lg p-5 hover:border-info-blue/50 transition-all group"
          >
            {/* Icon + name */}
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-2">
                <span className="text-2xl">{ATTACK_ICONS[key] || '⚡'}</span>
                <h2 className="text-base font-semibold text-gray-200 group-hover:text-info-blue transition-colors">
                  {info.name}
                </h2>
              </div>
              <ChevronRight className="w-4 h-4 text-gray-600 group-hover:text-info-blue transition-colors mt-1" />
            </div>

            {/* Badges */}
            <div className="flex flex-wrap gap-2 mb-3">
              <span className="px-2 py-0.5 text-xs rounded bg-info-blue/10 text-info-blue border border-info-blue/30 flex items-center gap-1">
                <Layers className="w-3 h-3" />
                {info.layer}
              </span>
              <span
                className={`px-2 py-0.5 text-xs rounded border flex items-center gap-1 ${
                  SEVERITY_STYLES[info.severity] || SEVERITY_STYLES.MEDIUM
                }`}
              >
                <AlertTriangle className="w-3 h-3" />
                {info.severity}
              </span>
            </div>

            {/* Summary */}
            <p className="text-xs text-gray-500 leading-relaxed">
              {ATTACK_SUMMARIES[key] || `Learn about ${info.name} attacks.`}
            </p>
          </button>
        ))}
      </div>

      {/* Footer tip */}
      <div className="text-xs text-gray-600 border-t border-cyber-border pt-4">
        Tip: You can also click on any attack type name in the Alerts or History
        pages to open its detailed explanation.
      </div>
    </div>
  )
}
