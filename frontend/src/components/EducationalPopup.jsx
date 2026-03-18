/**
 * Educational popup that explains each attack type in detail.
 *
 * This is the core educational feature — students can click on any
 * attack type name throughout the dashboard to learn about it.
 */

import { useEffect, useState } from 'react'
import {
  X,
  BookOpen,
  Shield,
  AlertTriangle,
  Layers,
  Lightbulb,
} from 'lucide-react'
import { getAttackExplanation } from '../utils/api'

export default function EducationalPopup({ attackType, onClose }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!attackType) return
    setLoading(true)
    getAttackExplanation(attackType)
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [attackType])

  if (!attackType) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative w-full max-w-2xl max-h-[85vh] overflow-y-auto bg-cyber-surface border border-cyber-border rounded-lg shadow-2xl">
        {/* Header */}
        <div className="sticky top-0 bg-cyber-surface border-b border-cyber-border p-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-info-blue" />
            <h2 className="text-lg font-bold text-gray-200">
              {data?.name || attackType}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-gray-500 hover:text-gray-300 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {loading ? (
          <div className="p-8 text-center text-gray-600">Loading...</div>
        ) : !data ? (
          <div className="p-8 text-center text-gray-600">
            No information available for this attack type.
          </div>
        ) : (
          <div className="p-6 space-y-6">
            {/* Meta badges */}
            <div className="flex flex-wrap gap-2">
              <span className="px-2 py-1 text-xs rounded bg-info-blue/10 text-info-blue border border-info-blue/30 flex items-center gap-1">
                <Layers className="w-3 h-3" />
                {data.layer}
              </span>
              <span
                className={`px-2 py-1 text-xs rounded border flex items-center gap-1 ${
                  data.severity === 'CRITICAL'
                    ? 'bg-attack-red/10 text-attack-red border-attack-red/30'
                    : data.severity === 'HIGH'
                    ? 'bg-red-900/20 text-red-400 border-red-800/30'
                    : 'bg-warn-yellow/10 text-warn-yellow border-warn-yellow/30'
                }`}
              >
                <AlertTriangle className="w-3 h-3" />
                Severity: {data.severity}
              </span>
            </div>

            {/* Description */}
            <div>
              <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-2">
                What is it?
              </h3>
              <p className="text-gray-300 text-sm leading-relaxed">
                {data.description}
              </p>
            </div>

            {/* How it works */}
            <div>
              <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-2">
                How it works
              </h3>
              <div className="space-y-1.5">
                {data.how_it_works?.map((step, i) => (
                  <div
                    key={i}
                    className="text-sm text-gray-400 pl-3 border-l-2 border-info-blue/30 py-0.5"
                  >
                    {step}
                  </div>
                ))}
              </div>
            </div>

            {/* Detection indicators */}
            <div>
              <h3 className="text-sm font-semibold text-warn-yellow uppercase tracking-wider mb-2 flex items-center gap-1">
                <Lightbulb className="w-4 h-4" />
                Detection indicators
              </h3>
              <ul className="space-y-1">
                {data.indicators?.map((indicator, i) => (
                  <li
                    key={i}
                    className="text-sm text-gray-400 flex items-start gap-2"
                  >
                    <span className="text-warn-yellow mt-1">•</span>
                    {indicator}
                  </li>
                ))}
              </ul>
            </div>

            {/* Mitigation */}
            <div>
              <h3 className="text-sm font-semibold text-matrix-green uppercase tracking-wider mb-2 flex items-center gap-1">
                <Shield className="w-4 h-4" />
                Mitigation strategies
              </h3>
              <ul className="space-y-1">
                {data.mitigation?.map((strategy, i) => (
                  <li
                    key={i}
                    className="text-sm text-gray-400 flex items-start gap-2"
                  >
                    <span className="text-matrix-green mt-1">✓</span>
                    {strategy}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
