import { useState, useEffect, useCallback } from 'react'
import {
  Settings as SettingsIcon,
  ChevronDown,
  ChevronRight,
  Save,
  RotateCcw,
  Eye,
  EyeOff,
  Check,
  X,
  Loader2,
} from 'lucide-react'
import {
  getSettings,
  updateSettings,
  getSettingsInterfaces,
  resetSettings,
  changePassword,
} from '../utils/api'

function Toast({ message, type, onClose }) {
  useEffect(() => {
    const timer = setTimeout(onClose, 3000)
    return () => clearTimeout(timer)
  }, [onClose])

  const colors = {
    success: 'border-matrix-green text-matrix-green',
    error: 'border-attack-red text-attack-red',
  }

  return (
    <div
      className={`fixed top-6 right-6 z-50 px-4 py-3 bg-cyber-surface border ${colors[type]} rounded-lg shadow-lg flex items-center gap-2 animate-fade-in`}
    >
      {type === 'success' ? <Check className="w-4 h-4" /> : <X className="w-4 h-4" />}
      <span className="text-sm">{message}</span>
    </div>
  )
}

function Section({ title, icon, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <div className="border border-cyber-border rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((prev) => !prev)}
        className="w-full flex items-center justify-between px-4 py-3 bg-cyber-surface hover:bg-white/5 transition-colors"
      >
        <div className="flex items-center gap-2">
          {icon}
          <span className="text-gray-200 font-medium text-sm">{title}</span>
        </div>
        {open ? (
          <ChevronDown className="w-4 h-4 text-gray-500" />
        ) : (
          <ChevronRight className="w-4 h-4 text-gray-500" />
        )}
      </button>
      {open && <div className="px-4 py-4 space-y-4 bg-cyber-bg/50">{children}</div>}
    </div>
  )
}

function NumberInput({ label, value, onChange, min, max, step = 1, hint }) {
  return (
    <div>
      <label className="block text-xs text-gray-400 mb-1">{label}</label>
      <input
        type="number"
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value === '' ? '' : Number(e.target.value))}
        min={min}
        max={max}
        step={step}
        className="w-full bg-cyber-surface border border-cyber-border rounded px-3 py-2 text-sm text-gray-200 focus:border-matrix-green focus:outline-none transition-colors"
      />
      {hint && <p className="text-xs text-gray-600 mt-1">{hint}</p>}
    </div>
  )
}

function TextInput({ label, value, onChange, placeholder, hint }) {
  return (
    <div>
      <label className="block text-xs text-gray-400 mb-1">{label}</label>
      <input
        type="text"
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-cyber-surface border border-cyber-border rounded px-3 py-2 text-sm text-gray-200 focus:border-matrix-green focus:outline-none transition-colors"
      />
      {hint && <p className="text-xs text-gray-600 mt-1">{hint}</p>}
    </div>
  )
}

function Toggle({ label, checked, onChange, hint }) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <span className="text-sm text-gray-200">{label}</span>
        {hint && <p className="text-xs text-gray-600 mt-0.5">{hint}</p>}
      </div>
      <button
        onClick={() => onChange(!checked)}
        className={`relative w-11 h-6 rounded-full transition-colors ${
          checked ? 'bg-matrix-green/30 border-matrix-green' : 'bg-cyber-surface border-gray-600'
        } border`}
      >
        <span
          className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full transition-transform ${
            checked ? 'translate-x-5 bg-matrix-green' : 'bg-gray-500'
          }`}
        />
      </button>
    </div>
  )
}

function SelectInput({ label, value, onChange, options, hint }) {
  return (
    <div>
      <label className="block text-xs text-gray-400 mb-1">{label}</label>
      <select
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
        className="w-full bg-cyber-surface border border-cyber-border rounded px-3 py-2 text-sm text-gray-200 focus:border-matrix-green focus:outline-none transition-colors"
      >
        <option value="">Auto-detect</option>
        {options.map((opt) => (
          <option key={opt.name} value={opt.name}>
            {opt.name} {opt.is_virtual ? '(virtual)' : ''} {opt.status === 'up' ? '' : `[${opt.status}]`}
          </option>
        ))}
      </select>
      {hint && <p className="text-xs text-gray-600 mt-1">{hint}</p>}
    </div>
  )
}

function SliderInput({ label, value, onChange, min, max, step = 0.01, hint }) {
  return (
    <div>
      <label className="block text-xs text-gray-400 mb-1">
        {label}: <span className="text-matrix-green">{value}</span>
      </label>
      <input
        type="range"
        value={value ?? min}
        onChange={(e) => onChange(Number(e.target.value))}
        min={min}
        max={max}
        step={step}
        className="w-full accent-matrix-green"
      />
      <div className="flex justify-between text-xs text-gray-600">
        <span>{min}</span>
        <span>{max}</span>
      </div>
      {hint && <p className="text-xs text-gray-600 mt-1">{hint}</p>}
    </div>
  )
}

function SaveButton({ onClick, saving, dirty }) {
  return (
    <button
      onClick={onClick}
      disabled={saving || !dirty}
      className={`flex items-center gap-2 px-4 py-2 rounded text-sm font-medium transition-all ${
        dirty
          ? 'bg-matrix-green/20 text-matrix-green border border-matrix-green hover:bg-matrix-green/30'
          : 'bg-cyber-surface text-gray-600 border border-cyber-border cursor-not-allowed'
      }`}
    >
      {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
      {saving ? 'Saving...' : 'Save'}
    </button>
  )
}

export default function Settings() {
  const [settings, setSettings] = useState(null)
  const [original, setOriginal] = useState(null)
  const [interfaces, setInterfaces] = useState([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState({})
  const [toast, setToast] = useState(null)

  // Password form
  const [currentPass, setCurrentPass] = useState('')
  const [newPass, setNewPass] = useState('')
  const [showCurrentPass, setShowCurrentPass] = useState(false)
  const [showNewPass, setShowNewPass] = useState(false)

  const showToast = useCallback((message, type = 'success') => {
    setToast({ message, type })
  }, [])

  useEffect(() => {
    async function load() {
      try {
        const [settingsData, interfacesData] = await Promise.all([
          getSettings(),
          getSettingsInterfaces(),
        ])
        setSettings(settingsData)
        setOriginal(settingsData)
        setInterfaces(interfacesData)
      } catch (err) {
        showToast(err.message, 'error')
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [showToast])

  const update = (key, value) => {
    setSettings((prev) => ({ ...prev, [key]: value }))
  }

  const isDirty = (keys) => {
    if (!settings || !original) return false
    return keys.some((k) => settings[k] !== original[k])
  }

  const saveSection = async (sectionName, keys) => {
    setSaving((prev) => ({ ...prev, [sectionName]: true }))
    try {
      const payload = {}
      for (const key of keys) {
        if (settings[key] !== original[key]) {
          payload[key] = settings[key]
        }
      }
      if (Object.keys(payload).length === 0) return

      const result = await updateSettings(payload)
      setSettings(result.settings)
      setOriginal(result.settings)
      showToast(`${sectionName} settings saved`)
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setSaving((prev) => ({ ...prev, [sectionName]: false }))
    }
  }

  const handleReset = async () => {
    if (!window.confirm('Reset ALL settings to factory defaults? This cannot be undone.')) return
    try {
      const result = await resetSettings()
      setSettings(result.settings)
      setOriginal(result.settings)
      showToast('Settings reset to defaults')
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  const handlePasswordChange = async () => {
    if (!currentPass || !newPass) {
      showToast('Both password fields are required', 'error')
      return
    }
    if (newPass.length < 6) {
      showToast('New password must be at least 6 characters', 'error')
      return
    }
    setSaving((prev) => ({ ...prev, password: true }))
    try {
      await changePassword(currentPass, newPass)
      setCurrentPass('')
      setNewPass('')
      showToast('Password changed successfully')
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setSaving((prev) => ({ ...prev, password: false }))
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 text-matrix-green animate-spin" />
      </div>
    )
  }

  if (!settings) {
    return (
      <div className="text-center py-12 text-gray-500">
        Failed to load settings. Check your connection.
      </div>
    )
  }

  const modeKeys = ['SIMULATION_MODE', 'SIM_DEVICE_COUNT', 'SIM_ATTACK_PROB', 'SIM_TICK_INTERVAL']
  const snifferKeys = ['SNIFFER_INTERFACE', 'SNIFFER_BPF_FILTER', 'SNIFFER_WINDOW_SECONDS', 'SNIFFER_MAX_BUFFER']
  const detectionKeys = [
    'THRESH_SYN_PPS', 'THRESH_UDP_PPS', 'THRESH_ICMP_PPS',
    'THRESH_HTTP_PPS', 'THRESH_ARP_PPS', 'ZSCORE_THRESHOLD', 'ZSCORE_MIN_SAMPLES',
  ]
  const mitigationKeys = ['AUTO_BLOCK', 'RATE_LIMIT_PPS', 'BLOCK_DURATION']
  const wsKeys = ['WS_INTERVAL']
  const scannerKeys = ['SCAN_INTERVAL', 'AUTO_SCAN']
  const authKeys = ['TOKEN_EXPIRE_MINUTES']

  return (
    <div className="max-w-3xl mx-auto space-y-4">
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <SettingsIcon className="w-6 h-6 text-matrix-green" />
          <h1 className="text-xl font-bold text-gray-200">Settings</h1>
        </div>
        <button
          onClick={handleReset}
          className="flex items-center gap-2 px-3 py-2 rounded text-sm text-gray-400 hover:text-attack-red border border-cyber-border hover:border-attack-red transition-colors"
        >
          <RotateCcw className="w-4 h-4" />
          Reset All
        </button>
      </div>

      {/* Mode Settings */}
      <Section title="Mode Settings" icon={<SettingsIcon className="w-4 h-4 text-info-blue" />} defaultOpen>
        <Toggle
          label="Simulation Mode"
          checked={settings.SIMULATION_MODE}
          onChange={(v) => update('SIMULATION_MODE', v)}
          hint="Enable fake traffic generation for demo/classroom use"
        />
        <SliderInput
          label="Simulated Device Count"
          value={settings.SIM_DEVICE_COUNT}
          onChange={(v) => update('SIM_DEVICE_COUNT', v)}
          min={1}
          max={20}
          step={1}
          hint="Number of fake devices to simulate"
        />
        <SliderInput
          label="Attack Probability"
          value={settings.SIM_ATTACK_PROB}
          onChange={(v) => update('SIM_ATTACK_PROB', v)}
          min={0}
          max={1}
          step={0.05}
          hint="Chance a simulated device becomes an attacker each tick"
        />
        <NumberInput
          label="Tick Interval (seconds)"
          value={settings.SIM_TICK_INTERVAL}
          onChange={(v) => update('SIM_TICK_INTERVAL', v)}
          min={0.5}
          max={30}
          step={0.5}
          hint="How often simulation generates new traffic"
        />
        <div className="pt-2">
          <SaveButton
            onClick={() => saveSection('Mode', modeKeys)}
            saving={saving.Mode}
            dirty={isDirty(modeKeys)}
          />
        </div>
      </Section>

      {/* Sniffer Settings */}
      <Section title="Sniffer Settings" icon={<SettingsIcon className="w-4 h-4 text-warn-yellow" />}>
        <SelectInput
          label="Network Interface"
          value={settings.SNIFFER_INTERFACE}
          onChange={(v) => update('SNIFFER_INTERFACE', v)}
          options={interfaces}
          hint="Interface to capture packets on (empty = auto-detect)"
        />
        <TextInput
          label="BPF Filter"
          value={settings.SNIFFER_BPF_FILTER}
          onChange={(v) => update('SNIFFER_BPF_FILTER', v)}
          placeholder="e.g., tcp port 80"
          hint="Berkeley Packet Filter expression (empty = capture all)"
        />
        <NumberInput
          label="Window Seconds"
          value={settings.SNIFFER_WINDOW_SECONDS}
          onChange={(v) => update('SNIFFER_WINDOW_SECONDS', v)}
          min={1}
          max={60}
          hint="Analysis window duration in seconds"
        />
        <NumberInput
          label="Max Buffer Size"
          value={settings.SNIFFER_MAX_BUFFER}
          onChange={(v) => update('SNIFFER_MAX_BUFFER', v)}
          min={1000}
          max={1000000}
          step={1000}
          hint="Maximum packets in rolling buffer per window"
        />
        <div className="pt-2">
          <SaveButton
            onClick={() => saveSection('Sniffer', snifferKeys)}
            saving={saving.Sniffer}
            dirty={isDirty(snifferKeys)}
          />
        </div>
      </Section>

      {/* Detection Thresholds */}
      <Section title="Detection Thresholds" icon={<SettingsIcon className="w-4 h-4 text-attack-red" />}>
        <div className="grid grid-cols-2 gap-4">
          <NumberInput
            label="SYN Flood PPS"
            value={settings.THRESH_SYN_PPS}
            onChange={(v) => update('THRESH_SYN_PPS', v)}
            min={1}
            hint="SYN packets/sec threshold"
          />
          <NumberInput
            label="UDP Flood PPS"
            value={settings.THRESH_UDP_PPS}
            onChange={(v) => update('THRESH_UDP_PPS', v)}
            min={1}
            hint="UDP packets/sec threshold"
          />
          <NumberInput
            label="ICMP Flood PPS"
            value={settings.THRESH_ICMP_PPS}
            onChange={(v) => update('THRESH_ICMP_PPS', v)}
            min={1}
            hint="ICMP packets/sec threshold"
          />
          <NumberInput
            label="HTTP Flood PPS"
            value={settings.THRESH_HTTP_PPS}
            onChange={(v) => update('THRESH_HTTP_PPS', v)}
            min={1}
            hint="HTTP packets/sec threshold"
          />
          <NumberInput
            label="ARP Spoof PPS"
            value={settings.THRESH_ARP_PPS}
            onChange={(v) => update('THRESH_ARP_PPS', v)}
            min={1}
            hint="ARP packets/sec threshold"
          />
        </div>
        <div className="border-t border-cyber-border pt-4 mt-2">
          <NumberInput
            label="Z-Score Threshold"
            value={settings.ZSCORE_THRESHOLD}
            onChange={(v) => update('ZSCORE_THRESHOLD', v)}
            min={1}
            max={10}
            step={0.1}
            hint="Standard deviations above mean to trigger alert"
          />
          <div className="mt-4">
            <NumberInput
              label="Z-Score Min Samples"
              value={settings.ZSCORE_MIN_SAMPLES}
              onChange={(v) => update('ZSCORE_MIN_SAMPLES', v)}
              min={5}
              max={200}
              hint="Minimum samples before z-score activates"
            />
          </div>
        </div>
        <div className="pt-2">
          <SaveButton
            onClick={() => saveSection('Detection', detectionKeys)}
            saving={saving.Detection}
            dirty={isDirty(detectionKeys)}
          />
        </div>
      </Section>

      {/* Mitigation Settings */}
      <Section title="Mitigation Settings" icon={<SettingsIcon className="w-4 h-4 text-matrix-green" />}>
        <Toggle
          label="Auto-Block"
          checked={settings.AUTO_BLOCK}
          onChange={(v) => update('AUTO_BLOCK', v)}
          hint="Automatically block detected attackers"
        />
        <NumberInput
          label="Rate Limit PPS"
          value={settings.RATE_LIMIT_PPS}
          onChange={(v) => update('RATE_LIMIT_PPS', v)}
          min={1}
          hint="Packets/sec cap before hard block"
        />
        <NumberInput
          label="Block Duration (seconds)"
          value={settings.BLOCK_DURATION}
          onChange={(v) => update('BLOCK_DURATION', v)}
          min={0}
          hint="Auto-block expiry time (0 = manual unblock only)"
        />
        <div className="pt-2">
          <SaveButton
            onClick={() => saveSection('Mitigation', mitigationKeys)}
            saving={saving.Mitigation}
            dirty={isDirty(mitigationKeys)}
          />
        </div>
      </Section>

      {/* Authentication */}
      <Section title="Authentication" icon={<SettingsIcon className="w-4 h-4 text-info-blue" />}>
        <NumberInput
          label="Token Expiry (minutes)"
          value={settings.TOKEN_EXPIRE_MINUTES}
          onChange={(v) => update('TOKEN_EXPIRE_MINUTES', v)}
          min={5}
          max={1440}
          hint="JWT token lifetime in minutes"
        />
        <div className="pt-2">
          <SaveButton
            onClick={() => saveSection('Auth', authKeys)}
            saving={saving.Auth}
            dirty={isDirty(authKeys)}
          />
        </div>

        <div className="border-t border-cyber-border pt-4 mt-2">
          <h3 className="text-sm text-gray-300 mb-3">Change Password</h3>
          <div className="space-y-3">
            <div className="relative">
              <label className="block text-xs text-gray-400 mb-1">Current Password</label>
              <div className="relative">
                <input
                  type={showCurrentPass ? 'text' : 'password'}
                  value={currentPass}
                  onChange={(e) => setCurrentPass(e.target.value)}
                  className="w-full bg-cyber-surface border border-cyber-border rounded px-3 py-2 pr-10 text-sm text-gray-200 focus:border-matrix-green focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowCurrentPass((p) => !p)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                >
                  {showCurrentPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <div className="relative">
              <label className="block text-xs text-gray-400 mb-1">New Password</label>
              <div className="relative">
                <input
                  type={showNewPass ? 'text' : 'password'}
                  value={newPass}
                  onChange={(e) => setNewPass(e.target.value)}
                  className="w-full bg-cyber-surface border border-cyber-border rounded px-3 py-2 pr-10 text-sm text-gray-200 focus:border-matrix-green focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowNewPass((p) => !p)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                >
                  {showNewPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
            <button
              onClick={handlePasswordChange}
              disabled={saving.password || !currentPass || !newPass}
              className={`flex items-center gap-2 px-4 py-2 rounded text-sm font-medium transition-all ${
                currentPass && newPass
                  ? 'bg-info-blue/20 text-info-blue border border-info-blue hover:bg-info-blue/30'
                  : 'bg-cyber-surface text-gray-600 border border-cyber-border cursor-not-allowed'
              }`}
            >
              {saving.password ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Save className="w-4 h-4" />
              )}
              Change Password
            </button>
          </div>
        </div>
      </Section>

      {/* WebSocket */}
      <Section title="WebSocket" icon={<SettingsIcon className="w-4 h-4 text-matrix-green" />}>
        <NumberInput
          label="Broadcast Interval (seconds)"
          value={settings.WS_INTERVAL}
          onChange={(v) => update('WS_INTERVAL', v)}
          min={0.5}
          max={30}
          step={0.5}
          hint="How often the server pushes updates to clients"
        />
        <div className="pt-2">
          <SaveButton
            onClick={() => saveSection('WebSocket', wsKeys)}
            saving={saving.WebSocket}
            dirty={isDirty(wsKeys)}
          />
        </div>
      </Section>

      {/* Scanner */}
      <Section title="Scanner" icon={<SettingsIcon className="w-4 h-4 text-warn-yellow" />}>
        <Toggle
          label="Auto-Scan"
          checked={settings.AUTO_SCAN}
          onChange={(v) => update('AUTO_SCAN', v)}
          hint="Automatically scan the network at regular intervals"
        />
        <NumberInput
          label="Scan Interval (seconds)"
          value={settings.SCAN_INTERVAL}
          onChange={(v) => update('SCAN_INTERVAL', v)}
          min={10}
          max={600}
          hint="Time between automatic network scans"
        />
        <div className="pt-2">
          <SaveButton
            onClick={() => saveSection('Scanner', scannerKeys)}
            saving={saving.Scanner}
            dirty={isDirty(scannerKeys)}
          />
        </div>
      </Section>
    </div>
  )
}
