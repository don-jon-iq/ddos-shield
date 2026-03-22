import { useEffect, useState } from 'react'
import {
  Shield,
  ShieldCheck,
  Activity,
  Monitor,
  AlertTriangle,
  History,
  Network,
  Wrench,
  BookOpen,
  LogOut,
  Wifi,
  WifiOff,
  ServerCog,
  Settings,
  Search,
  BarChart3,
  ShieldAlert,
  Bell,
  FileText,
} from 'lucide-react'
import { clearToken, getAlertCounts, getHealth } from '../utils/api'

const NAV_SECTIONS = [
  {
    title: 'Overview',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: Activity },
    ],
  },
  {
    title: 'Network',
    items: [
      { id: 'discovery', label: 'Discovery', icon: Search },
      { id: 'bandwidth', label: 'Bandwidth', icon: BarChart3 },
      { id: 'topology', label: 'Network Map', icon: Network },
      { id: 'devices', label: 'Traffic Monitor', icon: Monitor },
    ],
  },
  {
    title: 'Security',
    items: [
      { id: 'security', label: 'Security Audit', icon: ShieldAlert },
      { id: 'alert-center', label: 'Alert Center', icon: Bell },
      { id: 'protection', label: 'Protection', icon: ShieldCheck },
      { id: 'alerts', label: 'Attack Alerts', icon: AlertTriangle },
      { id: 'rescue', label: 'Rescue Panel', icon: Wrench },
    ],
  },
  {
    title: 'Reports',
    items: [
      { id: 'report', label: 'Audit Report', icon: FileText },
    ],
  },
  {
    title: 'Management',
    items: [
      { id: 'device-manager', label: 'Devices', icon: ServerCog },
      { id: 'history', label: 'Attack History', icon: History },
      { id: 'educational', label: 'Learn', icon: BookOpen },
    ],
  },
]

export default function Sidebar({ active, onNavigate, connected, onLogout }) {
  const [alertBadge, setAlertBadge] = useState(0)
  const [healthDot, setHealthDot] = useState('green')

  useEffect(() => {
    const loadBadges = async () => {
      try {
        const [counts, health] = await Promise.all([
          getAlertCounts(),
          getHealth(),
        ])
        const critical = counts?.by_severity?.CRITICAL || 0
        const high = counts?.by_severity?.HIGH || 0
        setAlertBadge(critical + high)

        const status = health?.score?.status || 'unknown'
        if (status === 'healthy') setHealthDot('green')
        else if (status === 'degraded') setHealthDot('yellow')
        else setHealthDot('red')
      } catch {
        // not ready
      }
    }
    loadBadges()
    const interval = setInterval(loadBadges, 15000)
    return () => clearInterval(interval)
  }, [])

  const handleLogout = () => {
    clearToken()
    onLogout()
  }

  return (
    <aside className="w-56 bg-cyber-surface border-r border-cyber-border flex flex-col h-screen fixed left-0 top-0">
      {/* Logo */}
      <div className="p-4 border-b border-cyber-border">
        <div className="flex items-center gap-2">
          <Shield className="w-6 h-6 text-matrix-green" />
          <span className="text-matrix-green font-bold text-lg text-glow-green">
            DDoS Shield
          </span>
        </div>
        <div className="flex items-center gap-1.5 mt-2 text-xs">
          {connected ? (
            <>
              <Wifi className="w-3 h-3 text-matrix-green" />
              <span className="text-matrix-green">Live</span>
            </>
          ) : (
            <>
              <WifiOff className="w-3 h-3 text-attack-red" />
              <span className="text-attack-red">Disconnected</span>
            </>
          )}
          {/* Health dot */}
          <span
            className={`w-2 h-2 rounded-full ml-2 ${
              healthDot === 'green' ? 'bg-matrix-green' :
              healthDot === 'yellow' ? 'bg-warn-yellow' : 'bg-attack-red'
            }`}
            title={`Network health: ${healthDot}`}
          />
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-1 overflow-y-auto">
        {NAV_SECTIONS.map((section) => (
          <div key={section.title}>
            <div className="px-4 pt-3 pb-1 text-[10px] uppercase tracking-wider text-gray-500 font-semibold">
              {section.title}
            </div>
            {section.items.map(({ id, label, icon: Icon }) => {
              const isActive = active === id
              const showBadge = id === 'alert-center' && alertBadge > 0
              return (
                <button
                  key={id}
                  onClick={() => onNavigate(id)}
                  className={`w-full flex items-center gap-3 px-4 py-2 text-sm transition-all ${
                    isActive
                      ? 'text-matrix-green bg-matrix-green/10 border-r-2 border-matrix-green'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span className="flex-1 text-left">{label}</span>
                  {showBadge && (
                    <span className="px-1.5 py-0.5 text-[10px] font-bold bg-attack-red text-white rounded-full min-w-[18px] text-center">
                      {alertBadge}
                    </span>
                  )}
                </button>
              )
            })}
          </div>
        ))}
      </nav>

      {/* Settings + Logout */}
      <div className="border-t border-cyber-border">
        <button
          onClick={() => onNavigate('settings')}
          className={`w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-all ${
            active === 'settings'
              ? 'text-matrix-green bg-matrix-green/10 border-r-2 border-matrix-green'
              : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
          }`}
        >
          <Settings className="w-4 h-4" />
          Settings
        </button>
      </div>

      <div className="p-4 border-t border-cyber-border">
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-2 px-3 py-2 text-sm text-gray-500 hover:text-attack-red transition-colors rounded"
        >
          <LogOut className="w-4 h-4" />
          Logout
        </button>
      </div>
    </aside>
  )
}
