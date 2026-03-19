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
} from 'lucide-react'
import { clearToken } from '../utils/api'

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: Activity },
  { id: 'device-manager', label: 'Devices', icon: ServerCog },
  { id: 'protection', label: 'Protection', icon: ShieldCheck },
  { id: 'devices', label: 'Traffic Monitor', icon: Monitor },
  { id: 'alerts', label: 'Attack Alerts', icon: AlertTriangle },
  { id: 'history', label: 'Attack History', icon: History },
  { id: 'topology', label: 'Network Map', icon: Network },
  { id: 'rescue', label: 'Rescue Panel', icon: Wrench },
  { id: 'educational', label: 'Learn', icon: BookOpen },
  { id: 'settings', label: 'Settings', icon: Settings },
]

export default function Sidebar({ active, onNavigate, connected, onLogout }) {
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
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-2 overflow-y-auto">
        {NAV_ITEMS.filter((item) => item.id !== 'settings').map(({ id, label, icon: Icon }) => {
          const isActive = active === id
          return (
            <button
              key={id}
              onClick={() => onNavigate(id)}
              className={`w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-all ${
                isActive
                  ? 'text-matrix-green bg-matrix-green/10 border-r-2 border-matrix-green'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
              }`}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          )
        })}
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
