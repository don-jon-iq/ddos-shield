import { useState } from 'react'
import { isAuthenticated } from './utils/api'
import useWebSocket from './hooks/useWebSocket'
import LoginPage from './components/LoginPage'
import Sidebar from './components/Sidebar'
import Dashboard from './components/Dashboard'
import DeviceList from './components/DeviceList'
import DeviceManager from './components/DeviceManager'
import ProtectionStatus from './components/ProtectionStatus'
import AttackAlerts from './components/AttackAlerts'
import AttackHistory from './components/AttackHistory'
import NetworkTopology from './components/NetworkTopology'
import RescuePanel from './components/RescuePanel'
import EducationalPopup from './components/EducationalPopup'
import EducationalPage from './components/EducationalPage'
import Settings from './components/Settings'
import NetworkDiscovery from './components/NetworkDiscovery'
import BandwidthMonitor from './components/BandwidthMonitor'
import SecurityAudit from './components/SecurityAudit'
import AlertCenter from './components/AlertCenter'
import DeviceDetail from './components/DeviceDetail'
import ReportPage from './components/ReportPage'

export default function App() {
  const [loggedIn, setLoggedIn] = useState(isAuthenticated())
  const [page, setPage] = useState('dashboard')
  const [educationalPopup, setEducationalPopup] = useState(null)
  const [selectedDeviceMAC, setSelectedDeviceMAC] = useState(null)

  const ws = useWebSocket()

  if (!loggedIn) {
    return <LoginPage onLogin={() => setLoggedIn(true)} />
  }

  const openDeviceDetail = (mac) => {
    setSelectedDeviceMAC(mac)
    setPage('device-detail')
  }

  const renderPage = () => {
    switch (page) {
      case 'dashboard':
        return (
          <Dashboard
            traffic={ws.traffic}
            alerts={ws.alerts}
            alertHistory={ws.alertHistory}
            trafficHistory={ws.trafficHistory}
            activeDevices={ws.activeDevices}
            wsClients={ws.wsClients}
          />
        )
      case 'discovery':
        return <NetworkDiscovery onDeviceClick={openDeviceDetail} />
      case 'bandwidth':
        return <BandwidthMonitor />
      case 'security':
        return <SecurityAudit onDeviceClick={openDeviceDetail} />
      case 'alert-center':
        return <AlertCenter />
      case 'report':
        return <ReportPage />
      case 'device-detail':
        return (
          <DeviceDetail
            mac={selectedDeviceMAC}
            onBack={() => setPage('discovery')}
          />
        )
      case 'device-manager':
        return <DeviceManager />
      case 'protection':
        return <ProtectionStatus />
      case 'devices':
        return <DeviceList traffic={ws.traffic} />
      case 'alerts':
        return (
          <AttackAlerts
            alerts={ws.alerts}
            alertHistory={ws.alertHistory}
            onShowEducational={setEducationalPopup}
          />
        )
      case 'history':
        return <AttackHistory onShowEducational={setEducationalPopup} />
      case 'topology':
        return <NetworkTopology traffic={ws.traffic} />
      case 'rescue':
        return <RescuePanel />
      case 'educational':
        return <EducationalPage onShowDetail={setEducationalPopup} />
      case 'settings':
        return <Settings />
      default:
        return null
    }
  }

  return (
    <div className="min-h-screen bg-cyber-bg">
      <Sidebar
        active={page}
        onNavigate={setPage}
        connected={ws.connected}
        onLogout={() => setLoggedIn(false)}
      />

      <main className="ml-56 p-6">{renderPage()}</main>

      {educationalPopup && (
        <EducationalPopup
          attackType={educationalPopup}
          onClose={() => setEducationalPopup(null)}
        />
      )}
    </div>
  )
}
