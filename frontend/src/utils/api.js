/**
 * API client for the DDoS Shield backend.
 *
 * All fetch calls go through this module so we can:
 *  - Attach the JWT token automatically
 *  - Handle errors consistently
 *  - Centralise the base URL
 */

const BASE_URL = '/api'

/**
 * Read the stored JWT token from sessionStorage.
 * We use sessionStorage (not localStorage) so the token is cleared
 * when the browser tab closes — a small security improvement.
 */
const getToken = () => sessionStorage.getItem('ddos_shield_token')

export const setToken = (token) => sessionStorage.setItem('ddos_shield_token', token)

export const clearToken = () => sessionStorage.removeItem('ddos_shield_token')

export const isAuthenticated = () => Boolean(getToken())

/**
 * Generic fetch wrapper with auth header injection.
 */
async function request(path, options = {}) {
  const token = getToken()
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  }

  const response = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
  })

  if (response.status === 401) {
    clearToken()
    throw new Error('Session expired — please log in again')
  }

  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail || `Request failed: ${response.status}`)
  }

  return response.json()
}

// --- Auth ---
export const login = (username, password) =>
  request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  })

// --- Dashboard ---
export const getStatus = () => request('/status')
export const getDevices = () => request('/devices')
export const getDevice = (mac) => request(`/devices/${encodeURIComponent(mac)}`)
export const getLiveTraffic = () => request('/traffic')

// --- Attacks ---
export const getAttacks = (params = {}) => {
  const qs = new URLSearchParams(params).toString()
  return request(`/attacks?${qs}`)
}
export const getAttackStats = () => request('/attacks/stats')

// --- Mitigation ---
export const blockMAC = (mac, reason = '') =>
  request('/mitigate/block', {
    method: 'POST',
    body: JSON.stringify({ mac_address: mac, reason }),
  })

export const unblockMAC = (mac) =>
  request('/mitigate/unblock', {
    method: 'POST',
    body: JSON.stringify({ mac_address: mac }),
  })

export const rateLimitMAC = (mac) =>
  request('/mitigate/rate-limit', {
    method: 'POST',
    body: JSON.stringify({ mac_address: mac }),
  })

export const isolateMAC = (mac) =>
  request('/mitigate/isolate', {
    method: 'POST',
    body: JSON.stringify({ mac_address: mac }),
  })

export const getBlocked = () => request('/blocked')

// --- Network ---
export const getInterfaces = () => request('/interfaces')

// --- Educational ---
export const getAttackExplanation = (type) =>
  request(`/educational/${encodeURIComponent(type)}`)

export const getAttackTypes = () => request('/educational')

// --- Scanner ---
export const scanNetwork = () => request('/devices/scan')
export const getDiscoveredDevices = () => request('/devices/discovered')
export const getScanStatus = () => request('/devices/scan/status')

// --- Managed Devices ---
export const getManagedDevices = () => request('/managed-devices')
export const getManagedDevice = (id) => request(`/managed-devices/${id}`)
export const addManagedDevice = (data) =>
  request('/managed-devices', {
    method: 'POST',
    body: JSON.stringify(data),
  })
export const updateManagedDevice = (id, data) =>
  request(`/managed-devices/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  })
export const deleteManagedDevice = (id) =>
  request(`/managed-devices/${id}`, { method: 'DELETE' })
export const toggleDeviceProtection = (id) =>
  request(`/managed-devices/${id}/protect`, { method: 'POST' })

// --- Settings ---
export const getSettings = () => request('/settings')
export const updateSettings = (data) =>
  request('/settings', {
    method: 'PUT',
    body: JSON.stringify(data),
  })
export const getSettingsInterfaces = () => request('/settings/interfaces')
export const resetSettings = () =>
  request('/settings/reset', { method: 'POST' })
export const getSettingsDefaults = () => request('/settings/defaults')
export const changePassword = (currentPassword, newPassword) =>
  request('/settings/password', {
    method: 'POST',
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
    }),
  })

// --- Protection ---
export const getProtectionStatus = () => request('/protection/status')
export const getProtectionLogs = (deviceId, limit = 50) => {
  const params = new URLSearchParams({ limit: String(limit) })
  if (deviceId != null) params.set('device_id', String(deviceId))
  return request(`/protection/logs?${params}`)
}
export const getProtectionSummary = () => request('/protection/summary')

// --- Port Scanner ---
export const scanDevicePorts = (ip, mac = '') =>
  request(`/ports/scan/${encodeURIComponent(ip)}?mac=${encodeURIComponent(mac)}`)
export const getDevicePorts = (ip) =>
  request(`/ports/${encodeURIComponent(ip)}`)
export const getAllPorts = () => request('/ports')
export const clearPortCache = (ip) =>
  request(`/ports/cache${ip ? `?ip=${encodeURIComponent(ip)}` : ''}`, { method: 'DELETE' })

// --- Security / Vulnerability ---
export const assessDeviceSecurity = (ip, mac = '') =>
  request(`/security/assess/${encodeURIComponent(ip)}?mac=${encodeURIComponent(mac)}`)
export const getSecurityGrade = () => request('/security/grade')
export const scanAllDevices = () => request('/security/scan-all')

// --- Bandwidth ---
export const getBandwidth = () => request('/bandwidth')
export const getTopTalkers = (limit = 10) => request(`/bandwidth/top-talkers?limit=${limit}`)
export const getProtocols = (mac) =>
  request(`/bandwidth/protocols${mac ? `?mac=${encodeURIComponent(mac)}` : ''}`)
export const getConnections = (mac) =>
  request(`/bandwidth/connections${mac ? `?mac=${encodeURIComponent(mac)}` : ''}`)
export const getBandwidthHistory = (mac, limit = 100) => {
  const params = new URLSearchParams({ limit: String(limit) })
  if (mac) params.set('mac', mac)
  return request(`/bandwidth/history?${params}`)
}
export const getDnsQueries = (mac, limit = 100) => {
  const params = new URLSearchParams({ limit: String(limit) })
  if (mac) params.set('mac', mac)
  return request(`/bandwidth/dns?${params}`)
}

// --- Alerts ---
export const getAlerts = (params = {}) => {
  const qs = new URLSearchParams(params).toString()
  return request(`/alerts?${qs}`)
}
export const getAlertCounts = () => request('/alerts/counts')
export const acknowledgeAlert = (id) =>
  request(`/alerts/${id}/acknowledge`, { method: 'POST' })
export const resolveAlert = (id) =>
  request(`/alerts/${id}/resolve`, { method: 'POST' })

// --- Health ---
export const getHealth = () => request('/health')
export const getHealthScore = () => request('/health/score')
export const getHealthHistory = (checkType, limit = 100) => {
  const params = new URLSearchParams({ limit: String(limit) })
  if (checkType) params.set('check_type', checkType)
  return request(`/health/history?${params}`)
}
export const runHealthCheck = () => request('/health/check', { method: 'POST' })

// --- Device Detail ---
export const getDeviceDetail = (ip) =>
  request(`/device-detail/${encodeURIComponent(ip)}`)

// --- Remediation ---
export const getRemediations = (ip, mac = '') =>
  request(`/remediation/${encodeURIComponent(ip)}?mac=${encodeURIComponent(mac)}`)
export const applyFix = (ip, vulnId) =>
  request('/remediation/apply-fix', {
    method: 'POST',
    body: JSON.stringify({ ip_address: ip, vuln_id: vulnId }),
  })
export const getAppliedFixes = (ip) =>
  request(`/remediation/fixes${ip ? `?ip=${encodeURIComponent(ip)}` : ''}`)
export const getFirewallSuggestions = () => request('/firewall/suggestions')

// --- Report ---
export const getAuditReport = () => request('/report')

// --- Simulation ---
export const getScenarios = () => request('/simulation/scenarios')
export const setScenario = (preset) =>
  request('/simulation/scenario', {
    method: 'POST',
    body: JSON.stringify({ preset }),
  })
