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
