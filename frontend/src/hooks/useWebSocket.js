/**
 * React hook for the DDoS Shield WebSocket connection.
 *
 * Educational note:
 *   This hook manages a persistent WebSocket connection to the backend.
 *   It automatically reconnects on disconnection with exponential backoff,
 *   and provides the latest traffic + alert data to any component that
 *   subscribes.
 *
 *   The WebSocket URL is derived from the current page location so it
 *   works in both development (Vite proxy) and production (same origin).
 */

import { useCallback, useEffect, useRef, useState } from 'react'

const MAX_RECONNECT_DELAY = 30000 // 30 seconds
const INITIAL_RECONNECT_DELAY = 1000 // 1 second

export default function useWebSocket() {
  const [traffic, setTraffic] = useState([])
  const [alerts, setAlerts] = useState([])
  const [connected, setConnected] = useState(false)
  const [activeDevices, setActiveDevices] = useState(0)
  const [wsClients, setWsClients] = useState(0)
  const [lastUpdate, setLastUpdate] = useState(null)

  // Keep a rolling history of alerts for the alerts panel
  const [alertHistory, setAlertHistory] = useState([])

  // Keep a rolling history of traffic snapshots for charts
  const [trafficHistory, setTrafficHistory] = useState([])

  const wsRef = useRef(null)
  const reconnectDelay = useRef(INITIAL_RECONNECT_DELAY)
  const reconnectTimer = useRef(null)

  const connect = useCallback(() => {
    // Build WebSocket URL from current location
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}/ws`

    try {
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
        reconnectDelay.current = INITIAL_RECONNECT_DELAY
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)

          if (data.type === 'update') {
            setTraffic(data.traffic || [])
            setAlerts(data.alerts || [])
            setActiveDevices(data.active_devices || 0)
            setWsClients(data.ws_clients || 0)
            setLastUpdate(data.timestamp)

            // Append to traffic history (keep last 60 snapshots ≈ 10 min at 10s windows)
            setTrafficHistory((prev) => {
              const entry = {
                timestamp: data.timestamp,
                devices: data.traffic || [],
              }
              const updated = [...prev, entry]
              return updated.length > 60 ? updated.slice(-60) : updated
            })

            // Append new alerts to history (keep last 200)
            if (data.alerts && data.alerts.length > 0) {
              setAlertHistory((prev) => {
                const newAlerts = data.alerts.map((a) => ({
                  ...a,
                  timestamp: data.timestamp,
                  id: `${data.timestamp}-${a.mac_address}-${a.attack_type}`,
                }))
                const updated = [...newAlerts, ...prev]
                return updated.length > 200 ? updated.slice(0, 200) : updated
              })
            }
          }
        } catch {
          // Ignore malformed messages
        }
      }

      ws.onclose = () => {
        setConnected(false)
        wsRef.current = null
        // Reconnect with exponential backoff
        reconnectTimer.current = setTimeout(() => {
          reconnectDelay.current = Math.min(
            reconnectDelay.current * 2,
            MAX_RECONNECT_DELAY
          )
          connect()
        }, reconnectDelay.current)
      }

      ws.onerror = () => {
        ws.close()
      }

      // Send periodic pings to keep the connection alive
      const pingInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send('ping')
        }
      }, 30000)

      ws.addEventListener('close', () => clearInterval(pingInterval))
    } catch {
      // WebSocket constructor can throw if URL is invalid
      setTimeout(connect, reconnectDelay.current)
    }
  }, [])

  useEffect(() => {
    connect()

    return () => {
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current)
      }
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [connect])

  return {
    traffic,
    alerts,
    alertHistory,
    trafficHistory,
    connected,
    activeDevices,
    wsClients,
    lastUpdate,
  }
}
