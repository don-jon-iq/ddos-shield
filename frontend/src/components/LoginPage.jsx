import { useState } from 'react'
import { Shield, AlertTriangle, Loader2 } from 'lucide-react'
import { login, setToken } from '../utils/api'

export default function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const data = await login(username, password)
      setToken(data.access_token)
      onLogin()
    } catch (err) {
      setError(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-cyber-bg flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-cyber-surface border-2 border-matrix-green glow-green mb-4">
            <Shield className="w-10 h-10 text-matrix-green" />
          </div>
          <h1 className="text-3xl font-bold text-matrix-green text-glow-green">
            DDoS Shield
          </h1>
          <p className="text-gray-500 mt-2 text-sm">
            Network Attack Monitoring System
          </p>
        </div>

        {/* Login form */}
        <form
          onSubmit={handleSubmit}
          className="cyber-card border-cyber-border"
        >
          <h2 className="text-lg font-semibold text-gray-300 mb-6">
            Authentication Required
          </h2>

          {error && (
            <div className="flex items-center gap-2 text-attack-red bg-attack-red/10 border border-attack-red/30 rounded px-3 py-2 mb-4 text-sm">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              {error}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label className="block text-xs text-gray-500 uppercase tracking-wider mb-1">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-matrix-green font-mono focus:outline-none focus:border-matrix-green transition-colors"
                placeholder="admin"
                autoFocus
              />
            </div>
            <div>
              <label className="block text-xs text-gray-500 uppercase tracking-wider mb-1">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-2 text-matrix-green font-mono focus:outline-none focus:border-matrix-green transition-colors"
                placeholder="••••••••"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading || !username || !password}
            className="w-full mt-6 py-2.5 bg-matrix-green/10 border border-matrix-green text-matrix-green rounded font-semibold hover:bg-matrix-green/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Authenticating...
              </>
            ) : (
              'Access Dashboard'
            )}
          </button>

          <p className="text-gray-600 text-xs mt-4 text-center">
            Default credentials: admin / ddos-shield-2024
          </p>
        </form>
      </div>
    </div>
  )
}
