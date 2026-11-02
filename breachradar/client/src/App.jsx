import { useState } from 'react'

export default function App() {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  async function handleSubmit(e) {
    e.preventDefault()
    setLoading(true)
    setError('')
    setResult(null)

    try {
      // relative URL — Vite proxies this to http://localhost:5000/api/scan
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      })

      const data = await res.json()

      if (!res.ok) {
        throw new Error(data.error || data.errors?.[0]?.msg || 'Scan failed')
      }

      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const severityColor = {
    Safe: 'bg-green-600',
    Low: 'bg-yellow-500',
    Medium: 'bg-orange-500',
    High: 'bg-red-500',
    Critical: 'bg-red-700',
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-8">
      <div className="max-w-2xl mx-auto">
        <h1 className="text-4xl font-bold mb-2">BreachRadar 🔐</h1>
        <p className="text-slate-400 mb-8">
          Scan an email against known data breaches.
        </p>

        <form onSubmit={handleSubmit} className="flex gap-2 mb-8">
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            className="flex-1 px-4 py-3 rounded-lg bg-slate-800 border border-slate-700 focus:outline-none focus:border-cyan-500"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 font-semibold"
          >
            {loading ? 'Scanning…' : 'Scan'}
          </button>
        </form>

        {error && (
          <div className="p-4 bg-red-900/40 border border-red-700 rounded-lg mb-6">
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-6">
            <div className="p-6 bg-slate-900 rounded-lg border border-slate-800">
              <div className="flex items-center justify-between mb-4">
                <span className="text-slate-400">Risk Score</span>
                <span
                  className={`px-3 py-1 rounded-full text-sm font-semibold ${
                    severityColor[result.severity] || 'bg-slate-700'
                  }`}
                >
                  {result.severity} — {result.riskScore}/100
                </span>
              </div>
              <div className="text-2xl font-bold">
                {result.breachCount} breach{result.breachCount === 1 ? '' : 'es'} found
              </div>
              <div className="text-slate-400 text-sm mt-1">{result.email}</div>
            </div>

            {result.breaches?.length > 0 && (
              <div className="space-y-3">
                <h2 className="text-xl font-semibold">Breaches</h2>
                {result.breaches.map((b, i) => (
                  <div
                    key={i}
                    className="p-4 bg-slate-900 rounded-lg border border-slate-800"
                  >
                    <div className="font-semibold text-lg">{b.name}</div>
                    <div className="text-slate-400 text-sm mb-2">
                      {b.breachDate} {b.domain && `· ${b.domain}`}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {b.dataClasses?.map((d, j) => (
                        <span
                          key={j}
                          className="text-xs px-2 py-1 rounded bg-slate-800 text-slate-300"
                        >
                          {d}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}