'use client'

import Link from 'next/link'
import { useEffect, useState } from 'react'

import { DetectionForm } from '@/components/detection-form'
import { ProtectedRoute } from '@/components/protected-route'
import { API_BASE_URL, getAuthHeader, getStoredUser } from '@/lib/auth'

type ScanResultItem = {
  id: string
  email: string
  url: string
  result: {
    status?: string
    confidence?: number
    message?: string
  }
  timestamp: string
}

export default function DashboardPage() {
  const user = getStoredUser()
  const [isLoading, setIsLoading] = useState(true)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [scanHistory, setScanHistory] = useState<ScanResultItem[]>([])
  const [refreshKey, setRefreshKey] = useState(0)

  useEffect(() => {
    const loadScanHistory = async () => {
      setIsLoading(true)
      setErrorMessage(null)

      try {
        const authHeaders = getAuthHeader()
        const response = await fetch(`${API_BASE_URL}/scan-results/history?limit=100`, {
          headers: authHeaders,
        })

        if (!response.ok) {
          throw new Error('Failed to load scan history.')
        }

        const payload = (await response.json()) as { items?: ScanResultItem[] }
        setScanHistory(payload.items || [])
      } catch (error) {
        setErrorMessage(error instanceof Error ? error.message : 'Unable to load scan history.')
      } finally {
        setIsLoading(false)
      }
    }

    void loadScanHistory()

    // Listen for scan completion events
    const handleScanCompleted = () => {
      setRefreshKey((prev) => prev + 1)
    }

    window.addEventListener('scanCompleted', handleScanCompleted)
    return () => window.removeEventListener('scanCompleted', handleScanCompleted)
  }, [refreshKey])

  const stats = {
    totalScans: scanHistory.length,
    phishingCount: scanHistory.filter((item) => item.result?.status === 'Phishing').length,
    suspiciousCount: scanHistory.filter((item) => item.result?.status === 'Suspicious').length,
  }

  const handleRefresh = () => {
    setRefreshKey((prev) => prev + 1)
  }

  return (
    <ProtectedRoute>
      <main className="min-h-screen bg-background px-6 py-12">
        <div className="mx-auto max-w-7xl">
          <div className="mb-10 flex flex-col gap-4 border-b border-muted pb-6 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-semibold text-primary">SentinelGuard AI</p>
              <h1 className="mt-2 text-3xl font-bold text-foreground">Dashboard</h1>
              <p className="mt-2 text-sm text-foreground/60">
                {user?.email ? `Logged in as ${user.email}` : 'Your scan results and activity.'}
              </p>
            </div>
            <div className="flex flex-wrap gap-3">
              <button
                onClick={handleRefresh}
                className="inline-flex rounded-lg border border-muted px-5 py-3 text-sm font-semibold text-foreground transition hover:bg-muted"
              >
                Refresh
              </button>
              <Link
                href="/admin"
                className="inline-flex rounded-lg bg-primary px-5 py-3 text-sm font-semibold text-white transition hover:bg-secondary"
              >
                Open admin dashboard
              </Link>
              <Link
                href="/"
                className="inline-flex rounded-lg border border-primary px-5 py-3 text-sm font-semibold text-primary transition hover:bg-muted"
              >
                Back to home
              </Link>
            </div>
          </div>

          <section className="mb-8 grid gap-4 md:grid-cols-3">
            <div className="rounded-xl border border-muted bg-white p-6 shadow-sm">
              <p className="text-sm text-foreground/60">Total Scans</p>
              <p className="mt-3 text-3xl font-bold text-foreground">{stats.totalScans}</p>
            </div>
            <div className="rounded-xl border border-muted bg-white p-6 shadow-sm">
              <p className="text-sm text-foreground/60">Phishing Detected</p>
              <p className="mt-3 text-3xl font-bold text-red-600">{stats.phishingCount}</p>
            </div>
            <div className="rounded-xl border border-muted bg-white p-6 shadow-sm">
              <p className="text-sm text-foreground/60">Suspicious</p>
              <p className="mt-3 text-3xl font-bold text-yellow-600">{stats.suspiciousCount}</p>
            </div>
          </section>

          <section className="mb-8 grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
            <div className="glass-panel rounded-2xl p-6">
              <p className="text-sm font-semibold text-primary">Quick Check</p>
              <h2 className="mt-2 text-2xl font-bold text-foreground">Check an email or URL right away</h2>
              <p className="mt-2 max-w-2xl text-sm text-foreground/60">
                Paste the email content you want reviewed and drop in the suspicious link. The scanner is ready as soon as you log in.
              </p>
              <div className="mt-6">
                <DetectionForm embedded />
              </div>
            </div>

            <div className="glass-panel rounded-2xl p-6">
              <p className="text-sm font-semibold text-primary">Workflow</p>
              <h2 className="mt-2 text-2xl font-bold text-foreground">Fastest way to verify a threat</h2>
              <div className="mt-6 space-y-4 text-sm text-foreground/70">
                <div className="rounded-xl border border-muted bg-white/70 p-4">
                  <p className="font-semibold text-foreground">1. Paste email content</p>
                  <p className="mt-1">Add the suspicious message text or headers you want to inspect.</p>
                </div>
                <div className="rounded-xl border border-muted bg-white/70 p-4">
                  <p className="font-semibold text-foreground">2. Add the URL</p>
                  <p className="mt-1">Include the destination link so the model can score the full threat.</p>
                </div>
                <div className="rounded-xl border border-muted bg-white/70 p-4">
                  <p className="font-semibold text-foreground">3. Review the result</p>
                  <p className="mt-1">Get an immediate verdict and see it saved in your scan history.</p>
                </div>
              </div>
            </div>
          </section>

          {errorMessage ? (
            <div className="mb-6 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
              {errorMessage}
            </div>
          ) : null}

          <section className="rounded-xl border border-muted bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-xl font-semibold text-foreground">Recent Scan Results</h2>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-muted text-sm">
                <thead className="bg-muted/40">
                  <tr>
                    <th className="px-4 py-3 text-left font-semibold text-foreground">Email</th>
                    <th className="px-4 py-3 text-left font-semibold text-foreground">URL</th>
                    <th className="px-4 py-3 text-left font-semibold text-foreground">Status</th>
                    <th className="px-4 py-3 text-left font-semibold text-foreground">Confidence</th>
                    <th className="px-4 py-3 text-left font-semibold text-foreground">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-muted">
                  {isLoading ? (
                    <tr>
                      <td className="px-4 py-4 text-foreground/60" colSpan={5}>
                        Loading scan results...
                      </td>
                    </tr>
                  ) : scanHistory.length === 0 ? (
                    <tr>
                      <td className="px-4 py-4 text-foreground/60" colSpan={5}>
                        No scans yet. Try analyzing an email or URL above.
                      </td>
                    </tr>
                  ) : (
                    scanHistory.map((item) => (
                      <tr key={item.id} className="hover:bg-muted/20">
                        <td className="max-w-xs truncate px-4 py-3 text-foreground/80">{item.email || '-'}</td>
                        <td className="max-w-xs truncate px-4 py-3 text-foreground/80">{item.url || '-'}</td>
                        <td className="px-4 py-3">
                          <span
                            className={`rounded-full px-2.5 py-1 text-xs font-semibold ${
                              item.result?.status === 'Phishing'
                                ? 'bg-red-100 text-red-700'
                                : item.result?.status === 'Suspicious'
                                  ? 'bg-yellow-100 text-yellow-700'
                                  : 'bg-green-100 text-green-700'
                            }`}
                          >
                            {item.result?.status || 'Unknown'}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-foreground/80">
                          {typeof item.result?.confidence === 'number'
                            ? `${Math.round(item.result.confidence)}%`
                            : '-'}
                        </td>
                        <td className="px-4 py-3 text-sm text-foreground/70">
                          {item.timestamp ? new Date(item.timestamp).toLocaleString() : '-'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </main>
    </ProtectedRoute>
  )
}
