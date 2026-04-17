'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useEffect, useMemo, useState } from 'react'

import { ProtectedRoute } from '@/components/protected-route'
import { API_BASE_URL, clearAuthStorage, getAuthHeader } from '@/lib/auth'

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

type UserItem = {
  id: string
  email: string
  created_at: string
  updated_at: string
}

type StatusFilter = 'All' | 'Safe' | 'Phishing'

export default function AdminDashboardPage() {
  const router = useRouter()
  const [isLoading, setIsLoading] = useState(true)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('All')
  const [scanResults, setScanResults] = useState<ScanResultItem[]>([])
  const [users, setUsers] = useState<UserItem[]>([])

  useEffect(() => {
    const loadAdminData = async () => {
      setIsLoading(true)
      setErrorMessage(null)

      try {
        const authHeaders = getAuthHeader()
        const [scanResponse, usersResponse] = await Promise.all([
          fetch(`${API_BASE_URL}/scan-results/history?limit=200`, {
            headers: authHeaders,
          }),
          fetch(`${API_BASE_URL}/users?limit=200`, {
            headers: authHeaders,
          }),
        ])

        if (scanResponse.status === 401 || usersResponse.status === 401) {
          clearAuthStorage()
          router.replace('/login')
          return
        }

        if (!scanResponse.ok || !usersResponse.ok) {
          throw new Error('Failed to load admin dashboard data.')
        }

        const scanPayload = (await scanResponse.json()) as { items?: ScanResultItem[] }
        const usersPayload = (await usersResponse.json()) as { items?: UserItem[] }

        setScanResults(scanPayload.items || [])
        setUsers(usersPayload.items || [])
      } catch (error) {
        setErrorMessage(
          error instanceof Error ? error.message : 'Unable to load admin data right now.'
        )
      } finally {
        setIsLoading(false)
      }
    }

    void loadAdminData()
  }, [router])

  const filteredScanResults = useMemo(() => {
    if (statusFilter === 'All') {
      return scanResults
    }

    return scanResults.filter((item) => item.result?.status === statusFilter)
  }, [scanResults, statusFilter])

  return (
    <ProtectedRoute requireRole="admin">
      <main className="min-h-screen bg-background px-6 py-12">
        <div className="mx-auto max-w-7xl space-y-8">
          <div className="flex flex-col gap-4 border-b border-muted pb-6 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-semibold text-primary">SentinelGuard AI</p>
              <h1 className="mt-2 text-3xl font-bold text-foreground">Admin Dashboard</h1>
              <p className="mt-2 text-sm text-foreground/60">
                Review scan outcomes and monitor user activity.
              </p>
            </div>
            <Link
              href="/dashboard"
              className="inline-flex rounded-lg border border-primary px-4 py-2 text-sm font-semibold text-primary transition hover:bg-muted"
            >
              Back to dashboard
            </Link>
          </div>

          {errorMessage ? (
            <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
              {errorMessage}
            </div>
          ) : null}

          <section className="rounded-xl border border-muted bg-white p-6 shadow-sm">
            <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <h2 className="text-xl font-semibold text-foreground">Scan Results</h2>
              <div className="flex items-center gap-2">
                <label htmlFor="statusFilter" className="text-sm font-medium text-foreground/70">
                  Filter
                </label>
                <select
                  id="statusFilter"
                  value={statusFilter}
                  onChange={(event) => setStatusFilter(event.target.value as StatusFilter)}
                  className="rounded-md border border-muted bg-background px-3 py-2 text-sm"
                >
                  <option value="All">All</option>
                  <option value="Safe">Safe</option>
                  <option value="Phishing">Phishing</option>
                </select>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-muted text-sm">
                <thead className="bg-muted/40">
                  <tr>
                    <th className="px-4 py-3 text-left font-semibold text-foreground">Email Input</th>
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
                  ) : filteredScanResults.length === 0 ? (
                    <tr>
                      <td className="px-4 py-4 text-foreground/60" colSpan={5}>
                        No scan results found.
                      </td>
                    </tr>
                  ) : (
                    filteredScanResults.map((item) => (
                      <tr key={item.id} className="hover:bg-muted/20">
                        <td className="px-4 py-3 text-foreground/80">{item.email || '-'}</td>
                        <td className="max-w-xs truncate px-4 py-3 text-foreground/80">{item.url || '-'}</td>
                        <td className="px-4 py-3">
                          <span
                            className={`rounded-full px-2.5 py-1 text-xs font-semibold ${
                              item.result?.status === 'Phishing'
                                ? 'bg-red-100 text-red-700'
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
                        <td className="px-4 py-3 text-foreground/70">
                          {item.timestamp ? new Date(item.timestamp).toLocaleString() : '-'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="rounded-xl border border-muted bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-xl font-semibold text-foreground">Users</h2>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-muted text-sm">
                <thead className="bg-muted/40">
                  <tr>
                    <th className="px-4 py-3 text-left font-semibold text-foreground">Email</th>
                    <th className="px-4 py-3 text-left font-semibold text-foreground">Created</th>
                    <th className="px-4 py-3 text-left font-semibold text-foreground">Updated</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-muted">
                  {isLoading ? (
                    <tr>
                      <td className="px-4 py-4 text-foreground/60" colSpan={3}>
                        Loading users...
                      </td>
                    </tr>
                  ) : users.length === 0 ? (
                    <tr>
                      <td className="px-4 py-4 text-foreground/60" colSpan={3}>
                        No users found.
                      </td>
                    </tr>
                  ) : (
                    users.map((user) => (
                      <tr key={user.id} className="hover:bg-muted/20">
                        <td className="px-4 py-3 text-foreground/80">{user.email || '-'}</td>
                        <td className="px-4 py-3 text-foreground/70">
                          {user.created_at ? new Date(user.created_at).toLocaleString() : '-'}
                        </td>
                        <td className="px-4 py-3 text-foreground/70">
                          {user.updated_at ? new Date(user.updated_at).toLocaleString() : '-'}
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
