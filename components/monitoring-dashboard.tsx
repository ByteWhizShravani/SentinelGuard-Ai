'use client'

export function MonitoringDashboard() {
  const threats = [
    {
      source: 'paypal-secure-auth.net',
      timestamp: '15 mins ago',
      type: 'Phishing',
      status: 'phishing',
      score: '98%',
    },
    {
      source: 'support@xyz.com',
      timestamp: '1 hour ago',
      type: 'Email Header',
      status: 'safe',
      score: '0.2%',
    },
    {
      source: 'verify-bank-details.exe',
      timestamp: '3 hours ago',
      type: 'Credential Harvest',
      status: 'phishing',
      score: '94%',
    },
    {
      source: 'newsletter@company.net',
      timestamp: '5 hours ago',
      type: 'Safe Content',
      status: 'safe',
      score: '0.1%',
    },
    {
      source: 'admin-portal-confirm.io',
      timestamp: '8 hours ago',
      type: 'URL Malicious',
      status: 'phishing',
      score: '87%',
    },
  ]

  const getStatusBadge = (status: string) => {
    if (status === 'phishing') {
      return (
        <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-100 text-red-700 text-xs font-semibold">
          <div className="w-2 h-2 rounded-full bg-red-500"></div>
          Phishing
        </span>
      )
    }
    return (
      <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-green-100 text-green-700 text-xs font-semibold">
        <div className="w-2 h-2 rounded-full bg-green-500"></div>
        Safe
      </span>
    )
  }

  return (
    <section className="max-w-7xl mx-auto px-6 py-16 md:py-24">
      <h2 className="text-4xl font-bold mb-12">Threat Monitoring Dashboard</h2>

      <div className="glass-panel overflow-x-auto rounded-xl">
        <table className="w-full">
          <thead>
            <tr className="border-b border-black/10 bg-white/76">
              <th className="text-left px-6 py-4 font-semibold text-foreground">ENTITY SOURCE</th>
              <th className="text-left px-6 py-4 font-semibold text-foreground">TIMESTAMP</th>
              <th className="text-left px-6 py-4 font-semibold text-foreground">THREAT TYPE</th>
              <th className="text-left px-6 py-4 font-semibold text-foreground">STATUS</th>
              <th className="text-left px-6 py-4 font-semibold text-foreground">SCORE</th>
            </tr>
          </thead>
          <tbody>
            {threats.map((threat, index) => (
              <tr
                key={index}
                className="border-b border-black/10 transition hover:bg-white/70"
              >
                <td className="px-6 py-4 text-sm font-mono text-foreground/70">
                  {threat.source}
                </td>
                <td className="px-6 py-4 text-sm text-foreground/60">{threat.timestamp}</td>
                <td className="px-6 py-4 text-sm text-foreground">{threat.type}</td>
                <td className="px-6 py-4">{getStatusBadge(threat.status)}</td>
                <td className="px-6 py-4 text-sm font-semibold">{threat.score}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
