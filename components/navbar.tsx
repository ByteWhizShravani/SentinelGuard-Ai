'use client'

import Link from 'next/link'

export function Navbar() {
  return (
    <nav className="sticky top-0 z-50 border-b border-black/10 bg-white/68 backdrop-blur-md backdrop-saturate-150">
      <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        {/* Logo */}
        <div className="text-xl font-bold text-foreground">
          SentinelGuard AI
        </div>

        {/* Center Menu */}
        <div className="hidden md:flex gap-8">
          <a href="#home" className="text-sm font-medium text-primary hover:text-secondary transition">
            Home
          </a>
          <a href="#detection" className="text-sm font-medium text-foreground hover:text-primary transition">
            Detection
          </a>
          <a href="#process" className="text-sm font-medium text-foreground hover:text-primary transition">
            Process
          </a>
          <a href="#features" className="text-sm font-medium text-foreground hover:text-primary transition">
            Features
          </a>
          <a href="#team" className="text-sm font-medium text-foreground hover:text-primary transition">
            Team
          </a>
        </div>

        {/* Right Section */}
        <div className="flex items-center gap-4">
          <Link href="/login" className="text-sm font-medium text-foreground hover:text-primary transition hidden sm:block">
            Sign In
          </Link>
          <Link href="/signup" className="rounded-full bg-primary px-6 py-2 text-sm font-semibold text-white transition hover:bg-secondary">
            Get Started
          </Link>
        </div>
      </div>
    </nav>
  )
}
