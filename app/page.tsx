'use client'

import { Navbar } from '@/components/navbar'
import { HeroSection } from '@/components/hero-section'
import { DetectionForm } from '@/components/detection-form'
import { DetectionLifecycle } from '@/components/detection-lifecycle'
import { FeaturesSection } from '@/components/features-section'
import { MonitoringDashboard } from '@/components/monitoring-dashboard'
import { TeamSection } from '@/components/team-section'
import { Footer } from '@/components/footer'

export default function Home() {
  return (
    <main className="glass-main min-h-screen">
      <Navbar />
      <HeroSection />
      <DetectionForm />
      <DetectionLifecycle />
      <FeaturesSection />
      <MonitoringDashboard />
      <TeamSection />
      <Footer />
    </main>
  )
}
