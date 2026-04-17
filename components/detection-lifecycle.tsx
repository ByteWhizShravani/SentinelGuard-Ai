'use client'

import { Database, Zap, Brain, CheckCircle2, AlertCircle } from 'lucide-react'

export function DetectionLifecycle() {
  const steps = [
    {
      number: 1,
      label: 'Input Data',
      icon: Database,
      description: 'Collecting email texts, URLs, and metadata',
    },
    {
      number: 2,
      label: 'Feature Extraction',
      icon: Zap,
      description: 'Breaking down complex patterns and characteristics',
    },
    {
      number: 3,
      label: 'AI Analysis',
      icon: Brain,
      description: 'Processing features through neural networks',
      highlight: true,
    },
    {
      number: 4,
      label: 'Prediction',
      icon: CheckCircle2,
      description: 'Generating threat assessment scores',
    },
    {
      number: 5,
      label: 'Alert Output',
      icon: AlertCircle,
      description: 'Delivering results and recommendations',
    },
  ]

  return (
    <section id="process" className="max-w-7xl mx-auto px-6 py-16 md:py-24">
      <div className="text-center mb-16">
        <h2 className="text-4xl font-bold mb-4">Detection Lifecycle</h2>
        <p className="text-foreground/60 text-lg">
          Our multi-layered analysis pipeline ensures precision security
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-5 gap-4 md:gap-0">
        {steps.map((step, index) => {
          const Icon = step.icon
          return (
            <div key={index} className="relative">
              <div
                className={`p-6 rounded-xl text-center transition ${
                  step.highlight
                    ? 'glass-panel z-10 scale-105 border-primary/45 md:scale-110'
                    : 'glass-panel hover:border-primary/40'
                }`}
              >
                <div
                  className={`inline-flex items-center justify-center w-12 h-12 rounded-full mb-4 ${
                    step.highlight
                      ? 'bg-primary text-white'
                      : 'bg-primary/20 text-primary'
                  }`}
                >
                  <Icon size={20} />
                </div>

                <h3 className="font-semibold text-foreground mb-2">{step.label}</h3>
                <p className="text-sm text-foreground/60">{step.description}</p>
              </div>

              {/* Connector Line */}
              {index < steps.length - 1 && (
                <div className="hidden md:block absolute top-1/2 -right-2 w-4 h-0.5 bg-black/25 transform -translate-y-1/2"></div>
              )}
            </div>
          )
        })}
      </div>
    </section>
  )
}
